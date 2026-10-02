package main

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/ahoo/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
	"github.com/ahoo/cpa-plugin-privacyfilter/walker"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

type privacyFilterPlugin struct {
	cfg          privacyFilterConfig
	engine       *privacyengine.Engine
	renderer     privacyengine.Renderer
	blockRuleIDs map[string]struct{}
	keyFilter    *keyFilter
	keyStats     *keyFilterStats
	// tok is non-nil only in mode: tokenize.
	tok        *tokenizer
	tokRuntime *tokenRuntime
	cache      *RequestScanCache
	revision   uint64
}

var _ pluginapi.RequestInterceptor = (*privacyFilterPlugin)(nil)

var errUnsupportedRequestShape = errors.New("privacyfilter: unsupported request shape")

type blockedFindingError struct {
	ruleID string
}

func (e *blockedFindingError) Error() string {
	return "privacyfilter: request matched a blocking rule"
}

func (p *privacyFilterPlugin) Identifier() string {
	return privacyFilterProvider
}

func (p *privacyFilterPlugin) InterceptRequestBeforeAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req, false)
}

func (p *privacyFilterPlugin) InterceptRequestAfterAuth(ctx context.Context, req pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error) {
	return p.interceptRequest(ctx, req, true)
}

func (p *privacyFilterPlugin) interceptRequest(ctx context.Context, req pluginapi.RequestInterceptRequest, afterAuth bool) (pluginapi.RequestInterceptResponse, error) {
	if p.cfg.shouldSkip(req.Model, req.RequestedModel, req.SourceFormat) {
		log.WithFields(log.Fields{
			"source_format": safeLogValue(req.SourceFormat),
			"model":         safeLogValue(req.RequestedModel),
		}).Warn("privacyfilter: request bypassed by skip configuration")
		return pluginapi.RequestInterceptResponse{}, nil
	}
	callerScope := callerScopeFromMetadata(req.Metadata)
	if p.keyFilter.active() {
		switch p.keyFilter.decide(callerScope, afterAuth) {
		case keyDecisionDefer:
			return pluginapi.RequestInterceptResponse{}, nil
		case keyDecisionSkip:
			p.keyStats.record(keyDecisionSkip)
			return pluginapi.RequestInterceptResponse{}, nil
		default:
			p.keyStats.record(keyDecisionFilter)
		}
	}
	if len(req.Body) == 0 {
		return p.handleFailure(req.SourceFormat, payload.ErrInvalidJSON), nil
	}

	modelContext := req.RequestedModel
	if modelContext == "" {
		modelContext = req.Model
	}
	state := p.cache.Acquire(req.RequestID, RequestScanContext{
		Revision:     p.revision,
		SourceFormat: req.SourceFormat,
		Model:        modelContext,
	})
	if state.Seen(req.Body) {
		return pluginapi.RequestInterceptResponse{}, nil
	}
	rendererState := state.GetOrCreateRendererState(func() any {
		return p.newRequestRendererState(req.RequestID, callerScope)
	})
	renderer, ok := rendererState.(privacyengine.Renderer)
	if !ok || renderer == nil {
		return p.handleFailure(req.SourceFormat, privacyengine.ErrInternalFailure), nil
	}
	tokens, tokenizing := renderer.(*tokenRenderer)

	result, errSanitize := p.sanitizeRequestWithRenderer(ctx, req.SourceFormat, req.Body, renderer)
	if errSanitize != nil {
		if tokenizing {
			tokens.discard()
		}
		return p.handleFailure(req.SourceFormat, errSanitize), nil
	}
	tokenized := 0
	if tokenizing {
		tokenized = tokens.commit()
	}
	if result.changed {
		state.Record(req.Body, result.body)
	} else {
		state.Record(req.Body, nil)
	}
	if result.findings > 0 || result.mlFlagged > 0 || result.unsupported > 0 {
		fields := log.Fields{
			"source_format": safeLogValue(req.SourceFormat),
			"model":         safeLogValue(req.RequestedModel),
			"mode":          string(p.cfg.Mode),
			"findings":      result.findings,
			"ml_flagged":    result.mlFlagged,
			"targets":       result.targets,
			"opaque":        result.opaque,
			"unsupported":   result.unsupported,
		}
		if tokenizing {
			fields["tokenized"] = tokenized
		}
		log.WithFields(fields).Info("privacyfilter: request inspection complete")
	}
	if !result.changed {
		return pluginapi.RequestInterceptResponse{}, nil
	}
	return pluginapi.RequestInterceptResponse{Body: result.body}, nil
}

// newRequestRendererState picks the renderer a request keeps across both
// interceptor passes: reversible tokens in tokenize mode, numbered irreversible
// placeholders otherwise.
func (p *privacyFilterPlugin) newRequestRendererState(requestID, callerScope string) privacyengine.Renderer {
	if p.tok != nil {
		if tokens := p.tok.newRenderer(requestID, callerScope, p.renderer); tokens != nil {
			return tokens
		}
	}
	return newRequestRenderer(p.renderer)
}

func (p *privacyFilterPlugin) handleFailure(sourceFormat string, err error) pluginapi.RequestInterceptResponse {
	var blocked *blockedFindingError
	if errors.As(err, &blocked) {
		log.WithFields(failureLogFields(sourceFormat, err)).Warn("privacyfilter: request blocked by privacy policy")
		return terminateRequest(
			sourceFormat,
			http.StatusUnprocessableEntity,
			"privacy_filter_rejected",
			"request blocked by privacy policy",
		)
	}
	if p.cfg.OnError == onErrorPassthrough {
		log.WithFields(failureLogFields(sourceFormat, err)).Warn("privacyfilter: inspection failed; request passed through by configuration")
		return pluginapi.RequestInterceptResponse{}
	}

	status := http.StatusServiceUnavailable
	code := "privacy_filter_internal_error"
	message := "privacy filter could not safely inspect the request"
	switch {
	case isLimitError(err):
		status = http.StatusRequestEntityTooLarge
		code = "privacy_filter_limit_exceeded"
		message = "request exceeds privacy inspection limits"
	case isUnsupportedError(err):
		status = http.StatusUnprocessableEntity
		code = "privacy_filter_unsupported_shape"
		message = "request shape is not safely inspectable"
	case isJSONError(err):
		status = http.StatusBadRequest
		code = "privacy_filter_invalid_json"
		message = "request body is not valid JSON"
	}
	log.WithFields(failureLogFields(sourceFormat, err)).Warn("privacyfilter: request inspection blocked")
	return terminateRequest(sourceFormat, status, code, message)
}

func failureLogFields(sourceFormat string, err error) log.Fields {
	fields := log.Fields{
		"source_format": safeLogValue(sourceFormat),
		"reason":        failureReason(err),
	}
	category, count, paths := failureDiagnostic(err)
	if category != "" {
		fields["issue_category"] = category
	}
	if count > 0 {
		fields["issue_count"] = count
	}
	if len(paths) > 0 {
		fields["issue_paths"] = strings.Join(paths, ",")
	}
	return fields
}

func failureDiagnostic(err error) (string, int, []string) {
	var unsupported *unsupportedRequestShapeError
	if errors.As(err, &unsupported) {
		return "unsupported_shape", unsupported.count, safeDiagnosticPaths(unsupported.paths)
	}
	var target *targetInspectionError
	if errors.As(err, &target) {
		category := "target_inspection"
		switch {
		case isLimitError(target.cause):
			category = "target_limit"
		case isJSONError(target.cause):
			category = "encoded_json_invalid"
		case isUnsupportedError(target.cause):
			category = "target_unsupported"
		}
		return category, 1, []string{safeDiagnosticPath(target.path)}
	}
	var shape *walker.ShapeError
	if errors.As(err, &shape) {
		return "invalid_shape", 1, []string{safeDiagnosticPath(shape.Path)}
	}
	var ambiguity *walker.AmbiguityError
	if errors.As(err, &ambiguity) {
		return "ambiguous_path", 1, []string{safeDiagnosticPath(ambiguity.Path)}
	}
	var unsupportedShape walker.UnsupportedShape
	if errors.As(err, &unsupportedShape) {
		return "unsupported_shape", 1, []string{safeDiagnosticPath(unsupportedShape.Path)}
	}
	return "", 0, nil
}

func safeDiagnosticPaths(paths []payload.Path) []string {
	if len(paths) == 0 {
		return nil
	}
	out := make([]string, 0, min(len(paths), maxFailureDiagnosticPaths))
	for _, path := range paths {
		if len(out) == maxFailureDiagnosticPaths {
			break
		}
		out = append(out, safeDiagnosticPath(path))
	}
	return out
}

func safeDiagnosticPath(path payload.Path) string {
	const maxSegments = 32
	var out strings.Builder
	out.WriteByte('$')
	for index, segment := range path {
		if index == maxSegments {
			out.WriteString(`["<truncated>"]`)
			break
		}
		if key, ok := segment.KeyValue(); ok {
			if !safeDiagnosticKey(key) {
				key = "<redacted>"
			}
			out.WriteByte('[')
			out.WriteString(strconv.Quote(key))
			out.WriteByte(']')
			continue
		}
		if arrayIndex, ok := segment.IndexValue(); ok {
			out.WriteByte('[')
			out.WriteString(strconv.Itoa(arrayIndex))
			out.WriteByte(']')
			continue
		}
		out.WriteString(`["<invalid>"]`)
	}
	return out.String()
}

func safeDiagnosticKey(key string) bool {
	switch key {
	case "messages", "message", "content", "role", "type", "text", "input", "output",
		"reasoning", "reasoning_content", "reasoning_details", "summary", "data", "signature",
		"encrypted_content", "format", "index", "id", "call_id", "tool_call_id", "name",
		"namespace", "status", "arguments", "function_call", "function_call_output", "tool_calls",
		"function", "custom_tool_call", "custom_tool_call_output", "additional_tools", "tools",
		"client_metadata", "x-codex-turn-metadata", "instructions", "prompt", "variables",
		"description", "parameters", "properties", "items", "schema", "input_schema", "output_schema",
		"system", "system_instruction", "parts", "contents", "candidates", "steps", "result",
		"action", "command", "environment", "code", "logs", "annotations", "metadata":
		return true
	default:
		return false
	}
}

func failureReason(err error) string {
	var blocked *blockedFindingError
	switch {
	case errors.As(err, &blocked):
		return "blocked_rule"
	case isLimitError(err):
		return "limit_exceeded"
	case isUnsupportedError(err):
		return "unsupported_shape"
	case isJSONError(err):
		return "invalid_json"
	default:
		return "internal_error"
	}
}

func isLimitError(err error) bool {
	return errors.Is(err, privacyengine.ErrBudgetExceeded) ||
		errors.Is(err, payload.ErrBodyTooLarge) ||
		errors.Is(err, payload.ErrDepthLimit) ||
		errors.Is(err, payload.ErrNodeLimit) ||
		errors.Is(err, payload.ErrStructuralLimit) ||
		errors.Is(err, payload.ErrStringTooLarge) ||
		errors.Is(err, payload.ErrReplacementLimit)
}

func isUnsupportedError(err error) bool {
	return errors.Is(err, errUnsupportedRequestShape) ||
		errors.Is(err, walker.ErrUnsupportedFormat) ||
		errors.Is(err, walker.ErrInvalidShape) ||
		errors.Is(err, walker.ErrUnsupportedShape) ||
		errors.Is(err, walker.ErrAmbiguousPath) ||
		errors.Is(err, payload.ErrRootNotObject)
}

func isJSONError(err error) bool {
	return errors.Is(err, payload.ErrInvalidJSON)
}

func safeLogValue(value string) string {
	value = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	const maxRunes = 128
	runes := []rune(value)
	if len(runes) > maxRunes {
		return string(runes[:maxRunes])
	}
	return value
}
