package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/ahoo/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
	"github.com/ahoo/cpa-plugin-privacyfilter/walker"
)

const maxFailureDiagnosticPaths = 4

type unsupportedRequestShapeError struct {
	count int
	paths []payload.Path
}

func (e *unsupportedRequestShapeError) Error() string {
	return "privacyfilter: unsupported request shape"
}

func (e *unsupportedRequestShapeError) Unwrap() error {
	return errUnsupportedRequestShape
}

type targetInspectionError struct {
	path  payload.Path
	cause error
}

func (e *targetInspectionError) Error() string {
	return "privacyfilter: request target inspection failed"
}

func (e *targetInspectionError) Unwrap() error {
	return e.cause
}

type sanitizeResult struct {
	body        []byte
	changed     bool
	findings    int
	targets     int
	skipped     int
	opaque      int
	unsupported int
	mlFlagged   int
}

type requestInspectionBudget struct {
	engine          *privacyengine.Budget
	limits          payload.Limits
	jsonNodes       int
	structuralBytes int
	// mlFlagged counts ML second-opinion hits. Shared by pointer so nested
	// scans accumulate into the request root; nil disables counting.
	mlFlagged *int
}

const maxEncodedJSONNesting = 4

func newRequestInspectionBudget(
	engine *privacyengine.Budget,
	limits payload.Limits,
	initialNodes int,
	initialStructuralBytes int,
) (*requestInspectionBudget, error) {
	normalized, err := limits.Normalized()
	if err != nil {
		return nil, err
	}
	if engine == nil {
		return nil, privacyengine.ErrInternalFailure
	}
	if initialNodes < 0 || initialStructuralBytes < 0 {
		return nil, privacyengine.ErrInternalFailure
	}
	if initialNodes > normalized.MaxNodes {
		return nil, fmt.Errorf("%w: cumulative JSON nodes exceed request limit", payload.ErrNodeLimit)
	}
	if initialStructuralBytes > normalized.MaxStructuralBytes {
		return nil, fmt.Errorf("%w: cumulative structure exceeds request limit", payload.ErrStructuralLimit)
	}
	return &requestInspectionBudget{
		engine:          engine,
		limits:          normalized,
		jsonNodes:       initialNodes,
		structuralBytes: initialStructuralBytes,
	}, nil
}

func (b *requestInspectionBudget) scanEncodedJSON(ctx context.Context, text string) (*payload.Document, error) {
	if b == nil || b.engine == nil {
		return nil, privacyengine.ErrInternalFailure
	}
	remainingNodes := b.limits.MaxNodes - b.jsonNodes
	if remainingNodes <= 0 {
		return nil, fmt.Errorf("%w: cumulative JSON node budget exhausted", payload.ErrNodeLimit)
	}
	remainingStructural := b.limits.MaxStructuralBytes - b.structuralBytes
	if remainingStructural <= 0 {
		return nil, fmt.Errorf("%w: cumulative structural budget exhausted", payload.ErrStructuralLimit)
	}
	scanLimits := b.limits
	scanLimits.MaxNodes = remainingNodes
	scanLimits.MaxStructuralBytes = remainingStructural
	document, err := payload.Scan(ctx, []byte(text), payload.ScanOptions{Limits: scanLimits})
	if err != nil {
		return nil, err
	}
	b.jsonNodes += document.NodeCount()
	b.structuralBytes += document.StructuralBytes()
	return document, nil
}

type requestRenderer struct {
	mu       sync.Mutex
	base     privacyengine.Renderer
	seen     map[[sha256.Size]byte]string
	produced map[[sha256.Size]byte]struct{}
	next     map[privacyengine.Kind]int
}

func newRequestRenderer(base privacyengine.Renderer) *requestRenderer {
	return &requestRenderer{
		base:     base,
		seen:     make(map[[sha256.Size]byte]string),
		produced: make(map[[sha256.Size]byte]struct{}),
		next:     make(map[privacyengine.Kind]int),
	}
}

func (r *requestRenderer) Render(ctx context.Context, finding privacyengine.Finding, plaintext string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := sha256.Sum256([]byte(string(finding.Kind) + "\x00" + plaintext))
	if replacement, ok := r.seen[key]; ok {
		return replacement, nil
	}
	base, err := r.base.Render(ctx, finding, plaintext)
	if err != nil {
		return "", err
	}
	r.next[finding.Kind]++
	replacement := numberedPlaceholder(base, r.next[finding.Kind])
	r.seen[key] = replacement
	r.produced[sha256.Sum256([]byte(replacement))] = struct{}{}
	return replacement, nil
}

func (r *requestRenderer) producedPlaceholder(value string) bool {
	if r == nil {
		return false
	}
	hash := sha256.Sum256([]byte(value))
	r.mu.Lock()
	_, ok := r.produced[hash]
	r.mu.Unlock()
	return ok
}

func numberedPlaceholder(base string, number int) string {
	if base == "" || number <= 1 {
		return base
	}
	suffix := "#" + strconv.Itoa(number)
	switch {
	case strings.HasSuffix(base, "]"):
		return strings.TrimSuffix(base, "]") + suffix + "]"
	case strings.HasSuffix(base, ">"):
		return strings.TrimSuffix(base, ">") + suffix + ">"
	default:
		return base + suffix
	}
}

func (p *privacyFilterPlugin) sanitizeRequest(ctx context.Context, sourceFormat string, body []byte) (sanitizeResult, error) {
	return p.sanitizeRequestWithRenderer(ctx, sourceFormat, body, newRequestRenderer(p.renderer))
}

func (p *privacyFilterPlugin) sanitizeRequestWithRenderer(
	ctx context.Context,
	sourceFormat string,
	body []byte,
	renderer privacyengine.Renderer,
) (sanitizeResult, error) {
	result := sanitizeResult{body: body}
	walked, err := walker.Walk(ctx, sourceFormat, body, walker.Options{
		ScanOptions: payload.ScanOptions{Limits: p.cfg.payloadLimits()},
	})
	if err != nil {
		return result, err
	}
	result.targets = len(walked.Targets)
	result.skipped = walked.Skipped
	result.opaque = walked.Opaque
	result.unsupported = walked.UnsupportedCount
	if walked.UnsupportedCount > 0 {
		paths := make([]payload.Path, 0, min(walked.UnsupportedCount, maxFailureDiagnosticPaths))
		for _, issue := range walked.Unsupported {
			if len(paths) == maxFailureDiagnosticPaths {
				break
			}
			paths = append(paths, issue.Path.Clone())
		}
		return result, &unsupportedRequestShapeError{count: walked.UnsupportedCount, paths: paths}
	}

	budget, err := privacyengine.NewBudget(p.cfg.engineLimits())
	if err != nil {
		return result, err
	}
	inspectionBudget, err := newRequestInspectionBudget(
		budget,
		p.cfg.payloadLimits(),
		walked.JSONNodes,
		walked.StructuralBytes,
	)
	if err != nil {
		return result, err
	}
	mlHits := 0
	inspectionBudget.mlFlagged = &mlHits
	if renderer == nil {
		renderer = newRequestRenderer(p.renderer)
	}
	replacements := make([]payload.Replacement, 0, len(walked.Targets))
	for _, target := range walked.Targets {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		value, findings, changed, err := p.sanitizeTarget(ctx, target, inspectionBudget, renderer)
		if err != nil {
			return result, &targetInspectionError{path: target.Path.Clone(), cause: err}
		}
		result.findings += findings
		if changed && p.cfg.Mode != modeAudit {
			replacements = append(replacements, payload.Replacement{Token: target.Token, Value: value})
		}
	}
	if p.cfg.Mode == modeAudit || len(replacements) == 0 {
		result.mlFlagged = mlHits
		return result, nil
	}
	out, changed, err := walked.Document.Replace(ctx, replacements)
	if err != nil {
		return result, err
	}
	if changed {
		result.body = out
		result.changed = true
	}
	result.mlFlagged = mlHits
	return result, nil
}

func (p *privacyFilterPlugin) sanitizeTarget(
	ctx context.Context,
	target walker.Target,
	budget *requestInspectionBudget,
	renderer privacyengine.Renderer,
) (string, int, bool, error) {
	if budget == nil {
		return target.Token.Value, 0, false, privacyengine.ErrInternalFailure
	}
	switch target.Mutable {
	case walker.MutabilityDirect:
		return p.sanitizeText(
			ctx,
			target.Token.Value,
			budget.engine,
			renderer,
			engineFieldContext(target.Context),
			budget.mlFlagged,
		)
	case walker.MutabilityEncodedJSON:
		return p.sanitizeJSONTextWithBudget(ctx, target.Token.Value, budget, renderer, target.Context, false, 0)
	case walker.MutabilityJSONOrPlain:
		return p.sanitizeJSONTextWithBudget(ctx, target.Token.Value, budget, renderer, target.Context, true, 0)
	default:
		return target.Token.Value, 0, false, fmt.Errorf("%w: invalid target mutability", errUnsupportedRequestShape)
	}
}

func (p *privacyFilterPlugin) sanitizeJSONText(
	ctx context.Context,
	text string,
	budget *privacyengine.Budget,
	renderer privacyengine.Renderer,
	outerContext walker.TargetContext,
	allowPlain bool,
) (string, int, bool, error) {
	inspectionBudget, err := newRequestInspectionBudget(budget, p.cfg.payloadLimits(), 0, 0)
	if err != nil {
		return text, 0, false, err
	}
	return p.sanitizeJSONTextWithBudget(ctx, text, inspectionBudget, renderer, outerContext, allowPlain, 0)
}

func (p *privacyFilterPlugin) sanitizeJSONTextWithLimits(
	ctx context.Context,
	text string,
	budget *privacyengine.Budget,
	renderer privacyengine.Renderer,
	outerContext walker.TargetContext,
	allowPlain bool,
	limits payload.Limits,
) (string, int, bool, error) {
	inspectionBudget, err := newRequestInspectionBudget(budget, limits, 0, 0)
	if err != nil {
		return text, 0, false, err
	}
	return p.sanitizeJSONTextWithBudget(ctx, text, inspectionBudget, renderer, outerContext, allowPlain, 0)
}

func (p *privacyFilterPlugin) sanitizeJSONTextWithBudget(
	ctx context.Context,
	text string,
	budget *requestInspectionBudget,
	renderer privacyengine.Renderer,
	outerContext walker.TargetContext,
	allowPlain bool,
	nesting int,
) (string, int, bool, error) {
	if budget == nil || budget.engine == nil {
		return text, 0, false, privacyengine.ErrInternalFailure
	}
	fieldContext := engineFieldContext(outerContext)
	if privacyengine.CredentialFieldApplies(fieldContext) {
		return p.sanitizeText(ctx, text, budget.engine, renderer, fieldContext, budget.mlFlagged)
	}
	sanitizePlain := func() (string, int, bool, error) {
		plainContext := fieldContext
		if !outerContext.Structured {
			plainContext.Structured = false
			plainContext.Encoded = false
		}
		return p.sanitizeText(ctx, text, budget.engine, renderer, plainContext, budget.mlFlagged)
	}
	if allowPlain && !looksLikeEncodedJSONContainer(text) {
		return sanitizePlain()
	}

	document, err := budget.scanEncodedJSON(ctx, text)
	if err != nil {
		if allowPlain && errors.Is(err, payload.ErrInvalidJSON) {
			return sanitizePlain()
		}
		return text, 0, false, fmt.Errorf("%w: encoded tool JSON: %w", errUnsupportedRequestShape, err)
	}
	if nesting > maxEncodedJSONNesting {
		return text, 0, false, fmt.Errorf("%w: encoded tool JSON: %w", errUnsupportedRequestShape, payload.ErrDepthLimit)
	}

	replacements := make([]payload.Replacement, 0, document.StringCount())
	findingCount := 0
	for index := 0; index < document.StringCount(); index++ {
		token, ok := document.StringTokenAt(index)
		if !ok {
			return text, 0, false, errors.New("privacy filter: encoded JSON token index is unavailable")
		}
		fields, ok := document.StringKeyContextAt(index)
		if !ok {
			return text, 0, false, errors.New("privacy filter: encoded JSON field context is unavailable")
		}
		innerContext := outerContext
		innerContext.Fields = mergeStringKeyContexts(fields, outerContext.Fields)
		innerContext.Structured = true
		innerContext.Encoded = true

		var out string
		var findings int
		var changed bool
		if looksLikeEncodedJSONContainer(token.Value) {
			out, findings, changed, err = p.sanitizeJSONTextWithBudget(
				ctx,
				token.Value,
				budget,
				renderer,
				innerContext,
				true,
				nesting+1,
			)
		} else {
			out, findings, changed, err = p.sanitizeText(
				ctx,
				token.Value,
				budget.engine,
				renderer,
				engineFieldContext(innerContext),
				budget.mlFlagged,
			)
		}
		if err != nil {
			return text, 0, false, err
		}
		findingCount += findings
		if changed && p.cfg.Mode != modeAudit {
			replacements = append(replacements, payload.Replacement{Token: token, Value: out})
		}
	}
	if p.cfg.Mode == modeAudit || len(replacements) == 0 {
		return text, findingCount, false, nil
	}
	out, changed, err := document.Replace(ctx, replacements)
	if err != nil {
		return text, 0, false, err
	}
	return string(out), findingCount, changed, nil
}

func mergeStringKeyContexts(inner, outer payload.StringKeyContext) payload.StringKeyContext {
	merged := payload.StringKeyContext{ImmediateKey: inner.ImmediateKey}
	hasCredentialAncestorKey := func() bool {
		if privacyengine.IsCredentialAncestorFieldKey(merged.ImmediateKey) {
			return true
		}
		for index := 0; index < int(merged.AncestorCount); index++ {
			if privacyengine.IsCredentialAncestorFieldKey(merged.Ancestors[index]) {
				return true
			}
		}
		return false
	}
	appendAncestor := func(key string) {
		if key == "" {
			return
		}
		if int(merged.AncestorCount) >= len(merged.Ancestors) {
			if privacyengine.IsCredentialAncestorFieldKey(key) && !hasCredentialAncestorKey() {
				merged.Ancestors[len(merged.Ancestors)-1] = key
			}
			return
		}
		merged.Ancestors[merged.AncestorCount] = key
		merged.AncestorCount++
	}
	innerCount := int(inner.AncestorCount)
	if innerCount > len(inner.Ancestors) {
		innerCount = len(inner.Ancestors)
	}
	for index := 0; index < innerCount; index++ {
		appendAncestor(inner.Ancestors[index])
	}
	appendAncestor(outer.ImmediateKey)
	outerCount := int(outer.AncestorCount)
	if outerCount > len(outer.Ancestors) {
		outerCount = len(outer.Ancestors)
	}
	for index := 0; index < outerCount; index++ {
		appendAncestor(outer.Ancestors[index])
	}
	return merged
}

func looksLikeEncodedJSONContainer(text string) bool {
	trimmed := strings.TrimSpace(text)
	return strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
}

func engineFieldContext(context walker.TargetContext) privacyengine.FieldContext {
	fieldContext := privacyengine.FieldContext{
		ImmediateKey:  context.Fields.ImmediateKey,
		AncestorCount: context.Fields.AncestorCount,
		Structured:    context.Structured,
		Encoded:       context.Encoded,
	}
	copy(fieldContext.Ancestors[:], context.Fields.Ancestors[:])
	switch context.ToolScope {
	case walker.ScopeToolInput:
		fieldContext.ToolScope = privacyengine.ToolScopeInput
	case walker.ScopeToolOutput:
		fieldContext.ToolScope = privacyengine.ToolScopeOutput
	}
	return fieldContext
}

func (p *privacyFilterPlugin) sanitizeText(
	ctx context.Context,
	text string,
	budget *privacyengine.Budget,
	renderer privacyengine.Renderer,
	fieldContext privacyengine.FieldContext,
	mlFlagged *int,
) (string, int, bool, error) {
	if tokens, ok := renderer.(*tokenRenderer); ok {
		if spans := tokens.knownSpans(text); len(spans) != 0 {
			return p.sanitizeAroundTokens(ctx, text, spans, budget, renderer, fieldContext, mlFlagged)
		}
	}
	preservePlaceholder := false
	if requestRenderer, ok := renderer.(*requestRenderer); ok {
		preservePlaceholder = requestRenderer.producedPlaceholder(text)
	}
	result, err := p.engine.Redact(ctx, text, privacyengine.RequestOptions{
		Budget:              budget,
		Renderer:            renderer,
		PreferredRuleIDs:    p.blockRuleIDs,
		FieldContext:        fieldContext,
		PreservePlaceholder: preservePlaceholder,
	})
	if err != nil {
		return text, 0, false, err
	}
	if p.cfg.Mode != modeAudit {
		for _, finding := range result.Findings {
			if _, blocked := p.blockRuleIDs[finding.RuleID]; blocked {
				return text, len(result.Findings), false, &blockedFindingError{ruleID: finding.RuleID}
			}
		}
	}
	if len(result.Findings) == 0 && !preservePlaceholder && p.cfg.MLAssist.Enabled {
		if flagged, replacement, err := p.mlSecondOpinion(ctx, text, renderer); err == nil && flagged {
			if mlFlagged != nil {
				*mlFlagged++
			}
			if replacement != "" {
				return replacement, 1, true, nil
			}
		}
	}
	return result.Redacted, len(result.Findings), result.Hit(), nil
}

// sanitizeAroundTokens inspects the text between tokens this request already
// issued and leaves the tokens themselves untouched. A second interceptor pass
// therefore neither detects a token as a secret nor wraps it in another token,
// and a token is never turned back into its value on the request path.
func (p *privacyFilterPlugin) sanitizeAroundTokens(
	ctx context.Context,
	text string,
	spans [][2]int,
	budget *privacyengine.Budget,
	renderer privacyengine.Renderer,
	fieldContext privacyengine.FieldContext,
	mlFlagged *int,
) (string, int, bool, error) {
	var out strings.Builder
	out.Grow(len(text))
	findings := 0
	changed := false
	previous := 0
	inspect := func(segment string) error {
		if segment == "" {
			return nil
		}
		redacted, count, hit, err := p.sanitizeText(ctx, segment, budget, renderer, fieldContext, mlFlagged)
		if err != nil {
			return err
		}
		findings += count
		changed = changed || hit
		out.WriteString(redacted)
		return nil
	}
	for _, span := range spans {
		if err := inspect(text[previous:span[0]]); err != nil {
			return text, findings, false, err
		}
		out.WriteString(text[span[0]:span[1]])
		previous = span[1]
	}
	if err := inspect(text[previous:]); err != nil {
		return text, findings, false, err
	}
	if !changed {
		return text, findings, false, nil
	}
	return out.String(), findings, true, nil
}

// mlSecondOpinion rescores text the deterministic engine left clean with the
// distilled student. It returns flagged=true when the score reaches the
// configured threshold, plus a redacted replacement in enforce mode (empty
// in audit mode, or when the plugin itself runs in audit mode).
//
// The ML verdict never overrides engine findings (this runs only on zero
// findings), never inspects placeholders, and fails open on scorer errors:
// the engine already passed the text.
func (p *privacyFilterPlugin) mlSecondOpinion(ctx context.Context, text string, renderer privacyengine.Renderer) (bool, string, error) {
	if strings.TrimSpace(text) == "" {
		return false, "", nil
	}
	score, err := mlScore(text)
	if err != nil {
		return false, "", err
	}
	if score < p.cfg.MLAssist.effectiveThreshold() {
		return false, "", nil
	}
	if !p.cfg.MLAssist.enforce() || p.cfg.Mode == modeAudit {
		return true, "", nil
	}
	replacement, err := renderer.Render(ctx, privacyengine.Finding{
		Kind:   privacyengine.KindSecret,
		RuleID: mlRuleID,
		Start:  0,
		End:    len(text),
	}, text)
	if err != nil {
		return false, "", err
	}
	return true, replacement, nil
}
