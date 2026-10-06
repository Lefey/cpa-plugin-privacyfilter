// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	pluginID                = "privacyfilter"
	syntheticValue          = "q7z"
	reasoningReplayText     = "integrity-replay-value"
	reasoningSensitiveValue = "replay@example.test"
	maxHTTPBody             = 2 << 20
)

type mockState struct {
	Requests                 int    `json:"requests"`
	BeforeOrderedRequests    int    `json:"before_ordered_requests"`
	AfterOrderedRequests     int    `json:"after_ordered_requests"`
	RedactedRequests         int    `json:"redacted_requests"`
	MarkerRequests           int    `json:"marker_requests"`
	BeforeProbeRequests      int    `json:"before_probe_requests"`
	AfterProbeRequests       int    `json:"after_probe_requests"`
	PlaceholderRequests      int    `json:"placeholder_requests"`
	ToolCallRequests         int    `json:"tool_call_requests"`
	ResponsesRequests        int    `json:"responses_requests"`
	ResponsesRedacted        int    `json:"responses_redacted"`
	ReasoningReplayRequests  int    `json:"reasoning_replay_requests"`
	ReasoningReplayPreserved int    `json:"reasoning_replay_preserved"`
	InvalidRequests          int    `json:"invalid_requests"`
	LastBodyBytes            int    `json:"last_body_bytes"`
	LastBodySHA256           string `json:"last_body_sha256"`
}

type synchronizedMockState struct {
	mu    sync.Mutex
	value mockState
}

type pluginListResponse struct {
	PluginsEnabled bool              `json:"plugins_enabled"`
	PluginsDir     string            `json:"plugins_dir"`
	Plugins        []pluginListEntry `json:"plugins"`
}

type pluginListEntry struct {
	ID               string          `json:"id"`
	Configured       bool            `json:"configured"`
	Registered       bool            `json:"registered"`
	Enabled          bool            `json:"enabled"`
	EffectiveEnabled bool            `json:"effective_enabled"`
	Metadata         *pluginMetadata `json:"metadata"`
}

type pluginMetadata struct {
	Name             string              `json:"name"`
	Version          string              `json:"version"`
	Author           string              `json:"author"`
	GitHubRepository string              `json:"github_repository"`
	ConfigFields     []pluginConfigField `json:"config_fields"`
}

type pluginConfigField struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	EnumValues  []string `json:"enum_values"`
	Description string   `json:"description"`
}

type hostIdentity struct {
	ImageReference string `json:"image_reference"`
	ImageDigest    string `json:"image_digest"`
	Version        string `json:"version"`
	Commit         string `json:"commit"`
	BuildDate      string `json:"build_date"`
}

type noStanzaAssertions struct {
	PluginsEnabled  bool `json:"plugins_enabled"`
	Discovered      bool `json:"discovered"`
	NotConfigured   bool `json:"not_configured"`
	NotRegistered   bool `json:"not_registered"`
	Disabled        bool `json:"disabled"`
	NotEffective    bool `json:"not_effective"`
	MetadataAbsent  bool `json:"metadata_absent"`
	OnlyCandidateID bool `json:"only_candidate_id"`
}

type explicitAssertions struct {
	AllConfigured            bool `json:"all_configured"`
	AllRegistered            bool `json:"all_registered"`
	AllEnabled               bool `json:"all_enabled"`
	AllEffective             bool `json:"all_effective"`
	MetadataExact            bool `json:"metadata_exact"`
	ConfigFieldsExact        bool `json:"config_fields_exact"`
	PrioritiesExact          bool `json:"priorities_exact"`
	SuccessfulForward        bool `json:"successful_forward"`
	BeforeAuthOrdered        bool `json:"before_auth_ordered"`
	AfterAuthOrdered         bool `json:"after_auth_ordered"`
	PrivacyFilterLast        bool `json:"privacyfilter_last"`
	ValueRedacted            bool `json:"value_redacted"`
	MarkerNotForwarded       bool `json:"marker_not_forwarded"`
	SuccessStateValid        bool `json:"success_state_valid"`
	ResponsesLiteForward     bool `json:"responses_lite_forward"`
	ResponsesLiteRedacted    bool `json:"responses_lite_redacted"`
	ReasoningReplayForward   bool `json:"reasoning_replay_forward"`
	ReasoningReplayPreserved bool `json:"reasoning_replay_preserved"`
	ActiveTermination        bool `json:"active_termination"`
	BlockedNotForwarded      bool `json:"blocked_not_forwarded"`
}

type phaseReport struct {
	SchemaVersion      int                 `json:"schema_version"`
	Mode               string              `json:"mode"`
	OfficialHost       hostIdentity        `json:"official_host"`
	Plugin             reportPlugin        `json:"plugin"`
	NoStanzaAssertions *noStanzaAssertions `json:"no_stanza_assertions,omitempty"`
	ExplicitAssertions *explicitAssertions `json:"explicit_assertions,omitempty"`
}

type reportPlugin struct {
	ID            string `json:"id"`
	Version       string `json:"version"`
	LibrarySHA256 string `json:"library_sha256"`
}

type verifierOptions struct {
	mode                string
	hostURL             string
	mockURL             string
	managementKey       string
	apiKey              string
	pluginVersion       string
	pluginSHA256        string
	imageReference      string
	imageDigest         string
	expectedHostVersion string
	expectedHostCommit  string
	expectedHostDate    string
	output              string
}

func main() {
	mode := flag.String("mode", "", "mock or verification mode")
	listen := flag.String("listen", ":9000", "mock server listen address")
	hostURL := flag.String("host-url", "", "official Host base URL")
	mockURL := flag.String("mock-url", "", "mock upstream base URL")
	managementKey := flag.String("management-key", "", "isolated management key")
	apiKey := flag.String("api-key", "", "isolated client API key")
	pluginVersion := flag.String("plugin-version", "", "expected plugin version")
	pluginSHA256 := flag.String("plugin-sha256", "", "expected plugin library SHA-256")
	imageReference := flag.String("image-reference", "", "official Host image reference")
	imageDigest := flag.String("image-digest", "", "official Host image digest")
	expectedHostVersion := flag.String("host-version", "", "expected Host version")
	expectedHostCommit := flag.String("host-commit", "", "expected Host commit")
	expectedHostDate := flag.String("host-build-date", "", "expected Host build date")
	output := flag.String("output", "", "exclusive verification report path")
	flag.Parse()

	if *mode == "mock" {
		if err := serveMock(*listen); err != nil {
			fatal("mock upstream failed")
		}
		return
	}

	opts := verifierOptions{
		mode:                *mode,
		hostURL:             strings.TrimRight(*hostURL, "/"),
		mockURL:             strings.TrimRight(*mockURL, "/"),
		managementKey:       *managementKey,
		apiKey:              *apiKey,
		pluginVersion:       *pluginVersion,
		pluginSHA256:        *pluginSHA256,
		imageReference:      *imageReference,
		imageDigest:         *imageDigest,
		expectedHostVersion: *expectedHostVersion,
		expectedHostCommit:  *expectedHostCommit,
		expectedHostDate:    *expectedHostDate,
		output:              *output,
	}
	if err := verify(opts); err != nil {
		fatal(err.Error())
	}
}

func serveMock(address string) error {
	state := &synchronizedMockState{}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /state", func(response http.ResponseWriter, _ *http.Request) {
		state.mu.Lock()
		snapshot := state.value
		state.mu.Unlock()
		response.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(response).Encode(snapshot)
	})
	mux.HandleFunc("POST /v1/chat/completions", func(response http.ResponseWriter, request *http.Request) {
		body, err := readBounded(request.Body)
		markerPresent := bytes.Contains(body, []byte(syntheticValue))
		beforeProbePresent := bytes.Contains(body, []byte("before-probe"))
		afterProbePresent := bytes.Contains(body, []byte("after-probe"))
		placeholderPresent := bytes.Contains(body, []byte("[密钥]"))
		toolCallPresent := bytes.Contains(body, []byte("tool_calls"))
		reasoningReplayPresent := bytes.Contains(body, []byte("reasoning_details"))
		toolRedacted := validRedactedToolRequest(body)
		reasoningReplayPreserved := validReasoningReplayRequest(body)
		redacted := toolRedacted || reasoningReplayPreserved
		digest := sha256.Sum256(body)

		state.mu.Lock()
		state.value.Requests++
		if reasoningReplayPresent {
			state.value.ReasoningReplayRequests++
		}
		if reasoningReplayPreserved {
			state.value.ReasoningReplayPreserved++
		}
		state.value.LastBodyBytes = len(body)
		state.value.LastBodySHA256 = hex.EncodeToString(digest[:])
		if redacted {
			// The low after-auth fixture emits the after-probe body only after it
			// observes both the high after-auth marker and the already-redacted
			// before-auth body. Reaching this state proves both ordered stages.
			state.value.BeforeOrderedRequests++
			state.value.AfterOrderedRequests++
			state.value.RedactedRequests++
		}
		if markerPresent {
			state.value.MarkerRequests++
		}
		if beforeProbePresent {
			state.value.BeforeProbeRequests++
		}
		if afterProbePresent {
			state.value.AfterProbeRequests++
		}
		if placeholderPresent {
			state.value.PlaceholderRequests++
		}
		if toolCallPresent {
			state.value.ToolCallRequests++
		}
		if err != nil || !redacted || markerPresent {
			state.value.InvalidRequests++
		}
		state.mu.Unlock()

		response.Header().Set("Content-Type", "application/json")
		response.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(response, `{"id":"chatcmpl-harness","object":"chat.completion","created":0,"model":"mock-model","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	})
	mux.HandleFunc("POST /v1/responses", func(response http.ResponseWriter, request *http.Request) {
		body, err := readBounded(request.Body)
		markerPresent := bytes.Contains(body, []byte(syntheticValue))
		placeholderPresent := bytes.Contains(body, []byte("[密钥]"))
		redacted := validRedactedResponsesLiteRequest(body)
		digest := sha256.Sum256(body)

		state.mu.Lock()
		state.value.Requests++
		state.value.ResponsesRequests++
		state.value.LastBodyBytes = len(body)
		state.value.LastBodySHA256 = hex.EncodeToString(digest[:])
		if redacted {
			state.value.RedactedRequests++
			state.value.ResponsesRedacted++
		}
		if markerPresent {
			state.value.MarkerRequests++
		}
		if placeholderPresent {
			state.value.PlaceholderRequests++
		}
		if err != nil || !redacted || markerPresent {
			state.value.InvalidRequests++
		}
		state.mu.Unlock()

		response.Header().Set("Content-Type", "text/event-stream")
		response.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(response, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp-harness\",\"object\":\"response\",\"created_at\":0,\"status\":\"completed\",\"model\":\"mock-model\",\"output\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1,\"total_tokens\":2}}}\n\n")
	})
	server := &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	return server.ListenAndServe()
}

func validRedactedToolRequest(body []byte) bool {
	var payload struct {
		Model    string `json:"model"`
		Messages []struct {
			Role      string `json:"role"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Model != "mock-model" || len(payload.Messages) != 1 || len(payload.Messages[0].ToolCalls) != 1 {
		return false
	}
	call := payload.Messages[0].ToolCalls[0]
	if payload.Messages[0].Role != "assistant" || call.ID != "after-probe" || call.Type != "function" || call.Function.Name != "probe" {
		return false
	}
	var arguments map[string]any
	if json.Unmarshal([]byte(call.Function.Arguments), &arguments) != nil || len(arguments) != 1 {
		return false
	}
	value, ok := arguments["api_key"].(string)
	return ok && value == "[密钥]"
}

func validReasoningReplayRequest(body []byte) bool {
	var payload struct {
		Model    string `json:"model"`
		Messages []struct {
			Role             string `json:"role"`
			Content          string `json:"content"`
			Reasoning        string `json:"reasoning"`
			ReasoningContent string `json:"reasoning_content"`
			ReasoningDetails []struct {
				Type      string `json:"type"`
				Text      string `json:"text"`
				Summary   string `json:"summary"`
				Data      string `json:"data"`
				Signature string `json:"signature"`
				ID        string `json:"id"`
				Format    string `json:"format"`
				Index     int    `json:"index"`
			} `json:"reasoning_details"`
		} `json:"messages"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Model != "mock-model" || len(payload.Messages) != 2 {
		return false
	}
	if payload.Messages[0].Role != "user" || payload.Messages[0].Content != "[邮箱]" {
		return false
	}
	assistant := payload.Messages[1]
	if assistant.Role != "assistant" || assistant.Content != "answer" ||
		assistant.Reasoning != reasoningReplayText || assistant.ReasoningContent != reasoningReplayText ||
		len(assistant.ReasoningDetails) != 3 {
		return false
	}
	text := assistant.ReasoningDetails[0]
	if text.Type != "reasoning.text" || text.Text != reasoningReplayText ||
		text.Signature != "integrity-signature" || text.ID != "rd_1" || text.Format != "unknown" || text.Index != 0 {
		return false
	}
	summary := assistant.ReasoningDetails[1]
	if summary.Type != "reasoning.summary" || summary.Summary != reasoningReplayText ||
		summary.ID != "rd_2" || summary.Format != "openai-responses-v1" || summary.Index != 1 {
		return false
	}
	encrypted := assistant.ReasoningDetails[2]
	return encrypted.Type == "reasoning.encrypted" && encrypted.Data == reasoningReplayText &&
		encrypted.ID == "rd_3" && encrypted.Format == "anthropic-claude-v1" && encrypted.Index == 2
}

func validRedactedResponsesLiteRequest(body []byte) bool {
	var payload struct {
		Model          string                     `json:"model"`
		ClientMetadata map[string]json.RawMessage `json:"client_metadata"`
		Input          []struct {
			Type   string            `json:"type"`
			Status string            `json:"status"`
			Input  string            `json:"input"`
			Tools  []json.RawMessage `json:"tools"`
		} `json:"input"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.Model != "mock-model" || len(payload.Input) != 2 {
		return false
	}
	if payload.Input[0].Type != "additional_tools" || len(payload.Input[0].Tools) != 1 {
		return false
	}
	if payload.Input[1].Type != "custom_tool_call" || payload.Input[1].Status != "completed" {
		return false
	}
	var customInput map[string]any
	if json.Unmarshal([]byte(payload.Input[1].Input), &customInput) != nil || len(customInput) != 1 || customInput["AK"] != "[密钥]" {
		return false
	}
	turnRaw, ok := payload.ClientMetadata["x-codex-turn-metadata"]
	if !ok {
		return false
	}
	var encodedTurn string
	if json.Unmarshal(turnRaw, &encodedTurn) != nil {
		return false
	}
	var turn map[string]any
	if json.Unmarshal([]byte(encodedTurn), &turn) != nil || len(turn) != 1 || turn["api_key"] != "[密钥]" {
		return false
	}
	var sessionID string
	if json.Unmarshal(payload.ClientMetadata["session_id"], &sessionID) != nil || sessionID != "session_1" {
		return false
	}
	return true
}

func configFieldsExact(fields []pluginConfigField) bool {
	expected := []pluginConfigField{
		{
			Name:        "mode",
			Type:        "enum",
			EnumValues:  []string{"redact", "tokenize", "audit"},
			Description: "Redact findings, replace them with tokens restored in the response, or audit without modifying requests.",
		},
		{
			Name:        "on_error",
			Type:        "enum",
			EnumValues:  []string{"block", "passthrough"},
			Description: "Block by default when a request cannot be safely inspected, or explicitly pass it through.",
		},
		{
			Name:        "gitleaks_toml",
			Type:        "string",
			Description: "Path to custom Gitleaks TOML. Empty uses the embedded pinned rules.",
		},
		{
			Name:        "gitleaks_mode",
			Type:        "enum",
			EnumValues:  []string{"extend", "replace"},
			Description: "Extend or replace embedded rules. Omitted with a custom file preserves legacy replace behavior.",
		},
		{
			Name:        "allow_unsupported_rules",
			Type:        "boolean",
			Description: "Allow explicitly reported unsupported semantics in a custom rule file.",
		},
		{
			Name:        "block_rule_ids",
			Type:        "array",
			Description: "Rule IDs that terminate the request instead of redacting it.",
		},
		{
			Name:        "replacements",
			Type:        "object",
			Description: "Typed placeholder overrides for email, phone, bank_card, iban, ip, and secret.",
		},
		{
			Name:        "phone_regions",
			Type:        "array",
			Description: "ISO 3166-1 alpha-2 regions whose national phone formats are recognised. International + numbers need no region.",
		},
		{
			Name:        "limits",
			Type:        "object",
			Description: "Bounded JSON scanning, text, finding, and replacement budgets.",
		},
		{
			Name:        "key_filter",
			Type:        "object",
			Description: "Inspect only (mode include) or all but (mode exclude) the listed client api_keys or caller_scopes; on_missing_identity is filter or skip. Empty lists inspect every request.",
		},
		{
			Name:        "tokenize",
			Type:        "object",
			Description: "Options for mode tokenize: token_format, hmac_secret, max_entries, ttl, and restore_scope (caller or request).",
		},
		{
			Name:        "skip_models",
			Type:        "array",
			Description: "Trusted break-glass model names to bypass inspection.",
		},
		{
			Name:        "skip_formats",
			Type:        "array",
			Description: "Trusted break-glass source formats to bypass inspection.",
		},
	}
	if len(fields) != len(expected) {
		return false
	}
	for index := range expected {
		if fields[index].Name != expected[index].Name ||
			fields[index].Type != expected[index].Type ||
			fields[index].Description != expected[index].Description ||
			len(fields[index].EnumValues) != len(expected[index].EnumValues) {
			return false
		}
		for enumIndex := range expected[index].EnumValues {
			if fields[index].EnumValues[enumIndex] != expected[index].EnumValues[enumIndex] {
				return false
			}
		}
	}
	return true
}

func verify(opts verifierOptions) error {
	if opts.hostURL == "" || opts.managementKey == "" || opts.pluginVersion == "" || opts.output == "" {
		return errors.New("required verifier argument is missing")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(opts.pluginSHA256) {
		return errors.New("plugin SHA-256 is invalid")
	}
	if !strings.HasPrefix(opts.imageDigest, "sha256:") || opts.imageReference == "" {
		return errors.New("official Host image identity is invalid")
	}

	client := &http.Client{Timeout: 15 * time.Second}
	plugins, identity, err := waitForPlugins(client, opts)
	if err != nil {
		return err
	}
	report := phaseReport{
		SchemaVersion: 1,
		Mode:          opts.mode,
		OfficialHost:  identity,
		Plugin: reportPlugin{
			ID:            pluginID,
			Version:       opts.pluginVersion,
			LibrarySHA256: opts.pluginSHA256,
		},
	}

	switch opts.mode {
	case "verify-no-stanza":
		assertions, errVerify := verifyNoStanza(plugins)
		if errVerify != nil {
			return errVerify
		}
		report.NoStanzaAssertions = &assertions
	case "verify-explicit":
		assertions, errVerify := verifyExplicit(client, opts, plugins)
		if errVerify != nil {
			return errVerify
		}
		report.ExplicitAssertions = &assertions
	default:
		return errors.New("unknown verification mode")
	}
	return writeReportExclusive(opts.output, report)
}

func waitForPlugins(client *http.Client, opts verifierOptions) (pluginListResponse, hostIdentity, error) {
	deadline := time.Now().Add(90 * time.Second)
	var last pluginListResponse
	for time.Now().Before(deadline) {
		request, err := http.NewRequest(http.MethodGet, opts.hostURL+"/v0/management/plugins", nil)
		if err != nil {
			return pluginListResponse{}, hostIdentity{}, errors.New("could not construct management request")
		}
		request.Header.Set("X-Management-Key", opts.managementKey)
		response, err := client.Do(request)
		if err == nil {
			plugins, identity, decodeErr := decodePluginList(response, opts)
			if decodeErr == nil {
				last = plugins
				if pluginPhaseReady(opts.mode, plugins) {
					return plugins, identity, nil
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return pluginListResponse{}, hostIdentity{}, fmt.Errorf(
		"official Host did not become ready: %s",
		summarizePluginState(last),
	)
}

func decodePluginList(response *http.Response, opts verifierOptions) (pluginListResponse, hostIdentity, error) {
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxHTTPBody))
		return pluginListResponse{}, hostIdentity{}, errors.New("management endpoint is not ready")
	}
	var plugins pluginListResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxHTTPBody+1))
	if decoder.Decode(&plugins) != nil {
		return pluginListResponse{}, hostIdentity{}, errors.New("management response is invalid")
	}
	identity := hostIdentity{
		ImageReference: opts.imageReference,
		ImageDigest:    opts.imageDigest,
		Version:        response.Header.Get("X-CPA-VERSION"),
		Commit:         response.Header.Get("X-CPA-COMMIT"),
		BuildDate:      response.Header.Get("X-CPA-BUILD-DATE"),
	}
	if identity.Version != opts.expectedHostVersion || identity.Commit != opts.expectedHostCommit || identity.BuildDate != opts.expectedHostDate {
		return pluginListResponse{}, hostIdentity{}, errors.New("official Host build identity mismatch")
	}
	return plugins, identity, nil
}

func pluginPhaseReady(mode string, response pluginListResponse) bool {
	switch mode {
	case "verify-no-stanza":
		return response.PluginsEnabled && len(response.Plugins) == 1 &&
			response.Plugins[0].ID == pluginID && !response.Plugins[0].Configured &&
			!response.Plugins[0].Registered && !response.Plugins[0].Enabled &&
			!response.Plugins[0].EffectiveEnabled
	case "verify-explicit":
		if !response.PluginsEnabled || len(response.Plugins) != 3 {
			return false
		}
		expected := map[string]bool{"order-high": false, "order-low": false, pluginID: false}
		for _, entry := range response.Plugins {
			if _, ok := expected[entry.ID]; !ok || !entry.Configured ||
				!entry.Registered || !entry.Enabled || !entry.EffectiveEnabled {
				return false
			}
			expected[entry.ID] = true
		}
		for _, seen := range expected {
			if !seen {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func verifyNoStanza(response pluginListResponse) (noStanzaAssertions, error) {
	assertions := noStanzaAssertions{PluginsEnabled: response.PluginsEnabled}
	if len(response.Plugins) == 1 && response.Plugins[0].ID == pluginID {
		assertions.OnlyCandidateID = true
		entry := response.Plugins[0]
		assertions.Discovered = true
		assertions.NotConfigured = !entry.Configured
		assertions.NotRegistered = !entry.Registered
		assertions.Disabled = !entry.Enabled
		assertions.NotEffective = !entry.EffectiveEnabled
		assertions.MetadataAbsent = entry.Metadata == nil
	}
	if !allTrue(
		assertions.PluginsEnabled,
		assertions.Discovered,
		assertions.NotConfigured,
		assertions.NotRegistered,
		assertions.Disabled,
		assertions.NotEffective,
		assertions.MetadataAbsent,
		assertions.OnlyCandidateID,
	) {
		return assertions, errors.New("no-stanza plugin state did not match the fail-disabled contract")
	}
	return assertions, nil
}

func verifyExplicit(client *http.Client, opts verifierOptions, response pluginListResponse) (explicitAssertions, error) {
	assertions := explicitAssertions{}
	expectedIDs := []string{"order-high", "order-low", pluginID}
	if len(response.Plugins) != len(expectedIDs) {
		return assertions, errors.New("explicit plugin set mismatch")
	}
	entries := make(map[string]pluginListEntry, len(response.Plugins))
	for _, entry := range response.Plugins {
		entries[entry.ID] = entry
	}
	if len(entries) != len(expectedIDs) {
		return assertions, errors.New("explicit plugin set mismatch")
	}
	assertions.AllConfigured = response.PluginsEnabled
	assertions.AllRegistered = true
	assertions.AllEnabled = true
	assertions.AllEffective = true
	for _, id := range expectedIDs {
		entry, ok := entries[id]
		assertions.AllConfigured = assertions.AllConfigured && ok && entry.Configured
		assertions.AllRegistered = assertions.AllRegistered && ok && entry.Registered
		assertions.AllEnabled = assertions.AllEnabled && ok && entry.Enabled
		assertions.AllEffective = assertions.AllEffective && ok && entry.EffectiveEnabled
	}
	privacy := entries[pluginID]
	assertions.MetadataExact = privacy.Metadata != nil &&
		privacy.Metadata.Name == pluginID &&
		privacy.Metadata.Version == opts.pluginVersion &&
		privacy.Metadata.Author == "ahoo (fork of rheodev)" &&
		privacy.Metadata.GitHubRepository == "https://github.com/ahoo/cpa-plugin-privacyfilter"
	assertions.ConfigFieldsExact = privacy.Metadata != nil && configFieldsExact(privacy.Metadata.ConfigFields)

	priorities := map[string]int{"order-high": 50, "order-low": 1, pluginID: 0}
	assertions.PrioritiesExact = true
	for id, priority := range priorities {
		config, err := fetchPluginConfig(client, opts, id)
		if err != nil || config["enabled"] != true || jsonNumber(config["priority"]) != priority {
			assertions.PrioritiesExact = false
		}
	}

	successStatus, err := postChat(client, opts, false)
	if err != nil {
		return assertions, err
	}
	assertions.SuccessfulForward = successStatus == http.StatusOK
	stateAfterSuccess, err := fetchMockState(client, opts.mockURL)
	if err != nil {
		return assertions, err
	}
	assertions.BeforeAuthOrdered = stateAfterSuccess.BeforeOrderedRequests == 1
	assertions.AfterAuthOrdered = stateAfterSuccess.AfterOrderedRequests == 1
	assertions.PrivacyFilterLast = stateAfterSuccess.RedactedRequests == 1
	assertions.ValueRedacted = stateAfterSuccess.RedactedRequests == 1
	assertions.MarkerNotForwarded = stateAfterSuccess.MarkerRequests == 0
	assertions.SuccessStateValid = stateAfterSuccess.Requests == 1 &&
		stateAfterSuccess.InvalidRequests == 0 &&
		stateAfterSuccess.BeforeProbeRequests == 0 &&
		stateAfterSuccess.AfterProbeRequests == 1 &&
		stateAfterSuccess.PlaceholderRequests == 1 &&
		stateAfterSuccess.ToolCallRequests == 1

	responsesStatus, err := postResponsesLite(client, opts)
	if err != nil {
		return assertions, err
	}
	assertions.ResponsesLiteForward = responsesStatus == http.StatusOK
	stateAfterResponses, err := fetchMockState(client, opts.mockURL)
	if err != nil {
		return assertions, err
	}
	assertions.ResponsesLiteRedacted = stateAfterResponses.Requests == 2 &&
		stateAfterResponses.ResponsesRequests == 1 &&
		stateAfterResponses.ResponsesRedacted == 1 &&
		stateAfterResponses.RedactedRequests == 2 &&
		stateAfterResponses.MarkerRequests == 0 &&
		stateAfterResponses.PlaceholderRequests == 2 &&
		stateAfterResponses.InvalidRequests == 0

	reasoningStatus, err := postReasoningReplay(client, opts)
	if err != nil {
		return assertions, err
	}
	assertions.ReasoningReplayForward = reasoningStatus == http.StatusOK
	stateAfterReasoning, err := fetchMockState(client, opts.mockURL)
	if err != nil {
		return assertions, err
	}
	assertions.ReasoningReplayPreserved = stateAfterReasoning.Requests == 3 &&
		stateAfterReasoning.ReasoningReplayRequests == 1 &&
		stateAfterReasoning.ReasoningReplayPreserved == 1 &&
		stateAfterReasoning.RedactedRequests == 3 &&
		stateAfterReasoning.InvalidRequests == 0

	blockedStatus, err := postChat(client, opts, true)
	if err != nil {
		return assertions, err
	}
	assertions.ActiveTermination = blockedStatus == http.StatusUnprocessableEntity
	stateAfterBlock, err := fetchMockState(client, opts.mockURL)
	if err != nil {
		return assertions, err
	}
	assertions.BlockedNotForwarded = stateAfterBlock == stateAfterReasoning

	if !allTrue(
		assertions.AllConfigured,
		assertions.AllRegistered,
		assertions.AllEnabled,
		assertions.AllEffective,
		assertions.MetadataExact,
		assertions.ConfigFieldsExact,
		assertions.PrioritiesExact,
		assertions.SuccessfulForward,
		assertions.BeforeAuthOrdered,
		assertions.AfterAuthOrdered,
		assertions.PrivacyFilterLast,
		assertions.ValueRedacted,
		assertions.MarkerNotForwarded,
		assertions.SuccessStateValid,
		assertions.ResponsesLiteForward,
		assertions.ResponsesLiteRedacted,
		assertions.ReasoningReplayForward,
		assertions.ReasoningReplayPreserved,
		assertions.ActiveTermination,
		assertions.BlockedNotForwarded,
	) {
		return assertions, fmt.Errorf(
			"explicit exact-Host assertion failed: configured=%t registered=%t high_registered=%t low_registered=%t privacy_registered=%t enabled=%t effective=%t metadata=%t fields=%t priorities=%t success_status=%d responses_status=%d reasoning_status=%d blocked_status=%d success_requests=%d responses_requests=%d reasoning_requests=%d reasoning_preserved=%d final_requests=%d before_ordered=%d after_ordered=%d redacted=%d responses_redacted=%d markers=%d before_probe=%d after_probe=%d placeholder=%d tool_call=%d invalid=%d body_bytes=%d body_sha256=%s",
			assertions.AllConfigured,
			assertions.AllRegistered,
			entries["order-high"].Registered,
			entries["order-low"].Registered,
			entries[pluginID].Registered,
			assertions.AllEnabled,
			assertions.AllEffective,
			assertions.MetadataExact,
			assertions.ConfigFieldsExact,
			assertions.PrioritiesExact,
			successStatus,
			responsesStatus,
			reasoningStatus,
			blockedStatus,
			stateAfterSuccess.Requests,
			stateAfterResponses.ResponsesRequests,
			stateAfterReasoning.ReasoningReplayRequests,
			stateAfterReasoning.ReasoningReplayPreserved,
			stateAfterBlock.Requests,
			stateAfterBlock.BeforeOrderedRequests,
			stateAfterBlock.AfterOrderedRequests,
			stateAfterBlock.RedactedRequests,
			stateAfterBlock.ResponsesRedacted,
			stateAfterBlock.MarkerRequests,
			stateAfterBlock.BeforeProbeRequests,
			stateAfterBlock.AfterProbeRequests,
			stateAfterBlock.PlaceholderRequests,
			stateAfterBlock.ToolCallRequests,
			stateAfterBlock.InvalidRequests,
			stateAfterBlock.LastBodyBytes,
			stateAfterBlock.LastBodySHA256,
		)
	}
	return assertions, nil
}

func fetchPluginConfig(client *http.Client, opts verifierOptions, id string) (map[string]any, error) {
	request, err := http.NewRequest(http.MethodGet, opts.hostURL+"/v0/management/plugins/"+id+"/config", nil)
	if err != nil {
		return nil, errors.New("could not construct plugin config request")
	}
	request.Header.Set("X-Management-Key", opts.managementKey)
	response, err := client.Do(request)
	if err != nil {
		return nil, errors.New("plugin config request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.New("plugin config endpoint returned an unexpected status")
	}
	var result map[string]any
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxHTTPBody+1))
	decoder.UseNumber()
	if decoder.Decode(&result) != nil {
		return nil, errors.New("plugin config response is invalid")
	}
	return result, nil
}

func jsonNumber(value any) int {
	number, ok := value.(json.Number)
	if !ok {
		return -1
	}
	parsed, err := number.Int64()
	if err != nil || parsed < 0 || parsed > 1<<30 {
		return -1
	}
	return int(parsed)
}

func postChat(client *http.Client, opts verifierOptions, blocked bool) (int, error) {
	body := []byte(`{"model":"mock-model","messages":[{"role":"user","content":"hello"}],"stream":false}`)
	if blocked {
		body = []byte(`{"model":"mock-model","messages":[{"role":"user","content":"hello","x_harness_extension":"safe"}],"stream":false}`)
	}
	request, err := http.NewRequest(http.MethodPost, opts.hostURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("could not construct chat request")
	}
	request.Header.Set("Authorization", "Bearer "+opts.apiKey)
	request.Header.Set("Content-Type", "application/json")
	if blocked {
		request.Header.Set("X-Harness-Block", "1")
	}
	response, err := client.Do(request)
	if err != nil {
		return 0, errors.New("chat request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxHTTPBody))
	return response.StatusCode, nil
}

func postReasoningReplay(client *http.Client, opts verifierOptions) (int, error) {
	body := []byte(`{
	  "model":"mock-model",
	  "messages":[
	    {"role":"user","content":"` + reasoningSensitiveValue + `"},
	    {
	      "role":"assistant",
	      "content":"answer",
	      "reasoning":"` + reasoningReplayText + `",
	      "reasoning_content":"` + reasoningReplayText + `",
	      "reasoning_details":[
	        {"type":"reasoning.text","text":"` + reasoningReplayText + `","signature":"integrity-signature","id":"rd_1","format":"unknown","index":0},
	        {"type":"reasoning.summary","summary":"` + reasoningReplayText + `","id":"rd_2","format":"openai-responses-v1","index":1},
	        {"type":"reasoning.encrypted","data":"` + reasoningReplayText + `","id":"rd_3","format":"anthropic-claude-v1","index":2}
	      ]
	    }
	  ],
	  "stream":false
	}`)
	request, err := http.NewRequest(http.MethodPost, opts.hostURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("could not construct reasoning replay request")
	}
	request.Header.Set("Authorization", "Bearer "+opts.apiKey)
	request.Header.Set("Content-Type", "application/json")
	// Preserve the compatibility body rather than replacing it with the ordering
	// probes' Chat Completions fixture. Privacyfilter still runs in both phases.
	request.Header.Set("X-Harness-Block", "1")
	response, err := client.Do(request)
	if err != nil {
		return 0, errors.New("reasoning replay request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxHTTPBody))
	return response.StatusCode, nil
}

func postResponsesLite(client *http.Client, opts verifierOptions) (int, error) {
	body := []byte(`{
	  "model":"mock-responses-model",
	  "client_metadata":{
	    "session_id":"session_1",
	    "x-codex-installation-id":"installation_1",
	    "x-codex-window-id":"window_1",
	    "thread_id":"thread_1",
	    "turn_id":"turn_1",
	    "root_turn_id":"root_1",
	    "x-codex-turn-metadata":"{\"api_key\":\"q7z\"}"
	  },
	  "input":[
	    {
	      "type":"additional_tools",
	      "id":"at_1",
	      "role":"developer",
	      "tools":[{
	        "type":"namespace",
	        "name":"functions",
	        "description":"interfaces",
	        "tools":[{
	          "type":"custom",
	          "name":"freeform",
	          "description":"freeform input",
	          "format":{"type":"grammar","syntax":"lark","definition":"start: WORD"}
	        }]
	      }]
	    },
	    {
	      "type":"custom_tool_call",
	      "id":"ct_1",
	      "call_id":"call_1",
	      "name":"freeform",
	      "status":"completed",
	      "input":"{\"AK\":\"q7z\"}"
	    }
	  ],
	  "stream":false
	}`)
	request, err := http.NewRequest(http.MethodPost, opts.hostURL+"/v1/responses", bytes.NewReader(body))
	if err != nil {
		return 0, errors.New("could not construct Responses Lite request")
	}
	request.Header.Set("Authorization", "Bearer "+opts.apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-OpenAI-Internal-Codex-Responses-Lite", "true")
	// Keep the synthetic ordering probes from replacing this Responses body with
	// their Chat Completions fixture. The privacy filter does not special-case the
	// header, so both interceptor stages still inspect the original request.
	request.Header.Set("X-Harness-Block", "1")
	response, err := client.Do(request)
	if err != nil {
		return 0, errors.New("Responses Lite request failed")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxHTTPBody))
	return response.StatusCode, nil
}

func fetchMockState(client *http.Client, mockURL string) (mockState, error) {
	response, err := client.Get(mockURL + "/state")
	if err != nil {
		return mockState{}, errors.New("mock state request failed")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return mockState{}, errors.New("mock state endpoint returned an unexpected status")
	}
	var state mockState
	if json.NewDecoder(io.LimitReader(response.Body, maxHTTPBody+1)).Decode(&state) != nil {
		return mockState{}, errors.New("mock state response is invalid")
	}
	return state, nil
}

func readBounded(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxHTTPBody+1))
	if err != nil || len(body) > maxHTTPBody {
		return body, errors.New("request body exceeds mock bound")
	}
	return body, nil
}

func writeReportExclusive(path string, report phaseReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return errors.New("could not encode verification report")
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return errors.New("could not create verification report")
	}
	if _, err = file.Write(data); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return errors.New("could not write verification report")
	}
	if err = file.Close(); err != nil {
		_ = os.Remove(path)
		return errors.New("could not close verification report")
	}
	return nil
}

func allTrue(values ...bool) bool {
	for _, value := range values {
		if !value {
			return false
		}
	}
	return true
}

func sha256String(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func fatal(message string) {
	// Errors are intentionally value-free. Hashing guards against accidental
	// inclusion of an input-derived diagnostic if future call sites regress.
	if strings.Contains(message, syntheticValue) {
		message = "verification failed (diagnostic " + sha256String(message)[:12] + ")"
	}
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}

func summarizePluginState(response pluginListResponse) string {
	entries := make(map[string]pluginListEntry, len(response.Plugins))
	for _, entry := range response.Plugins {
		entries[entry.ID] = entry
	}
	high := entries["order-high"]
	low := entries["order-low"]
	privacy := entries[pluginID]
	return fmt.Sprintf(
		"plugins_enabled=%t count=%d high_configured=%t high_registered=%t high_enabled=%t high_effective=%t low_configured=%t low_registered=%t low_enabled=%t low_effective=%t privacy_configured=%t privacy_registered=%t privacy_enabled=%t privacy_effective=%t",
		response.PluginsEnabled,
		len(response.Plugins),
		high.Configured,
		high.Registered,
		high.Enabled,
		high.EffectiveEnabled,
		low.Configured,
		low.Registered,
		low.Enabled,
		low.EffectiveEnabled,
		privacy.Configured,
		privacy.Registered,
		privacy.Enabled,
		privacy.EffectiveEnabled,
	)
}
