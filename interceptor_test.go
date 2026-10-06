package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ahoo/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
	"github.com/ahoo/cpa-plugin-privacyfilter/walker"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func newTestPlugin(t *testing.T) *privacyFilterPlugin {
	t.Helper()
	cfg := defaultConfig()
	engine, report, err := privacyengine.New(privacyengine.Config{
		EmbeddedTOML:          embeddedGitleaks,
		EmbeddedCompatibility: privacyengine.CompatibilitySkipUnsupported,
		DefaultLimits:         cfg.engineLimits(),
	})
	if err != nil {
		t.Fatalf("privacyengine.New() error = %v (report=%+v)", err, report)
	}
	renderer, err := cfg.renderer()
	if err != nil {
		t.Fatal(err)
	}
	return &privacyFilterPlugin{
		cfg:          cfg,
		engine:       engine,
		renderer:     renderer,
		blockRuleIDs: cfg.blockRuleSet(),
		cache: NewRequestScanCache(RequestScanCacheOptions{
			TTL:        defaultRequestCacheTTL,
			MaxEntries: 32,
		}),
		revision: 1,
	}
}

func redactForTest(t *testing.T, p *privacyFilterPlugin, sourceFormat, body string) ([]byte, int, error) {
	t.Helper()
	result, err := p.sanitizeRequest(context.Background(), sourceFormat, []byte(body))
	if err != nil {
		return nil, 0, err
	}
	if !result.changed {
		return nil, result.findings, nil
	}
	return result.body, result.findings, nil
}

func TestRedactRequestBody_EmailInContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"my email is test@example.com"}]}`
	modified, findings, err := redactForTest(t, p, "openai", body)
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if findings != 1 || modified == nil {
		t.Fatalf("findings=%d modified=%v, want one redaction", findings, modified != nil)
	}
	if !strings.Contains(string(modified), "[邮箱]") || strings.Contains(string(modified), "test@example.com") {
		t.Fatalf("email was not safely redacted: findings=%d body_len=%d", findings, len(modified))
	}
}

func TestRedactRequestBody_NoPII(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"hello world"}]}`
	modified, findings, err := redactForTest(t, p, "openai", body)
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if findings != 0 || modified != nil {
		t.Fatalf("findings=%d modified=%t body_len=%d, want unchanged", findings, modified != nil, len(modified))
	}
}

func TestRedactRequestBody_MultiPartContent(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":[{"type":"text","text":"my phone is +44 20 7946 0958"}]}]}`
	modified, findings, err := redactForTest(t, p, "openai", body)
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if findings != 1 || modified == nil || strings.Contains(string(modified), "7946") {
		t.Fatalf("phone was not safely redacted: findings=%d body_len=%d", findings, len(modified))
	}
}

func TestRedactRequestBody_ResponsesStringInput(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","input":"my email is test@example.com"}`
	modified, findings, err := redactForTest(t, p, "openai-response", body)
	if err != nil {
		t.Fatalf("redactRequestBody() error = %v", err)
	}
	if findings != 1 || modified == nil || strings.Contains(string(modified), "test@example.com") {
		t.Fatalf("email was not safely redacted: findings=%d body_len=%d", findings, len(modified))
	}
}

func TestRedactRequestBody_PreservesLargeInteger(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"id":9007199254740993,"messages":[{"role":"user","content":"test@example.com"}]}`
	modified, _, err := redactForTest(t, p, "openai", body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(modified), `"id":9007199254740993`) {
		t.Fatalf("large integer changed: body_len=%d", len(modified))
	}
}

func TestInterceptRequest_SkippedModel(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"gpt-4"}
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"test@example.com"}]}`
	resp, err := p.interceptRequest(context.Background(), pluginapi.RequestInterceptRequest{
		Model: "gpt-4",
		Body:  []byte(body),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil || resp.Terminate {
		t.Fatalf("skipped model did not pass through: terminate=%t status=%d body_len=%d", resp.Terminate, resp.StatusCode, len(resp.Body))
	}
}

func TestInterceptRequest_SkippedRequestedModel(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.SkipModels = []string{"gpt-4"}
	body := `{"model":"upstream-model","messages":[{"role":"user","content":"test@example.com"}]}`
	resp, err := p.interceptRequest(context.Background(), pluginapi.RequestInterceptRequest{
		Model:          "upstream-model",
		RequestedModel: "gpt-4",
		Body:           []byte(body),
	}, false)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil || resp.Terminate {
		t.Fatalf("skipped requested model did not pass through: terminate=%t status=%d body_len=%d", resp.Terminate, resp.StatusCode, len(resp.Body))
	}
}

func TestInterceptRequestAfterAuth_RedactsFinalRequest(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"test@example.com"}]}`
	resp, err := p.InterceptRequestAfterAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Model:        "gpt-4",
		Body:         []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body == nil || resp.Terminate || strings.Contains(string(resp.Body), "test@example.com") {
		t.Fatalf("unexpected response: terminate=%t status=%d body_len=%d", resp.Terminate, resp.StatusCode, len(resp.Body))
	}
}

func TestInterceptRequestBeforeAuth_Passthrough(t *testing.T) {
	p := newTestPlugin(t)
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"normal text"}]}`
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil || resp.Terminate {
		t.Fatalf("normal request changed: terminate=%t status=%d body_len=%d", resp.Terminate, resp.StatusCode, len(resp.Body))
	}
}

func TestRedactRequestBody_SecretDetectionUsesEmbeddedRules(t *testing.T) {
	p := newTestPlugin(t)
	const key = "LTAIABCDEFGHIJKLMNOPQRST"
	body := `{"model":"gpt-4","messages":[{"role":"user","content":"` + key + `"}]}`
	modified, findings, err := redactForTest(t, p, "openai", body)
	if err != nil {
		t.Fatal(err)
	}
	if findings != 1 || modified == nil || strings.Contains(string(modified), key) {
		t.Fatalf("Alibaba key was not redacted: findings=%d body_len=%d", findings, len(modified))
	}
}

func TestInterceptRequest_InvalidJSONFailsClosed(t *testing.T) {
	p := newTestPlugin(t)
	for _, body := range [][]byte{
		nil,
		[]byte(`not valid json with email test@example.com`),
	} {
		resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
			SourceFormat: "openai",
			Body:         body,
		})
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Terminate || resp.StatusCode != 400 {
			t.Fatalf("invalid JSON response: terminate=%t status=%d body_len=%d, want terminate 400", resp.Terminate, resp.StatusCode, len(resp.Body))
		}
	}
}

func TestInterceptRequest_InvalidJSONCanExplicitlyPassThrough(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.OnError = onErrorPassthrough
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(`not valid json`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Terminate || resp.Body != nil {
		t.Fatalf("passthrough response: terminate=%t status=%d body_len=%d", resp.Terminate, resp.StatusCode, len(resp.Body))
	}
}

func TestBlockingRuleTerminatesWithoutReturningBody(t *testing.T) {
	p := newTestPlugin(t)
	p.blockRuleIDs = map[string]struct{}{"alibaba-access-key-id": {}}
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"LTAIABCDEFGHIJKLMNOPQRST"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Terminate || resp.StatusCode != 422 || resp.Body != nil {
		t.Fatalf("block response: terminate=%t status=%d body_len=%d", resp.Terminate, resp.StatusCode, len(resp.Body))
	}
}

func TestBlockingRuleWinsWhenItsSpanOverlapsPII(t *testing.T) {
	p := newTestPlugin(t)
	engine, report, err := privacyengine.New(privacyengine.Config{
		CustomTOML: []byte(`
[[rules]]
id = "block-email"
regex = '''[a-z]+@example\.com'''
keywords = ["@example."]
`),
		CustomMode: privacyengine.CustomRulesReplace,
	})
	if err != nil {
		t.Fatalf("privacyengine.New(): %v (report=%+v)", err, report)
	}
	p.engine = engine
	p.blockRuleIDs = map[string]struct{}{"block-email": {}}

	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(`{"messages":[{"role":"user","content":"test@example.com"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Terminate || resp.StatusCode != 422 || resp.Body != nil {
		t.Fatalf("overlapping block response: terminate=%t status=%d body_len=%d", resp.Terminate, resp.StatusCode, len(resp.Body))
	}
}

func TestAuditModeDetectsWithoutMutation(t *testing.T) {
	p := newTestPlugin(t)
	p.cfg.Mode = modeAudit
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"test@example.com"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Terminate || resp.Body != nil {
		t.Fatalf("audit response: terminate=%t status=%d body_len=%d", resp.Terminate, resp.StatusCode, len(resp.Body))
	}
}

func TestConfigShouldSkip(t *testing.T) {
	cfg := defaultConfig()
	cfg.SkipModels = []string{"gpt-4", "claude-3"}
	cfg.SkipFormats = []string{"openai"}
	if !cfg.shouldSkip("gpt-4", "", "") {
		t.Fatal("should skip gpt-4")
	}
	if !cfg.shouldSkip("upstream-model", "claude-3", "") {
		t.Fatal("should skip requested claude-3")
	}
	if !cfg.shouldSkip("", "", "openai") {
		t.Fatal("should skip openai format")
	}
	if cfg.shouldSkip("gemini-pro", "", "claude") {
		t.Fatal("should not skip unknown model/format")
	}
}

func TestProtocolRedactionEndToEnd(t *testing.T) {
	const secret = "LTAIABCDEFGHIJKLMNOPQRST"
	tests := []struct {
		name   string
		format string
		body   string
	}{
		{
			name:   "openai chat",
			format: "openai",
			body: `{"model":"m","messages":[` +
				`{"role":"system","content":"` + secret + `"},` +
				`{"role":"assistant","content":"ok","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"ak\":\"` + secret + `\",\"n\":9007199254740993}"}}]},` +
				`{"role":"tool","tool_call_id":"c1","content":"` + secret + `"}]}`,
		},
		{
			name:   "openai responses",
			format: "openai-response",
			body: `{"model":"m","instructions":"` + secret + `","input":[` +
				`{"type":"message","role":"user","content":"` + secret + `"},` +
				`{"type":"function_call","name":"f","arguments":"{\"ak\":\"` + secret + `\"}"},` +
				`{"type":"function_call_output","output":"{\"ak\":\"` + secret + `\"}"}]}`,
		},
		{
			name:   "anthropic",
			format: "claude",
			body: `{"model":"m","system":[{"type":"text","text":"` + secret + `"}],"messages":[` +
				`{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"f","input":{"ak":"` + secret + `"}}]},` +
				`{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":{"ak":"` + secret + `","id":"` + secret + `","name":"` + secret + `","signature":"` + secret + `","tool_use_id":"` + secret + `"}}]}]}`,
		},
		{
			name:   "gemini",
			format: "gemini",
			body: `{"systemInstruction":{"parts":[{"text":"` + secret + `"}]},"contents":[` +
				`{"role":"model","parts":[{"functionCall":{"name":"f","args":{"ak":"` + secret + `"}}}]},` +
				`{"role":"user","parts":[{"functionResponse":{"name":"f","response":{"ak":"` + secret + `"}}}]}]}`,
		},
		{
			name:   "interactions",
			format: "interactions",
			body: `{"system_instruction":"` + secret + `","input":[` +
				`{"type":"function_call","name":"f","arguments":{"ak":"` + secret + `"}},` +
				`{"type":"function_result","name":"f","result":{"ak":"` + secret + `"}},` +
				`{"type":"user_input","content":"` + secret + `"}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestPlugin(t)
			result, err := p.sanitizeRequest(context.Background(), tc.format, []byte(tc.body))
			if err != nil {
				t.Fatalf("sanitizeRequest: %v", err)
			}
			if !result.changed || result.findings == 0 {
				t.Fatalf("result changed=%t findings=%d targets=%d body_len=%d, want changed findings", result.changed, result.findings, result.targets, len(result.body))
			}
			if strings.Contains(string(result.body), secret) {
				t.Fatalf("secret remained after sanitization: findings=%d body_len=%d", result.findings, len(result.body))
			}
			if !json.Valid(result.body) {
				t.Fatalf("sanitized body is invalid JSON: body_len=%d", len(result.body))
			}
		})
	}
}

func mustMarshalTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test JSON: %v", err)
	}
	return body
}

func TestShortCredentialFieldsAcrossStructuredToolProtocols(t *testing.T) {
	secretA := strings.Join([]string{"r4", "Q", "p7"}, "")
	secretB := strings.Join([]string{"m2", "N", "q8"}, "")
	ordinary := strings.Join([]string{"plain", "-", "value"}, "")
	unscopedArrayValue := strings.Join([]string{"array", "-", "item"}, "")
	unresolved := strings.Join([]string{"${", "API_KEY", "}"}, "")
	prose := strings.Join([]string{"AK", "/", "SK", " field names only"}, "")

	toolPayload := func() map[string]any {
		return map[string]any{
			"AK":           secretA,
			"api_key_name": ordinary,
			"id":           ordinary,
			"items":        []any{unscopedArrayValue},
			"monkey":       ordinary,
			"name":         ordinary,
			"nested":       map[string]any{"secretKey": secretB},
			"note":         prose,
			"role":         ordinary,
			"schema":       ordinary,
			"signature":    ordinary,
			"token":        []any{secretA, unresolved},
			"token_id":     ordinary,
		}
	}
	encodedPayload := func() string {
		return string(mustMarshalTestJSON(t, toolPayload()))
	}

	tests := []struct {
		name         string
		format       string
		body         any
		payloadCount int
	}{
		{
			name:   "openai chat encoded arguments and result",
			format: "openai",
			body: map[string]any{"model": "m", "messages": []any{
				map[string]any{"role": "assistant", "tool_calls": []any{
					map[string]any{"type": "function", "function": map[string]any{"name": "f", "arguments": encodedPayload()}},
				}},
				map[string]any{"role": "tool", "content": encodedPayload()},
			}},
			payloadCount: 2,
		},
		{
			name:   "openai responses encoded arguments and output",
			format: "openai-response",
			body: map[string]any{"model": "m", "input": []any{
				map[string]any{"type": "function_call", "name": "f", "arguments": encodedPayload()},
				map[string]any{"type": "function_call_output", "output": encodedPayload()},
			}},
			payloadCount: 2,
		},
		{
			name:   "anthropic native input and native or encoded results",
			format: "claude",
			body: map[string]any{"model": "m", "messages": []any{
				map[string]any{"role": "assistant", "content": []any{
					map[string]any{"type": "tool_use", "id": "t1", "name": "f", "input": toolPayload()},
				}},
				map[string]any{"role": "user", "content": []any{
					map[string]any{"type": "tool_result", "tool_use_id": "t1", "content": toolPayload()},
					map[string]any{"type": "tool_result", "tool_use_id": "t2", "content": encodedPayload()},
				}},
			}},
			payloadCount: 3,
		},
		{
			name:   "gemini native function call and response",
			format: "gemini",
			body: map[string]any{"contents": []any{
				map[string]any{"role": "model", "parts": []any{
					map[string]any{"functionCall": map[string]any{"name": "f", "args": toolPayload()}},
				}},
				map[string]any{"role": "user", "parts": []any{
					map[string]any{"functionResponse": map[string]any{"name": "f", "response": toolPayload()}},
				}},
			}},
			payloadCount: 2,
		},
		{
			name:   "interactions encoded and native function directions",
			format: "interactions",
			body: map[string]any{"input": []any{
				map[string]any{"type": "function_call", "name": "encoded", "arguments": encodedPayload()},
				map[string]any{"type": "function_call", "name": "native", "arguments": toolPayload()},
				map[string]any{"type": "function_result", "name": "native", "result": toolPayload()},
				map[string]any{"type": "function_call_output", "output": encodedPayload()},
			}},
			payloadCount: 4,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			plugin := newTestPlugin(t)
			body := mustMarshalTestJSON(t, testCase.body)
			result, err := plugin.sanitizeRequest(context.Background(), testCase.format, body)
			if err != nil {
				t.Fatalf("sanitizeRequest: %v", err)
			}
			if !result.changed {
				t.Fatal("structured credentials did not change the request")
			}
			if result.findings != 3*testCase.payloadCount {
				t.Fatalf("finding count = %d, want %d", result.findings, 3*testCase.payloadCount)
			}
			for index, secret := range []string{secretA, secretB} {
				if bytes.Contains(result.body, []byte(secret)) {
					t.Fatalf("credential value %d remained after sanitization", index)
				}
			}
			for index, preserved := range []string{ordinary, unscopedArrayValue, unresolved, prose} {
				if !bytes.Contains(result.body, []byte(preserved)) {
					t.Fatalf("non-credential value %d was not preserved", index)
				}
			}
			if got := bytes.Count(result.body, []byte("[密钥]")); got != 2*testCase.payloadCount {
				t.Fatalf("base placeholder count = %d, want %d", got, 2*testCase.payloadCount)
			}
			if got := bytes.Count(result.body, []byte("[密钥#2]")); got != testCase.payloadCount {
				t.Fatalf("numbered placeholder count = %d, want %d", got, testCase.payloadCount)
			}
			if !json.Valid(result.body) {
				t.Fatal("sanitized body is invalid JSON")
			}
		})
	}
}

func TestTypedToolOutputTextInspectsSerializedJSON(t *testing.T) {
	shortCredential := strings.Join([]string{"q", "7", "z"}, "")
	encoded := string(mustMarshalTestJSON(t, map[string]string{"api_key": shortCredential}))
	tests := []struct {
		name   string
		format string
		body   any
	}{
		{
			name:   "OpenAI multipart tool message",
			format: "openai",
			body: map[string]any{"messages": []any{map[string]any{
				"role": "tool", "content": []any{map[string]any{"type": "text", "text": encoded}},
			}}},
		},
		{
			name:   "Anthropic tool-result text block",
			format: "claude",
			body: map[string]any{"messages": []any{map[string]any{
				"role": "user",
				"content": []any{map[string]any{
					"type": "tool_result", "tool_use_id": "t1",
					"content": []any{map[string]any{"type": "text", "text": encoded}},
				}},
			}}},
		},
		{
			name:   "Responses tool-message text block",
			format: "openai-response",
			body: map[string]any{"input": []any{map[string]any{
				"type": "message", "role": "tool",
				"content": []any{map[string]any{"type": "text", "text": encoded}},
			}}},
		},
		{
			name:   "Responses function-output content list",
			format: "openai-response",
			body: map[string]any{"input": []any{map[string]any{
				"type": "function_call_output", "call_id": "c1",
				"output": []any{map[string]any{"type": "input_text", "text": encoded}},
			}}},
		},
		{
			name:   "Gemini function-response text part",
			format: "gemini",
			body: map[string]any{"contents": []any{map[string]any{
				"role": "user",
				"parts": []any{map[string]any{"functionResponse": map[string]any{
					"name": "f", "parts": []any{map[string]any{"text": encoded}},
				}}},
			}}},
		},
		{
			name:   "Interactions tool-role text block",
			format: "interactions",
			body: map[string]any{"input": []any{map[string]any{
				"role": "tool", "content": []any{map[string]any{"type": "text", "text": encoded}},
			}}},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			plugin := newTestPlugin(t)
			result, err := plugin.sanitizeRequest(
				context.Background(), testCase.format, mustMarshalTestJSON(t, testCase.body),
			)
			if err != nil {
				t.Fatal("typed tool-output fixture failed sanitization")
			}
			if !result.changed || result.findings != 1 || bytes.Contains(result.body, []byte(shortCredential)) {
				t.Fatal("typed tool-output serialized JSON retained a short credential")
			}
			if !json.Valid(result.body) {
				t.Fatal("typed tool-output sanitization produced invalid JSON")
			}
		})
	}
}

func TestNativeToolDataStringLeavesInspectSerializedJSON(t *testing.T) {
	shortCredential := strings.Join([]string{"m", "2", "n"}, "")
	encoded := string(mustMarshalTestJSON(t, map[string]string{"api_key": shortCredential}))
	tests := []struct {
		name   string
		format string
		body   any
	}{
		{
			name:   "Anthropic native tool input",
			format: "claude",
			body: map[string]any{"messages": []any{map[string]any{
				"role": "assistant", "content": []any{map[string]any{
					"type": "tool_use", "id": "t1", "name": "f",
					"input": map[string]string{"payload": encoded},
				}},
			}}},
		},
		{
			name:   "Anthropic native tool output",
			format: "claude",
			body: map[string]any{"messages": []any{map[string]any{
				"role": "user", "content": []any{map[string]any{
					"type": "tool_result", "tool_use_id": "t1",
					"content": map[string]string{"payload": encoded},
				}},
			}}},
		},
		{
			name:   "Gemini native tool input",
			format: "gemini",
			body: map[string]any{"contents": []any{map[string]any{
				"role": "model", "parts": []any{map[string]any{"functionCall": map[string]any{
					"name": "f", "args": map[string]string{"payload": encoded},
				}}},
			}}},
		},
		{
			name:   "Gemini native tool output",
			format: "gemini",
			body: map[string]any{"contents": []any{map[string]any{
				"role": "user", "parts": []any{map[string]any{"functionResponse": map[string]any{
					"name": "f", "response": map[string]string{"payload": encoded},
				}}},
			}}},
		},
		{
			name:   "Interactions native tool input",
			format: "interactions",
			body: map[string]any{"input": []any{map[string]any{
				"type": "function_call", "name": "f",
				"arguments": map[string]string{"payload": encoded},
			}}},
		},
		{
			name:   "Interactions native tool output",
			format: "interactions",
			body: map[string]any{"input": []any{map[string]any{
				"type": "function_result", "name": "f",
				"result": map[string]string{"payload": encoded},
			}}},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			plugin := newTestPlugin(t)
			result, err := plugin.sanitizeRequest(
				context.Background(), testCase.format, mustMarshalTestJSON(t, testCase.body),
			)
			if err != nil {
				t.Fatal("native tool-data fixture failed sanitization")
			}
			if !result.changed || result.findings != 1 || bytes.Contains(result.body, []byte(shortCredential)) {
				t.Fatal("native tool-data string leaf retained a serialized short credential")
			}
		})
	}
}

func TestEncodedCredentialContainersWithoutStringLeavesRedactWholeValue(t *testing.T) {
	credentialA := string(mustMarshalTestJSON(t, map[string]any{
		"count": 7,
		"ready": true,
		"empty": nil,
	}))
	credentialB := string(mustMarshalTestJSON(t, []any{1, false, nil}))
	arguments := string(mustMarshalTestJSON(t, map[string]string{
		"api_key":  credentialA,
		"password": credentialB,
	}))
	body := mustMarshalTestJSON(t, map[string]any{
		"messages": []any{map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":      "f",
					"arguments": arguments,
				},
			}},
		}},
	})

	plugin := newTestPlugin(t)
	result, err := plugin.sanitizeRequest(context.Background(), "openai", body)
	if err != nil {
		t.Fatal("encoded credential-container fixture failed sanitization")
	}
	if !result.changed || result.findings != 2 ||
		!bytes.Contains(result.body, []byte("[密钥]")) ||
		!bytes.Contains(result.body, []byte("[密钥#2]")) {
		t.Fatal("encoded credential containers were not wholly redacted")
	}
	if !json.Valid(result.body) {
		t.Fatal("encoded credential-container output is invalid JSON")
	}
}

func TestAbbreviatedCredentialNamesDoNotPropagateToDescendants(t *testing.T) {
	shortA := strings.Join([]string{"q", "7", "z"}, "")
	shortB := strings.Join([]string{"m", "2", "n"}, "")
	ordinaryA := strings.Join([]string{"sort", "-", "row"}, "")
	ordinaryB := strings.Join([]string{"partition", "-", "row"}, "")
	toolPayload := []any{
		map[string]any{"SK": map[string]string{"S": ordinaryA}},
		map[string]any{"AK": map[string]string{"S": ordinaryB}},
		map[string]string{"SK": shortA},
		map[string]string{"AK": shortB},
	}
	encodedPayload := string(mustMarshalTestJSON(t, toolPayload))
	tests := []struct {
		name   string
		format string
		body   any
	}{
		{
			name:   "encoded OpenAI arguments",
			format: "openai",
			body: map[string]any{"messages": []any{map[string]any{
				"role": "assistant",
				"tool_calls": []any{map[string]any{
					"type":     "function",
					"function": map[string]any{"name": "f", "arguments": encodedPayload},
				}},
			}}},
		},
		{
			name:   "native Anthropic input",
			format: "claude",
			body: map[string]any{"messages": []any{map[string]any{
				"role": "assistant",
				"content": []any{map[string]any{
					"type": "tool_use", "id": "t1", "name": "f", "input": toolPayload,
				}},
			}}},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			plugin := newTestPlugin(t)
			body := mustMarshalTestJSON(t, testCase.body)
			result, err := plugin.sanitizeRequest(context.Background(), testCase.format, body)
			if err != nil {
				t.Fatal("abbreviated credential-context fixture failed sanitization")
			}
			if !result.changed || result.findings != 2 {
				t.Fatalf("credential findings = %d, want 2", result.findings)
			}
			for index, preserved := range []string{ordinaryA, ordinaryB} {
				if !bytes.Contains(result.body, []byte(preserved)) {
					t.Fatalf("ordinary abbreviated-key descendant %d was not preserved", index)
				}
			}
			for index, redacted := range []string{shortA, shortB} {
				if bytes.Contains(result.body, []byte(redacted)) {
					t.Fatalf("immediate abbreviated credential %d remained", index)
				}
			}
		})
	}
}

func TestExpandedExactCredentialNamesRedactEndToEnd(t *testing.T) {
	fieldNames := []string{
		"AK", "SK",
		"api_key", "apiKey", "api_secret", "apiSecret", "api_secret_key", "apiSecretKey",
		"access_key", "accessKey", "access_key_id", "accessKeyId",
		"secret_key", "secretKey", "secret_access_key", "secretAccessKey",
		"aws_access_key_id", "awsAccessKeyId", "aws_secret_access_key", "awsSecretAccessKey",
		"client_secret", "clientSecret", "private_key", "privateKey",
		"token", "access_token", "accessToken", "api_token", "apiToken",
		"auth_token", "authToken", "refresh_token", "refreshToken",
		"session_token", "sessionToken", "id_token", "idToken",
		"client_token", "clientToken", "secret_token", "secretToken",
		"bearer_token", "bearerToken", "oauth_token", "oauthToken",
		"password", "passwd", "pwd", "credential", "secret", "secrets", "authorization",
	}
	shortCredential := strings.Join([]string{"q", "7", "z"}, "")
	toolPayload := make(map[string]string, len(fieldNames))
	for _, fieldName := range fieldNames {
		toolPayload[fieldName] = shortCredential
	}
	arguments := string(mustMarshalTestJSON(t, toolPayload))
	body := mustMarshalTestJSON(t, map[string]any{
		"messages": []any{map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":      "f",
					"arguments": arguments,
				},
			}},
		}},
	})
	plugin := newTestPlugin(t)
	result, err := plugin.sanitizeRequest(context.Background(), "openai", body)
	if err != nil {
		t.Fatal("expanded credential-field fixture failed sanitization")
	}
	if !result.changed || result.findings != len(fieldNames) {
		t.Fatalf("credential findings = %d, want %d", result.findings, len(fieldNames))
	}
	if bytes.Contains(result.body, []byte(shortCredential)) || !json.Valid(result.body) {
		t.Fatal("an expanded credential-field value remained after sanitization")
	}
}

func TestPlaceholderLikeCredentialCannotLeakFromEncodedToolJSON(t *testing.T) {
	secret := strings.Join([]string{"sk", "live", "real", "secret"}, "-")
	wrapped := "{{" + secret + "}}"
	arguments := string(mustMarshalTestJSON(t, map[string]any{"api_key": wrapped}))
	body := mustMarshalTestJSON(t, map[string]any{
		"messages": []any{map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"type":     "function",
				"function": map[string]any{"name": "lookup", "arguments": arguments},
			}},
		}},
	})
	plugin := newTestPlugin(t)
	result, err := plugin.sanitizeRequest(context.Background(), "openai", body)
	if err != nil {
		t.Fatal("placeholder-like credential request failed sanitization")
	}
	if !result.changed || result.findings != 1 || bytes.Contains(result.body, []byte(secret)) ||
		bytes.Contains(result.body, []byte(wrapped)) {
		t.Fatal("placeholder-like credential remained after sanitization")
	}
}

func TestCredentialFieldBlockingRuleTerminates(t *testing.T) {
	shortValue := strings.Join([]string{"q", "7", "q", "q", "2"}, "")
	arguments := string(mustMarshalTestJSON(t, map[string]any{"api_key": shortValue}))
	body := mustMarshalTestJSON(t, map[string]any{
		"messages": []any{map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"type":     "function",
				"function": map[string]any{"name": "f", "arguments": arguments},
			}},
		}},
	})
	plugin := newTestPlugin(t)
	plugin.blockRuleIDs = map[string]struct{}{"builtin.credential-field": {}}
	response, err := plugin.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         body,
	})
	if err != nil {
		t.Fatalf("InterceptRequestBeforeAuth: %v", err)
	}
	if !response.Terminate || response.StatusCode != 422 || response.Body != nil {
		t.Fatal("credential-field block rule did not terminate without a body")
	}
}

func TestConfiguredCredentialPlaceholdersRemainIdempotent(t *testing.T) {
	secretA := strings.Join([]string{"q", "7", "q", "q", "2"}, "")
	secretB := strings.Join([]string{"z", "4", "z", "z", "8"}, "")
	arguments := string(mustMarshalTestJSON(t, map[string]any{"AK": secretA, "SK": secretB}))
	body := mustMarshalTestJSON(t, map[string]any{
		"messages": []any{map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"type":     "function",
				"function": map[string]any{"name": "f", "arguments": arguments},
			}},
		}},
	})
	plugin := newTestPlugin(t)
	plugin.cfg.Replacements = map[string]string{"secret": "[CUSTOM]"}
	var err error
	plugin.renderer, err = plugin.cfg.renderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}

	renderer := newRequestRenderer(plugin.renderer)
	first, err := plugin.sanitizeRequestWithRenderer(context.Background(), "openai", body, renderer)
	if err != nil {
		t.Fatalf("first sanitizeRequest: %v", err)
	}
	if !first.changed || first.findings != 2 ||
		bytes.Contains(first.body, []byte(secretA)) || bytes.Contains(first.body, []byte(secretB)) ||
		bytes.Count(first.body, []byte("[CUSTOM]")) != 1 || bytes.Count(first.body, []byte("[CUSTOM#2]")) != 1 {
		t.Fatal("configured placeholders were not rendered as expected")
	}

	second, err := plugin.sanitizeRequestWithRenderer(context.Background(), "openai", first.body, renderer)
	if err != nil {
		t.Fatalf("second sanitizeRequest: %v", err)
	}
	if second.changed || second.findings != 0 || !bytes.Equal(second.body, first.body) {
		t.Fatal("configured placeholders were not idempotent")
	}
}

func TestOnlyRequestProducedPlaceholdersBypassSecondPassDetection(t *testing.T) {
	plugin := newTestPlugin(t)
	engine, _, err := privacyengine.New(privacyengine.Config{
		CustomTOML: []byte(`
[[rules]]
id = "placeholder-test"
regex = '''(?:TRIGGER|\[CUSTOM\])'''
`),
		CustomMode:          privacyengine.CustomRulesReplace,
		CustomCompatibility: privacyengine.CompatibilityError,
		DefaultLimits:       plugin.cfg.engineLimits(),
	})
	if err != nil {
		t.Fatalf("create test engine: %v", err)
	}
	plugin.engine = engine
	plugin.cfg.Replacements = map[string]string{"secret": "[CUSTOM]"}
	plugin.renderer, err = plugin.cfg.renderer()
	if err != nil {
		t.Fatalf("renderer: %v", err)
	}

	renderer := newRequestRenderer(plugin.renderer)
	budget, err := privacyengine.NewBudget(plugin.cfg.engineLimits())
	if err != nil {
		t.Fatalf("budget: %v", err)
	}
	produced, findings, changed, err := plugin.sanitizeText(context.Background(), "TRIGGER", budget, renderer, privacyengine.FieldContext{}, nil)
	if err != nil || !changed || findings != 1 || produced != "[CUSTOM]" {
		t.Fatalf("first pass = changed %v, findings %d, err %v", changed, findings, err)
	}
	_, findings, changed, err = plugin.sanitizeText(context.Background(), produced, budget, renderer, privacyengine.FieldContext{}, nil)
	if err != nil || changed || findings != 0 {
		t.Fatalf("request-produced placeholder was rescanned: changed %v, findings %d, err %v", changed, findings, err)
	}

	freshRenderer := newRequestRenderer(plugin.renderer)
	freshBudget, err := privacyengine.NewBudget(plugin.cfg.engineLimits())
	if err != nil {
		t.Fatalf("fresh budget: %v", err)
	}
	_, findings, _, err = plugin.sanitizeText(context.Background(), "[CUSTOM]", freshBudget, freshRenderer, privacyengine.FieldContext{}, nil)
	if err != nil || findings != 1 {
		t.Fatalf("user-supplied placeholder-shaped text bypassed detection: findings %d, err %v", findings, err)
	}
}

func TestShortCredentialRuleDoesNotTreatPlainToolOutputAsField(t *testing.T) {
	plain := strings.Join([]string{"r4", "Q", "p7", " AK/SK prose"}, "")
	body := mustMarshalTestJSON(t, map[string]any{
		"messages": []any{map[string]any{"role": "tool", "content": plain}},
	})
	plugin := newTestPlugin(t)
	result, err := plugin.sanitizeRequest(context.Background(), "openai", body)
	if err != nil {
		t.Fatalf("sanitizeRequest: %v", err)
	}
	if result.changed || result.findings != 0 {
		t.Fatalf("plain tool output produced %d findings", result.findings)
	}
	if !bytes.Equal(result.body, body) {
		t.Fatal("plain tool output bytes changed")
	}
}

func TestEncodedToolJSONPreservesLargeInteger(t *testing.T) {
	p := newTestPlugin(t)
	const body = `{"model":"m","messages":[{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"f","arguments":"{\"id\":9007199254740993,\"email\":\"test@example.com\"}"}}]}]}`
	result, err := p.sanitizeRequest(context.Background(), "openai", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if !result.changed || strings.Contains(string(result.body), "test@example.com") {
		t.Fatalf("tool JSON not sanitized: changed=%t findings=%d body_len=%d", result.changed, result.findings, len(result.body))
	}
	if !strings.Contains(string(result.body), `9007199254740993`) {
		t.Fatalf("tool JSON integer changed: body_len=%d", len(result.body))
	}
}

func TestEmptyReplacementStaysEmptyForMultipleValues(t *testing.T) {
	if got := numberedPlaceholder("", 2); got != "" {
		t.Fatalf("numbered empty replacement length = %d, want 0", len(got))
	}
}

func TestRequestRendererKeepsEqualityAndDistinguishesValues(t *testing.T) {
	p := newTestPlugin(t)
	const body = `{"model":"m","messages":[{"role":"user","content":"a@example.com b@example.com a@example.com"}]}`
	result, err := p.sanitizeRequest(context.Background(), "openai", []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	got := string(result.body)
	if strings.Count(got, "[邮箱]") != 2 || strings.Count(got, "[邮箱#2]") != 1 {
		t.Fatalf("unexpected request-local placeholders: base_count=%d numbered_count=%d body_len=%d", strings.Count(got, "[邮箱]"), strings.Count(got, "[邮箱#2]"), len(got))
	}
}

func TestNoFindingLeavesOriginalBytesUntouched(t *testing.T) {
	p := newTestPlugin(t)
	body := []byte(" \n{\"model\" : \"m\", \"messages\" : [{\"role\":\"user\",\"content\":\"hello\"}], \"n\":9007199254740993}\t")
	result, err := p.sanitizeRequest(context.Background(), "openai", body)
	if err != nil {
		t.Fatal(err)
	}
	if result.changed || &result.body[0] != &body[0] || string(result.body) != string(body) {
		t.Fatalf("no-hit body was copied or changed: changed=%t findings=%d targets=%d body_len=%d", result.changed, result.findings, result.targets, len(result.body))
	}
}

func TestUnsupportedFormatAndShapeFailClosed(t *testing.T) {
	p := newTestPlugin(t)
	for _, req := range []pluginapi.RequestInterceptRequest{
		{SourceFormat: "codex", Body: []byte(`{"input":"test@example.com"}`)},
		{SourceFormat: "openai", Body: []byte(`{"messages":[{"role":"user","content":[{"type":"future_block","text":"test@example.com"}]}]}`)},
	} {
		resp, err := p.InterceptRequestBeforeAuth(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Terminate || resp.StatusCode != 422 {
			t.Fatalf("response terminate=%t status=%d body_len=%d, want terminate 422", resp.Terminate, resp.StatusCode, len(resp.Body))
		}
	}
}

func TestLimitErrorsMapTo413(t *testing.T) {
	p := newTestPlugin(t)
	limits := []error{
		privacyengine.ErrBudgetExceeded,
		payload.ErrBodyTooLarge,
		payload.ErrDepthLimit,
		payload.ErrNodeLimit,
		payload.ErrStructuralLimit,
		payload.ErrStringTooLarge,
		payload.ErrReplacementLimit,
	}
	for _, limitErr := range limits {
		resp := p.handleFailure("openai", limitErr)
		if !resp.Terminate || resp.StatusCode != 413 ||
			!bytes.Contains(resp.ResponseBody, []byte(`"code":"privacy_filter_limit_exceeded"`)) {
			t.Fatalf("limit error %T mapped to wrong response", limitErr)
		}
		if got := failureReason(limitErr); got != "limit_exceeded" {
			t.Fatalf("failureReason() mismatch: got_len=%d", len(got))
		}
	}
}

func TestEncodedJSONScanLimitCausesArePreserved(t *testing.T) {
	tests := []struct {
		name      string
		text      string
		configure func(*privacyFilterPlugin)
		want      error
	}{
		{
			name: "body",
			text: `[]`,
			configure: func(p *privacyFilterPlugin) {
				p.cfg.Limits.MaxBodyBytes = 1
			},
			want: payload.ErrBodyTooLarge,
		},
		{
			name: "depth",
			text: `[0]`,
			configure: func(p *privacyFilterPlugin) {
				p.cfg.Limits.MaxDepth = 1
			},
			want: payload.ErrDepthLimit,
		},
		{
			name: "nodes",
			text: `[0]`,
			configure: func(p *privacyFilterPlugin) {
				p.cfg.Limits.MaxJSONNodes = 1
			},
			want: payload.ErrNodeLimit,
		},
		{
			name: "string",
			text: `"xx"`,
			configure: func(p *privacyFilterPlugin) {
				p.cfg.Limits.MaxStringBytes = 1
			},
			want: payload.ErrStringTooLarge,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			p := newTestPlugin(t)
			testCase.configure(p)
			budget, err := privacyengine.NewBudget(p.cfg.engineLimits())
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, sanitizeErr := p.sanitizeJSONText(
				context.Background(),
				testCase.text,
				budget,
				p.renderer,
				walker.TargetContext{ToolScope: walker.ScopeToolInput, Encoded: true},
				false,
			)
			assertEncodedJSONLimit(t, p, sanitizeErr, testCase.want)
		})
	}

	t.Run("structural", func(t *testing.T) {
		p := newTestPlugin(t)
		budget, err := privacyengine.NewBudget(p.cfg.engineLimits())
		if err != nil {
			t.Fatal(err)
		}
		limits := p.cfg.payloadLimits()
		limits.MaxStructuralBytes = 1_000
		_, _, _, sanitizeErr := p.sanitizeJSONTextWithLimits(
			context.Background(),
			`{"a":"b"}`,
			budget,
			p.renderer,
			walker.TargetContext{ToolScope: walker.ScopeToolInput, Encoded: true},
			false,
			limits,
		)
		assertEncodedJSONLimit(t, p, sanitizeErr, payload.ErrStructuralLimit)
	})
}

func assertEncodedJSONLimit(t *testing.T, p *privacyFilterPlugin, err, want error) {
	t.Helper()
	if !errors.Is(err, want) || !errors.Is(err, errUnsupportedRequestShape) {
		t.Fatal("encoded JSON scan did not preserve both error classifications")
	}
	resp := p.handleFailure("openai", err)
	if !resp.Terminate || resp.StatusCode != 413 {
		t.Fatal("encoded JSON limit did not map to terminate 413")
	}
}

func TestNestedEncodedJSONLimitsRemain413(t *testing.T) {
	toolArgumentsBody := func(t *testing.T, arguments string) []byte {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"messages": []any{map[string]any{
				"role": "assistant",
				"tool_calls": []any{map[string]any{
					"type": "function",
					"function": map[string]any{
						"name":      "f",
						"arguments": arguments,
					},
				}},
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}

	tests := []struct {
		name      string
		arguments func() string
		configure func(*privacyFilterPlugin)
		want      error
	}{
		{
			name: "depth",
			arguments: func() string {
				return strings.Repeat("[", 7) + "0" + strings.Repeat("]", 7)
			},
			configure: func(p *privacyFilterPlugin) {
				p.cfg.Limits.MaxDepth = 7
			},
			want: payload.ErrDepthLimit,
		},
		{
			name: "nodes",
			arguments: func() string {
				values := make([]int, 10)
				raw, err := json.Marshal(values)
				if err != nil {
					panic(err)
				}
				return string(raw)
			},
			configure: func(p *privacyFilterPlugin) {
				p.cfg.Limits.MaxJSONNodes = 10
			},
			want: payload.ErrNodeLimit,
		},
		{
			name: "detector",
			arguments: func() string {
				raw, err := json.Marshal(map[string]string{"email": "person" + "@example.test"})
				if err != nil {
					panic(err)
				}
				return string(raw)
			},
			configure: func(p *privacyFilterPlugin) {
				p.cfg.Limits.MaxTextBytes = 4
			},
			want: privacyengine.ErrBudgetExceeded,
		},
		{
			name: "replacement",
			arguments: func() string {
				raw, err := json.Marshal(map[string]string{
					"first":  "one" + "@example.test",
					"second": "two" + "@example.test",
				})
				if err != nil {
					panic(err)
				}
				return string(raw)
			},
			configure: func(p *privacyFilterPlugin) {
				p.cfg.Limits.MaxReplacements = 1
			},
			want: payload.ErrReplacementLimit,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			p := newTestPlugin(t)
			testCase.configure(p)
			body := toolArgumentsBody(t, testCase.arguments())
			_, sanitizeErr := p.sanitizeRequest(context.Background(), "openai", body)
			if !errors.Is(sanitizeErr, testCase.want) {
				t.Fatal("nested limit cause was not preserved")
			}
			resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
				SourceFormat: "openai",
				Body:         body,
			})
			if err != nil {
				t.Fatal(err)
			}
			if !resp.Terminate || resp.StatusCode != 413 ||
				!bytes.Contains(resp.ResponseBody, []byte(`"code":"privacy_filter_limit_exceeded"`)) {
				t.Fatal("nested limit did not map to terminate 413")
			}
		})
	}
}

func TestRecursiveEncodedJSONNestingLimitTerminatesWith413(t *testing.T) {
	nested := `["safe"]`
	for range maxEncodedJSONNesting + 1 {
		nested = string(mustMarshalTestJSON(t, map[string]string{"nested": nested}))
	}
	body := mustMarshalTestJSON(t, map[string]any{
		"messages": []any{map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":      "f",
					"arguments": nested,
				},
			}},
		}},
	})
	plugin := newTestPlugin(t)
	_, sanitizeErr := plugin.sanitizeRequest(context.Background(), "openai", body)
	if !errors.Is(sanitizeErr, payload.ErrDepthLimit) {
		t.Fatal("recursive encoded JSON did not preserve the depth-limit cause")
	}
	response, err := plugin.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         body,
	})
	if err != nil {
		t.Fatal("recursive nesting rejection returned a transport error")
	}
	if !response.Terminate || response.StatusCode != 413 {
		t.Fatal("recursive encoded JSON nesting limit did not terminate with 413")
	}
}

func TestRecursiveEncodedJSONBoundaryTreatsInvalidContainerPrefixAsPlainText(t *testing.T) {
	for _, prefix := range []string{"{", "["} {
		t.Run(prefix, func(t *testing.T) {
			nested := strings.Join([]string{prefix, "not-json"}, "")
			for range maxEncodedJSONNesting + 1 {
				nested = string(mustMarshalTestJSON(t, map[string]string{"nested": nested}))
			}
			body := mustMarshalTestJSON(t, map[string]any{
				"messages": []any{map[string]any{
					"role": "assistant",
					"tool_calls": []any{map[string]any{
						"type": "function",
						"function": map[string]any{
							"name":      "f",
							"arguments": nested,
						},
					}},
				}},
			})
			plugin := newTestPlugin(t)
			result, err := plugin.sanitizeRequest(context.Background(), "openai", body)
			if err != nil {
				t.Fatal("invalid JSON-like plain text at the recursion boundary was rejected")
			}
			if result.changed || result.findings != 0 || !bytes.Equal(result.body, body) {
				t.Fatal("invalid JSON-like plain text at the recursion boundary was modified")
			}
		})
	}
}

func TestOuterAndEncodedJSONShareCumulativeNodeLimit(t *testing.T) {
	inner := string(mustMarshalTestJSON(t, []string{"safe"}))
	arguments := string(mustMarshalTestJSON(t, map[string]string{"nested": inner}))
	body := mustMarshalTestJSON(t, map[string]any{
		"messages": []any{map[string]any{
			"role": "assistant",
			"tool_calls": []any{map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":      "f",
					"arguments": arguments,
				},
			}},
		}},
	})
	walked, err := walker.Walk(context.Background(), "openai", body)
	if err != nil {
		t.Fatal("outer request fixture did not walk")
	}
	plugin := newTestPlugin(t)
	plugin.cfg.Limits.MaxJSONNodes = walked.JSONNodes + 2
	_, sanitizeErr := plugin.sanitizeRequest(context.Background(), "openai", body)
	if !errors.Is(sanitizeErr, payload.ErrNodeLimit) {
		t.Fatal("outer and nested encoded JSON did not share the node budget")
	}
	response := plugin.handleFailure("openai", sanitizeErr)
	if !response.Terminate || response.StatusCode != 413 {
		t.Fatal("cumulative encoded JSON node limit did not terminate with 413")
	}
}

func TestNestedEncodedRootInheritsOuterCredentialFieldContext(t *testing.T) {
	shortCredential := strings.Join([]string{"q", "7", "z"}, "")
	tests := []struct {
		name  string
		inner any
	}{
		{name: "array root", inner: []string{shortCredential}},
		{name: "full inner ancestor context", inner: map[string]any{
			"a": map[string]any{"b": map[string]any{"c": map[string]any{
				"d": map[string]string{"value": shortCredential},
			}}},
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			inner := string(mustMarshalTestJSON(t, testCase.inner))
			arguments := string(mustMarshalTestJSON(t, map[string]string{"api_key": inner}))
			body := mustMarshalTestJSON(t, map[string]any{
				"messages": []any{map[string]any{
					"role": "assistant",
					"tool_calls": []any{map[string]any{
						"type": "function",
						"function": map[string]any{
							"name":      "f",
							"arguments": arguments,
						},
					}},
				}},
			})
			plugin := newTestPlugin(t)
			result, err := plugin.sanitizeRequest(context.Background(), "openai", body)
			if err != nil {
				t.Fatal("nested encoded credential fixture failed sanitization")
			}
			if !result.changed || result.findings != 1 || bytes.Contains(result.body, []byte(shortCredential)) {
				t.Fatal("nested encoded root did not inherit its outer credential context")
			}
		})
	}
}

func TestStringBearingProtocolExtensionsTerminateWith422(t *testing.T) {
	tests := []struct {
		name   string
		format string
		body   string
	}{
		{"openai", "openai", `{"messages":[{"role":"user","content":"ok","future":"extension"}]}`},
		{"responses", "openai-response", `{"input":[{"type":"message","role":"user","content":"ok","future":"extension"}]}`},
		{"anthropic", "claude", `{"messages":[{"role":"user","content":[{"type":"text","text":"ok","future":"extension"}]}]}`},
		{"gemini", "gemini", `{"contents":[{"role":"user","parts":[{"text":"ok","future":"extension"}]}]}`},
		{"interactions", "interactions", `{"input":[{"type":"user_input","content":"ok","future":"extension"}]}`},
		{"openai tool definition", "openai", `{"messages":[],"tools":[{"type":"function","function":{"name":"lookup","parameters":{},"future":"extension"}}]}`},
		{"openai nested media", "openai", `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://example.invalid","future":"extension"}}]}]}`},
		{"responses tool definition", "openai-response", `{"input":"ok","tools":[{"type":"function","name":"lookup","parameters":{},"future":"extension"}]}`},
		{"responses unadmitted root tool", "openai-response", `{"input":"ok","tools":[{"type":"shell"}]}`},
		{"anthropic tool definition", "claude", `{"messages":[],"tools":[{"name":"lookup","input_schema":{},"future":"extension"}]}`},
		{"gemini tool definition", "gemini", `{"contents":[],"tools":[{"functionDeclarations":[{"name":"lookup","parameters":{},"future":"extension"}]}]}`},
		{"gemini inline media", "gemini", `{"contents":[{"parts":[{"inlineData":{"data":"bytes","future":"extension"}}]}]}`},
		{"gemini built-in tool", "gemini", `{"contents":[],"tools":[{"googleSearch":{"future":"extension"}}]}`},
		{"interactions tool definition", "interactions", `{"input":"ok","tools":[{"type":"function","name":"lookup","parameters":{},"future":"extension"}]}`},
		{"interactions nested media", "interactions", `{"input":[{"type":"user_input","content":[{"type":"image","image_url":{"url":"https://example.invalid","future":"extension"}}]}]}`},
		{"responses web-search source", "openai-response", `{"input":[{"type":"web_search_call","action":{"type":"search","query":"ok","sources":[{"type":"url","url":"https://example.invalid","future":"extension"}]}}]}`},
		{"responses safety check", "openai-response", `{"input":[{"type":"computer_call","pending_safety_checks":[{"id":"safe_1","message":"control","future":"extension"}],"action":{"type":"wait"}}]}`},
		{"responses image revised prompt", "openai-response", `{"input":[{"type":"image_generation_call","id":"ig_1","status":"completed","result":"base64","revised_prompt":"visible prompt"}]}`},
		{"responses tool-search output", "openai-response", `{"input":[{"type":"tool_search_output","id":"tso_1","tools":[]}]}`},
		{"responses program", "openai-response", `{"input":[{"type":"program","id":"pg_1","code":"replay code","fingerprint":"fingerprint"}]}`},
		{"responses URL citation", "openai-response", `{"input":[{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"answer","annotations":[{"type":"url_citation","start_index":0,"end_index":6,"title":"title","url":"https://example.invalid"}]}]}]}`},
		{"responses output logprobs", "openai-response", `{"input":[{"type":"message","id":"msg_1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"a","annotations":[],"logprobs":[{"token":"a","bytes":[97],"logprob":-0.1,"top_logprobs":[]}]}]}]}`},
		{"responses root typed extension", "openai-response", `{"input":"ok","reasoning":{"effort":"medium","future":"extension"}}`},
		{"responses reasoning replay extension", "openai-response", `{"input":[{"type":"reasoning","id":"rs_1","summary":[{"type":"summary_text","text":"replay","future":"extension"}]}]}`},
		{"responses malformed media control", "openai-response", `{"input":[{"type":"message","role":"assistant","content":[{"type":"input_image","file_id":{"future":"extension"}}]}]}`},
		{"responses computer wrong-arm string", "openai-response", `{"input":[{"type":"computer_call","pending_safety_checks":[],"action":{"type":"wait","keys":["extension"]}}]}`},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			p := newTestPlugin(t)
			resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
				SourceFormat: testCase.format,
				Body:         []byte(testCase.body),
			})
			if err != nil {
				t.Fatal("interceptor returned an error")
			}
			if !resp.Terminate || resp.StatusCode != 422 {
				t.Fatal("string-bearing extension did not terminate with 422")
			}
		})
	}
}

func TestResponsesLiteCompatibilityRedactsWithoutRejecting(t *testing.T) {
	p := newTestPlugin(t)
	shortCredential := strings.Join([]string{"q", "7", "z"}, "")
	sensitiveEmail := strings.Join([]string{"person", "example.test"}, "@")
	sessionID := strings.Join([]string{"session", "1"}, "_")
	turnMetadata := mustMarshalTestJSON(t, map[string]any{
		"api_key":   shortCredential,
		"workspace": map[string]any{"label": "ordinary"},
	})
	customInput := mustMarshalTestJSON(t, map[string]any{"AK": shortCredential})
	body := mustMarshalTestJSON(t, map[string]any{
		"client_metadata": map[string]any{
			"session_id":              sessionID,
			"x-codex-installation-id": "installation_1",
			"x-codex-window-id":       "window_1",
			"thread_id":               "thread_1",
			"turn_id":                 "turn_1",
			"root_turn_id":            "root_1",
			"x-codex-turn-metadata":   string(turnMetadata),
			"future_transport_key":    map[string]any{"api_key": shortCredential},
		},
		"input": []any{
			map[string]any{
				"type": "additional_tools", "id": "at_1", "role": "developer",
				"tools": []any{map[string]any{
					"type": "namespace", "name": "functions", "description": sensitiveEmail,
					"tools": []any{
						map[string]any{
							"type": "function", "name": "lookup", "description": sensitiveEmail,
							"parameters": map[string]any{"type": "object"},
						},
						map[string]any{
							"type": "custom", "name": "freeform", "description": sensitiveEmail,
							"format": map[string]any{"type": "grammar", "syntax": "lark", "definition": "start: WORD"},
						},
					},
				}},
			},
			map[string]any{
				"type": "custom_tool_call", "id": "ct_1", "call_id": "call_1",
				"name": "freeform", "status": "completed", "input": string(customInput),
				"internal_chat_message_metadata_passthrough": map[string]any{
					"executed_tool_calls": []any{map[string]any{
						"arguments": map[string]any{"api_key": shortCredential},
					}},
				},
			},
		},
	})

	result, err := p.sanitizeRequest(context.Background(), "openai-response", body)
	if err != nil {
		t.Fatal("Responses Lite compatibility request failed sanitization")
	}
	if result.unsupported != 0 || !result.changed || result.findings < 2 {
		t.Fatal("Responses Lite compatibility request was not fully inspected")
	}
	if bytes.Contains(result.body, []byte(shortCredential)) || bytes.Contains(result.body, []byte(sensitiveEmail)) {
		t.Fatal("Responses Lite sensitive values survived redaction")
	}

	var decoded map[string]any
	if err = json.Unmarshal(result.body, &decoded); err != nil {
		t.Fatal("sanitized Responses Lite body is not valid JSON")
	}
	metadata, ok := decoded["client_metadata"].(map[string]any)
	if !ok || metadata["session_id"] != sessionID {
		t.Fatal("client transport metadata was not preserved")
	}
	items, ok := decoded["input"].([]any)
	if !ok || len(items) != 2 {
		t.Fatal("sanitized Responses Lite input shape changed")
	}
	call, ok := items[1].(map[string]any)
	if !ok || call["status"] != "completed" {
		t.Fatal("custom tool call status was not preserved")
	}
}

func TestOpenAIReasoningDetailsReplayDoesNotRejectOrMutate(t *testing.T) {
	p := newTestPlugin(t)
	sensitive := strings.Join([]string{"person", "example.test"}, "@")
	reasoningText := strings.Join([]string{"signed", "reasoning", "payload"}, "-")
	body := mustMarshalTestJSON(t, map[string]any{
		"messages": []any{
			map[string]any{"role": "user", "content": sensitive},
			map[string]any{
				"role":              "assistant",
				"content":           "answer",
				"reasoning":         reasoningText,
				"reasoning_content": reasoningText,
				"reasoning_details": []any{map[string]any{
					"type": "reasoning.text", "text": reasoningText,
					"format": "unknown", "index": 0,
				}},
			},
		},
	})
	result, err := p.sanitizeRequest(context.Background(), "openai", body)
	if err != nil {
		t.Fatal("OpenAI reasoning replay failed sanitization")
	}
	if result.unsupported != 0 || !result.changed {
		t.Fatal("OpenAI reasoning replay was rejected or user text was not redacted")
	}

	var decoded map[string]any
	if err = json.Unmarshal(result.body, &decoded); err != nil {
		t.Fatal("sanitized OpenAI reasoning replay is not valid JSON")
	}
	messages, ok := decoded["messages"].([]any)
	if !ok || len(messages) != 2 {
		t.Fatal("sanitized OpenAI reasoning replay messages changed shape")
	}
	user, ok := messages[0].(map[string]any)
	if !ok || user["content"] == sensitive {
		t.Fatal("user content was not redacted")
	}
	assistant, ok := messages[1].(map[string]any)
	if !ok || assistant["reasoning"] != reasoningText || assistant["reasoning_content"] != reasoningText {
		t.Fatal("legacy reasoning replay fields were modified")
	}
	details, ok := assistant["reasoning_details"].([]any)
	if !ok || len(details) != 1 {
		t.Fatal("reasoning_details changed shape")
	}
	detail, ok := details[0].(map[string]any)
	if !ok || detail["text"] != reasoningText || detail["type"] != "reasoning.text" || detail["format"] != "unknown" {
		t.Fatal("reasoning_details replay data was modified")
	}
}

func TestFailureDiagnosticsExposeOnlyAllowlistedPathKeys(t *testing.T) {
	sensitiveKey := strings.Join([]string{"credential", "value"}, "-")
	err := &unsupportedRequestShapeError{
		count: 2,
		paths: []payload.Path{
			{payload.Key("messages"), payload.Index(7), payload.Key("reasoning_details"), payload.Index(0), payload.Key("text")},
			{payload.Key("input"), payload.Index(1), payload.Key(sensitiveKey)},
		},
	}
	fields := failureLogFields("openai", err)
	if fields["issue_category"] != "unsupported_shape" || fields["issue_count"] != 2 {
		t.Fatal("failure diagnostic category or count mismatch")
	}
	paths, ok := fields["issue_paths"].(string)
	if !ok || !strings.Contains(paths, `$["messages"][7]["reasoning_details"][0]["text"]`) ||
		!strings.Contains(paths, `$["input"][1]["<redacted>"]`) {
		t.Fatal("failure diagnostic paths did not preserve safe structure")
	}
	if strings.Contains(paths, sensitiveKey) {
		t.Fatal("failure diagnostic exposed an untrusted object key")
	}
}

func TestEncodedFailureDiagnosticRetainsOnlyOuterSafePath(t *testing.T) {
	err := &targetInspectionError{
		path:  payload.Path{payload.Key("client_metadata"), payload.Key("x-codex-turn-metadata")},
		cause: errors.Join(errUnsupportedRequestShape, payload.ErrInvalidJSON),
	}
	category, count, paths := failureDiagnostic(err)
	if category != "encoded_json_invalid" || count != 1 || len(paths) != 1 ||
		paths[0] != `$["client_metadata"]["x-codex-turn-metadata"]` {
		t.Fatal("encoded target failure diagnostic mismatch")
	}
	if !errors.Is(err, errUnsupportedRequestShape) || !errors.Is(err, payload.ErrInvalidJSON) {
		t.Fatal("encoded target failure lost error classification")
	}
}

func TestResponsesLiteMalformedTurnMetadataTerminates(t *testing.T) {
	body := mustMarshalTestJSON(t, map[string]any{
		"client_metadata": map[string]any{
			"x-codex-turn-metadata": "{not-json",
		},
		"input": "ok",
	})
	resp, err := newTestPlugin(t).InterceptRequestBeforeAuth(
		context.Background(),
		pluginapi.RequestInterceptRequest{SourceFormat: "openai-response", Body: body},
	)
	if err != nil {
		t.Fatal("interceptor returned an error")
	}
	if !resp.Terminate || resp.StatusCode != 422 {
		t.Fatal("malformed encoded turn metadata did not terminate with 422")
	}
}

func TestResponsesSafeFileAnnotationsPreserveMetadataDuringRedaction(t *testing.T) {
	p := newTestPlugin(t)
	sensitive := strings.Join([]string{"person", "example.test"}, "@")
	fileID := strings.Join([]string{"file", "1"}, "_")
	filename := strings.Join([]string{"doc", "txt"}, ".")
	body := mustMarshalTestJSON(t, map[string]any{
		"input": []any{map[string]any{
			"type": "message", "id": "msg_1", "role": "assistant", "status": "completed",
			"content": []any{map[string]any{
				"type": "output_text", "text": sensitive,
				"annotations": []any{map[string]any{
					"type": "file_citation", "file_id": fileID, "filename": filename, "index": 0,
				}},
			}},
		}},
	})
	result, err := p.sanitizeRequest(context.Background(), "openai-response", body)
	if err != nil {
		t.Fatal("safe file annotation request failed sanitization")
	}
	if !result.changed || bytes.Contains(result.body, []byte(sensitive)) ||
		!bytes.Contains(result.body, []byte(fileID)) || !bytes.Contains(result.body, []byte(filename)) ||
		!json.Valid(result.body) {
		t.Fatal("file annotation metadata was not preserved during redaction")
	}
}

func TestGeminiMediaDisplayNamesAreSanitized(t *testing.T) {
	p := newTestPlugin(t)
	sensitive := strings.Join([]string{"attachment", "example.test"}, "@")
	body, err := json.Marshal(map[string]any{
		"contents": []any{map[string]any{
			"role": "user",
			"parts": []any{
				map[string]any{"inlineData": map[string]any{"mimeType": "image/png", "data": "base64", "displayName": sensitive}},
				map[string]any{"fileData": map[string]any{"fileUri": "https://example.invalid/file", "displayName": sensitive}},
			},
		}},
	})
	if err != nil {
		t.Fatal("failed to construct Gemini media request")
	}
	result, sanitizeErr := p.sanitizeRequest(context.Background(), "gemini", body)
	if sanitizeErr != nil {
		t.Fatal("supported Gemini media request failed sanitization")
	}
	if !result.changed || bytes.Contains(result.body, []byte(sensitive)) {
		t.Fatal("Gemini media display name was not sanitized")
	}
}

func TestResponsesMCPAndShellAndSearchTextCannotLeak(t *testing.T) {
	p := newTestPlugin(t)
	sensitive := strings.Join([]string{"person", "example.test"}, "@")
	shortCredential := strings.Join([]string{"q", "7"}, "")
	encodedInput, err := json.Marshal(map[string]string{"note": sensitive})
	if err != nil {
		t.Fatal("failed to construct encoded input")
	}
	encodedOutput, err := json.Marshal(map[string]string{"result": sensitive})
	if err != nil {
		t.Fatal("failed to construct encoded output")
	}
	body, err := json.Marshal(map[string]any{
		"input": []any{
			map[string]any{
				"type": "mcp_list_tools", "id": "mcp_list_1", "server_label": "server", "error": sensitive,
			},
			map[string]any{
				"type": "mcp_approval_request", "id": "mcp_approval_1", "server_label": "server", "name": "lookup",
				"arguments": string(encodedInput),
			},
			map[string]any{
				"type": "mcp_approval_response", "id": "mcp_approval_response_1", "approval_request_id": "mcp_approval_1",
				"approve": false, "reason": sensitive,
			},
			map[string]any{
				"type": "mcp_call", "id": "mcp_1", "server_label": "server", "name": "lookup",
				"arguments": string(encodedInput), "error": sensitive, "output": sensitive,
			},
			map[string]any{
				"type": "local_shell_call", "id": "local_1", "call_id": "call_1", "status": "completed",
				"action": map[string]any{
					"type": "exec", "command": []string{"run " + sensitive}, "env": map[string]string{"API_KEY": shortCredential},
				},
			},
			map[string]any{
				"type": "local_shell_call_output", "id": "local_out_1", "status": "completed", "output": string(encodedOutput),
			},
			map[string]any{
				"type": "shell_call", "id": "shell_1", "call_id": "call_2", "status": "completed",
				"action": map[string]any{"commands": []string{"run " + sensitive}},
			},
			map[string]any{
				"type": "shell_call_output", "id": "shell_out_1", "call_id": "call_2", "status": "completed",
				"output": []any{map[string]any{
					"outcome": map[string]any{"type": "exit", "exit_code": 0}, "stdout": sensitive, "stderr": sensitive,
				}},
			},
			map[string]any{
				"type": "file_search_call", "id": "file_search_1", "status": "completed", "queries": []string{sensitive},
				"results": []any{map[string]any{"text": sensitive, "attributes": map[string]any{"note": sensitive}}},
			},
			map[string]any{
				"type": "web_search_call", "id": "web_search_1", "status": "completed",
				"action": map[string]any{"type": "search", "query": sensitive},
			},
		},
	})
	if err != nil {
		t.Fatal("failed to construct request")
	}
	result, sanitizeErr := p.sanitizeRequest(context.Background(), "openai-response", body)
	if sanitizeErr != nil {
		t.Fatal("supported Responses request failed sanitization")
	}
	if !result.changed {
		t.Fatal("supported Responses request was not changed")
	}
	if bytes.Contains(result.body, []byte(sensitive)) || bytes.Contains(result.body, []byte(shortCredential)) {
		t.Fatal("supported Responses request retained sensitive target text")
	}
}

func TestToolDescriptionsAndSchemasAreSanitizedAcrossProtocols(t *testing.T) {
	sensitive := strings.Join([]string{"schema", "example.test"}, "@")
	schema := map[string]any{
		"type":        "object",
		"description": sensitive,
		"properties":  map[string]any{"value": map[string]any{"type": "string", "default": sensitive}},
	}
	tests := []struct {
		name   string
		format string
		body   map[string]any
	}{
		{name: "OpenAI chat", format: "openai", body: map[string]any{
			"messages": []any{},
			"tools": []any{map[string]any{"type": "function", "function": map[string]any{
				"name": "lookup", "description": sensitive, "parameters": schema,
			}}},
		}},
		{name: "Responses", format: "openai-response", body: map[string]any{
			"input": "ok",
			"tools": []any{map[string]any{
				"type": "function", "name": "lookup", "description": sensitive,
				"parameters": schema, "output_schema": schema,
			}},
		}},
		{name: "Anthropic", format: "claude", body: map[string]any{
			"messages": []any{},
			"tools": []any{map[string]any{
				"name": "lookup", "description": sensitive, "input_schema": schema,
			}},
		}},
		{name: "Gemini", format: "gemini", body: map[string]any{
			"contents": []any{},
			"tools": []any{map[string]any{"functionDeclarations": []any{map[string]any{
				"name": "lookup", "description": sensitive, "parameters": schema,
			}}}},
		}},
		{name: "Interactions", format: "interactions", body: map[string]any{
			"input": "ok",
			"tools": []any{map[string]any{
				"type": "function", "name": "lookup", "description": sensitive, "parameters": schema,
			}},
		}},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			body := mustMarshalTestJSON(t, testCase.body)
			result, err := newTestPlugin(t).sanitizeRequest(context.Background(), testCase.format, body)
			if err != nil {
				t.Fatal("tool metadata failed sanitization")
			}
			if !result.changed || result.findings < 2 || bytes.Contains(result.body, []byte(sensitive)) {
				t.Fatal("tool metadata retained sensitive model-visible text")
			}
		})
	}
}

func TestResponsesReasoningReplayTextIsSanitized(t *testing.T) {
	sensitive := strings.Join([]string{"reasoning", "example.test"}, "@")
	body := mustMarshalTestJSON(t, map[string]any{
		"input": []any{map[string]any{
			"type": "reasoning", "id": "rs_1", "status": "completed",
			"summary": []any{map[string]any{"type": "summary_text", "text": sensitive}},
			"content": []any{map[string]any{"type": "reasoning_text", "text": sensitive}},
		}},
	})
	result, err := newTestPlugin(t).sanitizeRequest(context.Background(), "openai-response", body)
	if err != nil {
		t.Fatal("reasoning replay failed sanitization")
	}
	if !result.changed || result.findings != 2 || bytes.Contains(result.body, []byte(sensitive)) {
		t.Fatal("reasoning replay retained sensitive text")
	}
}

func TestNestedEncodedToolJSONPreservesCredentialContext(t *testing.T) {
	shortCredential := strings.Join([]string{"q", "7", "z"}, "")
	inner := string(mustMarshalTestJSON(t, map[string]any{"password": shortCredential}))
	arguments := string(mustMarshalTestJSON(t, map[string]any{"wrapper": inner}))
	body := mustMarshalTestJSON(t, map[string]any{
		"input": []any{map[string]any{
			"type": "function_call", "id": "fc_1", "call_id": "call_1",
			"name": "lookup", "arguments": arguments,
		}},
	})
	result, err := newTestPlugin(t).sanitizeRequest(context.Background(), "openai-response", body)
	if err != nil {
		t.Fatal("nested encoded JSON failed sanitization")
	}
	if !result.changed || result.findings != 1 || bytes.Contains(result.body, []byte(shortCredential)) {
		t.Fatal("nested encoded JSON retained a short credential")
	}
}

func TestResponsesLocalShellPlainOutputIsSanitized(t *testing.T) {
	sensitive := strings.Join([]string{"shell", "example.test"}, "@")
	body := mustMarshalTestJSON(t, map[string]any{
		"input": []any{map[string]any{
			"type": "local_shell_call_output", "id": "local_1", "status": "completed",
			"output": "plain output " + sensitive,
		}},
	})
	result, err := newTestPlugin(t).sanitizeRequest(context.Background(), "openai-response", body)
	if err != nil {
		t.Fatal("plain local-shell output failed sanitization")
	}
	if !result.changed || result.findings != 1 || bytes.Contains(result.body, []byte(sensitive)) {
		t.Fatal("plain local-shell output retained sensitive text")
	}
}

func TestMalformedEncodedToolArgumentsFailClosed(t *testing.T) {
	p := newTestPlugin(t)
	body := []byte(`{"messages":[{"role":"assistant","tool_calls":[{"type":"function","function":{"name":"f","arguments":"{not-json"}}]}]}`)
	_, sanitizeErr := p.sanitizeRequest(context.Background(), "openai", body)
	if !errors.Is(sanitizeErr, payload.ErrInvalidJSON) || !errors.Is(sanitizeErr, errUnsupportedRequestShape) {
		t.Fatal("malformed encoded JSON did not preserve both error classifications")
	}
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		SourceFormat: "openai",
		Body:         body,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Terminate || resp.StatusCode != 422 {
		t.Fatalf("response terminate=%t status=%d body_len=%d, want terminate 422", resp.Terminate, resp.StatusCode, len(resp.Body))
	}
}

func TestBeforeAndUnchangedAfterScanOnlyOnce(t *testing.T) {
	p := newTestPlugin(t)
	req := pluginapi.RequestInterceptRequest{
		RequestID:      "request-cache-1",
		SourceFormat:   "openai",
		Model:          "upstream-model",
		RequestedModel: "alias",
		Body:           []byte(`{"model":"m","messages":[{"role":"user","content":"test@example.com"}]}`),
	}
	before, err := p.InterceptRequestBeforeAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if before.Body == nil {
		t.Fatal("before-auth did not redact")
	}
	req.Body = before.Body
	after, err := p.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if after.Body != nil || after.Terminate {
		t.Fatalf("unchanged after-auth body was rescanned: terminate=%t status=%d body_len=%d", after.Terminate, after.StatusCode, len(after.Body))
	}
	stats := p.cache.Stats()
	if stats.Records != 1 || stats.SeenHits != 1 {
		t.Fatalf("cache stats = %+v, want one scan and one hit", stats)
	}

	if err := p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{
		RequestID: "request-cache-1",
		Outcome:   pluginapi.RequestCompletionSucceeded,
	}); err != nil {
		t.Fatal(err)
	}
	if p.cache.Len() != 0 {
		t.Fatalf("cache retained %d entries after completion", p.cache.Len())
	}
}

func TestChangedAfterAuthBodyIsRescanned(t *testing.T) {
	p := newTestPlugin(t)
	req := pluginapi.RequestInterceptRequest{
		RequestID:    "request-cache-2",
		SourceFormat: "openai",
		Model:        "m",
		Body:         []byte(`{"model":"m","messages":[{"role":"user","content":"hello"}]}`),
	}
	before, err := p.InterceptRequestBeforeAuth(context.Background(), req)
	if err != nil || before.Body != nil || before.Terminate {
		t.Fatalf("before terminate=%t status=%d body_len=%d err=%v", before.Terminate, before.StatusCode, len(before.Body), err)
	}
	req.Body = []byte(`{"model":"m","messages":[{"role":"user","content":"hello"},{"role":"user","content":"second@example.com"}]}`)
	after, err := p.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if after.Body == nil || strings.Contains(string(after.Body), "second@example.com") {
		t.Fatalf("changed after body was not sanitized: terminate=%t status=%d body_len=%d", after.Terminate, after.StatusCode, len(after.Body))
	}
	stats := p.cache.Stats()
	if stats.Records != 2 || stats.SeenMisses < 2 {
		t.Fatalf("cache stats = %+v", stats)
	}
}

func TestRegistrationCapabilityJSON(t *testing.T) {
	caps := abiCapabilities{RequestInterceptor: true, RequestLifecyclePlugin: true}
	raw, err := json.Marshal(caps)
	if err != nil {
		t.Fatal(err)
	}
	for index, field := range []string{`"request_interceptor":true`, `"request_lifecycle_plugin":true`} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("capability field %d missing from JSON of length %d", index, len(raw))
		}
	}
}
