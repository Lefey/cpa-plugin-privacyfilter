package main

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var testTokenPattern = regexp.MustCompile(`pf-(?:email|phone|idcard|bankcard|ip|secret)-[0-9a-f]{12}`)

const (
	testTokenizeKeyA = "sk-tokenize-client-a"
	testTokenizeKeyB = "sk-tokenize-client-b"
	testSecretEmail  = "alice.secret@example.com"
)

// newTokenizePlugin builds a plugin through the production path so the
// registration, runtime, and renderer wiring is what a Host would get.
func newTokenizePlugin(t *testing.T, extraYAML string) *privacyFilterPlugin {
	t.Helper()
	plugin, err := buildPlugin([]byte("mode: tokenize\n"+extraYAML), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p, ok := plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	if !ok || p.tok == nil {
		t.Fatal("tokenize plugin was not built")
	}
	return p
}

func callerMetadata(apiKey string) map[string]any {
	if apiKey == "" {
		return nil
	}
	return map[string]any{callerScopeMetadataKey: callerScope(apiKey)}
}

// sendRequest runs both interceptor passes the way the Host does and returns
// the body the provider would receive.
func sendRequest(t *testing.T, p *privacyFilterPlugin, requestID, apiKey, format, body string) []byte {
	t.Helper()
	req := pluginapi.RequestInterceptRequest{
		RequestID:    requestID,
		SourceFormat: format,
		Model:        "test-model",
		Body:         []byte(body),
		Metadata:     callerMetadata(apiKey),
	}
	before, err := p.InterceptRequestBeforeAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if before.Terminate {
		t.Fatalf("request was terminated before auth: status=%d", before.StatusCode)
	}
	upstream := req.Body
	if len(before.Body) != 0 {
		upstream = before.Body
	}
	req.Body = upstream
	after, err := p.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if after.Terminate {
		t.Fatalf("request was terminated after auth: status=%d", after.StatusCode)
	}
	if len(after.Body) != 0 {
		upstream = after.Body
	}
	return upstream
}

func chatBody(content string) string {
	encoded, _ := json.Marshal(content)
	return `{"model":"test-model","messages":[{"role":"user","content":` + string(encoded) + `}]}`
}

func completeRequest(p *privacyFilterPlugin, requestID string, outcome pluginapi.RequestCompletionOutcome) {
	_ = p.HandleRequestComplete(context.Background(), pluginapi.RequestCompletion{RequestID: requestID, Outcome: outcome})
}

func TestTokenizeRequestReplacesValuesWithTokens(t *testing.T) {
	p := newTokenizePlugin(t, "")
	upstream := sendRequest(t, p, "req-1", testTokenizeKeyA, "openai",
		chatBody("mail "+testSecretEmail+" and again "+testSecretEmail+", also bob@example.org"))
	if strings.Contains(string(upstream), testSecretEmail) || strings.Contains(string(upstream), "bob@example.org") {
		t.Fatal("original value reached the provider body")
	}
	tokens := testTokenPattern.FindAllString(string(upstream), -1)
	if len(tokens) != 3 || tokens[0] != tokens[1] || tokens[0] == tokens[2] {
		t.Fatalf("expected the same token twice and a different one, got %d tokens", len(tokens))
	}
	if !json.Valid(upstream) {
		t.Fatal("tokenized body is not valid JSON")
	}
	if stats := p.tok.vault.stats(); stats.Entries != 2 {
		t.Fatalf("vault entries = %d, want 2", stats.Entries)
	}
}

func TestTokenizeSecondPassIsStable(t *testing.T) {
	p := newTokenizePlugin(t, "")
	body := chatBody("mail " + testSecretEmail)
	req := pluginapi.RequestInterceptRequest{
		RequestID: "req-2pass", SourceFormat: "openai", Model: "m",
		Body: []byte(body), Metadata: callerMetadata(testTokenizeKeyA),
	}
	before, err := p.InterceptRequestBeforeAuth(context.Background(), req)
	if err != nil || len(before.Body) == 0 {
		t.Fatalf("first pass did not tokenize: err=%v", err)
	}
	token := testTokenPattern.FindString(string(before.Body))

	// Unchanged body on the second pass: recognised, not rewritten.
	req.Body = before.Body
	after, err := p.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil || after.Body != nil || after.Terminate {
		t.Fatalf("unchanged second pass was rewritten: err=%v", err)
	}

	// Another interceptor changed the body between the passes. The token
	// already present must stay as it is, and the same value must map to the
	// same token again rather than to a token of a token.
	changed := strings.Replace(string(before.Body), `"content":"`, `"content":"key=`+token+` and `+testSecretEmail+` then `, 1)
	req.Body = []byte(changed)
	after, err = p.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil || after.Terminate {
		t.Fatalf("rescan failed: err=%v", err)
	}
	if len(after.Body) == 0 {
		t.Fatal("rescan left the new plaintext value in place")
	}
	out := string(after.Body)
	if strings.Contains(out, testSecretEmail) {
		t.Fatal("rescan left the original value in the body")
	}
	for _, found := range testTokenPattern.FindAllString(out, -1) {
		if found != token {
			t.Fatal("rescan produced a different token for the same value or re-tokenized a token")
		}
	}
	if got := len(testTokenPattern.FindAllString(out, -1)); got != 3 {
		t.Fatalf("tokens after rescan = %d, want 3", got)
	}
	if stats := p.tok.vault.stats(); stats.Entries != 1 {
		t.Fatalf("vault entries = %d, want 1", stats.Entries)
	}
}

func TestTokenizeHistoryKeepsTheSameToken(t *testing.T) {
	p := newTokenizePlugin(t, "")
	first := sendRequest(t, p, "turn-1", testTokenizeKeyA, "openai", chatBody("mail "+testSecretEmail))
	token := testTokenPattern.FindString(string(first))
	completeRequest(p, "turn-1", pluginapi.RequestCompletionSucceeded)

	// The client got the value back restored and resends it as history.
	history := `{"model":"m","messages":[{"role":"user","content":"mail ` + testSecretEmail +
		`"},{"role":"assistant","content":"noted ` + testSecretEmail + `"},{"role":"user","content":"thanks"}]}`
	second := sendRequest(t, p, "turn-2", testTokenizeKeyA, "openai", history)
	found := testTokenPattern.FindAllString(string(second), -1)
	if len(found) != 2 || found[0] != token || found[1] != token {
		t.Fatalf("history value did not keep its token: %d tokens", len(found))
	}
	// Another caller gets an unrelated token for the same value.
	other := sendRequest(t, p, "turn-other", testTokenizeKeyB, "openai", chatBody("mail "+testSecretEmail))
	if testTokenPattern.FindString(string(other)) == token {
		t.Fatal("two API keys share a token for the same value")
	}
}

func TestTokenizeBlockRuleRunsBeforeTokenization(t *testing.T) {
	// LTAI... is detected by the embedded alibaba-access-key-id rule.
	p := newTokenizePlugin(t, "block_rule_ids: [alibaba-access-key-id]\n")
	body := chatBody("mail " + testSecretEmail + " key LTAIABCDEFGHIJKLMNOPQRST")
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		RequestID: "req-blocked", SourceFormat: "openai", Model: "m",
		Body: []byte(body), Metadata: callerMetadata(testTokenizeKeyA),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Terminate || resp.StatusCode != 422 {
		t.Fatalf("blocking rule did not terminate: terminate=%t status=%d", resp.Terminate, resp.StatusCode)
	}
	if stats := p.tok.vault.stats(); stats.Entries != 0 || stats.Stored != 0 {
		t.Fatalf("a blocked request left mappings behind: %+v", stats)
	}
	if p.tok.sessions.len() != 0 {
		t.Fatal("a blocked request opened a restore session")
	}
}

func TestTokenizeInspectionFailureLeavesNoMapping(t *testing.T) {
	p := newTokenizePlugin(t, "")
	resp, err := p.InterceptRequestBeforeAuth(context.Background(), pluginapi.RequestInterceptRequest{
		RequestID: "req-bad", SourceFormat: "openai", Model: "m",
		Body:     []byte(`{"messages":[{"role":"user","content":"` + testSecretEmail + `"}],"unknown_text_field":{"x":"y"}}`),
		Metadata: callerMetadata(testTokenizeKeyA),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.Terminate {
		t.Skip("fixture is inspectable in this protocol table")
	}
	if stats := p.tok.vault.stats(); stats.Entries != 0 {
		t.Fatalf("a rejected request left mappings behind: %+v", stats)
	}
}

func TestTokenizeRespectsKeyFilter(t *testing.T) {
	p := newTokenizePlugin(t, "key_filter:\n  mode: include\n  api_keys: ["+testTokenizeKeyA+"]\n")
	body := chatBody("mail " + testSecretEmail)

	skipped := sendRequest(t, p, "req-skipped", testTokenizeKeyB, "openai", body)
	if string(skipped) != body {
		t.Fatal("a request skipped by key was modified")
	}
	if p.tok.vault.stats().Entries != 0 || p.tok.sessions.len() != 0 {
		t.Fatal("a request skipped by key was tokenized or tracked")
	}
	// Its response is not touched either, even if it carries a live token.
	listed := sendRequest(t, p, "req-listed", testTokenizeKeyA, "openai", body)
	token := testTokenPattern.FindString(string(listed))
	if token == "" {
		t.Fatal("listed key was not tokenized")
	}
	response := `{"choices":[{"message":{"role":"assistant","content":"echo ` + token + `"}}]}`
	resp, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestID: "req-skipped", SourceFormat: "openai", Body: []byte(response), Metadata: callerMetadata(testTokenizeKeyB),
	})
	if err != nil || resp.Body != nil {
		t.Fatalf("response of a skipped request was rewritten: err=%v", err)
	}
	chunk, err := p.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{
		RequestID: "req-skipped", SourceFormat: "openai", ChunkIndex: 0,
		Body: []byte(`{"choices":[{"index":0,"delta":{"content":"` + token + `"}}]}`),
	})
	if err != nil || chunk.Body != nil || chunk.DropChunk {
		t.Fatalf("stream of a skipped request was rewritten: err=%v", err)
	}
}

func TestTokenizeWithoutIdentityFallsBackToRequestScope(t *testing.T) {
	p := newTokenizePlugin(t, "")
	upstream := sendRequest(t, p, "req-anon", "", "openai", chatBody("mail "+testSecretEmail))
	token := testTokenPattern.FindString(string(upstream))
	if token == "" {
		t.Fatal("anonymous request was not tokenized")
	}
	if !p.tok.vault.has(requestPartitionPrefix + "req-anon") {
		t.Fatal("anonymous request did not get its own partition")
	}
	completeRequest(p, "req-anon", pluginapi.RequestCompletionSucceeded)
	if p.tok.vault.stats().Entries != 0 {
		t.Fatal("request-scoped mappings survived request completion")
	}

	// No RequestID and no caller: nothing to tie a restore to, so the value is
	// redacted irreversibly rather than tokenized.
	untracked := sendRequest(t, p, "", "", "openai", chatBody("mail "+testSecretEmail))
	if strings.Contains(string(untracked), testSecretEmail) || testTokenPattern.Match(untracked) {
		t.Fatal("untracked request was not irreversibly redacted")
	}
}

func TestRedactModeRegistrationAndBehaviorUnchanged(t *testing.T) {
	plugin, err := buildPlugin(nil, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	if p.tok != nil || p.tokRuntime != nil {
		t.Fatal("redact mode created tokenize state")
	}
	if plugin.Capabilities.ResponseInterceptor != nil || plugin.Capabilities.StreamChunkInterceptor != nil {
		t.Fatal("redact mode declared response interceptors")
	}
	upstream := sendRequest(t, p, "req-redact", testTokenizeKeyA, "openai", chatBody("mail "+testSecretEmail))
	if strings.Contains(string(upstream), testSecretEmail) || testTokenPattern.Match(upstream) || !strings.Contains(string(upstream), "[邮箱]") {
		t.Fatal("redact mode no longer emits the irreversible placeholder")
	}
	// The response hooks are inert outside tokenize mode.
	resp, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestID: "req-redact", SourceFormat: "openai", Body: []byte(`{"choices":[{"message":{"content":"pf-secret-0123456789ab"}}]}`),
	})
	if err != nil || resp.Body != nil {
		t.Fatal("redact mode rewrote a response")
	}
	chunk, err := p.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{
		RequestID: "req-redact", SourceFormat: "openai", Body: []byte(`{"choices":[{"delta":{"content":"p"}}]}`),
	})
	if err != nil || chunk.Body != nil || chunk.DropChunk {
		t.Fatal("redact mode rewrote a stream chunk")
	}
}
