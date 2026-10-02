package main

import (
	"context"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

const (
	testListedKey   = "sk-listed-client-key"
	testUnlistedKey = "sk-other-client-key"
	testEmailBody   = `{"model":"gpt-4","messages":[{"role":"user","content":"reach me at test@example.com"}]}`
)

func TestCallerScopeMatchesHostDerivation(t *testing.T) {
	// Independent vector for the pinned Host's session.CallerScope definition:
	// hex(sha256("cli-proxy-api:caller-scope:v1\x00" + trimmed key)).
	const want = "9d42415888c4109e532fc413dc079e690c2ee43bcef63825c1f86e3f38346c7a"
	if got := callerScope("  " + testListedKey + "\n"); got != want {
		t.Fatalf("caller scope derivation drifted from the Host definition: len=%d", len(got))
	}
	if callerScope("   ") != "" {
		t.Fatal("blank key must not produce a caller scope")
	}
}

func TestParseConfigKeyFilter(t *testing.T) {
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeyFilter.active() || cfg.KeyFilter.Mode != keyFilterInclude || cfg.KeyFilter.OnMissingIdentity != missingIdentityFilter {
		t.Fatalf("key filter defaults = %+v", cfg.KeyFilter)
	}

	valid := []string{
		"key_filter:\n  api_keys: []\n",
		"key_filter:\n  mode: exclude\n",
		"key_filter:\n  mode: include\n  api_keys: [sk-a, sk-b]\n",
		"key_filter:\n  mode: exclude\n  api_keys: [sk-a]\n  on_missing_identity: skip\n",
		"key_filter:\n  caller_scopes: ['" + callerScope("sk-a") + "']\n",
		"key_filter:\n  caller_scopes: ['" + strings.ToUpper(callerScope("sk-a")) + "']\n  api_keys: [sk-b]\n",
	}
	for index, raw := range valid {
		if _, err := parseConfig([]byte(raw)); err != nil {
			t.Errorf("parseConfig rejected valid key_filter index=%d: %v", index, err)
		}
	}

	invalid := []string{
		"key_filter:\n  mode: only\n  api_keys: [sk-a]\n",
		"key_filter:\n  mode: ''\n",
		"key_filter:\n  on_missing_identity: allow\n",
		"key_filter:\n  api_keys: [sk-a, sk-a]\n",
		"key_filter:\n  api_keys: [sk-a, ' sk-a ']\n",
		"key_filter:\n  api_keys: ['']\n",
		"key_filter:\n  api_keys: ['   ']\n",
		"key_filter:\n  caller_scopes: [abc]\n",
		"key_filter:\n  caller_scopes: ['" + strings.Repeat("g", 64) + "']\n",
		"key_filter:\n  caller_scopes: ['" + callerScope("sk-a") + "', '" + callerScope("sk-a") + "']\n",
		"key_filter:\n  api_keys: [sk-a]\n  caller_scopes: ['" + callerScope("sk-a") + "']\n",
		"key_filter:\n  api_keys: [sk-a]\n  api_keys: [sk-b]\n",
		"key_filter:\n  mode: include\n  mode: exclude\n",
		"key_filter:\n  keys: [sk-a]\n",
		"key_filter: [sk-a]\n",
	}
	for index, raw := range invalid {
		if _, err := parseConfig([]byte(raw)); err == nil {
			t.Errorf("parseConfig accepted invalid key_filter index=%d", index)
		}
	}
}

func TestKeyFilterErrorsNeverEchoKeys(t *testing.T) {
	const secretKey = "sk-very-secret-client-key"
	for _, raw := range []string{
		"key_filter:\n  api_keys: [" + secretKey + ", " + secretKey + "]\n",
		"key_filter:\n  api_keys: [" + secretKey + "]\n  caller_scopes: ['" + callerScope(secretKey) + "']\n",
		"key_filter:\n  caller_scopes: [" + secretKey + "]\n",
	} {
		_, err := parseConfig([]byte(raw))
		if err == nil {
			t.Fatal("invalid key_filter was accepted")
		}
		if strings.Contains(err.Error(), secretKey) || strings.Contains(err.Error(), callerScope(secretKey)) {
			t.Fatal("key_filter error echoed a key or caller identifier")
		}
	}
}

func newKeyFilterTestPlugin(t *testing.T, mode keyFilterMode, onMissing missingIdentityPolicy, keys ...string) *privacyFilterPlugin {
	t.Helper()
	p := newTestPlugin(t)
	p.cfg.KeyFilter = keyFilterConfig{Mode: mode, APIKeys: keys, OnMissingIdentity: onMissing}
	compiled, err := p.cfg.KeyFilter.compile()
	if err != nil {
		t.Fatal(err)
	}
	p.keyFilter = compiled
	p.keyStats = &keyFilterStats{}
	return p
}

func keyFilterRequest(requestID, apiKey string) pluginapi.RequestInterceptRequest {
	req := pluginapi.RequestInterceptRequest{
		RequestID:    requestID,
		SourceFormat: "openai",
		Model:        "gpt-4",
		Body:         []byte(testEmailBody),
	}
	if apiKey != "" {
		req.Metadata = map[string]any{callerScopeMetadataKey: callerScope(apiKey)}
	}
	return req
}

func assertInspected(t *testing.T, name string, resp pluginapi.RequestInterceptResponse, want bool) {
	t.Helper()
	if resp.Terminate {
		t.Fatalf("%s: request was terminated with status %d", name, resp.StatusCode)
	}
	inspected := resp.Body != nil
	if inspected != want {
		t.Fatalf("%s: inspected=%t, want %t", name, inspected, want)
	}
	if inspected && strings.Contains(string(resp.Body), "test@example.com") {
		t.Fatalf("%s: inspected body still carries the email", name)
	}
}

func TestKeyFilterIncludeAndExclude(t *testing.T) {
	cases := []struct {
		name      string
		mode      keyFilterMode
		apiKey    string
		inspected bool
	}{
		{"include listed", keyFilterInclude, testListedKey, true},
		{"include unlisted", keyFilterInclude, testUnlistedKey, false},
		{"exclude listed", keyFilterExclude, testListedKey, false},
		{"exclude unlisted", keyFilterExclude, testUnlistedKey, true},
	}
	for _, tc := range cases {
		for _, stage := range []string{"before", "after"} {
			p := newKeyFilterTestPlugin(t, tc.mode, missingIdentityFilter, testListedKey)
			req := keyFilterRequest("req-"+tc.name+stage, tc.apiKey)
			var resp pluginapi.RequestInterceptResponse
			var err error
			if stage == "before" {
				resp, err = p.InterceptRequestBeforeAuth(context.Background(), req)
			} else {
				resp, err = p.InterceptRequestAfterAuth(context.Background(), req)
			}
			if err != nil {
				t.Fatal(err)
			}
			assertInspected(t, tc.name+"/"+stage, resp, tc.inspected)
		}
	}
}

func TestKeyFilterEmptyListKeepsLegacyBehavior(t *testing.T) {
	for _, mode := range []keyFilterMode{keyFilterInclude, keyFilterExclude} {
		p := newKeyFilterTestPlugin(t, mode, missingIdentitySkip)
		// No caller identity and an unlisted caller are both inspected: an empty
		// list disables the key filter entirely.
		resp, err := p.InterceptRequestBeforeAuth(context.Background(), keyFilterRequest("", ""))
		if err != nil {
			t.Fatal(err)
		}
		assertInspected(t, string(mode)+"/anonymous", resp, true)
		resp, err = p.InterceptRequestBeforeAuth(context.Background(), keyFilterRequest("", testUnlistedKey))
		if err != nil {
			t.Fatal(err)
		}
		assertInspected(t, string(mode)+"/unlisted", resp, true)
	}
}

func TestKeyFilterMissingIdentity(t *testing.T) {
	for _, tc := range []struct {
		policy    missingIdentityPolicy
		inspected bool
	}{
		{missingIdentityFilter, true},
		{missingIdentitySkip, false},
	} {
		for _, mode := range []keyFilterMode{keyFilterInclude, keyFilterExclude} {
			p := newKeyFilterTestPlugin(t, mode, tc.policy, testListedKey)
			name := string(mode) + "/" + string(tc.policy)

			// Before credential selection an unidentified request is never
			// modified or rejected, whatever the policy.
			before, err := p.InterceptRequestBeforeAuth(context.Background(), keyFilterRequest("req-"+name, ""))
			if err != nil {
				t.Fatal(err)
			}
			assertInspected(t, name+"/before", before, false)

			after, err := p.InterceptRequestAfterAuth(context.Background(), keyFilterRequest("req-"+name, ""))
			if err != nil {
				t.Fatal(err)
			}
			assertInspected(t, name+"/after", after, tc.inspected)
		}
	}
}

func TestKeyFilterBlankIdentityCountsAsMissing(t *testing.T) {
	p := newKeyFilterTestPlugin(t, keyFilterInclude, missingIdentityFilter, testListedKey)
	for _, metadata := range []map[string]any{
		{callerScopeMetadataKey: ""},
		{callerScopeMetadataKey: "   "},
		{callerScopeMetadataKey: 42},
		{"other": "value"},
	} {
		req := keyFilterRequest("", "")
		req.Metadata = metadata
		resp, err := p.InterceptRequestAfterAuth(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		assertInspected(t, "blank identity", resp, true)
	}
}

func TestKeyFilterSkippedRequestIsNeverBlocked(t *testing.T) {
	p := newKeyFilterTestPlugin(t, keyFilterInclude, missingIdentityFilter, testListedKey)
	for _, body := range [][]byte{nil, []byte("not json test@example.com")} {
		// An unlisted caller's uninspectable request must pass, not hit on_error.
		req := keyFilterRequest("", testUnlistedKey)
		req.Body = body
		resp, err := p.InterceptRequestBeforeAuth(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Terminate || resp.Body != nil {
			t.Fatalf("skipped caller was touched: terminate=%t status=%d", resp.Terminate, resp.StatusCode)
		}
		// The same body from a listed caller still fails closed.
		req = keyFilterRequest("", testListedKey)
		req.Body = body
		resp, err = p.InterceptRequestBeforeAuth(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !resp.Terminate {
			t.Fatal("listed caller's uninspectable request was not blocked")
		}
	}
}

func TestKeyFilterTwoPassStaysConsistent(t *testing.T) {
	p := newKeyFilterTestPlugin(t, keyFilterInclude, missingIdentityFilter, testListedKey)

	before, err := p.InterceptRequestBeforeAuth(context.Background(), keyFilterRequest("req-two-pass", testListedKey))
	if err != nil {
		t.Fatal(err)
	}
	assertInspected(t, "listed/before", before, true)
	// The Host feeds the redacted body to the after-auth pass; it must be
	// recognised as already inspected rather than rewritten again.
	second := keyFilterRequest("req-two-pass", testListedKey)
	second.Body = before.Body
	after, err := p.InterceptRequestAfterAuth(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	assertInspected(t, "listed/after", after, false)

	// A skipped caller leaves no request state behind on either pass.
	for _, intercept := range []func(context.Context, pluginapi.RequestInterceptRequest) (pluginapi.RequestInterceptResponse, error){
		p.InterceptRequestBeforeAuth, p.InterceptRequestAfterAuth,
	} {
		resp, err := intercept(context.Background(), keyFilterRequest("req-skipped", testUnlistedKey))
		if err != nil {
			t.Fatal(err)
		}
		assertInspected(t, "unlisted", resp, false)
	}
	if got := p.cache.Len(); got != 1 {
		t.Fatalf("request cache entries = %d, want only the inspected request", got)
	}
}

func TestKeyFilterCombinesWithSkipModelsAndFormats(t *testing.T) {
	p := newKeyFilterTestPlugin(t, keyFilterInclude, missingIdentityFilter, testListedKey)
	p.cfg.SkipModels = []string{"trusted-model"}
	p.cfg.SkipFormats = []string{"gemini"}

	// A listed key does not override skip_models / skip_formats.
	req := keyFilterRequest("", testListedKey)
	req.Model = "trusted-model"
	resp, err := p.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	assertInspected(t, "listed key + skipped model", resp, false)

	req = keyFilterRequest("", testListedKey)
	req.SourceFormat = "gemini"
	resp, err = p.InterceptRequestAfterAuth(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	assertInspected(t, "listed key + skipped format", resp, false)

	// Neither skip applies and the key is listed: inspected.
	resp, err = p.InterceptRequestAfterAuth(context.Background(), keyFilterRequest("", testListedKey))
	if err != nil {
		t.Fatal(err)
	}
	assertInspected(t, "listed key", resp, true)

	// The skips do not widen the key filter either.
	resp, err = p.InterceptRequestAfterAuth(context.Background(), keyFilterRequest("", testUnlistedKey))
	if err != nil {
		t.Fatal(err)
	}
	assertInspected(t, "unlisted key", resp, false)
}

func TestKeyFilterCountsDecisions(t *testing.T) {
	p := newKeyFilterTestPlugin(t, keyFilterInclude, missingIdentityFilter, testListedKey)
	for _, apiKey := range []string{testListedKey, testUnlistedKey, testUnlistedKey} {
		if _, err := p.InterceptRequestAfterAuth(context.Background(), keyFilterRequest("", apiKey)); err != nil {
			t.Fatal(err)
		}
	}
	if filtered, skipped := p.keyStats.filtered.Load(), p.keyStats.skippedByKey.Load(); filtered != 1 || skipped != 2 {
		t.Fatalf("decision counters = filtered %d skipped %d, want 1 and 2", filtered, skipped)
	}
}

func TestBuildPluginCompilesKeyFilter(t *testing.T) {
	plugin, err := buildPlugin([]byte("key_filter:\n  mode: exclude\n  api_keys: ["+testListedKey+"]\n"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	if !p.keyFilter.active() || p.keyFilter.include {
		t.Fatal("built plugin did not carry the exclude key filter")
	}
	if _, err := buildPlugin([]byte("key_filter:\n  api_keys: [a, a]\n"), t.TempDir()); err == nil {
		t.Fatal("buildPlugin accepted duplicate key_filter keys")
	}
}

func TestConfigDecodeErrorsNeverEchoValues(t *testing.T) {
	const secretKey = "sk-live-1234567890abcdef"
	for _, raw := range []string{
		"key_filter:\n  api_keys: " + secretKey + "\n",
		"key_filter:\n  api_keys: sk-short\n",
		"key_filter:\n  " + secretKey + ": x\n",
		"key_filter:\n  caller_scopes: " + secretKey + "\n",
		"tokenize:\n  hmac_secret: [" + secretKey + "]\n",
		"tokenize:\n  ttl: " + secretKey + "\n",
		"tokenize:\n  max_entries: " + secretKey + "\n",
		secretKey + ": true\n",
	} {
		_, err := parseConfig([]byte(raw))
		if err == nil {
			t.Fatal("malformed config was accepted")
		}
		message := err.Error()
		for _, leak := range []string{secretKey, "sk-live", "sk-short", "1234567890"} {
			if strings.Contains(message, leak) {
				t.Fatalf("decode error echoed part of a configured value: %q", leak)
			}
		}
		if !strings.Contains(message, "line ") {
			t.Fatalf("decode error lost its position: %s", message)
		}
	}
}
