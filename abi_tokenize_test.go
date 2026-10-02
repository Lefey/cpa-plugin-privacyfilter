package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// rawRegistrationForTest returns the registration result exactly as the Host
// would read it.
func rawRegistrationForTest(t *testing.T, hostSchema uint32, config []byte) json.RawMessage {
	t.Helper()
	req, err := json.Marshal(abiLifecycleRequest{SchemaVersion: hostSchema, ConfigYAML: config, PluginDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handlePrivacyFilterRegister(req)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("registration envelope not OK: err=%v", err)
	}
	return env.Result
}

// callABIForTest sends one RPC through the dispatcher and decodes its result.
func callABIForTest[T any](t *testing.T, method string, request any) T {
	t.Helper()
	payload, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := handlePrivacyFilterABIMethod(context.Background(), method, payload)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	var env abiEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || !env.OK {
		t.Fatalf("%s envelope not OK: err=%v", method, err)
	}
	var result T
	if err := json.Unmarshal(env.Result, &result); err != nil {
		t.Fatalf("%s result: %v", method, err)
	}
	return result
}

func TestRegistrationIsUnchangedOutsideTokenizeMode(t *testing.T) {
	for _, config := range []string{"", "mode: redact\n", "mode: audit\n", "key_filter:\n  api_keys: [sk-a]\n"} {
		resetABIStateForTest(t)
		result := rawRegistrationForTest(t, pluginabi.SchemaVersion, []byte(config))
		var registration struct {
			SchemaVersion uint32          `json:"schema_version"`
			Capabilities  json.RawMessage `json:"capabilities"`
		}
		if err := json.Unmarshal(result, &registration); err != nil {
			t.Fatal(err)
		}
		if registration.SchemaVersion != 2 {
			t.Fatalf("config %q: schema = %d, want 2", config, registration.SchemaVersion)
		}
		// Byte-for-byte the pre-tokenize capability object: no new keys at all.
		if got := string(registration.Capabilities); got != `{"request_interceptor":true,"request_lifecycle_plugin":true}` {
			t.Fatalf("config %q: capabilities = %s", config, got)
		}
	}
}

func TestRegistrationDeclaresResponseHooksInTokenizeMode(t *testing.T) {
	for _, tc := range []struct {
		hostSchema uint32
		wantSchema uint32
	}{
		{2, 2}, {3, 3}, {4, 4}, {5, 5}, {pluginabi.SchemaVersion, 5},
	} {
		resetABIStateForTest(t)
		reg := registerWithConfigForTest(t, tc.hostSchema, []byte("mode: tokenize\n"))
		if reg.SchemaVersion != tc.wantSchema {
			t.Fatalf("host schema %d: negotiated %d, want %d", tc.hostSchema, reg.SchemaVersion, tc.wantSchema)
		}
		if !reg.Capabilities.RequestInterceptor || !reg.Capabilities.RequestLifecyclePlugin ||
			!reg.Capabilities.ResponseInterceptor || !reg.Capabilities.StreamChunkInterceptor {
			t.Fatalf("host schema %d: capabilities = %+v", tc.hostSchema, reg.Capabilities)
		}
	}
	// The capability names are the ones the Host decodes.
	resetABIStateForTest(t)
	result := string(rawRegistrationForTest(t, pluginabi.SchemaVersion, []byte("mode: tokenize\n")))
	for _, name := range []string{`"response_interceptor":true`, `"response_stream_interceptor":true`} {
		if !strings.Contains(result, name) {
			t.Fatalf("registration lacks %s", name)
		}
	}
}

func TestRegistrationListsNewConfigFields(t *testing.T) {
	resetABIStateForTest(t)
	reg := registerForTest(t, pluginabi.SchemaVersion)
	fields := make(map[string]pluginapi.ConfigField)
	for _, field := range reg.Metadata.ConfigFields {
		fields[field.Name] = field
	}
	if len(fields) != 12 {
		t.Fatalf("config fields = %d, want 12", len(fields))
	}
	if fields["key_filter"].Type != pluginapi.ConfigFieldTypeObject || fields["tokenize"].Type != pluginapi.ConfigFieldTypeObject {
		t.Fatal("key_filter and tokenize must be object fields")
	}
	if got := strings.Join(fields["mode"].EnumValues, ","); got != "redact,tokenize,audit" {
		t.Fatalf("mode enum = %s", got)
	}
}

func TestABITokenizeRoundTrip(t *testing.T) {
	resetABIStateForTest(t)
	registerWithConfigForTest(t, pluginabi.SchemaVersion, []byte("mode: tokenize\n"))
	metadata := callerMetadata(testTokenizeKeyA)

	before := callABIForTest[pluginapi.RequestInterceptResponse](t, pluginabi.MethodRequestInterceptBefore, pluginapi.RequestInterceptRequest{
		RequestID: "abi-req", SourceFormat: "openai", Model: "m", Stream: true,
		Body: []byte(chatBody("mail " + testSecretEmail)), Metadata: metadata,
	})
	token := testTokenPattern.FindString(string(before.Body))
	if token == "" || strings.Contains(string(before.Body), testSecretEmail) {
		t.Fatal("request was not tokenized through the ABI")
	}

	response := callABIForTest[pluginapi.ResponseInterceptResponse](t, pluginabi.MethodResponseInterceptAfter, pluginapi.ResponseInterceptRequest{
		RequestID: "abi-req", SourceFormat: "openai", StatusCode: 200, Metadata: metadata,
		Body: []byte(`{"choices":[{"message":{"content":"it is ` + token + `"}}]}`),
	})
	if !strings.Contains(string(response.Body), testSecretEmail) {
		t.Fatal("non-stream response was not restored through the ABI")
	}

	init := callABIForTest[pluginapi.StreamChunkInterceptResponse](t, pluginabi.MethodResponseInterceptStreamChunk, pluginapi.StreamChunkInterceptRequest{
		RequestID: "abi-req", SourceFormat: "openai", ChunkIndex: pluginapi.StreamChunkHeaderInitIndex, Metadata: metadata,
	})
	if init.Body != nil || init.DropChunk {
		t.Fatal("header-init chunk was modified")
	}
	var streamed strings.Builder
	chunks := providerStream("openai", []string{"it is " + token[:8], token[8:] + "."}, nil)
	for index, chunk := range chunks {
		out := callABIForTest[pluginapi.StreamChunkInterceptResponse](t, pluginabi.MethodResponseInterceptStreamChunk, pluginapi.StreamChunkInterceptRequest{
			RequestID: "abi-req", SourceFormat: "openai", ChunkIndex: index, Body: chunk, Metadata: metadata,
		})
		body := chunk
		if len(out.Body) != 0 {
			body = out.Body
		}
		text, _ := clientView(t, "openai", [][]byte{body})
		streamed.WriteString(text)
	}
	if streamed.String() != "it is "+testSecretEmail+"." {
		t.Fatal("stream was not restored through the ABI")
	}

	privacyFilterABIState.RLock()
	runtime := privacyFilterABIState.runtime
	privacyFilterABIState.RUnlock()
	if runtime.loadedTokenRuntime().sessions.len() != 1 {
		t.Fatal("request has no restore session")
	}
	callABIForTest[struct{}](t, pluginabi.MethodRequestComplete, pluginapi.RequestCompletion{
		RequestID: "abi-req", Outcome: pluginapi.RequestCompletionCanceled, Stream: true,
	})
	if runtime.loadedTokenRuntime().sessions.len() != 0 {
		t.Fatal("request.complete did not release the restore session")
	}
}

func TestReconfigureKeepsTokensAndShutdownClearsThem(t *testing.T) {
	resetABIStateForTest(t)
	registerWithConfigForTest(t, pluginabi.SchemaVersion, []byte("mode: tokenize\n"))
	metadata := callerMetadata(testTokenizeKeyA)
	first := callABIForTest[pluginapi.RequestInterceptResponse](t, pluginabi.MethodRequestInterceptBefore, pluginapi.RequestInterceptRequest{
		RequestID: "before-reconfigure", SourceFormat: "openai", Model: "m",
		Body: []byte(chatBody("mail " + testSecretEmail)), Metadata: metadata,
	})
	token := testTokenPattern.FindString(string(first.Body))

	// A reconfigure with an unchanged (empty) hmac_secret keeps the process key
	// and the issued mappings, so an in-flight response is still restored and
	// the same value keeps its token.
	registerWithConfigForTest(t, pluginabi.SchemaVersion, []byte("mode: tokenize\ntokenize:\n  max_entries: 50\n"))
	response := callABIForTest[pluginapi.ResponseInterceptResponse](t, pluginabi.MethodResponseInterceptAfter, pluginapi.ResponseInterceptRequest{
		RequestID: "before-reconfigure", SourceFormat: "openai",
		Body: []byte(`{"choices":[{"message":{"content":"` + token + `"}}]}`),
	})
	if !strings.Contains(string(response.Body), testSecretEmail) {
		t.Fatal("reconfigure lost an in-flight mapping")
	}
	second := callABIForTest[pluginapi.RequestInterceptResponse](t, pluginabi.MethodRequestInterceptBefore, pluginapi.RequestInterceptRequest{
		RequestID: "after-reconfigure", SourceFormat: "openai", Model: "m",
		Body: []byte(chatBody("mail " + testSecretEmail)), Metadata: metadata,
	})
	if testTokenPattern.FindString(string(second.Body)) != token {
		t.Fatal("token changed across a reconfigure with the same secret")
	}

	privacyFilterABIState.RLock()
	runtime := privacyFilterABIState.runtime
	privacyFilterABIState.RUnlock()
	tokens := runtime.loadedTokenRuntime()
	if tokens.vault.stats().MaxEntries != 50 {
		t.Fatal("reconfigure did not apply the new vault bound")
	}
	PrivacyFilterPluginShutdown()
	if tokens.vault.stats().Entries != 0 || tokens.sessions.len() != 0 {
		t.Fatal("shutdown left mappings or sessions in memory")
	}
}

func TestLeavingTokenizeModeClearsStoredValues(t *testing.T) {
	resetABIStateForTest(t)
	registerWithConfigForTest(t, pluginabi.SchemaVersion, []byte("mode: tokenize\n"))
	callABIForTest[pluginapi.RequestInterceptResponse](t, pluginabi.MethodRequestInterceptBefore, pluginapi.RequestInterceptRequest{
		RequestID: "before-switch", SourceFormat: "openai", Model: "m",
		Body: []byte(chatBody("mail " + testSecretEmail)), Metadata: callerMetadata(testTokenizeKeyA),
	})
	privacyFilterABIState.RLock()
	tokens := privacyFilterABIState.runtime.loadedTokenRuntime()
	privacyFilterABIState.RUnlock()
	if tokens.vault.stats().Entries == 0 {
		t.Fatal("fixture stored no mapping")
	}
	reg := registerWithConfigForTest(t, pluginabi.SchemaVersion, []byte("mode: redact\n"))
	if reg.Capabilities.ResponseInterceptor || reg.Capabilities.StreamChunkInterceptor || reg.SchemaVersion != 2 {
		t.Fatalf("redact registration after tokenize = %+v schema %d", reg.Capabilities, reg.SchemaVersion)
	}
	if tokens.vault.stats().Entries != 0 || tokens.sessions.len() != 0 {
		t.Fatal("values stayed in memory after leaving tokenize mode")
	}
}
