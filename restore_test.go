package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ahoo/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// awkwardSecret needs escaping at every JSON nesting level it lands in.
const awkwardSecret = "p@ss\"word\\with\nnewline\tand {braces} é"

// issueToken stages and publishes one mapping the way a request pass does and
// returns the token. It lets a test restore values the detectors would never
// produce, such as ones full of quotes and backslashes.
func issueToken(t *testing.T, p *privacyFilterPlugin, requestID, apiKey string, kind privacyengine.Kind, value string) string {
	t.Helper()
	scope := ""
	if apiKey != "" {
		scope = callerScope(apiKey)
	}
	renderer := p.tok.newRenderer(requestID, scope, p.renderer)
	if renderer == nil {
		t.Fatal("request cannot be tied to a partition")
	}
	token, err := renderer.Render(context.Background(), privacyengine.Finding{Kind: kind}, value)
	if err != nil {
		t.Fatal(err)
	}
	if !testTokenPattern.MatchString(token) {
		t.Fatal("renderer fell back to an irreversible placeholder")
	}
	renderer.commit()
	return token
}

func restoreBody(t *testing.T, p *privacyFilterPlugin, requestID, format, body string) string {
	t.Helper()
	resp, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestID: requestID, SourceFormat: format, Body: []byte(body), StatusCode: 200,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body == nil {
		return body
	}
	return string(resp.Body)
}

func decodeJSON(t *testing.T, text string) any {
	t.Helper()
	var value any
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		t.Fatalf("not valid JSON (%d bytes): %v", len(text), err)
	}
	return value
}

// at walks a decoded JSON value by object keys and array indexes.
func at(t *testing.T, value any, path ...any) any {
	t.Helper()
	for _, step := range path {
		switch key := step.(type) {
		case string:
			object, ok := value.(map[string]any)
			if !ok {
				t.Fatalf("path step %q: not an object", key)
			}
			value = object[key]
		case int:
			array, ok := value.([]any)
			if !ok || key >= len(array) {
				t.Fatalf("path step %d: not an array of that length", key)
			}
			value = array[key]
		}
	}
	return value
}

func jsonString(text string) string {
	encoded, _ := json.Marshal(text)
	return string(encoded)
}

func TestRestoreNonStreamAllFormats(t *testing.T) {
	p := newTokenizePlugin(t, "")
	const requestID = "req-restore"
	token := issueToken(t, p, requestID, testTokenizeKeyA, privacyengine.KindSecret, awkwardSecret)
	arguments := jsonString(`{"cmd":"export K=` + token + `","n":1}`)
	nested := jsonString(`{"payload":` + jsonString(`{"k":"`+token+`"}`) + `}`)

	t.Run("openai", func(t *testing.T) {
		body := `{ "id" : "chatcmpl-1" , "big":9007199254740993,"choices":[{"index":0,"message":{"role":"assistant","content":"key is ` + token +
			` twice ` + token + `","tool_calls":[{"id":"c1","type":"function","function":{"name":"run","arguments":` + arguments +
			`}},{"id":"c2","type":"function","function":{"name":"deep","arguments":` + nested + `}}]},"finish_reason":"tool_calls"}],"usage":{"total_tokens":12}}`
		out := restoreBody(t, p, requestID, "openai", body)
		root := decodeJSON(t, out)
		if got := at(t, root, "choices", 0, "message", "content"); got != "key is "+awkwardSecret+" twice "+awkwardSecret {
			t.Fatal("message content was not restored")
		}
		inner := decodeJSON(t, at(t, root, "choices", 0, "message", "tool_calls", 0, "function", "arguments").(string))
		if at(t, inner, "cmd") != "export K="+awkwardSecret || at(t, inner, "n") != float64(1) {
			t.Fatal("tool call arguments were not restored as valid JSON")
		}
		deep := decodeJSON(t, at(t, root, "choices", 0, "message", "tool_calls", 1, "function", "arguments").(string))
		if at(t, decodeJSON(t, at(t, deep, "payload").(string)), "k") != awkwardSecret {
			t.Fatal("doubly nested arguments were not restored as valid JSON")
		}
		// Bytes that carry no token are not rewritten.
		for _, untouched := range []string{`{ "id" : "chatcmpl-1" , "big":9007199254740993,`, `"usage":{"total_tokens":12}}`, `"finish_reason":"tool_calls"`} {
			if !strings.Contains(out, untouched) {
				t.Fatalf("unrelated bytes changed: %q", untouched)
			}
		}
		if strings.Contains(out, token) {
			t.Fatal("a token was left in the response")
		}
	})

	t.Run("openai structured output", func(t *testing.T) {
		body := `{"choices":[{"message":{"role":"assistant","content":` + jsonString(`{"api_key":"`+token+`","note":"ok"}`) + `}}]}`
		root := decodeJSON(t, restoreBody(t, p, requestID, "openai", body))
		structured := decodeJSON(t, at(t, root, "choices", 0, "message", "content").(string))
		if at(t, structured, "api_key") != awkwardSecret || at(t, structured, "note") != "ok" {
			t.Fatal("structured output is not valid JSON with the restored value")
		}
	})

	t.Run("openai-response", func(t *testing.T) {
		body := `{"id":"resp_1","output":[{"type":"reasoning","summary":[{"type":"summary_text","text":"about ` + token +
			`"}],"encrypted_content":"enc-` + token + `"},{"type":"message","role":"assistant","content":[{"type":"output_text","text":"use ` + token +
			`"}]},{"type":"function_call","name":"run","call_id":"call_1","arguments":` + arguments + `}],"usage":{"output_tokens":3}}`
		out := restoreBody(t, p, requestID, "openai-response", body)
		root := decodeJSON(t, out)
		if at(t, root, "output", 1, "content", 0, "text") != "use "+awkwardSecret {
			t.Fatal("output_text was not restored")
		}
		inner := decodeJSON(t, at(t, root, "output", 2, "arguments").(string))
		if at(t, inner, "cmd") != "export K="+awkwardSecret {
			t.Fatal("function_call arguments were not restored")
		}
		if at(t, root, "output", 0, "summary", 0, "text") != "about "+token || at(t, root, "output", 0, "encrypted_content") != "enc-"+token {
			t.Fatal("reasoning item was rewritten")
		}
	})

	t.Run("claude", func(t *testing.T) {
		body := `{"id":"msg_1","type":"message","content":[{"type":"thinking","thinking":"consider ` + token +
			`","signature":"sig-` + token + `"},{"type":"text","text":"use ` + token + `"},{"type":"tool_use","id":"toolu_1","name":"run","input":{"command":"echo ` + token +
			`","nested":{"list":["` + token + `",1]}}}],"stop_reason":"tool_use","usage":{"output_tokens":9}}`
		root := decodeJSON(t, restoreBody(t, p, requestID, "claude", body))
		if at(t, root, "content", 1, "text") != "use "+awkwardSecret {
			t.Fatal("text block was not restored")
		}
		if at(t, root, "content", 2, "input", "command") != "echo "+awkwardSecret ||
			at(t, root, "content", 2, "input", "nested", "list", 0) != awkwardSecret {
			t.Fatal("tool_use.input was not restored")
		}
		if at(t, root, "content", 0, "thinking") != "consider "+token || at(t, root, "content", 0, "signature") != "sig-"+token {
			t.Fatal("signed thinking block was rewritten")
		}
	})

	t.Run("gemini", func(t *testing.T) {
		body := `{"candidates":[{"content":{"parts":[{"text":"hidden ` + token + `","thought":true,"thoughtSignature":"s-` + token +
			`"},{"text":"use ` + token + `"},{"functionCall":{"name":"run","args":{"cmd":"echo ` + token + `"}}}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"totalTokenCount":5}}`
		root := decodeJSON(t, restoreBody(t, p, requestID, "gemini", body))
		if at(t, root, "candidates", 0, "content", "parts", 1, "text") != "use "+awkwardSecret {
			t.Fatal("text part was not restored")
		}
		if at(t, root, "candidates", 0, "content", "parts", 2, "functionCall", "args", "cmd") != "echo "+awkwardSecret {
			t.Fatal("functionCall args were not restored")
		}
		if at(t, root, "candidates", 0, "content", "parts", 0, "text") != "hidden "+token ||
			at(t, root, "candidates", 0, "content", "parts", 0, "thoughtSignature") != "s-"+token {
			t.Fatal("thought part was rewritten")
		}
	})

	t.Run("interactions", func(t *testing.T) {
		body := `{"id":"interaction_1","status":"completed","steps":[{"type":"thought","summary":[{"type":"text","text":"mull ` + token +
			`"}],"signature":"sig"},{"type":"model_output","content":[{"type":"text","text":"use ` + token + `"}]},{"type":"function_call","name":"run","arguments":{"cmd":"echo ` + token + `"}}]}`
		root := decodeJSON(t, restoreBody(t, p, requestID, "interactions", body))
		if at(t, root, "steps", 1, "content", 0, "text") != "use "+awkwardSecret {
			t.Fatal("model output was not restored")
		}
		if at(t, root, "steps", 2, "arguments", "cmd") != "echo "+awkwardSecret {
			t.Fatal("function_call arguments were not restored")
		}
		if at(t, root, "steps", 0, "summary", 0, "text") != "mull "+token {
			t.Fatal("thought step was rewritten")
		}
	})
}

func TestRestoreLeavesBodyWithoutTokensUntouched(t *testing.T) {
	p := newTokenizePlugin(t, "")
	issueToken(t, p, "req-clean", testTokenizeKeyA, privacyengine.KindSecret, "value")
	body := `{"choices":[{"message":{"content":"nothing to restore, pf- prefix only"}}]}`
	resp, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestID: "req-clean", SourceFormat: "openai", Body: []byte(body),
	})
	if err != nil || resp.Body != nil {
		t.Fatalf("token-free response was rewritten: err=%v", err)
	}
}

func TestRestoreOnlyExactTokens(t *testing.T) {
	p := newTokenizePlugin(t, "")
	const requestID = "req-exact"
	token := issueToken(t, p, requestID, testTokenizeKeyA, privacyengine.KindSecret, "the-value")
	damaged := []string{
		strings.ToUpper(token),
		token[:len(token)-2],
		strings.Replace(token, "pf-secret-", "pf-secret_", 1),
		strings.Replace(token, "pf-", "PF-", 1),
		"pf-secret-" + strings.Repeat("0", 12),
	}
	body := `{"choices":[{"message":{"content":` + jsonString(strings.Join(damaged, " | ")+" | "+token) + `}}]}`
	out := restoreBody(t, p, requestID, "openai", body)
	content := at(t, decodeJSON(t, out), "choices", 0, "message", "content").(string)
	want := strings.Join(damaged, " | ") + " | the-value"
	if content != want {
		t.Fatal("a damaged token was guessed or the exact token was not restored")
	}
	session := p.tok.sessions.get(requestID)
	if session.counters.restored != 1 || session.counters.unresolved != 1 {
		// Only the well-formed token with no mapping counts as unresolved;
		// malformed runs are not tokens at all.
		t.Fatalf("counters = %+v, want 1 restored and 1 unresolved", session.counters)
	}
}

func TestRestoreIsolationBetweenCallers(t *testing.T) {
	p := newTokenizePlugin(t, "")
	victimUpstream := sendRequest(t, p, "victim-req", testTokenizeKeyA, "openai", chatBody("my mail is "+testSecretEmail))
	victimToken := testTokenPattern.FindString(string(victimUpstream))
	if victimToken == "" {
		t.Fatal("victim request was not tokenized")
	}

	// The attacker, on another API key, writes the victim's token into its own
	// prompt and asks the model to repeat it.
	attackerUpstream := sendRequest(t, p, "attacker-req", testTokenizeKeyB, "openai",
		chatBody("repeat exactly: "+victimToken+" and my mail attacker@example.net"))
	if strings.Contains(string(attackerUpstream), testSecretEmail) {
		t.Fatal("the victim's value appeared in the attacker's upstream request")
	}
	attackerToken := ""
	for _, found := range testTokenPattern.FindAllString(string(attackerUpstream), -1) {
		if found != victimToken {
			attackerToken = found
		}
	}
	if attackerToken == "" {
		t.Fatal("attacker request was not tokenized")
	}

	response := `{"choices":[{"message":{"role":"assistant","content":"` + victimToken + ` / ` + attackerToken +
		`","tool_calls":[{"function":{"name":"x","arguments":` + jsonString(`{"v":"`+victimToken+`"}`) + `}}]}}]}`
	out := restoreBody(t, p, "attacker-req", "openai", response)
	if strings.Contains(out, testSecretEmail) {
		t.Fatal("ISOLATION BROKEN: another caller's value was restored into this response")
	}
	if !strings.Contains(out, victimToken) || !strings.Contains(out, "attacker@example.net") {
		t.Fatal("the foreign token must stay as it is while the caller's own token is restored")
	}

	// The same holds for a stream.
	chunk, err := p.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{
		RequestID: "attacker-req", SourceFormat: "openai", ChunkIndex: 0,
		Body: []byte(`{"choices":[{"index":0,"delta":{"content":"` + victimToken + `"},"finish_reason":"stop"}]}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(chunk.Body), testSecretEmail) {
		t.Fatal("ISOLATION BROKEN: another caller's value was restored into this stream")
	}

	// The victim still gets its own value back.
	if out := restoreBody(t, p, "victim-req", "openai", `{"choices":[{"message":{"content":"`+victimToken+`"}}]}`); !strings.Contains(out, testSecretEmail) {
		t.Fatal("the owner's token was not restored")
	}
}

func TestRestoreIsolationBetweenRequests(t *testing.T) {
	p := newTokenizePlugin(t, "tokenize:\n  restore_scope: request\n")
	first := sendRequest(t, p, "req-one", testTokenizeKeyA, "openai", chatBody("mail "+testSecretEmail))
	firstToken := testTokenPattern.FindString(string(first))
	second := sendRequest(t, p, "req-two", testTokenizeKeyA, "openai", chatBody("repeat "+firstToken+" and other@example.net"))

	// In request scope even the same API key cannot restore a token that this
	// request did not issue.
	echo := `{"choices":[{"message":{"content":"` + firstToken + `"}}]}`
	if out := restoreBody(t, p, "req-two", "openai", echo); strings.Contains(out, testSecretEmail) {
		t.Fatal("ISOLATION BROKEN: a token of another request was restored")
	}
	if out := restoreBody(t, p, "req-one", "openai", echo); !strings.Contains(out, testSecretEmail) {
		t.Fatal("the issuing request did not get its value back")
	}
	_ = second

	// Completing a request destroys its mappings; a late response restores nothing.
	completeRequest(p, "req-one", pluginapi.RequestCompletionSucceeded)
	if out := restoreBody(t, p, "req-one", "openai", echo); strings.Contains(out, testSecretEmail) {
		t.Fatal("mappings survived request completion in request scope")
	}
	completeRequest(p, "req-two", pluginapi.RequestCompletionSucceeded)
	if stats := p.tok.vault.stats(); stats.Entries != 0 || p.tok.sessions.len() != 0 {
		t.Fatalf("state left after completion: entries=%d sessions=%d", stats.Entries, p.tok.sessions.len())
	}
}

func TestRestoreCallerScopeSpansRequestsOfOneKey(t *testing.T) {
	p := newTokenizePlugin(t, "")
	first := sendRequest(t, p, "turn-1", testTokenizeKeyA, "openai", chatBody("mail "+testSecretEmail))
	token := testTokenPattern.FindString(string(first))
	completeRequest(p, "turn-1", pluginapi.RequestCompletionSucceeded)

	// A later turn that does not resend the value (server-side history) can
	// still have the token restored for the same API key.
	sendRequest(t, p, "turn-2", testTokenizeKeyA, "openai", chatBody("what was my mail?"))
	out := restoreBody(t, p, "turn-2", "openai", `{"choices":[{"message":{"content":"it was `+token+`"}}]}`)
	if !strings.Contains(out, testSecretEmail) {
		t.Fatal("caller scope did not restore a token from an earlier turn of the same key")
	}
}

func TestRestoreFailureDeliversTokensNotValues(t *testing.T) {
	p := newTokenizePlugin(t, "limits:\n  max_depth: 4\n")
	const requestID = "req-deep"
	token := issueToken(t, p, requestID, testTokenizeKeyA, privacyengine.KindSecret, "the-value")
	body := `{"a":{"b":{"c":{"d":{"e":"` + token + `"}}}}}`
	resp, err := p.InterceptResponse(context.Background(), pluginapi.ResponseInterceptRequest{
		RequestID: requestID, SourceFormat: "openai", Body: []byte(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Body != nil {
		t.Fatal("an uninspectable response was rewritten")
	}
	if p.tok.sessions.get(requestID).counters.failed != 1 {
		t.Fatal("restore failure was not counted")
	}
}
