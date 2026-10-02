package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ahoo/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var streamFormats = []string{"openai", "claude", "openai-response", "gemini", "interactions"}

// providerStream builds the chunks a provider would emit, in the framing the
// Host hands to a stream interceptor for that format: bare JSON objects for
// openai and gemini, SSE text for the others.
func providerStream(format string, textDeltas, argumentDeltas []string) [][]byte {
	var chunks [][]byte
	add := func(format string, args ...any) { chunks = append(chunks, []byte(fmt.Sprintf(format, args...))) }
	q := jsonString
	switch format {
	case "openai":
		add(`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`)
		for _, delta := range textDeltas {
			add(`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":%s},"finish_reason":null}]}`, q(delta))
		}
		for index, delta := range argumentDeltas {
			if index == 0 {
				add(`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"run","arguments":%s}}]},"finish_reason":null}]}`, q(delta))
				continue
			}
			add(`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":%s}}]},"finish_reason":null}]}`, q(delta))
		}
		add(`{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`)
		add(`{"id":"c1","object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":11,"total_tokens":18}}`)
	case "claude":
		add("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"content\":[],\"usage\":{\"input_tokens\":7}}}\n\n")
		add("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
		for _, delta := range textDeltas {
			add("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":%s}}\n\n", q(delta))
		}
		add("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
		add("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_1\",\"name\":\"run\",\"input\":{}}}\n\n")
		for _, delta := range argumentDeltas {
			add("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":%s}}\n\n", q(delta))
		}
		add("event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n")
		add("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":11}}\n\n")
		add("event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	case "openai-response":
		sequence := 0
		event := func(name, body string) {
			sequence++
			add("event: %s\ndata: {\"type\":%s,\"sequence_number\":%d,%s}", name, q(name), sequence, body)
		}
		event("response.created", `"response":{"id":"resp_1","status":"in_progress"}`)
		for _, delta := range textDeltas {
			event("response.output_text.delta", `"item_id":"msg_1","output_index":0,"content_index":0,"delta":`+q(delta))
		}
		event("response.output_text.done", `"item_id":"msg_1","output_index":0,"content_index":0,"text":`+q(strings.Join(textDeltas, "")))
		event("response.output_item.done", `"output_index":0,"item":{"id":"msg_1","type":"message","content":[{"type":"output_text","text":`+q(strings.Join(textDeltas, ""))+`}]}`)
		for _, delta := range argumentDeltas {
			event("response.function_call_arguments.delta", `"item_id":"fc_1","output_index":1,"delta":`+q(delta))
		}
		event("response.function_call_arguments.done", `"item_id":"fc_1","output_index":1,"arguments":`+q(strings.Join(argumentDeltas, "")))
		event("response.completed", `"response":{"id":"resp_1","status":"completed","usage":{"output_tokens":11}}`)
	case "gemini":
		for _, delta := range textDeltas {
			add(`{"candidates":[{"content":{"parts":[{"text":%s}],"role":"model"},"index":0}],"modelVersion":"g"}`, q(delta))
		}
		arguments := strings.Join(argumentDeltas, "")
		if arguments == "" {
			arguments = "{}"
		}
		// Gemini delivers a function call as one complete object, not as deltas.
		add(`{"candidates":[{"content":{"parts":[{"functionCall":{"name":"run","args":%s}}],"role":"model"},"index":0}]}`, arguments)
		add(`{"candidates":[{"content":{"parts":[{"text":""}],"role":"model"},"finishReason":"STOP","index":0}],"usageMetadata":{"totalTokenCount":18}}`)
	case "interactions":
		add("event: interaction.created\ndata: {\"interaction\":{\"id\":\"interaction_1\"},\"event_type\":\"interaction.created\"}")
		add("event: step.start\ndata: {\"index\":0,\"step\":{\"type\":\"model_output\"},\"event_type\":\"step.start\"}")
		for _, delta := range textDeltas {
			add("event: step.delta\ndata: {\"index\":0,\"delta\":{\"type\":\"text\",\"text\":%s},\"event_type\":\"step.delta\"}", q(delta))
		}
		add("event: step.stop\ndata: {\"index\":0,\"event_type\":\"step.stop\"}")
		add("event: step.start\ndata: {\"index\":1,\"step\":{\"type\":\"function_call\",\"id\":\"call_1\",\"name\":\"run\",\"arguments\":{}},\"event_type\":\"step.start\"}")
		for _, delta := range argumentDeltas {
			add("event: step.delta\ndata: {\"index\":1,\"delta\":{\"type\":\"arguments_delta\",\"arguments\":%s},\"event_type\":\"step.delta\"}", q(delta))
		}
		add("event: step.stop\ndata: {\"index\":1,\"event_type\":\"step.stop\"}")
		add("event: interaction.completed\ndata: {\"interaction\":{\"usage\":{\"total_output_tokens\":11}},\"event_type\":\"interaction.completed\"}")
	}
	return chunks
}

// runStream feeds chunks through the stream interceptor the way the Host does
// and returns what would be delivered downstream.
func runStream(t testing.TB, p *privacyFilterPlugin, requestID, format string, chunks [][]byte) [][]byte {
	t.Helper()
	if _, err := p.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{
		RequestID: requestID, SourceFormat: format, ChunkIndex: pluginapi.StreamChunkHeaderInitIndex,
	}); err != nil {
		t.Fatal(err)
	}
	var delivered [][]byte
	for index, chunk := range chunks {
		resp, err := p.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{
			RequestID: requestID, SourceFormat: format, ChunkIndex: index, Body: bytes.Clone(chunk),
		})
		if err != nil {
			t.Fatal(err)
		}
		if resp.DropChunk {
			continue
		}
		if len(resp.Body) != 0 {
			delivered = append(delivered, resp.Body)
			continue
		}
		delivered = append(delivered, chunk)
	}
	return delivered
}

// streamEvents parses delivered chunks into their JSON events, failing on any
// payload that is not valid JSON.
func streamEvents(t testing.TB, chunks [][]byte) []map[string]any {
	t.Helper()
	var events []map[string]any
	for _, chunk := range chunks {
		for _, line := range strings.Split(string(chunk), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "event:") {
				continue
			}
			line = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
			if line == "[DONE]" {
				continue
			}
			var event map[string]any
			if err := json.Unmarshal([]byte(line), &event); err != nil {
				t.Fatalf("delivered event is not valid JSON: %v", err)
			}
			events = append(events, event)
		}
	}
	return events
}

// clientView reassembles what a client reading only deltas would display: the
// visible text, and the tool-call arguments either as streamed JSON text or,
// for Gemini, as the decoded object re-encoded.
func clientView(t testing.TB, format string, chunks [][]byte) (text, arguments string) {
	t.Helper()
	var textOut, argumentsOut strings.Builder
	for _, event := range streamEvents(t, chunks) {
		switch format {
		case "openai":
			choices, _ := event["choices"].([]any)
			for _, rawChoice := range choices {
				delta, _ := rawChoice.(map[string]any)["delta"].(map[string]any)
				if content, ok := delta["content"].(string); ok {
					textOut.WriteString(content)
				}
				calls, _ := delta["tool_calls"].([]any)
				for _, rawCall := range calls {
					function, _ := rawCall.(map[string]any)["function"].(map[string]any)
					if fragment, ok := function["arguments"].(string); ok {
						argumentsOut.WriteString(fragment)
					}
				}
			}
		case "claude":
			if event["type"] != "content_block_delta" {
				continue
			}
			delta, _ := event["delta"].(map[string]any)
			if fragment, ok := delta["text"].(string); ok {
				textOut.WriteString(fragment)
			}
			if fragment, ok := delta["partial_json"].(string); ok {
				argumentsOut.WriteString(fragment)
			}
		case "openai-response":
			fragment, _ := event["delta"].(string)
			switch event["type"] {
			case "response.output_text.delta":
				textOut.WriteString(fragment)
			case "response.function_call_arguments.delta":
				argumentsOut.WriteString(fragment)
			}
		case "gemini":
			candidates, _ := event["candidates"].([]any)
			for _, rawCandidate := range candidates {
				content, _ := rawCandidate.(map[string]any)["content"].(map[string]any)
				parts, _ := content["parts"].([]any)
				for _, rawPart := range parts {
					part, _ := rawPart.(map[string]any)
					if fragment, ok := part["text"].(string); ok {
						textOut.WriteString(fragment)
					}
					if call, ok := part["functionCall"].(map[string]any); ok {
						encoded, _ := json.Marshal(call["args"])
						argumentsOut.Write(encoded)
					}
				}
			}
		case "interactions":
			if event["event_type"] != "step.delta" {
				continue
			}
			delta, _ := event["delta"].(map[string]any)
			if fragment, ok := delta["text"].(string); ok {
				textOut.WriteString(fragment)
			}
			if fragment, ok := delta["arguments"].(string); ok {
				argumentsOut.WriteString(fragment)
			}
		}
	}
	return textOut.String(), argumentsOut.String()
}

// splitAt cuts text at the given ascending byte offsets.
func splitAt(text string, cuts ...int) []string {
	var pieces []string
	previous := 0
	for _, cut := range cuts {
		if cut <= previous || cut >= len(text) {
			continue
		}
		pieces = append(pieces, text[previous:cut])
		previous = cut
	}
	return append(pieces, text[previous:])
}

func splitEvery(text string, size int) []string {
	var pieces []string
	for len(text) > size {
		pieces = append(pieces, text[:size])
		text = text[size:]
	}
	return append(pieces, text)
}

func splitRandom(random *rand.Rand, text string) []string {
	var pieces []string
	for len(text) > 0 {
		size := 1 + random.Intn(min(len(text), 9))
		pieces = append(pieces, text[:size])
		text = text[size:]
	}
	return pieces
}

type streamCase struct {
	plugin    *privacyFilterPlugin
	requestID string
	token     string
	// text and arguments are what the provider streams; wantText and wantCmd
	// are what the client must end up with.
	text, arguments   string
	wantText, wantCmd string
}

func newStreamCase(t testing.TB, requestID string) streamCase {
	t.Helper()
	plugin, err := buildPlugin([]byte("mode: tokenize\n"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	return streamCaseFor(t, p, requestID)
}

func streamCaseFor(t testing.TB, p *privacyFilterPlugin, requestID string) streamCase {
	t.Helper()
	renderer := p.tok.newRenderer(requestID, callerScope(testTokenizeKeyA), p.renderer)
	token, err := renderer.Render(context.Background(), privacyengine.Finding{Kind: privacyengine.KindSecret}, awkwardSecret)
	if err != nil {
		t.Fatal(err)
	}
	renderer.commit()
	return streamCase{
		plugin:    p,
		requestID: requestID,
		token:     token,
		text:      "Set it with " + token + " and again " + token + ". Done, p",
		arguments: `{"cmd":"export K=` + token + `","n":1,"tail":"pf-"}`,
		wantText:  "Set it with " + awkwardSecret + " and again " + awkwardSecret + ". Done, p",
		wantCmd:   "export K=" + awkwardSecret,
	}
}

// check streams the case with the given splits and verifies the client view.
func (c streamCase) check(t testing.TB, format string, textDeltas, argumentDeltas []string) {
	t.Helper()
	delivered := runStream(t, c.plugin, c.requestID, format, providerStream(format, textDeltas, argumentDeltas))
	text, arguments := clientView(t, format, delivered)
	if text != c.wantText {
		t.Fatalf("%s: restored text differs: got %d bytes, want %d (pieces=%d)", format, len(text), len(c.wantText), len(textDeltas))
	}
	var decoded map[string]any
	if err := json.Unmarshal([]byte(arguments), &decoded); err != nil {
		t.Fatalf("%s: restored tool arguments are not valid JSON: %v (pieces=%d)", format, err, len(argumentDeltas))
	}
	if decoded["cmd"] != c.wantCmd || decoded["tail"] != "pf-" {
		t.Fatalf("%s: tool arguments were not restored exactly (pieces=%d)", format, len(argumentDeltas))
	}
	if unflushed := c.plugin.tok.sessions.get(c.requestID).stream.unflushed(); unflushed != 0 {
		t.Fatalf("%s: %d buffers still withhold text after the terminal event", format, unflushed)
	}
}

func TestStreamRestoreUnsplit(t *testing.T) {
	c := newStreamCase(t, "req-stream")
	for _, format := range streamFormats {
		c.check(t, format, []string{c.text}, []string{c.arguments})
	}
}

func TestStreamRestoreTokenSplitInTwo(t *testing.T) {
	c := newStreamCase(t, "req-stream")
	textStart := strings.Index(c.text, c.token)
	argumentsStart := strings.Index(c.arguments, c.token)
	for _, format := range streamFormats {
		// Every cut point inside the token, plus the two boundaries.
		for cut := 0; cut <= len(c.token); cut++ {
			c.check(t, format, splitAt(c.text, textStart+cut), splitAt(c.arguments, argumentsStart+cut))
		}
	}
}

func TestStreamRestoreTokenSplitInThree(t *testing.T) {
	c := newStreamCase(t, "req-stream")
	textStart := strings.Index(c.text, c.token)
	argumentsStart := strings.Index(c.arguments, c.token)
	for _, format := range streamFormats {
		for first := 1; first < len(c.token)-1; first += 2 {
			for second := first + 1; second < len(c.token); second += 3 {
				c.check(t, format,
					splitAt(c.text, textStart+first, textStart+second),
					splitAt(c.arguments, argumentsStart+first, argumentsStart+second))
			}
		}
	}
}

func TestStreamRestoreFixedSizeAndPerCharacter(t *testing.T) {
	c := newStreamCase(t, "req-stream")
	for _, format := range streamFormats {
		for _, size := range []int{1, 2, 3, 5, 7, 11, len(c.token) - 1, len(c.token), len(c.token) + 1} {
			c.check(t, format, splitEvery(c.text, size), splitEvery(c.arguments, size))
		}
	}
}

func TestStreamRestoreRandomSplits(t *testing.T) {
	c := newStreamCase(t, "req-stream")
	for seed := int64(1); seed <= 150; seed++ {
		random := rand.New(rand.NewSource(seed))
		for _, format := range streamFormats {
			c.check(t, format, splitRandom(random, c.text), splitRandom(random, c.arguments))
		}
	}
}

func FuzzStreamRestoreRandomSplits(f *testing.F) {
	for seed := int64(0); seed < 8; seed++ {
		f.Add(seed, uint8(seed))
	}
	c := newStreamCase(f, "req-fuzz")
	f.Fuzz(func(t *testing.T, seed int64, formatIndex uint8) {
		random := rand.New(rand.NewSource(seed))
		format := streamFormats[int(formatIndex)%len(streamFormats)]
		c.check(t, format, splitRandom(random, c.text), splitRandom(random, c.arguments))
	})
}

func TestStreamHoldsBackAtMostOneTokenLength(t *testing.T) {
	c := newStreamCase(t, "req-latency")
	p := c.plugin
	session := p.tok.sessions.get(c.requestID)
	// Per-character feed: after every delta the withheld run must be shorter
	// than a token, and text that cannot start a token is released at once.
	chunks := providerStream("openai", splitEvery("abc "+c.token+" xyz", 1), nil)
	runStreamInit(t, p, c.requestID, "openai")
	for index, chunk := range chunks {
		if _, err := p.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{
			RequestID: c.requestID, SourceFormat: "openai", ChunkIndex: index, Body: chunk,
		}); err != nil {
			t.Fatal(err)
		}
		for _, channel := range session.stream.channels {
			if len(channel.held) >= len(c.token) {
				t.Fatalf("withheld %d bytes, a token is %d", len(channel.held), len(c.token))
			}
		}
	}
	// A prefix that stops matching is released by the very next delta.
	c2 := streamCaseFor(t, p, "req-latency-2")
	delivered := runStream(t, p, c2.requestID, "openai", providerStream("openai", []string{"pf-sec", "ure line"}, nil)[:3])
	text, _ := clientView(t, "openai", delivered)
	if text != "pf-secure line" {
		t.Fatalf("a broken prefix was not released immediately: got %d bytes", len(text))
	}
}

func runStreamInit(t testing.TB, p *privacyFilterPlugin, requestID, format string) {
	t.Helper()
	if _, err := p.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{
		RequestID: requestID, SourceFormat: format, ChunkIndex: pluginapi.StreamChunkHeaderInitIndex,
	}); err != nil {
		t.Fatal(err)
	}
}

func TestStreamLeavesServiceEventsByteIdentical(t *testing.T) {
	c := newStreamCase(t, "req-service")
	p := c.plugin
	untouched := map[string][]string{
		"openai": {
			`{"id":"c1","choices":[],"usage":{"prompt_tokens":7,"completion_tokens":11,"total_tokens":18,"big":9007199254740993}}`,
			`{"id":"c1","choices":[{"index":0,"delta":{"reasoning_content":"thinking ` + c.token + `"},"finish_reason":null}]}`,
			`{ "id" : "c1" , "choices" : [ { "index" : 0 , "delta" : { "content" : "plain" } } ] }`,
		},
		"claude": {
			"event: ping\ndata: {\"type\": \"ping\"}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"thinking_delta\",\"thinking\":\"about " + c.token + "\"}}\n\n",
			"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"signature_delta\",\"signature\":\"sig" + c.token + "\"}}\n\n",
			"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7,\"cache_read_input_tokens\":3}}}\n\n",
			": keep-alive\n\n",
		},
		"openai-response": {
			"event: response.reasoning_summary_text.delta\ndata: {\"type\":\"response.reasoning_summary_text.delta\",\"item_id\":\"rs_1\",\"delta\":\"" + c.token + "\"}",
			"event: response.output_item.done\ndata: {\"type\":\"response.output_item.done\",\"output_index\":0,\"item\":{\"id\":\"rs_1\",\"type\":\"reasoning\",\"encrypted_content\":\"enc" + c.token + "\",\"summary\":[{\"type\":\"summary_text\",\"text\":\"" + c.token + "\"}]}}",
			"data: [DONE]\n\n",
		},
		"gemini": {
			`{"candidates":[{"content":{"parts":[{"text":"musing ` + c.token + `","thought":true,"thoughtSignature":"s` + c.token + `"}],"role":"model"},"index":0}],"usageMetadata":{"totalTokenCount":18}}`,
		},
		"interactions": {
			"event: step.delta\ndata: {\"index\":0,\"delta\":{\"signature\":\"sig" + c.token + "\",\"type\":\"thought_signature\"},\"event_type\":\"step.delta\"}",
			"event: step.delta\ndata: {\"index\":0,\"delta\":{\"content\":{\"text\":\"" + c.token + "\",\"type\":\"text\"},\"type\":\"thought_summary\"},\"event_type\":\"step.delta\"}",
		},
	}
	for format, chunks := range untouched {
		runStreamInit(t, p, c.requestID, format)
		for index, chunk := range chunks {
			resp, err := p.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{
				RequestID: c.requestID, SourceFormat: format, ChunkIndex: index, Body: []byte(chunk),
			})
			if err != nil {
				t.Fatal(err)
			}
			if resp.DropChunk || (resp.Body != nil && string(resp.Body) != chunk) {
				t.Fatalf("%s service event %d was rewritten", format, index)
			}
		}
	}
}

func TestStreamResponsesDoneEventsAreRestored(t *testing.T) {
	c := newStreamCase(t, "req-done")
	delivered := runStream(t, c.plugin, c.requestID, "openai-response",
		providerStream("openai-response", splitEvery(c.text, 4), splitEvery(c.arguments, 4)))
	sawText, sawArguments, sawItem := false, false, false
	for _, event := range streamEvents(t, delivered) {
		switch event["type"] {
		case "response.output_text.done":
			sawText = event["text"] == c.wantText
		case "response.function_call_arguments.done":
			var decoded map[string]any
			if json.Unmarshal([]byte(event["arguments"].(string)), &decoded) == nil {
				sawArguments = decoded["cmd"] == c.wantCmd
			}
		case "response.output_item.done":
			item, _ := event["item"].(map[string]any)
			content, _ := item["content"].([]any)
			sawItem = len(content) == 1 && content[0].(map[string]any)["text"] == c.wantText
		}
	}
	if !sawText || !sawArguments || !sawItem {
		t.Fatalf("complete strings in done events were not restored: text=%t arguments=%t item=%t", sawText, sawArguments, sawItem)
	}
}

func TestStreamResponsesSplitEventAndDataLines(t *testing.T) {
	c := newStreamCase(t, "req-lines")
	var chunks [][]byte
	for _, chunk := range providerStream("openai-response", splitEvery(c.text, 5), splitEvery(c.arguments, 5)) {
		// The Host may hand the "event:" and "data:" lines over separately.
		lines := strings.SplitN(string(chunk), "\n", 2)
		chunks = append(chunks, []byte(lines[0]), []byte(lines[1]))
	}
	delivered := runStream(t, c.plugin, c.requestID, "openai-response", chunks)
	text, arguments := clientView(t, "openai-response", delivered)
	var decoded map[string]any
	if text != c.wantText || json.Unmarshal([]byte(arguments), &decoded) != nil || decoded["cmd"] != c.wantCmd {
		t.Fatal("stream with separately delivered event and data lines was not restored")
	}
	for _, chunk := range delivered {
		if bytes.HasPrefix(chunk, []byte("event:")) && !bytes.Contains(chunk, []byte("\ndata:")) {
			t.Fatal("an event line was delivered without its data line")
		}
	}
}

func TestStreamSyntheticDeltaPrecedesTerminalEvent(t *testing.T) {
	c := newStreamCase(t, "req-order")
	// Both blocks end in a run that could still become a token, so each needs
	// a delta that delivers the withheld tail before the block closes.
	for format, terminal := range map[string]string{"claude": "content_block_stop", "interactions": "step.stop", "openai-response": "response.output_text.done"} {
		delivered := runStream(t, c.plugin, c.requestID, format, providerStream(format, []string{"ends with pf-sec"}, []string{`{"a":"pf-`, `"}`}))
		text, _ := clientView(t, format, delivered)
		if text != "ends with pf-sec" {
			t.Fatalf("%s: withheld tail was lost: got %d bytes", format, len(text))
		}
		joined := string(bytes.Join(delivered, []byte("\n")))
		tailAt := strings.Index(joined, `pf-sec"`)
		terminalAt := strings.Index(joined, terminal)
		if tailAt < 0 || terminalAt < 0 || tailAt > terminalAt {
			t.Fatalf("%s: tail delta does not precede %s", format, terminal)
		}
	}
}

func TestStreamHeaderInitResetsBuffers(t *testing.T) {
	c := newStreamCase(t, "req-retry")
	p := c.plugin
	// First attempt dies mid-token; the bootstrap retry starts over.
	runStream(t, p, c.requestID, "openai", providerStream("openai", []string{"abandoned pf-secr"}, nil)[:2])
	if p.tok.sessions.get(c.requestID).stream.unflushed() != 1 {
		t.Fatal("fixture did not leave a withheld tail")
	}
	delivered := runStream(t, p, c.requestID, "openai", providerStream("openai", []string{"fresh " + c.token}, nil))
	if text, _ := clientView(t, "openai", delivered); text != "fresh "+awkwardSecret {
		t.Fatalf("retry was polluted by the abandoned attempt: got %d bytes", len(text))
	}
}

func TestStreamCancellationReleasesState(t *testing.T) {
	baseline := runtime.NumGoroutine()
	p := newTokenizePlugin(t, "tokenize:\n  restore_scope: request\n")
	for index := 0; index < 20; index++ {
		requestID := "req-cancel-" + strconv.Itoa(index)
		upstream := sendRequest(t, p, requestID, testTokenizeKeyA, "claude",
			`{"model":"m","max_tokens":10,"messages":[{"role":"user","content":"mail `+testSecretEmail+`"}]}`)
		token := testTokenPattern.FindString(string(upstream))
		if token == "" {
			t.Fatal("request was not tokenized")
		}
		// The client disconnects while a token is half delivered.
		chunks := providerStream("claude", []string{"partial " + token[:7]}, nil)[:3]
		runStream(t, p, requestID, "claude", chunks)
		if p.tok.sessions.get(requestID).stream.unflushed() != 1 {
			t.Fatal("fixture did not leave a withheld tail")
		}
		completeRequest(p, requestID, pluginapi.RequestCompletionCanceled)
		// A late chunk after cancellation is passed through untouched.
		late, err := p.InterceptStreamChunk(context.Background(), pluginapi.StreamChunkInterceptRequest{
			RequestID: requestID, SourceFormat: "claude", ChunkIndex: 9,
			Body: []byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"" + token + "\"}}\n\n"),
		})
		if err != nil || late.Body != nil || late.DropChunk {
			t.Fatal("a chunk after cancellation was rewritten")
		}
	}
	if sessions, stats := p.tok.sessions.len(), p.tok.vault.stats(); sessions != 0 || stats.Entries != 0 || stats.Partitions != 0 {
		t.Fatalf("cancelled streams left state: sessions=%d entries=%d partitions=%d", sessions, stats.Entries, stats.Partitions)
	}
	if got := p.tokRuntime.stats.unflushed.Load(); got != 20 {
		t.Fatalf("unflushed counter = %d, want 20", got)
	}
	if p.cache.Len() != 0 {
		t.Fatalf("request scan cache entries = %d after cancellation", p.cache.Len())
	}
	// The plugin starts no goroutines, so there is nothing to leak.
	time.Sleep(10 * time.Millisecond)
	if now := runtime.NumGoroutine(); now > baseline {
		t.Fatalf("goroutines grew from %d to %d", baseline, now)
	}
}

func TestStreamConcurrentRequests(t *testing.T) {
	p := newTokenizePlugin(t, "")
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			random := rand.New(rand.NewSource(int64(worker)))
			for round := 0; round < 12; round++ {
				requestID := fmt.Sprintf("req-%d-%d", worker, round)
				apiKey := testTokenizeKeyA
				if worker%2 == 1 {
					apiKey = testTokenizeKeyB
				}
				format := streamFormats[(worker+round)%len(streamFormats)]
				upstream := sendRequest(t, p, requestID, apiKey, "openai", chatBody("mail "+testSecretEmail))
				token := testTokenPattern.FindString(string(upstream))
				text := "your mail " + token + " is set"
				delivered := runStream(t, p, requestID, format, providerStream(format, splitRandom(random, text), []string{"{}"}))
				if got, _ := clientView(t, format, delivered); got != "your mail "+testSecretEmail+" is set" {
					t.Errorf("worker %d round %d (%s): stream was not restored", worker, round, format)
				}
				completeRequest(p, requestID, pluginapi.RequestCompletionSucceeded)
			}
		}(worker)
	}
	wait.Wait()
	if p.tok.sessions.len() != 0 {
		t.Fatalf("sessions left after completion: %d", p.tok.sessions.len())
	}
}

func TestStreamStructuredOutputIsEscaped(t *testing.T) {
	c := newStreamCase(t, "req-structured")
	// A text channel that streams JSON (structured output) gets the value
	// escaped for the string literal it lands in.
	structured := `{"api_key":"` + c.token + `","ok":true}`
	for _, format := range []string{"openai", "claude", "openai-response", "interactions"} {
		delivered := runStream(t, c.plugin, c.requestID, format, providerStream(format, splitEvery(structured, 6), []string{"{}"}))
		text, _ := clientView(t, format, delivered)
		var decoded map[string]any
		if err := json.Unmarshal([]byte(text), &decoded); err != nil || decoded["api_key"] != awkwardSecret {
			t.Fatalf("%s: streamed structured output is not valid JSON with the restored value: %v", format, err)
		}
	}
}

func TestStreamSessionEvictionAndExpiry(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	vault := newTokenVault(100, time.Minute, clock.Now)
	registry := newRestoreRegistry(2, time.Minute, clock.Now, func(session *restoreSession) {
		if session.requestScoped {
			vault.dropPartition(session.partition)
		}
	})
	for _, id := range []string{"a", "b"} {
		vault.put(requestPartitionPrefix+id, "tok", "v")
		registry.open(id, requestPartitionPrefix+id, true)
		clock.Advance(time.Second)
	}
	// A third request evicts the least recently active one and its mappings.
	vault.put(requestPartitionPrefix+"c", "tok", "v")
	registry.open("c", requestPartitionPrefix+"c", true)
	if registry.get("a") != nil || vault.has(requestPartitionPrefix+"a") {
		t.Fatal("evicted session or its mappings survived")
	}
	if registry.get("b") == nil || registry.get("c") == nil {
		t.Fatal("live sessions were evicted")
	}
	// Idle sessions expire; close is idempotent.
	clock.Advance(2 * time.Minute)
	if registry.get("b") != nil {
		t.Fatal("idle session did not expire")
	}
	if registry.close("b") != nil || registry.close("missing") != nil {
		t.Fatal("close returned a session that was already gone")
	}
	registry.open("d", requestPartitionPrefix+"d", true)
	if registry.len() != 1 {
		t.Fatalf("expired sessions were retained: %d", registry.len())
	}
}
