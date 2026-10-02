package main

import (
	"bytes"
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
	"github.com/ahoo/cpa-plugin-privacyfilter/walker"
)

const (
	// maxStreamChannels bounds the reassembly buffers of one stream. A delta on
	// a channel beyond the bound is restored without cross-chunk reassembly.
	maxStreamChannels = 1024
	// maxStreamCarryBytes bounds the "event:" lines held back while their
	// "data:" line is awaited. A longer run is delivered as it arrived.
	maxStreamCarryBytes = 16 << 10
)

// streamChannel reassembles one independently streamed string: one text block,
// one tool call's arguments, one candidate. It withholds only a trailing run
// that could still grow into a token, which is at most one byte short of the
// longest token.
type streamChannel struct {
	held string

	// jsonMode means the streamed string is itself JSON text, so a value that
	// lands inside one of its string literals must be escaped for it. Tool-call
	// arguments always are. A text block is assumed to be JSON (structured
	// output) while it starts with { or [ and keeps looking like JSON; sniffed
	// marks that revocable assumption.
	jsonMode bool
	sniffed  bool
	decided  bool
	inString bool
	escaped  bool
	// depth, literal and previous let a sniffed channel notice that its text is
	// not JSON after all.
	depth    int
	literal  string
	previous byte

	// kind, group, slot and template let a protocol synthesise the delta that
	// delivers a withheld tail before the block's terminal event.
	kind     string
	group    string
	slot     int
	template map[string]any
}

// feed appends delta and returns the text that can be released now. final
// releases everything, because nothing can complete a withheld prefix anymore.
func (c *streamChannel) feed(r *restorer, delta string, final bool) string {
	buffer := delta
	if c.held != "" {
		buffer = c.held + delta
		c.held = ""
	}
	codec := r.codec
	var out strings.Builder
	out.Grow(len(buffer))
	for offset := 0; offset < len(buffer); {
		if length, ok := codec.matchAt(buffer, offset); ok {
			token := buffer[offset : offset+length]
			if value, found := r.resolve(token); found {
				if c.jsonMode && c.inString {
					out.WriteString(jsonStringContent(value))
				} else {
					out.WriteString(value)
				}
			} else {
				out.WriteString(token)
			}
			c.observeToken()
			offset += length
			continue
		}
		if !final && len(buffer)-offset < codec.maxLen && codec.isProperPrefix(buffer[offset:]) {
			c.held = buffer[offset:]
			break
		}
		c.observe(buffer[offset])
		out.WriteByte(buffer[offset])
		offset++
	}
	return out.String()
}

// observe advances the JSON string-literal tracker over one emitted byte. A
// text channel decides whether it carries JSON from its first visible byte.
func (c *streamChannel) observe(b byte) {
	if !c.decided {
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			return
		}
		c.decided = true
		if !c.jsonMode && (b == '{' || b == '[') {
			c.jsonMode, c.sniffed = true, true
		}
	}
	if !c.jsonMode {
		return
	}
	switch {
	case c.escaped:
		c.escaped = false
	case c.inString && b == '\\':
		c.escaped = true
	case b == '"':
		c.inString = !c.inString
	case !c.inString && c.sniffed && !c.plausibleJSON(b):
		// Prose such as "[Note] ..." only looked like JSON. From here on it is
		// plain text and values are restored verbatim.
		c.jsonMode, c.inString = false, false
	}
	c.previous = b
}

// plausibleJSON checks one byte outside a string literal against JSON grammar
// closely enough to tell structured output from prose: brackets must nest and
// nothing may follow the closed top-level value, letters must spell true,
// false or null, and an exponent must follow a digit.
func (c *streamChannel) plausibleJSON(b byte) bool {
	if c.literal != "" {
		if b != c.literal[0] {
			return false
		}
		c.literal = c.literal[1:]
		return true
	}
	if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
		return true
	}
	if c.depth == 0 && b != '{' && b != '[' {
		return false
	}
	switch b {
	case '{', '[':
		c.depth++
	case '}', ']':
		c.depth--
	case 't':
		c.literal = "rue"
	case 'f':
		c.literal = "alse"
	case 'n':
		c.literal = "ull"
	case 'e', 'E':
		return c.previous >= '0' && c.previous <= '9'
	case ',', ':', '-', '+', '.':
	default:
		return b >= '0' && b <= '9'
	}
	return true
}

// observeToken accounts for a token. Its bytes are [a-z0-9-], which cannot
// open, close, or escape anything.
func (c *streamChannel) observeToken() {
	c.decided = true
	c.escaped = false
	if c.jsonMode && c.sniffed && !c.inString {
		// A bare token is not JSON either.
		c.jsonMode = false
	}
}

// streamState is the response-side reassembly state of one stream.
type streamState struct {
	channels map[string]*streamChannel
	// carry is an SSE "event:" line whose "data:" line has not arrived yet.
	carry []byte
	// broken disables further rewriting after an internal failure, so a stream
	// is never left half-processed with inconsistent buffers.
	broken bool
	// warned limits the per-stream failure warning to one log line; the total
	// is reported when the request completes.
	warned bool
}

func newStreamState() *streamState {
	return &streamState{channels: make(map[string]*streamChannel)}
}

// unflushed counts buffers that still withhold text.
func (s *streamState) unflushed() int {
	if s == nil {
		return 0
	}
	count := 0
	for _, channel := range s.channels {
		if channel.held != "" {
			count++
		}
	}
	return count
}

// synthEvent is a delta the plugin inserts to deliver a withheld tail.
type synthEvent struct {
	name    string
	payload []byte
}

// streamProcessor rewrites the chunks of one stream.
type streamProcessor struct {
	ctx      context.Context
	r        *restorer
	state    *streamState
	protocol walker.Protocol
	known    bool
}

func newStreamProcessor(ctx context.Context, r *restorer, state *streamState, sourceFormat string) *streamProcessor {
	protocol, err := walker.DefaultRegistry.Resolve(sourceFormat)
	return &streamProcessor{ctx: ctx, r: r, state: state, protocol: protocol, known: err == nil}
}

// channel returns the buffer for key. tracked is false when the stream already
// uses the maximum number of buffers; such a delta must be fed as final.
func (sp *streamProcessor) channel(key string, jsonMode bool) (channel *streamChannel, tracked bool) {
	if existing, ok := sp.state.channels[key]; ok {
		return existing, true
	}
	channel = &streamChannel{jsonMode: jsonMode, decided: jsonMode, slot: -1}
	if len(sp.state.channels) >= maxStreamChannels {
		return channel, false
	}
	sp.state.channels[key] = channel
	return channel, true
}

func (sp *streamProcessor) feed(key string, jsonMode bool, delta string, final bool) (string, *streamChannel) {
	channel, tracked := sp.channel(key, jsonMode)
	return channel.feed(sp.r, delta, final || !tracked), channel
}

// drain releases whatever key still withholds and forgets the buffer.
func (sp *streamProcessor) drain(key string) (string, *streamChannel) {
	channel, ok := sp.state.channels[key]
	if !ok {
		return "", nil
	}
	delete(sp.state.channels, key)
	return channel.feed(sp.r, "", true), channel
}

// keys returns the buffer keys selected by match, in a stable order.
func (sp *streamProcessor) keys(match func(key string, channel *streamChannel) bool) []string {
	var keys []string
	for key, channel := range sp.state.channels {
		if match == nil || match(key, channel) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// chunk rewrites one stream chunk. drop asks the Host to withhold the chunk
// because all of it was carried over to the next one.
func (sp *streamProcessor) chunk(body []byte) (out []byte, drop bool) {
	data := body
	if len(sp.state.carry) != 0 {
		joined := append([]byte(nil), sp.state.carry...)
		if !bytes.HasSuffix(joined, []byte("\n")) {
			joined = append(joined, '\n')
		}
		data = append(joined, body...)
		sp.state.carry = nil
	}

	var buffer bytes.Buffer
	buffer.Grow(len(data))
	blockStart := 0
	blockHasEvent, blockHasData := false, false
	for _, line := range bytes.SplitAfter(data, []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		content := bytes.TrimRight(line, "\r\n")
		ending := line[len(content):]
		stripped := bytes.TrimLeft(content, " \t")
		if len(stripped) == 0 {
			buffer.Write(line)
			blockStart = buffer.Len()
			blockHasEvent, blockHasData = false, false
			continue
		}
		if bytes.HasPrefix(stripped, []byte("event:")) {
			blockHasEvent = true
			buffer.Write(line)
			continue
		}
		after := stripped
		framed := bytes.HasPrefix(stripped, []byte("data:"))
		if framed {
			after = stripped[len("data:"):]
		}
		eventPayload := bytes.TrimSpace(after)
		if len(eventPayload) == 0 || eventPayload[0] != '{' {
			// Not a JSON object event: "[DONE]", an SSE comment or field, or a
			// transport this plugin does not parse (for example a JSON-array
			// fragment). It is delivered as it is; a token inside it stays a
			// token and is reported.
			blockHasData = blockHasData || framed
			sp.reportUnparsed(line)
			buffer.Write(line)
			continue
		}
		blockHasData = true
		rewritten, pre := sp.event(eventPayload)
		if len(pre) != 0 {
			block := append([]byte(nil), buffer.Bytes()[blockStart:]...)
			buffer.Truncate(blockStart)
			for _, synthetic := range pre {
				if blockHasEvent && synthetic.name != "" {
					buffer.WriteString("event: ")
					buffer.WriteString(synthetic.name)
					buffer.WriteByte('\n')
				}
				buffer.WriteString("data: ")
				buffer.Write(synthetic.payload)
				buffer.WriteString("\n\n")
			}
			blockStart = buffer.Len()
			buffer.Write(block)
			if !framed {
				// A bare JSON chunk cannot carry two events; frame both.
				buffer.WriteString("data: ")
			}
		}
		start := len(content) - len(bytes.TrimLeftFunc(after, unicode.IsSpace))
		end := start + len(eventPayload)
		buffer.Write(content[:start])
		buffer.Write(rewritten)
		buffer.Write(content[end:])
		buffer.Write(ending)
	}
	if blockHasEvent && !blockHasData && blockStart < buffer.Len() && buffer.Len()-blockStart <= maxStreamCarryBytes {
		sp.state.carry = append([]byte(nil), buffer.Bytes()[blockStart:]...)
		buffer.Truncate(blockStart)
	}
	if buffer.Len() == 0 {
		return nil, true
	}
	return buffer.Bytes(), false
}

// reportUnparsed counts a delivered fragment that still carries a token because
// it could not be parsed.
func (sp *streamProcessor) reportUnparsed(fragment []byte) {
	if sp.r.codec.containsBytes(fragment) {
		sp.r.counters.failed++
	}
}

// event rewrites one JSON event and returns the events to deliver before it.
func (sp *streamProcessor) event(raw []byte) ([]byte, []synthEvent) {
	work := raw
	if sp.protocol == walker.ProtocolGemini && sp.known {
		// Gemini mixes streamed text parts with complete function-call parts in
		// one event; restore the complete strings first and leave text parts to
		// the reassembly buffers.
		if out, changed, err := sp.r.document(sp.ctx, work, geminiTextPartPath, 0); err != nil {
			sp.r.counters.failed++
		} else if changed {
			work = out
		}
	}
	doc, ok := parseEventDoc(work)
	if !ok {
		sp.reportUnparsed(work)
		return work, nil
	}
	pre, walk := sp.handle(doc)
	out, ok := doc.render(sp.ctx, sp.r.limits)
	if !ok {
		sp.r.counters.failed++
	}
	if walk {
		if restored, changed, err := sp.r.document(sp.ctx, out, nil, 0); err != nil {
			sp.r.counters.failed++
		} else if changed {
			out = restored
		}
	}
	return out, pre
}

func (sp *streamProcessor) handle(doc *eventDoc) (pre []synthEvent, walk bool) {
	if !sp.known {
		return nil, true
	}
	switch sp.protocol {
	case walker.ProtocolOpenAI:
		return sp.handleOpenAIChat(doc), false
	case walker.ProtocolClaude:
		return sp.handleClaude(doc)
	case walker.ProtocolOpenAIResponse:
		return sp.handleResponses(doc)
	case walker.ProtocolGemini:
		sp.handleGemini(doc)
		return nil, false
	case walker.ProtocolInteractions:
		return sp.handleInteractions(doc)
	default:
		return nil, true
	}
}

// --- OpenAI Chat Completions -------------------------------------------------

// handleOpenAIChat reassembles delta.content and per-tool-call arguments for
// each choice. A withheld tail is merged into the chunk that carries
// finish_reason, because a chat chunk is one bare JSON object and cannot be
// followed by a second event.
func (sp *streamProcessor) handleOpenAIChat(doc *eventDoc) []synthEvent {
	for position, rawChoice := range arrayAt(doc.root, "choices") {
		choice, ok := rawChoice.(map[string]any)
		if !ok {
			continue
		}
		index := position
		if value, ok := intAt(choice, "index"); ok {
			index = value
		}
		reason, _ := stringAt(choice, "finish_reason")
		finished := reason != ""
		prefix := "o:" + strconv.Itoa(index) + ":"
		base := payload.Path{payload.Key("choices"), payload.Index(position)}
		seen := make(map[string]bool)

		feedField := func(container map[string]any, path payload.Path, field, key string, jsonMode bool) {
			text, ok := stringAt(container, field)
			if !ok {
				return
			}
			seen[key] = true
			out, _ := sp.feed(key, jsonMode, text, finished)
			doc.set(append(path.Clone(), payload.Key(field)), container, field, text, out)
		}

		feedField(choice, base, "text", prefix+"c", false)
		delta := objectAt(choice, "delta")
		deltaPath := append(base.Clone(), payload.Key("delta"))
		if delta != nil {
			feedField(delta, deltaPath, "content", prefix+"c", false)
			if call := objectAt(delta, "function_call"); call != nil {
				feedField(call, append(deltaPath.Clone(), payload.Key("function_call")), "arguments", prefix+"f", true)
			}
			for toolPosition, rawCall := range arrayAt(delta, "tool_calls") {
				call, ok := rawCall.(map[string]any)
				if !ok {
					continue
				}
				toolIndex := toolPosition
				if value, ok := intAt(call, "index"); ok {
					toolIndex = value
				}
				function := objectAt(call, "function")
				if function == nil {
					continue
				}
				path := append(deltaPath.Clone(), payload.Key("tool_calls"), payload.Index(toolPosition), payload.Key("function"))
				feedField(function, path, "arguments", prefix+"t:"+strconv.Itoa(toolIndex), true)
			}
		}
		if !finished {
			continue
		}
		pending := sp.keys(func(key string, _ *streamChannel) bool {
			return strings.HasPrefix(key, prefix) && !seen[key]
		})
		for _, key := range pending {
			tail, _ := sp.drain(key)
			if tail == "" {
				continue
			}
			if delta == nil {
				delta = make(map[string]any)
				choice["delta"] = delta
			}
			suffix := strings.TrimPrefix(key, prefix)
			switch {
			case suffix == "c":
				existing, _ := delta["content"].(string)
				delta["content"] = existing + tail
			case suffix == "f":
				call := objectAt(delta, "function_call")
				if call == nil {
					call = make(map[string]any)
					delta["function_call"] = call
				}
				existing, _ := call["arguments"].(string)
				call["arguments"] = existing + tail
			default:
				toolIndex, err := strconv.Atoi(strings.TrimPrefix(suffix, "t:"))
				if err != nil {
					continue
				}
				calls, _ := delta["tool_calls"].([]any)
				delta["tool_calls"] = append(calls, map[string]any{
					"index":    toolIndex,
					"function": map[string]any{"arguments": tail},
				})
			}
			doc.structural = true
		}
		// Buffers of a finished choice that held nothing are simply forgotten.
		for _, key := range sp.keys(func(key string, _ *streamChannel) bool { return strings.HasPrefix(key, prefix) }) {
			delete(sp.state.channels, key)
		}
	}
	return nil
}

// --- Anthropic Messages ------------------------------------------------------

func (sp *streamProcessor) handleClaude(doc *eventDoc) (pre []synthEvent, walk bool) {
	kind, _ := stringAt(doc.root, "type")
	flush := func(key string) {
		tail, channel := sp.drain(key)
		if tail == "" || channel == nil {
			return
		}
		field := "text"
		if channel.kind == "input_json_delta" {
			field = "partial_json"
		}
		if encoded, err := encodeJSONValue(map[string]any{
			"type":  "content_block_delta",
			"index": channel.slot,
			"delta": map[string]any{"type": channel.kind, field: tail},
		}); err == nil {
			pre = append(pre, synthEvent{name: "content_block_delta", payload: encoded})
		}
	}
	switch kind {
	case "content_block_delta":
		index, _ := intAt(doc.root, "index")
		delta := objectAt(doc.root, "delta")
		deltaKind, _ := stringAt(delta, "type")
		field, jsonMode := "", false
		switch deltaKind {
		case "text_delta":
			field = "text"
		case "input_json_delta":
			field, jsonMode = "partial_json", true
		default:
			// thinking_delta, signature_delta and unknown deltas stay untouched.
			return nil, false
		}
		text, ok := stringAt(delta, field)
		if !ok {
			return nil, false
		}
		out, channel := sp.feed("c:"+strconv.Itoa(index), jsonMode, text, false)
		channel.kind, channel.slot = deltaKind, index
		doc.set(payload.Path{payload.Key("delta"), payload.Key(field)}, delta, field, text, out)
		return nil, false
	case "content_block_stop":
		index, _ := intAt(doc.root, "index")
		flush("c:" + strconv.Itoa(index))
		return pre, false
	case "message_delta", "message_stop", "error":
		for _, key := range sp.keys(nil) {
			flush(key)
		}
		return pre, true
	default:
		return nil, true
	}
}

// --- OpenAI Responses --------------------------------------------------------

func (sp *streamProcessor) handleResponses(doc *eventDoc) (pre []synthEvent, walk bool) {
	kind, _ := stringAt(doc.root, "type")
	itemID, _ := stringAt(doc.root, "item_id")
	outputIndex, hasOutputIndex := intAt(doc.root, "output_index")
	if !hasOutputIndex {
		outputIndex = -1
	}
	item := itemID
	if item == "" {
		item = "#" + strconv.Itoa(outputIndex)
	}
	contentIndex, _ := intAt(doc.root, "content_index")
	textKey := "r:t:" + item + ":" + strconv.Itoa(contentIndex)
	argumentsKey := "r:a:" + item
	inputKey := "r:i:" + item

	flush := func(key string) {
		tail, channel := sp.drain(key)
		if tail == "" || channel == nil || channel.template == nil {
			return
		}
		synthetic := make(map[string]any, len(channel.template)+1)
		for name, value := range channel.template {
			synthetic[name] = value
		}
		synthetic["delta"] = tail
		if encoded, err := encodeJSONValue(synthetic); err == nil {
			pre = append(pre, synthEvent{name: channel.kind, payload: encoded})
		}
	}
	feedDelta := func(key string, jsonMode bool) {
		text, ok := stringAt(doc.root, "delta")
		if !ok {
			return
		}
		out, channel := sp.feed(key, jsonMode, text, false)
		channel.kind, channel.group, channel.slot = kind, itemID, outputIndex
		template := make(map[string]any, len(doc.root))
		for name, value := range doc.root {
			if name != "delta" {
				template[name] = value
			}
		}
		channel.template = template
		doc.set(payload.Path{payload.Key("delta")}, doc.root, "delta", text, out)
	}

	switch kind {
	case "response.output_text.delta":
		feedDelta(textKey, false)
		return nil, false
	case "response.function_call_arguments.delta", "response.mcp_call_arguments.delta":
		feedDelta(argumentsKey, true)
		return nil, false
	case "response.custom_tool_call_input.delta":
		feedDelta(inputKey, false)
		return nil, false
	case "response.output_text.done", "response.content_part.done":
		flush(textKey)
		return pre, true
	case "response.function_call_arguments.done", "response.mcp_call_arguments.done":
		flush(argumentsKey)
		return pre, true
	case "response.custom_tool_call_input.done":
		flush(inputKey)
		return pre, true
	case "response.output_item.done":
		doneID, _ := stringAt(objectAt(doc.root, "item"), "id")
		for _, key := range sp.keys(func(_ string, channel *streamChannel) bool {
			return (doneID != "" && channel.group == doneID) || (hasOutputIndex && channel.slot == outputIndex)
		}) {
			flush(key)
		}
		return pre, true
	case "response.completed", "response.incomplete", "response.failed", "error":
		for _, key := range sp.keys(nil) {
			flush(key)
		}
		return pre, true
	}
	if strings.HasSuffix(kind, ".delta") {
		// Reasoning, refusal, audio and other deltas are not reassembled.
		return nil, false
	}
	return nil, true
}

// --- Gemini GenerateContent --------------------------------------------------

// geminiTextPartPath matches candidates[].content.parts[].text.
func geminiTextPartPath(path payload.Path) bool {
	if len(path) < 3 {
		return false
	}
	last, _ := path[len(path)-1].KeyValue()
	parent, _ := path[len(path)-3].KeyValue()
	_, indexed := path[len(path)-2].IndexValue()
	return last == "text" && parent == "parts" && indexed
}

// handleGemini reassembles the plain text parts of each candidate. A withheld
// tail is merged into the chunk that carries finishReason, or placed ahead of
// a chunk that carries only non-text parts.
func (sp *streamProcessor) handleGemini(doc *eventDoc) {
	root := doc.root
	var base payload.Path
	if inner := objectAt(root, "response"); inner != nil && root["candidates"] == nil {
		root = inner
		base = payload.Path{payload.Key("response")}
	}
	for position, rawCandidate := range arrayAt(root, "candidates") {
		candidate, ok := rawCandidate.(map[string]any)
		if !ok {
			continue
		}
		index := position
		if value, ok := intAt(candidate, "index"); ok {
			index = value
		}
		reason, _ := stringAt(candidate, "finishReason")
		finished := reason != ""
		key := "g:" + strconv.Itoa(index)
		content := objectAt(candidate, "content")
		parts := arrayAt(content, "parts")

		lastText := -1
		for partPosition, rawPart := range parts {
			if _, ok := geminiPlainText(rawPart); ok {
				lastText = partPosition
			}
		}
		for partPosition, rawPart := range parts {
			text, ok := geminiPlainText(rawPart)
			if !ok {
				continue
			}
			part := rawPart.(map[string]any)
			out, _ := sp.feed(key, false, text, finished && partPosition == lastText)
			path := append(base.Clone(),
				payload.Key("candidates"), payload.Index(position), payload.Key("content"),
				payload.Key("parts"), payload.Index(partPosition), payload.Key("text"))
			doc.set(path, part, "text", text, out)
		}
		if lastText >= 0 || (!finished && len(parts) == 0) {
			continue
		}
		tail, _ := sp.drain(key)
		if tail == "" {
			continue
		}
		if content == nil {
			content = map[string]any{"role": "model"}
			candidate["content"] = content
		}
		content["parts"] = append([]any{map[string]any{"text": tail}}, parts...)
		doc.structural = true
	}
}

func geminiPlainText(rawPart any) (string, bool) {
	part, ok := rawPart.(map[string]any)
	if !ok {
		return "", false
	}
	if thought, _ := part["thought"].(bool); thought {
		return "", false
	}
	return stringAt(part, "text")
}

// --- Interactions ------------------------------------------------------------

func (sp *streamProcessor) handleInteractions(doc *eventDoc) (pre []synthEvent, walk bool) {
	kind, _ := stringAt(doc.root, "event_type")
	flush := func(key string) {
		tail, channel := sp.drain(key)
		if tail == "" || channel == nil {
			return
		}
		field := "text"
		if channel.kind == "arguments_delta" {
			field = "arguments"
		}
		if encoded, err := encodeJSONValue(map[string]any{
			"index":      channel.slot,
			"delta":      map[string]any{"type": channel.kind, field: tail},
			"event_type": "step.delta",
		}); err == nil {
			pre = append(pre, synthEvent{name: "step.delta", payload: encoded})
		}
	}
	switch kind {
	case "step.delta":
		index, _ := intAt(doc.root, "index")
		delta := objectAt(doc.root, "delta")
		deltaKind, _ := stringAt(delta, "type")
		field, jsonMode := "", false
		switch deltaKind {
		case "text":
			field = "text"
		case "arguments_delta":
			field, jsonMode = "arguments", true
		default:
			return nil, true
		}
		text, ok := stringAt(delta, field)
		if !ok {
			return nil, true
		}
		out, channel := sp.feed("i:"+strconv.Itoa(index), jsonMode, text, false)
		channel.kind, channel.slot = deltaKind, index
		doc.set(payload.Path{payload.Key("delta"), payload.Key(field)}, delta, field, text, out)
		return nil, false
	case "step.stop":
		index, _ := intAt(doc.root, "index")
		flush("i:" + strconv.Itoa(index))
		return pre, false
	case "interaction.completed", "interaction.complete", "interaction.failed", "finish", "error":
		for _, key := range sp.keys(nil) {
			flush(key)
		}
		return pre, true
	default:
		return nil, true
	}
}

// --- event document ----------------------------------------------------------

type eventEdit struct {
	path  payload.Path
	value string
}

// eventDoc is one decoded stream event plus the changes to apply to it.
// String replacements are spliced into the original bytes; only a structural
// change (a merged tail) re-encodes the event.
type eventDoc struct {
	raw        []byte
	root       map[string]any
	edits      []eventEdit
	structural bool
}

func parseEventDoc(raw []byte) (*eventDoc, bool) {
	value, ok := decodeJSONValue(raw)
	if !ok {
		return nil, false
	}
	root, ok := value.(map[string]any)
	if !ok {
		return nil, false
	}
	return &eventDoc{raw: raw, root: root}, true
}

// set records that container[key], found at path, changes from before to after.
func (d *eventDoc) set(path payload.Path, container map[string]any, key, before, after string) {
	if before == after {
		return
	}
	container[key] = after
	d.edits = append(d.edits, eventEdit{path: path, value: after})
}

// render returns the event bytes with every change applied. ok is false when
// the changes could not be applied and the original bytes are returned.
func (d *eventDoc) render(ctx context.Context, limits payload.Limits) (out []byte, ok bool) {
	if !d.structural && len(d.edits) == 0 {
		return d.raw, true
	}
	if !d.structural {
		if spliced, applied := d.splice(ctx, limits); applied {
			return spliced, true
		}
	}
	encoded, err := encodeJSONValue(d.root)
	if err != nil {
		return d.raw, false
	}
	return encoded, true
}

func (d *eventDoc) splice(ctx context.Context, limits payload.Limits) ([]byte, bool) {
	document, err := payload.Scan(ctx, d.raw, payload.ScanOptions{Limits: limits})
	if err != nil {
		return nil, false
	}
	replacements := make([]payload.Replacement, 0, len(d.edits))
	for _, edit := range d.edits {
		token, err := document.StringAt(edit.path)
		if err != nil {
			return nil, false
		}
		replacements = append(replacements, payload.Replacement{Token: token, Value: edit.value})
	}
	out, _, err := document.Replace(ctx, replacements)
	if err != nil {
		return nil, false
	}
	return out, true
}

func objectAt(container map[string]any, key string) map[string]any {
	object, _ := container[key].(map[string]any)
	return object
}

func arrayAt(container map[string]any, key string) []any {
	array, _ := container[key].([]any)
	return array
}

func stringAt(container map[string]any, key string) (string, bool) {
	text, ok := container[key].(string)
	return text, ok
}

func intAt(container map[string]any, key string) (int, bool) {
	number, ok := container[key].(json.Number)
	if !ok {
		return 0, false
	}
	value, err := strconv.Atoi(number.String())
	if err != nil {
		return 0, false
	}
	return value, true
}
