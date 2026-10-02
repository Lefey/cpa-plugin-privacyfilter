package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
)

// restorer turns tokens back into their original values for one response. It
// reads a single vault partition, so a token issued to another caller (or, in
// request scope, to another request) is never resolved.
type restorer struct {
	codec     *tokenCodec
	vault     *tokenVault
	partition string
	limits    payload.Limits
	counters  *restoreCounters
}

// resolve returns the value for an exact token. A token-shaped run with no
// mapping in this partition is counted and left as it is; a damaged token
// (wrong case, truncated) never reaches this point because it does not match.
func (r *restorer) resolve(token string) (string, bool) {
	value, ok := r.vault.get(r.partition, token)
	if !ok {
		r.counters.unresolved++
		return "", false
	}
	r.counters.restored++
	return value, true
}

// text restores every token in a complete piece of text.
func (r *restorer) text(text string) (string, bool) {
	var out strings.Builder
	changed := false
	previous := 0
	for offset := 0; offset < len(text); {
		length, ok := r.codec.matchAt(text, offset)
		if !ok {
			offset++
			continue
		}
		if value, found := r.resolve(text[offset : offset+length]); found {
			out.WriteString(text[previous:offset])
			out.WriteString(value)
			previous = offset + length
			changed = true
		}
		offset += length
	}
	if !changed {
		return text, false
	}
	out.WriteString(text[previous:])
	return out.String(), true
}

// value restores one decoded JSON string. A string that itself carries a JSON
// document (tool-call arguments, structured output) is restored one level
// down, so the value is escaped for the inner string it lands in and then
// again, by the caller's encoder, for the outer one.
func (r *restorer) value(ctx context.Context, text string, nesting int) (string, bool) {
	if nesting < maxEncodedJSONNesting && looksLikeEncodedJSONContainer(text) {
		if out, changed, err := r.document(ctx, []byte(text), nil, nesting+1); err == nil {
			if !changed {
				return text, false
			}
			return string(out), true
		}
	}
	return r.text(text)
}

// document restores tokens inside the string values of one JSON document and
// leaves every other byte untouched. Object keys are never rewritten. skip
// excludes values by path; reasoning and integrity fields are always excluded
// at the top level because rewriting signed model reasoning breaks its replay.
func (r *restorer) document(ctx context.Context, body []byte, skip func(payload.Path) bool, nesting int) ([]byte, bool, error) {
	if !r.codec.containsBytes(body) {
		return body, false, nil
	}
	document, err := payload.Scan(ctx, body, payload.ScanOptions{Limits: r.limits})
	if err != nil {
		return body, false, err
	}
	var protected []payload.Path
	protectedReady := nesting != 0
	var replacements []payload.Replacement
	for index := 0; index < document.StringCount(); index++ {
		metadata, ok := document.StringMetadataAt(index)
		if !ok || !r.codec.contains(metadata.Value) {
			continue
		}
		if err := ctx.Err(); err != nil {
			return body, false, err
		}
		token, ok := document.StringTokenAt(index)
		if !ok {
			continue
		}
		if !protectedReady {
			protected = protectedPaths(body)
			protectedReady = true
		}
		if pathProtected(token.Path, protected) || (skip != nil && skip(token.Path)) {
			continue
		}
		if restored, changed := r.value(ctx, token.Value, nesting); changed {
			replacements = append(replacements, payload.Replacement{Token: token, Value: restored})
		}
	}
	if len(replacements) == 0 {
		return body, false, nil
	}
	out, changed, err := document.Replace(ctx, replacements)
	if err != nil {
		return body, false, err
	}
	return out, changed, nil
}

func pathProtected(path payload.Path, protected []payload.Path) bool {
	for _, prefix := range protected {
		if path.HasPrefix(prefix) {
			return true
		}
	}
	return false
}

// protectedPaths lists the subtrees that hold model reasoning or integrity
// data. A decoding failure protects nothing: the scanner already validated the
// body, and an unprotected value is restored, not leaked.
func protectedPaths(body []byte) []payload.Path {
	root, ok := decodeJSONValue(body)
	if !ok {
		return nil
	}
	var protected []payload.Path
	var walk func(value any, path payload.Path)
	walk = func(value any, path payload.Path) {
		switch typed := value.(type) {
		case map[string]any:
			if isReasoningObject(typed) {
				protected = append(protected, path.Clone())
				return
			}
			for key, child := range typed {
				next := append(path.Clone(), payload.Key(key))
				if isProtectedKey(key) {
					protected = append(protected, next)
					continue
				}
				walk(child, next)
			}
		case []any:
			for index, child := range typed {
				walk(child, append(path.Clone(), payload.Index(index)))
			}
		}
	}
	walk(root, nil)
	return protected
}

func isProtectedKey(key string) bool {
	switch key {
	case "signature", "encrypted_content", "thinking", "reasoning", "reasoning_content",
		"reasoning_details", "thought_signature", "thoughtSignature":
		return true
	default:
		return false
	}
}

func isReasoningObject(object map[string]any) bool {
	if thought, ok := object["thought"].(bool); ok && thought {
		return true
	}
	kind, _ := object["type"].(string)
	switch kind {
	case "thinking", "redacted_thinking", "reasoning", "thought", "thought_summary", "thought_signature":
		return true
	}
	return strings.HasPrefix(kind, "response.reasoning")
}

// decodeJSONValue decodes one JSON value, keeping numbers as their literals.
func decodeJSONValue(body []byte) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	return value, true
}

// encodeJSONValue is json.Marshal without HTML escaping, so restored text is
// not rewritten beyond what JSON requires.
func encodeJSONValue(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buffer.Bytes(), "\n"), nil
}

// jsonStringContent returns text escaped for placement inside a JSON string
// literal, without the surrounding quotes.
func jsonStringContent(text string) string {
	encoded, err := encodeJSONValue(text)
	if err != nil || len(encoded) < 2 {
		return ""
	}
	return string(encoded[1 : len(encoded)-1])
}
