package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ahoo/cpa-plugin-privacyfilter/internal/privacyengine"
)

type restoreScope string

const (
	// restoreScopeCaller restores tokens issued to the same downstream API key.
	restoreScopeCaller restoreScope = "caller"
	// restoreScopeRequest restores only tokens issued for the same request.
	restoreScopeRequest restoreScope = "request"
)

const (
	defaultTokenFormat      = "pf-{kind}-{hash12}"
	defaultTokenMaxEntries  = 100_000
	defaultTokenTTL         = time.Hour
	hardMaxTokenEntries     = 1_000_000
	minTokenTTL             = time.Second
	hardMaxTokenTTL         = 7 * 24 * time.Hour
	minTokenHashLen         = 8
	maxTokenHashLen         = sha256.Size * 2
	minHMACSecretBytes      = 16
	maxHMACSecretBytes      = 1024
	maxTokenFormatBytes     = 64
	tokenFormatKindVariable = "kind"
	tokenFormatHashVariable = "hash"
)

// tokenizeConfig mirrors the tokenize mapping. It is validated even when mode
// is not tokenize, so a typo cannot hide until the mode is switched on.
type tokenizeConfig struct {
	TokenFormat  string        `yaml:"token_format"`
	HMACSecret   string        `yaml:"hmac_secret"`
	MaxEntries   int           `yaml:"max_entries"`
	TTL          time.Duration `yaml:"ttl"`
	RestoreScope restoreScope  `yaml:"restore_scope"`
}

func defaultTokenizeConfig() tokenizeConfig {
	return tokenizeConfig{
		TokenFormat:  defaultTokenFormat,
		MaxEntries:   defaultTokenMaxEntries,
		TTL:          defaultTokenTTL,
		RestoreScope: restoreScopeCaller,
	}
}

func (cfg tokenizeConfig) validate() error {
	if _, err := parseTokenFormat(cfg.TokenFormat); err != nil {
		return fmt.Errorf("invalid privacyfilter config: tokenize.token_format %w", err)
	}
	if secret := len(cfg.HMACSecret); secret != 0 && (secret < minHMACSecretBytes || secret > maxHMACSecretBytes) {
		return fmt.Errorf("invalid privacyfilter config: tokenize.hmac_secret must be empty or %d to %d bytes", minHMACSecretBytes, maxHMACSecretBytes)
	}
	if cfg.MaxEntries <= 0 || cfg.MaxEntries > hardMaxTokenEntries {
		return fmt.Errorf("invalid privacyfilter config: tokenize.max_entries must be within [1,%d]", hardMaxTokenEntries)
	}
	if cfg.TTL < minTokenTTL || cfg.TTL > hardMaxTokenTTL {
		return fmt.Errorf("invalid privacyfilter config: tokenize.ttl must be within [%s,%s]", minTokenTTL, hardMaxTokenTTL)
	}
	switch cfg.RestoreScope {
	case restoreScopeCaller, restoreScopeRequest:
	default:
		return fmt.Errorf("invalid privacyfilter config: tokenize.restore_scope must be %q or %q", restoreScopeCaller, restoreScopeRequest)
	}
	return nil
}

// tokenKindNames are the {kind} spellings. They use only [a-z0-9] so a token
// never needs JSON escaping, and none is a prefix of another so two templates
// cannot match at the same offset.
var tokenKindNames = []struct {
	kind privacyengine.Kind
	name string
}{
	{privacyengine.KindEmail, "email"},
	{privacyengine.KindPhone, "phone"},
	{privacyengine.KindIDCard, "idcard"},
	{privacyengine.KindBankCard, "bankcard"},
	{privacyengine.KindIP, "ip"},
	{privacyengine.KindSecret, "secret"},
}

// tokenTemplate is one fixed-length token shape: prefix, hashLen lowercase
// hexadecimal characters, suffix.
type tokenTemplate struct {
	kind    privacyengine.Kind
	name    string
	prefix  string
	suffix  string
	hashLen int
}

func (t tokenTemplate) length() int { return len(t.prefix) + t.hashLen + len(t.suffix) }

// templateMatches reports whether text agrees with the template on every
// position both have. A text longer than the template only needs to start
// with it.
func templateMatches[T ~string | ~[]byte](t *tokenTemplate, text T) bool {
	limit := min(len(text), t.length())
	hashStart := len(t.prefix)
	hashEnd := hashStart + t.hashLen
	for index := 0; index < limit; index++ {
		c := text[index]
		switch {
		case index < hashStart:
			if c != t.prefix[index] {
				return false
			}
		case index < hashEnd:
			if !isLowerHex(c) {
				return false
			}
		default:
			if c != t.suffix[index-hashEnd] {
				return false
			}
		}
	}
	return true
}

func isLowerHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
}

type tokenFormatPart struct {
	literal string
	kind    bool
	hashLen int
}

// parseTokenFormat validates a token_format template. The result is the list
// of literal, {kind} and {hashN} parts in order.
func parseTokenFormat(format string) ([]tokenFormatPart, error) {
	if format == "" || len(format) > maxTokenFormatBytes {
		return nil, fmt.Errorf("must be 1 to %d bytes", maxTokenFormatBytes)
	}
	var parts []tokenFormatPart
	var literal strings.Builder
	flush := func() {
		if literal.Len() != 0 {
			parts = append(parts, tokenFormatPart{literal: literal.String()})
			literal.Reset()
		}
	}
	kinds, hashes := 0, 0
	for index := 0; index < len(format); {
		c := format[index]
		switch {
		case c == '{':
			end := strings.IndexByte(format[index:], '}')
			if end < 0 {
				return nil, fmt.Errorf("has an unterminated placeholder")
			}
			name := format[index+1 : index+end]
			index += end + 1
			flush()
			switch {
			case name == tokenFormatKindVariable:
				kinds++
				parts = append(parts, tokenFormatPart{kind: true})
			case strings.HasPrefix(name, tokenFormatHashVariable):
				digits := name[len(tokenFormatHashVariable):]
				length, err := strconv.Atoi(digits)
				if err != nil || strconv.Itoa(length) != digits || length < minTokenHashLen || length > maxTokenHashLen {
					return nil, fmt.Errorf("needs {hashN} with N within [%d,%d]", minTokenHashLen, maxTokenHashLen)
				}
				hashes++
				parts = append(parts, tokenFormatPart{hashLen: length})
			default:
				return nil, fmt.Errorf("supports only the {kind} and {hashN} placeholders")
			}
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-':
			literal.WriteByte(c)
			index++
		default:
			return nil, fmt.Errorf("may contain only [a-z0-9-] outside placeholders")
		}
	}
	flush()
	if hashes != 1 {
		return nil, fmt.Errorf("needs exactly one {hashN} placeholder")
	}
	if kinds > 1 {
		return nil, fmt.Errorf("allows at most one {kind} placeholder")
	}
	if len(parts) == 1 {
		// A bare hexadecimal run would match ordinary hashes and identifiers.
		return nil, fmt.Errorf("needs a literal or {kind} part next to {hashN}")
	}
	return parts, nil
}

// tokenCodec mints deterministic tokens and recognises them in text. It is
// immutable after construction and safe for concurrent use.
type tokenCodec struct {
	key       []byte
	templates []tokenTemplate
	byKind    map[privacyengine.Kind]int
	maxLen    int
	first     [256]bool
}

func newTokenCodec(format string, key []byte) (*tokenCodec, error) {
	parts, err := parseTokenFormat(format)
	if err != nil {
		return nil, fmt.Errorf("token_format %w", err)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("token HMAC key is empty")
	}
	hasKind := false
	for _, part := range parts {
		hasKind = hasKind || part.kind
	}
	codec := &tokenCodec{
		key:    append([]byte(nil), key...),
		byKind: make(map[privacyengine.Kind]int, len(tokenKindNames)),
	}
	build := func(kindName string) tokenTemplate {
		var template tokenTemplate
		var current *string = &template.prefix
		for _, part := range parts {
			switch {
			case part.hashLen != 0:
				template.hashLen = part.hashLen
				current = &template.suffix
			case part.kind:
				*current += kindName
			default:
				*current += part.literal
			}
		}
		return template
	}
	for _, entry := range tokenKindNames {
		if !hasKind {
			// One shared shape; the kind still separates values in the MAC.
			if len(codec.templates) == 0 {
				codec.templates = append(codec.templates, build(""))
			}
			codec.byKind[entry.kind] = 0
			continue
		}
		template := build(entry.name)
		template.kind = entry.kind
		template.name = entry.name
		codec.byKind[entry.kind] = len(codec.templates)
		codec.templates = append(codec.templates, template)
	}
	for _, template := range codec.templates {
		codec.maxLen = max(codec.maxLen, template.length())
		if template.prefix != "" {
			codec.first[template.prefix[0]] = true
			continue
		}
		for c := 0; c < 256; c++ {
			if isLowerHex(byte(c)) {
				codec.first[c] = true
			}
		}
	}
	return codec, nil
}

// mint derives the token for one value. namespace separates callers so the same
// value under two API keys yields unrelated tokens. The output is stable for
// the lifetime of the key.
func (c *tokenCodec) mint(namespace string, kind privacyengine.Kind, value string) (string, bool) {
	index, ok := c.byKind[kind]
	if !ok {
		return "", false
	}
	template := c.templates[index]
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte(namespace))
	mac.Write([]byte{0})
	mac.Write([]byte(kind))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	digest := hex.EncodeToString(mac.Sum(nil))
	return template.prefix + digest[:template.hashLen] + template.suffix, true
}

// tokenAt returns the length of the token starting at text[offset:].
func tokenAt[T ~string | ~[]byte](c *tokenCodec, text T, offset int) (int, bool) {
	if offset >= len(text) || !c.first[text[offset]] {
		return 0, false
	}
	rest := text[offset:]
	for index := range c.templates {
		template := &c.templates[index]
		if len(rest) >= template.length() && templateMatches(template, rest) {
			return template.length(), true
		}
	}
	return 0, false
}

func (c *tokenCodec) matchAt(text string, offset int) (int, bool) {
	return tokenAt(c, text, offset)
}

// isProperPrefix reports whether text is a strict prefix of some token, that
// is, whether more input could still complete it.
func (c *tokenCodec) isProperPrefix(text string) bool {
	if text == "" || !c.first[text[0]] {
		return false
	}
	for index := range c.templates {
		template := &c.templates[index]
		if len(text) < template.length() && templateMatches(template, text) {
			return true
		}
	}
	return false
}

// contains reports whether text holds at least one token-shaped run.
func (c *tokenCodec) contains(text string) bool {
	return tokenIn(c, text)
}

// containsBytes is contains for a raw body. Tokens need no JSON escaping, so
// they appear verbatim in encoded JSON.
func (c *tokenCodec) containsBytes(text []byte) bool {
	return tokenIn(c, text)
}

func tokenIn[T ~string | ~[]byte](c *tokenCodec, text T) bool {
	for offset := 0; offset < len(text); offset++ {
		if _, ok := tokenAt(c, text, offset); ok {
			return true
		}
	}
	return false
}

// newProcessTokenKey returns the per-process key used when hmac_secret is empty.
func newProcessTokenKey() ([]byte, error) {
	key := make([]byte, sha256.Size)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate token key: %w", err)
	}
	return key, nil
}
