package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ahoo/cpa-plugin-privacyfilter/internal/privacyengine"
)

func TestParseConfigTokenize(t *testing.T) {
	cfg, err := parseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != modeRedact {
		t.Fatalf("default mode = %q, want redact", cfg.Mode)
	}
	if cfg.Tokenize.TokenFormat != "pf-{kind}-{hash12}" || cfg.Tokenize.MaxEntries != 100000 ||
		cfg.Tokenize.TTL != time.Hour || cfg.Tokenize.RestoreScope != restoreScopeCaller || cfg.Tokenize.HMACSecret != "" {
		t.Fatalf("tokenize defaults = %+v", cfg.Tokenize)
	}

	cfg, err = parseConfig([]byte(`
mode: tokenize
tokenize:
  token_format: "tok-{hash16}-{kind}"
  hmac_secret: "0123456789abcdef0123"
  max_entries: 500
  ttl: 90m
  restore_scope: request
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != modeTokenize || cfg.Tokenize.MaxEntries != 500 || cfg.Tokenize.TTL != 90*time.Minute ||
		cfg.Tokenize.RestoreScope != restoreScopeRequest || cfg.Tokenize.TokenFormat != "tok-{hash16}-{kind}" {
		t.Fatalf("tokenize config = %+v", cfg.Tokenize)
	}

	invalid := []string{
		"mode: reversible\n",
		"tokenize:\n  token_format: ''\n",
		"tokenize:\n  token_format: 'pf-{kind}'\n",
		"tokenize:\n  token_format: '{hash12}'\n",
		"tokenize:\n  token_format: 'PF-{kind}-{hash12}'\n",
		"tokenize:\n  token_format: 'pf_{kind}_{hash12}'\n",
		"tokenize:\n  token_format: 'pf-{kind}-{hash12}\"'\n",
		"tokenize:\n  token_format: 'pf-{kind}-{hash4}'\n",
		"tokenize:\n  token_format: 'pf-{kind}-{hash65}'\n",
		"tokenize:\n  token_format: 'pf-{kind}-{hash012}'\n",
		"tokenize:\n  token_format: 'pf-{kind}-{hash}'\n",
		"tokenize:\n  token_format: 'pf-{kind}-{hash12}-{hash12}'\n",
		"tokenize:\n  token_format: 'pf-{kind}-{kind}-{hash12}'\n",
		"tokenize:\n  token_format: 'pf-{type}-{hash12}'\n",
		"tokenize:\n  token_format: 'pf-{kind-{hash12}'\n",
		"tokenize:\n  hmac_secret: short\n",
		"tokenize:\n  max_entries: 0\n",
		"tokenize:\n  max_entries: -5\n",
		"tokenize:\n  max_entries: 1000001\n",
		"tokenize:\n  ttl: 0s\n",
		"tokenize:\n  ttl: 500ms\n",
		"tokenize:\n  ttl: 169h\n",
		"tokenize:\n  ttl: soon\n",
		"tokenize:\n  restore_scope: global\n",
		"tokenize:\n  restore_scope: ''\n",
		"tokenize:\n  ttl: 1h\n  ttl: 2h\n",
		"tokenize:\n  secret: x\n",
	}
	for index, raw := range invalid {
		if _, err := parseConfig([]byte(raw)); err == nil {
			t.Errorf("parseConfig accepted invalid tokenize config index=%d", index)
		}
	}
}

func TestTokenizeErrorNeverEchoesSecret(t *testing.T) {
	_, err := parseConfig([]byte("tokenize:\n  hmac_secret: tooshort-x\n"))
	if err == nil || strings.Contains(err.Error(), "tooshort-x") {
		t.Fatalf("hmac_secret error missing or echoing the secret: %v", err != nil)
	}
}

func TestTokenCodecDeterminismAndSeparation(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	codec, err := newTokenCodec(defaultTokenFormat, key)
	if err != nil {
		t.Fatal(err)
	}
	mint := func(c *tokenCodec, namespace string, kind privacyengine.Kind, value string) string {
		t.Helper()
		token, ok := c.mint(namespace, kind, value)
		if !ok {
			t.Fatalf("mint failed for kind %q", kind)
		}
		return token
	}

	first := mint(codec, "caller-a", privacyengine.KindSecret, "value-one")
	if again := mint(codec, "caller-a", privacyengine.KindSecret, "value-one"); again != first {
		t.Fatal("the same value produced two different tokens")
	}
	if !regexp.MustCompile(`^pf-secret-[0-9a-f]{12}$`).MatchString(first) {
		t.Fatalf("token has an unexpected shape: len=%d", len(first))
	}
	if other := mint(codec, "caller-a", privacyengine.KindSecret, "value-two"); other == first {
		t.Fatal("two values of one kind share a token")
	}
	if other := mint(codec, "caller-b", privacyengine.KindSecret, "value-one"); other == first {
		t.Fatal("two callers share a token for the same value")
	}
	if other := mint(codec, "caller-a", privacyengine.KindEmail, "value-one"); strings.TrimPrefix(other, "pf-email-") == strings.TrimPrefix(first, "pf-secret-") {
		t.Fatal("two kinds share a digest for the same value")
	}

	// A second codec with the same key agrees (stable across reconfigure);
	// a different key does not (tokens change with the secret).
	same, err := newTokenCodec(defaultTokenFormat, key)
	if err != nil {
		t.Fatal(err)
	}
	if mint(same, "caller-a", privacyengine.KindSecret, "value-one") != first {
		t.Fatal("token is not stable for a fixed key")
	}
	different, err := newTokenCodec(defaultTokenFormat, []byte("another-key-another-key-another!"))
	if err != nil {
		t.Fatal(err)
	}
	if mint(different, "caller-a", privacyengine.KindSecret, "value-one") == first {
		t.Fatal("token did not change with the key")
	}

	// Every kind has a distinct, JSON-safe spelling.
	seen := make(map[string]bool)
	for _, entry := range tokenKindNames {
		token := mint(codec, "", entry.kind, "v")
		if seen[token] || !regexp.MustCompile(`^[a-z0-9-]+$`).MatchString(token) {
			t.Fatalf("kind %q token is duplicated or not [a-z0-9-]", entry.kind)
		}
		seen[token] = true
		encoded, _ := json.Marshal(token)
		if string(encoded) != `"`+token+`"` {
			t.Fatalf("kind %q token needs JSON escaping", entry.kind)
		}
	}
}

func TestTokenCodecMatching(t *testing.T) {
	codec, err := newTokenCodec(defaultTokenFormat, []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	token, _ := codec.mint("", privacyengine.KindSecret, "value")
	text := "before " + token + " after"
	if length, ok := codec.matchAt(text, len("before ")); !ok || length != len(token) {
		t.Fatalf("token not matched in place: ok=%t length=%d", ok, length)
	}
	if !codec.contains(text) || !codec.containsBytes([]byte(text)) {
		t.Fatal("contains missed a token")
	}
	for _, damaged := range []string{
		strings.ToUpper(token),
		token[:len(token)-1],
		strings.Replace(token, "pf-", "pf_", 1),
		strings.Replace(token, "secret", "Secret", 1),
		token[:len(token)-1] + "g",
		"pf-unknown-0123456789ab",
	} {
		if codec.contains(damaged) {
			t.Fatalf("damaged token of length %d was accepted", len(damaged))
		}
	}
	for cut := 1; cut < len(token); cut++ {
		if !codec.isProperPrefix(token[:cut]) {
			t.Fatalf("prefix of length %d is not recognised as incomplete", cut)
		}
	}
	if codec.isProperPrefix(token) || codec.isProperPrefix("") || codec.isProperPrefix("px") || codec.isProperPrefix("pf-secret-zz") {
		t.Fatal("isProperPrefix accepted a complete token or a non-prefix")
	}

	// A format without {kind} and with a suffix still round-trips.
	custom, err := newTokenCodec("{hash8}-x", []byte("0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	customToken, _ := custom.mint("", privacyengine.KindEmail, "value")
	if length, ok := custom.matchAt(customToken, 0); !ok || length != len("00000000-x") {
		t.Fatalf("custom format token did not match: ok=%t length=%d", ok, length)
	}
	phoneToken, _ := custom.mint("", privacyengine.KindPhone, "value")
	if phoneToken == customToken {
		t.Fatal("kinds collide when the format has no {kind}")
	}
}

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func TestTokenVaultIsolationAndLifecycle(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	vault := newTokenVault(100, time.Minute, clock.Now)

	if got := vault.put("part-a", "tok-1", "value-a"); got != tokenPutStored {
		t.Fatalf("first put = %d", got)
	}
	if got := vault.put("part-a", "tok-1", "value-a"); got != tokenPutRefreshed {
		t.Fatalf("repeated put = %d", got)
	}
	if got := vault.put("part-a", "tok-1", "other"); got != tokenPutCollision {
		t.Fatalf("colliding put = %d", got)
	}
	if value, ok := vault.get("part-a", "tok-1"); !ok || value != "value-a" {
		t.Fatal("collision overwrote the original mapping")
	}
	// The same token string in another partition is unrelated.
	if _, ok := vault.get("part-b", "tok-1"); ok {
		t.Fatal("a token resolved in a partition that never issued it")
	}
	if got := vault.put("part-b", "tok-1", "value-b"); got != tokenPutStored {
		t.Fatalf("put into second partition = %d", got)
	}
	if value, _ := vault.get("part-a", "tok-1"); value != "value-a" {
		t.Fatal("second partition changed the first")
	}
	if vault.put("", "tok", "v") != tokenPutRejected || vault.put("p", "", "v") != tokenPutRejected {
		t.Fatal("empty partition or token was accepted")
	}

	if removed := vault.dropPartition("part-a"); removed != 1 {
		t.Fatalf("dropPartition removed %d", removed)
	}
	if _, ok := vault.get("part-a", "tok-1"); ok || vault.has("part-a") {
		t.Fatal("dropped partition still resolves")
	}
	if !vault.has("part-b") || vault.stats().Entries != 1 {
		t.Fatalf("unrelated partition was affected: %+v", vault.stats())
	}
	if vault.clear() != 1 || vault.stats().Entries != 0 || vault.stats().Partitions != 0 {
		t.Fatal("clear left entries behind")
	}
}

func TestTokenVaultTTL(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	vault := newTokenVault(100, time.Minute, clock.Now)
	vault.put("p", "old", "v1")
	clock.Advance(40 * time.Second)
	vault.put("p", "new", "v2")

	// A restore refreshes the sliding TTL.
	if _, ok := vault.get("p", "old"); !ok {
		t.Fatal("live token did not resolve")
	}
	clock.Advance(40 * time.Second)
	if _, ok := vault.get("p", "old"); !ok {
		t.Fatal("token expired although it was used 40s ago")
	}
	// "new" was never used again: 70s after it was issued it is gone, while
	// "old", used 30s ago, is still live.
	clock.Advance(30 * time.Second)
	if _, ok := vault.peek("p", "old"); !ok {
		t.Fatal("recently used token expired")
	}
	if _, ok := vault.get("p", "new"); ok {
		t.Fatal("token outlived its TTL")
	}
	clock.Advance(time.Minute)
	if vault.has("p") || vault.stats().Entries != 0 {
		t.Fatalf("expired entries were retained: %+v", vault.stats())
	}
	if vault.stats().Expirations != 2 {
		t.Fatalf("expirations = %d, want 2", vault.stats().Expirations)
	}
	// peek must not keep a token alive.
	vault.put("p", "peeked", "v")
	clock.Advance(40 * time.Second)
	if _, ok := vault.peek("p", "peeked"); !ok {
		t.Fatal("peek missed a live token")
	}
	clock.Advance(40 * time.Second)
	if _, ok := vault.peek("p", "peeked"); ok {
		t.Fatal("peek extended the TTL")
	}
}

func TestTokenVaultMaxEntries(t *testing.T) {
	clock := &fakeClock{now: time.Unix(1_700_000_000, 0)}
	vault := newTokenVault(3, time.Hour, clock.Now)
	for _, token := range []string{"t1", "t2", "t3"} {
		vault.put("p", token, "v-"+token)
		clock.Advance(time.Second)
	}
	// Touch t1 so t2 is now the least recently used.
	if _, ok := vault.get("p", "t1"); !ok {
		t.Fatal("t1 missing before overflow")
	}
	vault.put("q", "t4", "v-t4")
	if stats := vault.stats(); stats.Entries != 3 || stats.Evictions != 1 {
		t.Fatalf("overflow stats = %+v", stats)
	}
	if _, ok := vault.get("p", "t2"); ok {
		t.Fatal("least recently used token survived the overflow")
	}
	for _, probe := range [][2]string{{"p", "t1"}, {"p", "t3"}, {"q", "t4"}} {
		if _, ok := vault.get(probe[0], probe[1]); !ok {
			t.Fatalf("token %s/%s was evicted instead of the oldest", probe[0], probe[1])
		}
	}
	// Shrinking through reconfigure evicts immediately.
	vault.configure(1, time.Hour)
	if stats := vault.stats(); stats.Entries != 1 || stats.MaxEntries != 1 {
		t.Fatalf("shrunk vault stats = %+v", stats)
	}
}
