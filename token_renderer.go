package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/ahoo/cpa-plugin-privacyfilter/internal/privacyengine"
)

// tokenStats are process-wide tokenize counters. Counters are the only
// tokenize facts that are ever logged.
type tokenStats struct {
	tokenized  atomic.Uint64
	restored   atomic.Uint64
	unresolved atomic.Uint64
	unflushed  atomic.Uint64
	failed     atomic.Uint64
	collisions atomic.Uint64
	untracked  atomic.Uint64
}

// tokenRuntime is the tokenize state that must outlive a reconfigure: issued
// mappings, in-flight response sessions, and the per-process HMAC key.
type tokenRuntime struct {
	vault      *tokenVault
	sessions   *restoreRegistry
	processKey []byte
	stats      tokenStats
}

func newTokenRuntime(cfg tokenizeConfig) (*tokenRuntime, error) {
	key, err := newProcessTokenKey()
	if err != nil {
		return nil, err
	}
	runtime := &tokenRuntime{processKey: key}
	runtime.vault = newTokenVault(cfg.MaxEntries, cfg.TTL, nil)
	runtime.sessions = newRestoreRegistry(maxRestoreSessions, cfg.TTL, nil, runtime.releaseSession)
	return runtime, nil
}

// releaseSession destroys what belonged to one request alone.
func (r *tokenRuntime) releaseSession(session *restoreSession) {
	if r == nil || session == nil {
		return
	}
	if session.requestScoped {
		r.vault.dropPartition(session.partition)
	}
}

func (r *tokenRuntime) clear() {
	if r == nil {
		return
	}
	r.sessions.clear()
	r.vault.clear()
}

// tokenizer is the tokenize policy of one configuration revision.
type tokenizer struct {
	codec    *tokenCodec
	scope    restoreScope
	vault    *tokenVault
	sessions *restoreRegistry
	stats    *tokenStats
}

func newTokenizer(cfg tokenizeConfig, runtime *tokenRuntime) (*tokenizer, error) {
	if runtime == nil {
		return nil, fmt.Errorf("privacyfilter: tokenize runtime is unavailable")
	}
	key := runtime.processKey
	if cfg.HMACSecret != "" {
		key = []byte(cfg.HMACSecret)
	}
	codec, err := newTokenCodec(cfg.TokenFormat, key)
	if err != nil {
		return nil, err
	}
	runtime.vault.configure(cfg.MaxEntries, cfg.TTL)
	runtime.sessions.configure(cfg.TTL)
	return &tokenizer{
		codec:    codec,
		scope:    cfg.RestoreScope,
		vault:    runtime.vault,
		sessions: runtime.sessions,
		stats:    &runtime.stats,
	}, nil
}

// sessionFor returns the restore session of a response. The RequestID alone
// identifies it; the caller check is defence in depth, so that a response
// carrying another caller's identity is never restored from this session.
func (t *tokenizer) sessionFor(requestID string, metadata map[string]any) *restoreSession {
	session := t.sessions.get(requestID)
	if session == nil {
		return nil
	}
	if caller := callerScopeFromMetadata(metadata); caller != "" && session.caller != "" && caller != session.caller {
		return nil
	}
	return session
}

// partitionFor selects the vault partition a request issues into and restores
// from. A caller partition needs an authenticated caller; without one the
// request falls back to its own partition, which is the narrower scope.
func (t *tokenizer) partitionFor(requestID, callerScope string) (partition string, requestScoped, ok bool) {
	if t.scope == restoreScopeCaller && callerScope != "" {
		return callerPartitionPrefix + callerScope, false, true
	}
	if requestID != "" {
		return requestPartitionPrefix + requestID, true, true
	}
	return "", false, false
}

// newRenderer returns the request renderer, or nil when the request cannot be
// tied to a partition and must be redacted irreversibly instead.
func (t *tokenizer) newRenderer(requestID, callerScope string, fallback privacyengine.Renderer) *tokenRenderer {
	partition, requestScoped, ok := t.partitionFor(requestID, callerScope)
	if !ok {
		t.stats.untracked.Add(1)
		return nil
	}
	return &tokenRenderer{
		tokenizer:     t,
		fallback:      fallback,
		requestID:     requestID,
		namespace:     callerScope,
		partition:     partition,
		requestScoped: requestScoped,
		pending:       make(map[string]string),
	}
}

// tokenRenderer replaces findings with reversible tokens for one request.
//
// Mappings are staged in pending and reach the vault only through commit, after
// the whole request passed inspection. A request rejected by block_rule_ids or
// by an inspection error therefore never leaves a mapping behind.
type tokenRenderer struct {
	tokenizer     *tokenizer
	fallback      privacyengine.Renderer
	requestID     string
	namespace     string
	partition     string
	requestScoped bool

	mu      sync.Mutex
	pending map[string]string
}

var _ privacyengine.Renderer = (*tokenRenderer)(nil)

// Render implements privacyengine.Renderer.
func (r *tokenRenderer) Render(ctx context.Context, finding privacyengine.Finding, plaintext string) (string, error) {
	if ctx == nil {
		return "", privacyengine.ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	token, ok := r.tokenizer.codec.mint(r.namespace, finding.Kind, plaintext)
	if !ok {
		return r.fallback.Render(ctx, finding, plaintext)
	}
	r.mu.Lock()
	staged, isStaged := r.pending[token]
	r.mu.Unlock()
	if !isStaged {
		staged, isStaged = r.tokenizer.vault.peek(r.partition, token)
	}
	if isStaged && staged != plaintext {
		// Two values share a truncated MAC. Restoring either would be a guess,
		// so this one is redacted irreversibly instead.
		r.tokenizer.stats.collisions.Add(1)
		return r.fallback.Render(ctx, finding, plaintext)
	}
	r.mu.Lock()
	r.pending[token] = plaintext
	r.mu.Unlock()
	return token, nil
}

// known reports whether token was already issued in this request's partition.
func (r *tokenRenderer) known(token string) bool {
	r.mu.Lock()
	_, staged := r.pending[token]
	r.mu.Unlock()
	if staged {
		return true
	}
	_, issued := r.tokenizer.vault.peek(r.partition, token)
	return issued
}

// knownSpans returns the byte ranges of already issued tokens in text, in
// order. A token-shaped run that was not issued here is ordinary text.
func (r *tokenRenderer) knownSpans(text string) [][2]int {
	codec := r.tokenizer.codec
	var spans [][2]int
	for offset := 0; offset < len(text); {
		length, ok := codec.matchAt(text, offset)
		if !ok {
			offset++
			continue
		}
		if r.known(text[offset : offset+length]) {
			spans = append(spans, [2]int{offset, offset + length})
			offset += length
			continue
		}
		offset++
	}
	return spans
}

// commit publishes the staged mappings and opens the response session. It
// returns the number of distinct tokens this pass put into the request.
func (r *tokenRenderer) commit() int {
	r.mu.Lock()
	staged := r.pending
	r.pending = make(map[string]string)
	r.mu.Unlock()

	published := 0
	for token, value := range staged {
		switch r.tokenizer.vault.put(r.partition, token, value) {
		case tokenPutStored, tokenPutRefreshed:
			published++
		case tokenPutCollision:
			r.tokenizer.stats.collisions.Add(1)
		}
	}
	if published > 0 {
		r.tokenizer.stats.tokenized.Add(uint64(published))
	}
	// A caller partition can hold tokens from earlier turns that this response
	// may legitimately reference, so the session opens whenever it is non-empty.
	if r.tokenizer.vault.has(r.partition) {
		r.tokenizer.sessions.open(r.requestID, r.partition, r.namespace, r.requestScoped)
	}
	return published
}

// discard drops mappings staged by a request that will not be forwarded.
func (r *tokenRenderer) discard() {
	r.mu.Lock()
	r.pending = make(map[string]string)
	r.mu.Unlock()
}
