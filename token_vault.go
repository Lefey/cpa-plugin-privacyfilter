package main

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

// tokenVaultStats is a value-free snapshot of the vault.
type tokenVaultStats struct {
	Entries     int
	Partitions  int
	MaxEntries  int
	TTL         time.Duration
	Stored      uint64
	Collisions  uint64
	Expirations uint64
	Evictions   uint64
	Dropped     uint64
}

type tokenVaultEntry struct {
	partition  string
	token      string
	value      string
	lastAccess time.Time
	element    *list.Element
}

// tokenVault maps issued tokens back to their original values. It lives only
// in process memory and is never serialized or logged.
//
// Entries are grouped into partitions (one per caller, or one per request) and
// a lookup never crosses a partition: knowing another partition's token gives
// no access to its value. The whole vault shares one LRU bounded by maxEntries
// and a sliding TTL refreshed whenever a token is issued or restored.
type tokenVault struct {
	mu         sync.Mutex
	partitions map[string]map[string]*tokenVaultEntry
	lru        list.List
	entries    int
	maxEntries int
	ttl        time.Duration
	now        func() time.Time

	stored      atomic.Uint64
	collisions  atomic.Uint64
	expirations atomic.Uint64
	evictions   atomic.Uint64
	dropped     atomic.Uint64
}

func newTokenVault(maxEntries int, ttl time.Duration, now func() time.Time) *tokenVault {
	if now == nil {
		now = time.Now
	}
	return &tokenVault{
		partitions: make(map[string]map[string]*tokenVaultEntry),
		maxEntries: maxEntries,
		ttl:        ttl,
		now:        now,
	}
}

// configure applies new bounds, evicting immediately if the vault shrank.
func (v *tokenVault) configure(maxEntries int, ttl time.Duration) {
	if v == nil {
		return
	}
	v.mu.Lock()
	v.maxEntries = maxEntries
	v.ttl = ttl
	v.pruneExpiredLocked(v.now())
	v.evictOverflowLocked()
	v.mu.Unlock()
}

type tokenPutResult uint8

const (
	tokenPutStored tokenPutResult = iota
	tokenPutRefreshed
	// tokenPutCollision means the token already maps to a different value in
	// this partition. The existing mapping is kept.
	tokenPutCollision
	tokenPutRejected
)

// put records token -> value in partition.
func (v *tokenVault) put(partition, token, value string) tokenPutResult {
	if v == nil || partition == "" || token == "" {
		return tokenPutRejected
	}
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.maxEntries <= 0 {
		return tokenPutRejected
	}
	v.pruneExpiredLocked(now)
	tokens := v.partitions[partition]
	if entry, ok := tokens[token]; ok {
		if entry.value != value {
			v.collisions.Add(1)
			return tokenPutCollision
		}
		entry.lastAccess = now
		v.lru.MoveToFront(entry.element)
		return tokenPutRefreshed
	}
	if tokens == nil {
		tokens = make(map[string]*tokenVaultEntry)
		v.partitions[partition] = tokens
	}
	entry := &tokenVaultEntry{partition: partition, token: token, value: value, lastAccess: now}
	entry.element = v.lru.PushFront(entry)
	tokens[token] = entry
	v.entries++
	v.stored.Add(1)
	v.evictOverflowLocked()
	return tokenPutStored
}

// get returns the value for token in partition and refreshes its TTL.
func (v *tokenVault) get(partition, token string) (string, bool) {
	return v.lookup(partition, token, true)
}

// peek is get without the TTL refresh.
func (v *tokenVault) peek(partition, token string) (string, bool) {
	return v.lookup(partition, token, false)
}

func (v *tokenVault) lookup(partition, token string, touch bool) (string, bool) {
	if v == nil || partition == "" {
		return "", false
	}
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	entry, ok := v.partitions[partition][token]
	if !ok {
		return "", false
	}
	if v.expired(entry, now) {
		v.removeLocked(entry)
		v.expirations.Add(1)
		return "", false
	}
	if touch {
		entry.lastAccess = now
		v.lru.MoveToFront(entry.element)
	}
	return entry.value, true
}

// has reports whether partition currently holds any live mapping.
func (v *tokenVault) has(partition string) bool {
	if v == nil || partition == "" {
		return false
	}
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pruneExpiredLocked(now)
	return len(v.partitions[partition]) != 0
}

// dropPartition removes every mapping in partition and returns the count.
func (v *tokenVault) dropPartition(partition string) int {
	if v == nil || partition == "" {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	tokens := v.partitions[partition]
	removed := len(tokens)
	for _, entry := range tokens {
		v.lru.Remove(entry.element)
		entry.element = nil
	}
	delete(v.partitions, partition)
	v.entries -= removed
	v.dropped.Add(uint64(removed))
	return removed
}

// prune removes expired mappings and returns the count.
func (v *tokenVault) prune() int {
	if v == nil {
		return 0
	}
	now := v.now()
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.pruneExpiredLocked(now)
}

// clear removes every mapping.
func (v *tokenVault) clear() int {
	if v == nil {
		return 0
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	removed := v.entries
	v.partitions = make(map[string]map[string]*tokenVaultEntry)
	v.lru.Init()
	v.entries = 0
	return removed
}

func (v *tokenVault) stats() tokenVaultStats {
	if v == nil {
		return tokenVaultStats{}
	}
	v.mu.Lock()
	entries, partitions, maxEntries, ttl := v.entries, len(v.partitions), v.maxEntries, v.ttl
	v.mu.Unlock()
	return tokenVaultStats{
		Entries:     entries,
		Partitions:  partitions,
		MaxEntries:  maxEntries,
		TTL:         ttl,
		Stored:      v.stored.Load(),
		Collisions:  v.collisions.Load(),
		Expirations: v.expirations.Load(),
		Evictions:   v.evictions.Load(),
		Dropped:     v.dropped.Load(),
	}
}

func (v *tokenVault) expired(entry *tokenVaultEntry, now time.Time) bool {
	return v.ttl > 0 && now.Sub(entry.lastAccess) >= v.ttl
}

// pruneExpiredLocked removes the expired LRU suffix. Every access moves an
// entry to the front, so a live tail means everything before it is live.
func (v *tokenVault) pruneExpiredLocked(now time.Time) int {
	removed := 0
	for element := v.lru.Back(); element != nil; {
		entry := element.Value.(*tokenVaultEntry)
		if !v.expired(entry, now) {
			break
		}
		previous := element.Prev()
		v.removeLocked(entry)
		removed++
		element = previous
	}
	if removed > 0 {
		v.expirations.Add(uint64(removed))
	}
	return removed
}

func (v *tokenVault) evictOverflowLocked() {
	for v.entries > v.maxEntries {
		oldest := v.lru.Back()
		if oldest == nil {
			return
		}
		v.removeLocked(oldest.Value.(*tokenVaultEntry))
		v.evictions.Add(1)
	}
}

func (v *tokenVault) removeLocked(entry *tokenVaultEntry) {
	tokens := v.partitions[entry.partition]
	delete(tokens, entry.token)
	if len(tokens) == 0 {
		delete(v.partitions, entry.partition)
	}
	if entry.element != nil {
		v.lru.Remove(entry.element)
		entry.element = nil
	}
	v.entries--
}
