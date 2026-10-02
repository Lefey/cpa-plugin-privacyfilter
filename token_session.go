package main

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// maxRestoreSessions bounds concurrently tracked requests. A request beyond
	// the bound evicts the least recently active one, whose response is then
	// delivered with its tokens unrestored.
	maxRestoreSessions = 8192

	callerPartitionPrefix  = "c\x00"
	requestPartitionPrefix = "r\x00"
)

// restoreCounters are the only response-side facts that reach the logs.
type restoreCounters struct {
	restored   int
	unresolved int
	failed     int
}

// restoreSession is the response-side state of one tokenized request: which
// vault partition its response may read, and the stream reassembly buffers.
// It never holds an original value outside those buffers' pending output.
type restoreSession struct {
	requestID string
	partition string
	// requestScoped means the partition belongs to this request alone and is
	// destroyed with the session.
	requestScoped bool

	// mu serialises response processing for the request. The Host delivers
	// stream chunks in order, but nothing in the ABI forbids overlap.
	mu       sync.Mutex
	stream   *streamState
	counters restoreCounters

	lastAccess time.Time
	element    *list.Element
}

// restoreRegistry tracks sessions by RequestID with an LRU bound and a sliding
// idle TTL. request.complete removes a session; the bounds are the fallback
// for a lifecycle notification that never arrives.
type restoreRegistry struct {
	mu       sync.Mutex
	sessions map[string]*restoreSession
	lru      list.List
	max      int
	ttl      time.Duration
	now      func() time.Time
	// release runs for every session leaving the registry, outside mu.
	release func(*restoreSession)

	expired atomic.Uint64
	evicted atomic.Uint64
}

func newRestoreRegistry(maxSessions int, ttl time.Duration, now func() time.Time, release func(*restoreSession)) *restoreRegistry {
	if now == nil {
		now = time.Now
	}
	return &restoreRegistry{
		sessions: make(map[string]*restoreSession),
		max:      maxSessions,
		ttl:      ttl,
		now:      now,
		release:  release,
	}
}

func (r *restoreRegistry) configure(ttl time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.ttl = ttl
	r.mu.Unlock()
}

// open returns the session for requestID, creating it when needed. A request
// keeps one session across the before-auth and after-auth passes.
func (r *restoreRegistry) open(requestID, partition string, requestScoped bool) *restoreSession {
	if r == nil || requestID == "" || partition == "" {
		return nil
	}
	now := r.now()
	var released []*restoreSession
	r.mu.Lock()
	released = r.pruneLocked(now, released)
	session, ok := r.sessions[requestID]
	if ok && session.partition != partition {
		r.removeLocked(session)
		released = append(released, session)
		ok = false
	}
	if ok {
		session.lastAccess = now
		r.lru.MoveToFront(session.element)
	} else {
		session = &restoreSession{
			requestID:     requestID,
			partition:     partition,
			requestScoped: requestScoped,
			lastAccess:    now,
		}
		session.element = r.lru.PushFront(session)
		r.sessions[requestID] = session
		for len(r.sessions) > r.max {
			oldest := r.lru.Back()
			if oldest == nil {
				break
			}
			victim := oldest.Value.(*restoreSession)
			r.removeLocked(victim)
			r.evicted.Add(1)
			released = append(released, victim)
		}
	}
	r.mu.Unlock()
	r.releaseAll(released)
	return session
}

// get returns the live session for requestID and refreshes its idle TTL.
func (r *restoreRegistry) get(requestID string) *restoreSession {
	if r == nil || requestID == "" {
		return nil
	}
	now := r.now()
	r.mu.Lock()
	session, ok := r.sessions[requestID]
	if !ok {
		r.mu.Unlock()
		return nil
	}
	if r.ttl > 0 && now.Sub(session.lastAccess) >= r.ttl {
		r.removeLocked(session)
		r.expired.Add(1)
		r.mu.Unlock()
		r.releaseAll([]*restoreSession{session})
		return nil
	}
	session.lastAccess = now
	r.lru.MoveToFront(session.element)
	r.mu.Unlock()
	return session
}

// close removes and returns the session for requestID. It is idempotent.
func (r *restoreRegistry) close(requestID string) *restoreSession {
	if r == nil || requestID == "" {
		return nil
	}
	r.mu.Lock()
	session, ok := r.sessions[requestID]
	if ok {
		r.removeLocked(session)
	}
	r.mu.Unlock()
	if !ok {
		return nil
	}
	r.releaseAll([]*restoreSession{session})
	return session
}

// clear removes every session.
func (r *restoreRegistry) clear() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	released := make([]*restoreSession, 0, len(r.sessions))
	for _, session := range r.sessions {
		session.element = nil
		released = append(released, session)
	}
	r.sessions = make(map[string]*restoreSession)
	r.lru.Init()
	r.mu.Unlock()
	r.releaseAll(released)
	return len(released)
}

func (r *restoreRegistry) len() int {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

func (r *restoreRegistry) pruneLocked(now time.Time, released []*restoreSession) []*restoreSession {
	if r.ttl <= 0 {
		return released
	}
	for element := r.lru.Back(); element != nil; {
		session := element.Value.(*restoreSession)
		if now.Sub(session.lastAccess) < r.ttl {
			break
		}
		previous := element.Prev()
		r.removeLocked(session)
		r.expired.Add(1)
		released = append(released, session)
		element = previous
	}
	return released
}

func (r *restoreRegistry) removeLocked(session *restoreSession) {
	delete(r.sessions, session.requestID)
	if session.element != nil {
		r.lru.Remove(session.element)
		session.element = nil
	}
}

func (r *restoreRegistry) releaseAll(sessions []*restoreSession) {
	if r.release == nil {
		return
	}
	for _, session := range sessions {
		r.release(session)
	}
}
