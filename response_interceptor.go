package main

import (
	"bytes"
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var (
	_ pluginapi.ResponseInterceptor    = (*privacyFilterPlugin)(nil)
	_ pluginapi.StreamChunkInterceptor = (*privacyFilterPlugin)(nil)
)

// restorerFor binds the response of one request to its vault partition.
func (p *privacyFilterPlugin) restorerFor(session *restoreSession) *restorer {
	return &restorer{
		codec:     p.tok.codec,
		vault:     p.tok.vault,
		partition: session.partition,
		limits:    p.cfg.payloadLimits(),
		counters:  &session.counters,
	}
}

// InterceptResponse restores tokens in a successful non-streaming response.
//
// Only a request that was tokenized has a session, so a request skipped by
// key_filter, skip_models or skip_formats is returned untouched. The Host
// treats an interceptor error as "deliver the response unchanged"; a failure
// therefore leaves tokens, never values, in the response and is logged.
func (p *privacyFilterPlugin) InterceptResponse(ctx context.Context, req pluginapi.ResponseInterceptRequest) (pluginapi.ResponseInterceptResponse, error) {
	if p == nil || p.tok == nil || len(req.Body) == 0 {
		return pluginapi.ResponseInterceptResponse{}, nil
	}
	session := p.tok.sessions.get(req.RequestID)
	if session == nil || !p.tok.codec.containsBytes(req.Body) {
		return pluginapi.ResponseInterceptResponse{}, nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()

	out, changed, err := p.restorerFor(session).document(ctx, req.Body, nil, 0)
	if err != nil {
		session.counters.failed++
		log.WithFields(log.Fields{
			"source_format":  safeLogValue(req.SourceFormat),
			"reason":         failureReason(err),
			"restore_failed": true,
		}).Warn("privacyfilter: response delivered with unrestored tokens")
		return pluginapi.ResponseInterceptResponse{}, nil
	}
	if !changed {
		return pluginapi.ResponseInterceptResponse{}, nil
	}
	return pluginapi.ResponseInterceptResponse{Body: out}, nil
}

// InterceptStreamChunk restores tokens in one stream chunk, reassembling
// tokens that the provider split across deltas.
func (p *privacyFilterPlugin) InterceptStreamChunk(ctx context.Context, req pluginapi.StreamChunkInterceptRequest) (resp pluginapi.StreamChunkInterceptResponse, err error) {
	if p == nil || p.tok == nil {
		return pluginapi.StreamChunkInterceptResponse{}, nil
	}
	session := p.tok.sessions.get(req.RequestID)
	if session == nil {
		return pluginapi.StreamChunkInterceptResponse{}, nil
	}
	session.mu.Lock()
	defer session.mu.Unlock()

	if req.ChunkIndex == pluginapi.StreamChunkHeaderInitIndex {
		// A bootstrap retry restarts the stream; buffers of the abandoned
		// attempt must not leak into the new one.
		session.stream = newStreamState()
		return pluginapi.StreamChunkInterceptResponse{}, nil
	}
	if len(req.Body) == 0 {
		return pluginapi.StreamChunkInterceptResponse{}, nil
	}
	if session.stream == nil {
		session.stream = newStreamState()
	}
	state := session.stream
	if state.broken {
		return pluginapi.StreamChunkInterceptResponse{}, nil
	}
	defer func() {
		if recover() == nil {
			return
		}
		// Reassembly state is unknown after a panic. Stop rewriting this stream
		// rather than emit text out of order; the rest is delivered with its
		// tokens unrestored.
		state.broken = true
		session.counters.failed++
		log.WithFields(log.Fields{
			"source_format":  safeLogValue(req.SourceFormat),
			"reason":         "internal_error",
			"restore_failed": true,
		}).Warn("privacyfilter: stream delivered with unrestored tokens")
		resp, err = pluginapi.StreamChunkInterceptResponse{}, nil
	}()

	failedBefore := session.counters.failed
	processor := newStreamProcessor(ctx, p.restorerFor(session), state, req.SourceFormat)
	out, drop := processor.chunk(req.Body)
	if session.counters.failed != failedBefore && !state.warned {
		state.warned = true
		log.WithFields(log.Fields{
			"source_format":  safeLogValue(req.SourceFormat),
			"reason":         "event_rewrite",
			"restore_failed": true,
		}).Warn("privacyfilter: stream event delivered with unrestored tokens")
	}
	if drop {
		return pluginapi.StreamChunkInterceptResponse{DropChunk: true}, nil
	}
	if bytes.Equal(out, req.Body) {
		return pluginapi.StreamChunkInterceptResponse{}, nil
	}
	return pluginapi.StreamChunkInterceptResponse{Body: out}, nil
}

// releaseRestoreSession ends the response side of a request: the session and
// its stream buffers are dropped and, in request scope, so are its mappings.
// It runs on every terminal outcome, including client cancellation.
func releaseRestoreSession(runtime *tokenRuntime, done pluginapi.RequestCompletion) {
	if runtime == nil || done.RequestID == "" {
		return
	}
	session := runtime.sessions.close(done.RequestID)
	if session == nil {
		return
	}
	session.mu.Lock()
	counters := session.counters
	unflushed := session.stream.unflushed()
	session.stream = nil
	session.mu.Unlock()

	runtime.stats.restored.Add(uint64(counters.restored))
	runtime.stats.unresolved.Add(uint64(counters.unresolved))
	runtime.stats.failed.Add(uint64(counters.failed))
	runtime.stats.unflushed.Add(uint64(unflushed))
	if counters.restored == 0 && counters.unresolved == 0 && counters.failed == 0 && unflushed == 0 {
		return
	}
	entry := log.WithFields(log.Fields{
		"outcome":        safeLogValue(string(done.Outcome)),
		"stream":         done.Stream,
		"restored":       counters.restored,
		"unresolved":     counters.unresolved,
		"unflushed":      unflushed,
		"restore_failed": counters.failed,
	})
	if counters.failed != 0 || unflushed != 0 {
		entry.Warn("privacyfilter: token restoration incomplete")
		return
	}
	entry.Info("privacyfilter: token restoration complete")
}
