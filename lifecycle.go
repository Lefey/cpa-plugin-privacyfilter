package main

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

var _ pluginapi.RequestLifecyclePlugin = (*privacyFilterPlugin)(nil)

// HandleRequestComplete releases the request fingerprint, request-local
// renderer state, and (in tokenize mode) the response restore session after
// the final response or stream chunk. Complete is idempotent; TTL/LRU remain a
// fallback for missing best-effort notifications.
func (p *privacyFilterPlugin) HandleRequestComplete(_ context.Context, done pluginapi.RequestCompletion) error {
	if p == nil {
		return nil
	}
	releaseRequestScanState(p.cache, done)
	if p.tok != nil {
		releaseRestoreSession(p.tokRuntime, done)
	}
	return nil
}

func releaseRequestScanState(cache *RequestScanCache, done pluginapi.RequestCompletion) {
	if cache == nil || done.RequestID == "" {
		return
	}
	removed := cache.Complete(done.RequestID)
	if removed && log.IsLevelEnabled(log.DebugLevel) {
		stats := cache.Stats()
		log.WithFields(log.Fields{
			"outcome":       safeLogValue(string(done.Outcome)),
			"stream":        done.Stream,
			"cache_entries": stats.Entries,
		}).Debug("privacyfilter: request scan state released")
	}
}
