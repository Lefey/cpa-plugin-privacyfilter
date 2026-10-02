package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

const (
	// callerScopeMetadataKey is the Host execution-metadata key that carries the
	// authenticated downstream caller. The Host never passes the raw API key to
	// interceptors; it passes this irreversible digest instead.
	callerScopeMetadataKey = "caller_scope"
	// callerScopeDomain must match sdk/cliproxy/session.CallerScope in the pinned
	// Host. If the Host changes its derivation, configured api_keys stop matching
	// and an include list silently filters nothing; revalidate on every SDK bump.
	callerScopeDomain = "cli-proxy-api:caller-scope:v1\x00"

	callerScopeHexLen = sha256.Size * 2
)

type keyFilterMode string

const (
	keyFilterInclude keyFilterMode = "include"
	keyFilterExclude keyFilterMode = "exclude"
)

type missingIdentityPolicy string

const (
	missingIdentityFilter missingIdentityPolicy = "filter"
	missingIdentitySkip   missingIdentityPolicy = "skip"
)

// keyFilterConfig mirrors the key_filter mapping. Both lists empty means the
// key filter is inactive and every request is inspected, as before.
type keyFilterConfig struct {
	Mode keyFilterMode `yaml:"mode"`
	// APIKeys are downstream client keys in plaintext. They are hashed at load
	// and never retained, logged, or echoed in errors.
	APIKeys []string `yaml:"api_keys"`
	// CallerScopes are precomputed identifiers (64 hex characters), for
	// operators who do not want plaintext keys in the plugin stanza.
	CallerScopes      []string              `yaml:"caller_scopes"`
	OnMissingIdentity missingIdentityPolicy `yaml:"on_missing_identity"`
}

func defaultKeyFilterConfig() keyFilterConfig {
	return keyFilterConfig{Mode: keyFilterInclude, OnMissingIdentity: missingIdentityFilter}
}

func (cfg keyFilterConfig) active() bool {
	return len(cfg.APIKeys) != 0 || len(cfg.CallerScopes) != 0
}

// callerScope reproduces the Host's caller identifier for one API key.
func callerScope(apiKey string) string {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(callerScopeDomain + apiKey))
	return hex.EncodeToString(sum[:])
}

func callerScopeFromMetadata(metadata map[string]any) string {
	scope, _ := metadata[callerScopeMetadataKey].(string)
	return strings.TrimSpace(scope)
}

// compile validates the mapping and returns the identifier set. Errors name the
// list and position only; they never contain a key or identifier.
func (cfg keyFilterConfig) compile() (*keyFilter, error) {
	switch cfg.Mode {
	case keyFilterInclude, keyFilterExclude:
	default:
		return nil, fmt.Errorf("invalid privacyfilter config: key_filter.mode must be %q or %q", keyFilterInclude, keyFilterExclude)
	}
	switch cfg.OnMissingIdentity {
	case missingIdentityFilter, missingIdentitySkip:
	default:
		return nil, fmt.Errorf("invalid privacyfilter config: key_filter.on_missing_identity must be %q or %q", missingIdentityFilter, missingIdentitySkip)
	}

	scopes := make(map[string]struct{}, len(cfg.APIKeys)+len(cfg.CallerScopes))
	for index, apiKey := range cfg.APIKeys {
		scope := callerScope(apiKey)
		if scope == "" {
			return nil, fmt.Errorf("invalid privacyfilter config: key_filter.api_keys[%d] is empty", index)
		}
		if _, duplicate := scopes[scope]; duplicate {
			return nil, fmt.Errorf("invalid privacyfilter config: key_filter.api_keys[%d] duplicates an earlier entry", index)
		}
		scopes[scope] = struct{}{}
	}
	for index, scope := range cfg.CallerScopes {
		scope = strings.ToLower(strings.TrimSpace(scope))
		if !validCallerScope(scope) {
			return nil, fmt.Errorf("invalid privacyfilter config: key_filter.caller_scopes[%d] must be %d hexadecimal characters", index, callerScopeHexLen)
		}
		if _, duplicate := scopes[scope]; duplicate {
			return nil, fmt.Errorf("invalid privacyfilter config: key_filter.caller_scopes[%d] duplicates an earlier entry", index)
		}
		scopes[scope] = struct{}{}
	}
	return &keyFilter{
		include:   cfg.Mode == keyFilterInclude,
		scopes:    scopes,
		onMissing: cfg.OnMissingIdentity,
	}, nil
}

func validCallerScope(scope string) bool {
	if len(scope) != callerScopeHexLen {
		return false
	}
	for index := 0; index < len(scope); index++ {
		c := scope[index]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type keyDecision uint8

const (
	// keyDecisionFilter inspects the request.
	keyDecisionFilter keyDecision = iota
	// keyDecisionSkip passes the request through untouched.
	keyDecisionSkip
	// keyDecisionDefer leaves a before-auth request untouched because the
	// caller is not known yet; the after-auth pass decides.
	keyDecisionDefer
)

// keyFilter is the compiled, immutable key_filter policy.
type keyFilter struct {
	include   bool
	scopes    map[string]struct{}
	onMissing missingIdentityPolicy
}

func (f *keyFilter) active() bool {
	return f != nil && len(f.scopes) != 0
}

// decide selects the action for one interceptor call. A request whose caller
// is unknown is never modified or rejected before credential selection; at the
// after-auth stage it fails closed unless on_missing_identity says otherwise.
func (f *keyFilter) decide(scope string, afterAuth bool) keyDecision {
	if !f.active() {
		return keyDecisionFilter
	}
	if scope == "" {
		if !afterAuth {
			return keyDecisionDefer
		}
		if f.onMissing == missingIdentitySkip {
			return keyDecisionSkip
		}
		return keyDecisionFilter
	}
	if _, listed := f.scopes[scope]; listed == f.include {
		return keyDecisionFilter
	}
	return keyDecisionSkip
}

// keyFilterStats counts key_filter decisions. It holds counters only, so a
// decision can be logged without any caller identifier.
type keyFilterStats struct {
	filtered     atomic.Uint64
	skippedByKey atomic.Uint64
}

func (s *keyFilterStats) record(decision keyDecision) {
	if s == nil {
		return
	}
	name := "filtered"
	if decision == keyDecisionSkip {
		name = "skipped_by_key"
		s.skippedByKey.Add(1)
	} else {
		s.filtered.Add(1)
	}
	if log.IsLevelEnabled(log.DebugLevel) {
		log.WithFields(log.Fields{
			"decision":             name,
			"filtered_total":       s.filtered.Load(),
			"skipped_by_key_total": s.skippedByKey.Load(),
		}).Debug("privacyfilter: key filter decision")
	}
}
