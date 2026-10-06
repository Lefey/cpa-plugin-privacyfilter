package main

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

var (
	pluginVersion  = "0.3.6"
	pluginRevision = "unknown"
)

const (
	defaultRequestCacheTTL        = 10 * time.Minute
	defaultRequestCacheMaxEntries = 4096
)

type runtimeState struct {
	cache    *RequestScanCache
	revision atomic.Uint64
	keyStats keyFilterStats

	// tokens is created by the first mode: tokenize configuration and then
	// kept, so issued mappings and the process HMAC key survive a reconfigure.
	tokensMu sync.Mutex
	tokens   *tokenRuntime
}

func (r *runtimeState) tokenRuntime(cfg tokenizeConfig) (*tokenRuntime, error) {
	r.tokensMu.Lock()
	defer r.tokensMu.Unlock()
	if r.tokens == nil {
		tokens, err := newTokenRuntime(cfg)
		if err != nil {
			return nil, err
		}
		r.tokens = tokens
	}
	return r.tokens, nil
}

// loadedTokenRuntime returns the tokenize state if any configuration created it.
func (r *runtimeState) loadedTokenRuntime() *tokenRuntime {
	if r == nil {
		return nil
	}
	r.tokensMu.Lock()
	defer r.tokensMu.Unlock()
	return r.tokens
}

func newRuntimeState() *runtimeState {
	return &runtimeState{cache: NewRequestScanCache(RequestScanCacheOptions{
		TTL:        defaultRequestCacheTTL,
		MaxEntries: defaultRequestCacheMaxEntries,
	})}
}

func (r *runtimeState) nextRevision() uint64 {
	if r == nil {
		return 1
	}
	return r.revision.Add(1)
}

func buildPlugin(configYAML []byte, pluginDir string) (pluginapi.Plugin, error) {
	return buildPluginWithRuntime(configYAML, pluginDir, newRuntimeState())
}

func buildPluginWithRuntime(configYAML []byte, pluginDir string, runtime *runtimeState) (pluginapi.Plugin, error) {
	cfg, errParse := parseConfig(configYAML)
	if errParse != nil {
		return pluginapi.Plugin{}, errParse
	}
	if pluginDir == "" {
		pluginDir = inferPluginDir()
	}

	if runtime == nil {
		runtime = newRuntimeState()
	}
	keys, errKeys := cfg.KeyFilter.compile()
	if errKeys != nil {
		return pluginapi.Plugin{}, errKeys
	}
	p := &privacyFilterPlugin{
		cfg:       cfg,
		keyFilter: keys,
		keyStats:  &runtime.keyStats,
		cache:     runtime.cache,
		revision:  runtime.nextRevision(),
	}

	engine, _, errEngine := newEngine(pluginDir, cfg)
	if errEngine != nil {
		return pluginapi.Plugin{}, errEngine
	}
	if errReplacement := validateReplacementSafety(engine, cfg.Replacements); errReplacement != nil {
		return pluginapi.Plugin{}, errReplacement
	}
	renderer, errRenderer := cfg.renderer()
	if errRenderer != nil {
		return pluginapi.Plugin{}, errRenderer
	}
	p.engine = engine
	p.renderer = renderer
	p.blockRuleIDs = cfg.blockRuleSet()
	if cfg.Mode == modeTokenize {
		tokens, errTokens := runtime.tokenRuntime(cfg.Tokenize)
		if errTokens != nil {
			return pluginapi.Plugin{}, errTokens
		}
		tok, errTokenizer := newTokenizer(cfg.Tokenize, tokens)
		if errTokenizer != nil {
			return pluginapi.Plugin{}, errTokenizer
		}
		p.tok = tok
		p.tokRuntime = tokens
	}
	capabilities := pluginapi.Capabilities{
		RequestInterceptor:     p,
		RequestLifecyclePlugin: p,
	}
	if p.tok != nil {
		// Response hooks are declared only in tokenize mode, so every other
		// mode keeps the request-only registration and its Host overhead.
		capabilities.ResponseInterceptor = p
		capabilities.StreamChunkInterceptor = p
	}

	return pluginapi.Plugin{
		SchemaVersion: implementedSchemaVersion,
		Metadata: pluginapi.Metadata{
			Name:             pluginName,
			Version:          pluginVersion,
			Author:           "ahoo (fork of rheodev)",
			GitHubRepository: "https://github.com/ahoo/cpa-plugin-privacyfilter",
			ConfigFields: []pluginapi.ConfigField{
				{
					Name:        "mode",
					Type:        pluginapi.ConfigFieldTypeEnum,
					EnumValues:  []string{string(modeRedact), string(modeTokenize), string(modeAudit)},
					Description: "Redact findings, replace them with tokens restored in the response, or audit without modifying requests.",
				},
				{
					Name:        "on_error",
					Type:        pluginapi.ConfigFieldTypeEnum,
					EnumValues:  []string{string(onErrorBlock), string(onErrorPassthrough)},
					Description: "Block by default when a request cannot be safely inspected, or explicitly pass it through.",
				},
				{
					Name:        "gitleaks_toml",
					Type:        pluginapi.ConfigFieldTypeString,
					Description: "Path to custom Gitleaks TOML. Empty uses the embedded pinned rules.",
				},
				{
					Name:        "gitleaks_mode",
					Type:        pluginapi.ConfigFieldTypeEnum,
					EnumValues:  []string{string(customRulesExtend), string(customRulesReplace)},
					Description: "Extend or replace embedded rules. Omitted with a custom file preserves legacy replace behavior.",
				},
				{
					Name:        "allow_unsupported_rules",
					Type:        pluginapi.ConfigFieldTypeBoolean,
					Description: "Allow explicitly reported unsupported semantics in a custom rule file.",
				},
				{
					Name:        "block_rule_ids",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Rule IDs that terminate the request instead of redacting it.",
				},
				{
					Name:        "replacements",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "Typed placeholder overrides for email, phone, bank_card, iban, ip, and secret.",
				},
				{
					Name:        "phone_regions",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "ISO 3166-1 alpha-2 regions whose national phone formats are recognised. International + numbers need no region.",
				},
				{
					Name:        "limits",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "Bounded JSON scanning, text, finding, and replacement budgets.",
				},
				{
					Name:        "key_filter",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "Inspect only (mode include) or all but (mode exclude) the listed client api_keys or caller_scopes; on_missing_identity is filter or skip. Empty lists inspect every request.",
				},
				{
					Name:        "tokenize",
					Type:        pluginapi.ConfigFieldTypeObject,
					Description: "Options for mode tokenize: token_format, hmac_secret, max_entries, ttl, and restore_scope (caller or request).",
				},
				{
					Name:        "skip_models",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Trusted break-glass model names to bypass inspection.",
				},
				{
					Name:        "skip_formats",
					Type:        pluginapi.ConfigFieldTypeArray,
					Description: "Trusted break-glass source formats to bypass inspection.",
				},
			},
		},
		Capabilities: capabilities,
	}, nil
}
