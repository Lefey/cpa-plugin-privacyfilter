package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ahoo/cpa-plugin-privacyfilter/internal/privacyengine"
	"github.com/ahoo/cpa-plugin-privacyfilter/payload"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const privacyFilterProvider = "privacyfilter"
const pluginName = "privacyfilter"

const (
	hardMaxTextBytes = 32 << 20
	hardMaxTextNodes = 100_000
	hardMaxFindings  = 4_096
)

type filterMode string

const (
	modeRedact filterMode = "redact"
	// modeTokenize replaces findings with reversible tokens and restores them
	// in the provider response before it reaches the client.
	modeTokenize filterMode = "tokenize"
	modeAudit    filterMode = "audit"
)

type errorPolicy string

const (
	onErrorBlock       errorPolicy = "block"
	onErrorPassthrough errorPolicy = "passthrough"
)

type customRuleMode string

const (
	customRulesExtend  customRuleMode = "extend"
	customRulesReplace customRuleMode = "replace"
)

type limitsConfig struct {
	MaxBodyBytes        int `yaml:"max_body_bytes"`
	MaxDepth            int `yaml:"max_depth"`
	MaxJSONNodes        int `yaml:"max_json_nodes"`
	MaxStructuralBytes  int `yaml:"max_structural_bytes"`
	MaxStringBytes      int `yaml:"max_string_bytes"`
	MaxReplacements     int `yaml:"max_replacements"`
	MaxReplacementBytes int `yaml:"max_replacement_bytes"`
	MaxTextBytes        int `yaml:"max_text_bytes"`
	MaxTextNodes        int `yaml:"max_text_nodes"`
	MaxFindings         int `yaml:"max_findings"`
}

type privacyFilterConfig struct {
	// CLIProxyAPI currently includes these host-owned fields in the YAML passed to
	// native plugins. Accept but never use them; the host enforces both values.
	Enabled  bool `yaml:"enabled"`
	Priority int  `yaml:"priority"`

	// Existing v0.2 fields remain valid.
	GitleaksTOML string   `yaml:"gitleaks_toml"`
	SkipModels   []string `yaml:"skip_models"`
	SkipFormats  []string `yaml:"skip_formats"`

	Mode                  filterMode        `yaml:"mode"`
	OnError               errorPolicy       `yaml:"on_error"`
	GitleaksMode          customRuleMode    `yaml:"gitleaks_mode"`
	AllowUnsupportedRules bool              `yaml:"allow_unsupported_rules"`
	BlockRuleIDs          []string          `yaml:"block_rule_ids"`
	Replacements          map[string]string `yaml:"replacements"`
	Limits                limitsConfig      `yaml:"limits"`
	// Tokenize configures mode: tokenize. It is ignored by the other modes.
	Tokenize tokenizeConfig `yaml:"tokenize"`
	// KeyFilter restricts inspection to (or away from) listed downstream API
	// keys. Inactive when both of its lists are empty.
	KeyFilter keyFilterConfig `yaml:"key_filter"`
	// MLAssist is the distilled sensitive-text student (second opinion).
	// It only rescores texts the deterministic engine left clean; it never
	// overrides engine findings. Disabled by default.
	MLAssist mlAssistConfig `yaml:"ml_assist"`
}

// mlAssistMode selects what happens when the ML second opinion fires.
type mlAssistMode string

const (
	mlAssistAudit   mlAssistMode = "audit"
	mlAssistEnforce mlAssistMode = "enforce"
)

// mlAssistConfig mirrors the ml_assist mapping.
type mlAssistConfig struct {
	Enabled   bool         `yaml:"enabled"`
	Threshold float64      `yaml:"threshold"`
	Mode      mlAssistMode `yaml:"mode"`
}

// effectiveThreshold returns the configured threshold, defaulting to the
// validated 0.5 separation point when unset.
func (m mlAssistConfig) effectiveThreshold() float64 {
	if m.Threshold <= 0 {
		return 0.5
	}
	return m.Threshold
}

// enforce reports whether a firing second opinion redacts. Audit (the
// default) only counts.
func (m mlAssistConfig) enforce() bool {
	return m.Enabled && m.Mode == mlAssistEnforce
}

func defaultConfig() privacyFilterConfig {
	jsonLimits := payload.DefaultLimits()
	return privacyFilterConfig{
		Mode:      modeRedact,
		OnError:   onErrorBlock,
		KeyFilter: defaultKeyFilterConfig(),
		Tokenize:  defaultTokenizeConfig(),
		Limits: limitsConfig{
			MaxBodyBytes:        jsonLimits.MaxBodyBytes,
			MaxDepth:            jsonLimits.MaxDepth,
			MaxJSONNodes:        jsonLimits.MaxNodes,
			MaxStructuralBytes:  jsonLimits.MaxStructuralBytes,
			MaxStringBytes:      jsonLimits.MaxStringBytes,
			MaxReplacements:     jsonLimits.MaxReplacements,
			MaxReplacementBytes: jsonLimits.MaxReplacementBytes,
			// The detector budget is cumulative across every selected text node.
			// Keep it aligned with the body ceiling rather than the engine's
			// conservative one-text default; the JSON walker enforces the body cap.
			MaxTextBytes: hardMaxTextBytes,
			MaxTextNodes: hardMaxTextNodes,
			MaxFindings:  hardMaxFindings,
		},
	}
}

func parseConfig(raw []byte) (privacyFilterConfig, error) {
	cfg := defaultConfig()
	if len(bytes.TrimSpace(raw)) == 0 {
		return cfg, nil
	}

	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return cfg, fmt.Errorf("invalid privacyfilter config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return cfg, fmt.Errorf("invalid privacyfilter config: multiple YAML documents are not allowed")
		}
		return cfg, fmt.Errorf("invalid privacyfilter config: %w", err)
	}
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (cfg privacyFilterConfig) validate() error {
	switch cfg.Mode {
	case modeRedact, modeTokenize, modeAudit:
	default:
		return fmt.Errorf("invalid privacyfilter config: mode must be %q, %q, or %q", modeRedact, modeTokenize, modeAudit)
	}
	if err := cfg.Tokenize.validate(); err != nil {
		return err
	}
	switch cfg.OnError {
	case onErrorBlock, onErrorPassthrough:
	default:
		return fmt.Errorf("invalid privacyfilter config: on_error must be %q or %q", onErrorBlock, onErrorPassthrough)
	}
	if cfg.GitleaksMode != "" && cfg.GitleaksMode != customRulesExtend && cfg.GitleaksMode != customRulesReplace {
		return fmt.Errorf("invalid privacyfilter config: gitleaks_mode must be %q or %q", customRulesExtend, customRulesReplace)
	}
	if strings.TrimSpace(cfg.GitleaksTOML) == "" && cfg.GitleaksMode != "" {
		return fmt.Errorf("invalid privacyfilter config: gitleaks_mode requires gitleaks_toml")
	}
	if _, err := cfg.payloadLimits().Normalized(); err != nil {
		return fmt.Errorf("invalid privacyfilter config: %w", err)
	}
	if cfg.Limits.MaxTextBytes <= 0 || cfg.Limits.MaxTextNodes <= 0 || cfg.Limits.MaxFindings <= 0 {
		return fmt.Errorf("invalid privacyfilter config: detector limits must be positive")
	}
	if cfg.Limits.MaxTextBytes > hardMaxTextBytes || cfg.Limits.MaxTextNodes > hardMaxTextNodes || cfg.Limits.MaxFindings > hardMaxFindings {
		return fmt.Errorf("invalid privacyfilter config: configured detector limit exceeds hard maximum")
	}
	for kind := range cfg.Replacements {
		if _, ok := replacementKind(kind); !ok {
			return fmt.Errorf("invalid privacyfilter config: unknown replacement kind %q", kind)
		}
	}
	switch cfg.MLAssist.Mode {
	case "", mlAssistAudit, mlAssistEnforce:
	default:
		return fmt.Errorf("invalid privacyfilter config: ml_assist.mode must be %q or %q", mlAssistAudit, mlAssistEnforce)
	}
	if cfg.MLAssist.Threshold < 0 || cfg.MLAssist.Threshold > 1 {
		return fmt.Errorf("invalid privacyfilter config: ml_assist.threshold must be within [0,1]")
	}
	if _, err := cfg.KeyFilter.compile(); err != nil {
		return err
	}
	seenRules := make(map[string]struct{}, len(cfg.BlockRuleIDs))
	for _, ruleID := range cfg.BlockRuleIDs {
		ruleID = strings.TrimSpace(ruleID)
		if ruleID == "" {
			return fmt.Errorf("invalid privacyfilter config: block_rule_ids cannot contain an empty id")
		}
		if _, duplicate := seenRules[ruleID]; duplicate {
			return fmt.Errorf("invalid privacyfilter config: duplicate block rule id %q", ruleID)
		}
		seenRules[ruleID] = struct{}{}
	}
	return nil
}

func (cfg privacyFilterConfig) payloadLimits() payload.Limits {
	return payload.Limits{
		MaxBodyBytes:        cfg.Limits.MaxBodyBytes,
		MaxDepth:            cfg.Limits.MaxDepth,
		MaxNodes:            cfg.Limits.MaxJSONNodes,
		MaxStructuralBytes:  cfg.Limits.MaxStructuralBytes,
		MaxStringBytes:      cfg.Limits.MaxStringBytes,
		MaxReplacements:     cfg.Limits.MaxReplacements,
		MaxReplacementBytes: cfg.Limits.MaxReplacementBytes,
	}
}

func (cfg privacyFilterConfig) engineLimits() privacyengine.Limits {
	return privacyengine.Limits{
		MaxBytes:    cfg.Limits.MaxTextBytes,
		MaxNodes:    cfg.Limits.MaxTextNodes,
		MaxFindings: cfg.Limits.MaxFindings,
	}
}

func (cfg privacyFilterConfig) renderer() (privacyengine.Renderer, error) {
	overrides := make(map[privacyengine.Kind]string, len(cfg.Replacements))
	for name, replacement := range cfg.Replacements {
		kind, ok := replacementKind(name)
		if !ok {
			return nil, fmt.Errorf("unknown replacement kind %q", name)
		}
		overrides[kind] = replacement
	}
	return privacyengine.NewPlaceholderRenderer(overrides), nil
}

func validateReplacementSafety(engine *privacyengine.Engine, replacements map[string]string) error {
	for name, replacement := range replacements {
		if replacement == "" {
			continue
		}
		findings, err := engine.Detect(context.Background(), replacement, privacyengine.RequestOptions{})
		if err != nil {
			return fmt.Errorf("validate replacement %q: %w", name, err)
		}
		if len(findings) > 0 {
			return fmt.Errorf("invalid privacyfilter config: replacement %q is itself sensitive", name)
		}
	}
	return nil
}

func replacementKind(name string) (privacyengine.Kind, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case string(privacyengine.KindEmail):
		return privacyengine.KindEmail, true
	case string(privacyengine.KindPhone):
		return privacyengine.KindPhone, true
	case string(privacyengine.KindIDCard):
		return privacyengine.KindIDCard, true
	case string(privacyengine.KindBankCard):
		return privacyengine.KindBankCard, true
	case string(privacyengine.KindIP):
		return privacyengine.KindIP, true
	case string(privacyengine.KindSecret):
		return privacyengine.KindSecret, true
	default:
		return "", false
	}
}

func (cfg privacyFilterConfig) blockRuleSet() map[string]struct{} {
	out := make(map[string]struct{}, len(cfg.BlockRuleIDs))
	for _, ruleID := range cfg.BlockRuleIDs {
		out[strings.TrimSpace(ruleID)] = struct{}{}
	}
	return out
}

func (cfg privacyFilterConfig) shouldSkip(model, requestedModel, format string) bool {
	for _, m := range cfg.SkipModels {
		trimmed := strings.TrimSpace(m)
		if strings.EqualFold(trimmed, model) || strings.EqualFold(trimmed, requestedModel) {
			return true
		}
	}
	for _, f := range cfg.SkipFormats {
		if strings.EqualFold(strings.TrimSpace(f), format) {
			return true
		}
	}
	return false
}

type ruleMaterial struct {
	embedded            []byte
	custom              []byte
	mode                privacyengine.CustomRuleMode
	customCompatibility privacyengine.CompatibilityPolicy
	source              string
}

const embeddedGitleaksSHA256 = "e163e53b9e7e8a8511e77271e2b323ed057759542a6d988258afe3a1fa329caf"

var expectedEmbeddedCompatibilityIssues = []privacyengine.CompatibilityIssue{
	{Source: privacyengine.RuleSourceEmbedded, Feature: "global.allowlist.paths", Action: privacyengine.CompatibilityIgnored, Detail: "path criteria are unavailable for protocol text"},
	{Source: privacyengine.RuleSourceEmbedded, RuleID: "freemius-secret-key", Feature: "rule.path", Action: privacyengine.CompatibilitySkipped, Detail: "path-constrained rules do not run for pathless protocol text"},
	{Source: privacyengine.RuleSourceEmbedded, RuleID: "generic-api-key", Feature: "rule.allowlists[3].paths", Action: privacyengine.CompatibilityIgnored, Detail: "path criteria are unavailable for protocol text"},
	{Source: privacyengine.RuleSourceEmbedded, RuleID: "github-app-token", Feature: "rule.allowlists[0].paths", Action: privacyengine.CompatibilityIgnored, Detail: "path criteria are unavailable for protocol text"},
	{Source: privacyengine.RuleSourceEmbedded, RuleID: "github-pat", Feature: "rule.allowlists[0].paths", Action: privacyengine.CompatibilityIgnored, Detail: "path criteria are unavailable for protocol text"},
	{Source: privacyengine.RuleSourceEmbedded, RuleID: "hashicorp-tf-password", Feature: "rule.path", Action: privacyengine.CompatibilitySkipped, Detail: "path-constrained rules do not run for pathless protocol text"},
	{Source: privacyengine.RuleSourceEmbedded, RuleID: "kubernetes-secret-yaml", Feature: "rule.path", Action: privacyengine.CompatibilitySkipped, Detail: "path-constrained rules do not run for pathless protocol text"},
	{Source: privacyengine.RuleSourceEmbedded, RuleID: "nuget-config-password", Feature: "rule.path", Action: privacyengine.CompatibilitySkipped, Detail: "path-constrained rules do not run for pathless protocol text"},
	{Source: privacyengine.RuleSourceEmbedded, RuleID: "pkcs12-file", Feature: "rule.path-only", Action: privacyengine.CompatibilitySkipped, Detail: "path-only rules cannot produce a protocol-text span"},
}

func validatePinnedEmbeddedRules(report privacyengine.CompatibilityReport) error {
	if fmt.Sprintf("%x", sha256.Sum256(embeddedGitleaks)) != embeddedGitleaksSHA256 {
		return fmt.Errorf("privacyfilter: embedded privacy rules do not match the pinned snapshot")
	}
	if report.RulesSeen != 222 || report.RulesLoaded != 217 || report.RulesSkipped != 5 {
		return fmt.Errorf("privacyfilter: embedded privacy rule compatibility summary changed")
	}
	if len(report.Issues) != len(expectedEmbeddedCompatibilityIssues) {
		return fmt.Errorf("privacyfilter: embedded privacy rule compatibility issues changed")
	}
	for index, got := range report.Issues {
		want := expectedEmbeddedCompatibilityIssues[index]
		if got.Source != want.Source || got.RuleID != want.RuleID || got.Feature != want.Feature || got.Action != want.Action || got.Detail != want.Detail {
			return fmt.Errorf("privacyfilter: embedded privacy rule compatibility issue %d changed", index)
		}
	}
	return nil
}

func (cfg privacyFilterConfig) loadRuleMaterial(pluginDir string) (ruleMaterial, error) {
	configured := strings.TrimSpace(cfg.GitleaksTOML)
	if configured == "" {
		// An omitted path always means the rules compiled into this library. Do not
		// let a writable or stale file beside the plugin silently replace policy.
		return ruleMaterial{embedded: embeddedGitleaks, source: "embedded"}, nil
	}

	path := configured
	if !filepath.IsAbs(path) {
		path = filepath.Join(pluginDir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ruleMaterial{}, fmt.Errorf("read configured privacy rules: %w", err)
	}
	mode := privacyengine.CustomRulesReplace
	if cfg.GitleaksMode == customRulesExtend {
		mode = privacyengine.CustomRulesExtend
	}
	compatibility := privacyengine.CompatibilityError
	if cfg.AllowUnsupportedRules {
		compatibility = privacyengine.CompatibilitySkipUnsupported
	}
	material := ruleMaterial{
		custom:              data,
		mode:                mode,
		customCompatibility: compatibility,
		source:              path,
	}
	if mode == privacyengine.CustomRulesExtend {
		material.embedded = embeddedGitleaks
	}
	return material, nil
}

func newEngine(pluginDir string, cfg privacyFilterConfig) (*privacyengine.Engine, privacyengine.CompatibilityReport, error) {
	material, err := cfg.loadRuleMaterial(pluginDir)
	if err != nil {
		return nil, privacyengine.CompatibilityReport{}, err
	}
	engineConfig := privacyengine.Config{
		EmbeddedTOML:          material.embedded,
		CustomTOML:            material.custom,
		CustomMode:            material.mode,
		EmbeddedCompatibility: privacyengine.CompatibilitySkipUnsupported,
		CustomCompatibility:   material.customCompatibility,
		DefaultLimits:         cfg.engineLimits(),
	}
	engine, report, err := privacyengine.New(engineConfig)
	if err != nil {
		return nil, report, fmt.Errorf("create privacy engine: %w", err)
	}

	if len(material.embedded) != 0 {
		embeddedReport := report
		if len(material.custom) != 0 {
			_, embeddedReport, err = privacyengine.New(privacyengine.Config{
				EmbeddedTOML:          material.embedded,
				EmbeddedCompatibility: privacyengine.CompatibilitySkipUnsupported,
				DefaultLimits:         cfg.engineLimits(),
			})
			if err != nil {
				return nil, embeddedReport, fmt.Errorf("validate embedded privacy rules: %w", err)
			}
		}
		if err = validatePinnedEmbeddedRules(embeddedReport); err != nil {
			return nil, report, err
		}
	}

	log.WithFields(log.Fields{
		"rules_seen":    report.RulesSeen,
		"rules_loaded":  report.RulesLoaded,
		"rules_skipped": report.RulesSkipped,
		"rule_source":   material.source,
	}).Info("privacyfilter: privacy engine loaded")
	return engine, report, nil
}
