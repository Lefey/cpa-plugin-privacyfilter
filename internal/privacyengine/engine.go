package privacyengine

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

// Config constructs an immutable Engine from TOML bytes. EmbeddedTOML is the
// repository-pinned snapshot. CustomTOML, when present, requires an explicit
// Extend or Replace mode. The custom compatibility policy defaults to strict
// rejection; skipping unsupported embedded snapshot features is also opt-in.
type Config struct {
	EmbeddedTOML          []byte
	CustomTOML            []byte
	CustomMode            CustomRuleMode
	EmbeddedCompatibility CompatibilityPolicy
	CustomCompatibility   CompatibilityPolicy
	DefaultLimits         Limits
	// PhoneRegions lists the ISO 3166-1 alpha-2 regions whose national phone
	// number formats are recognised. Numbers in international format are
	// recognised for every country without it.
	PhoneRegions []string
}

// Engine is immutable after construction and safe for concurrent use.
type Engine struct {
	rules            []secretRule
	globalAllowlists []compiledAllowlist
	limits           Limits
	phoneRegions     []phoneRegion
	report           CompatibilityReport
}

// New parses, validates, and compiles the configured rulesets.
func New(config Config) (*Engine, CompatibilityReport, error) {
	var report CompatibilityReport
	limits, err := normalizeLimits(config.DefaultLimits)
	if err != nil {
		return nil, report, err
	}
	phoneRegions, err := normalizePhoneRegions(config.PhoneRegions)
	if err != nil {
		return nil, report, err
	}
	if !validCompatibilityPolicy(config.EmbeddedCompatibility) || !validCompatibilityPolicy(config.CustomCompatibility) {
		return nil, report, fmt.Errorf("privacyengine: invalid compatibility policy")
	}

	hasEmbedded := len(config.EmbeddedTOML) != 0
	hasCustom := len(config.CustomTOML) != 0
	if hasCustom && config.CustomMode == CustomRulesNone {
		return nil, report, fmt.Errorf("privacyengine: custom TOML requires explicit extend or replace mode")
	}
	if !hasCustom && config.CustomMode != CustomRulesNone {
		return nil, report, fmt.Errorf("privacyengine: custom rule mode set without custom TOML")
	}
	if config.CustomMode != CustomRulesNone && config.CustomMode != CustomRulesExtend && config.CustomMode != CustomRulesReplace {
		return nil, report, fmt.Errorf("privacyengine: invalid custom rule mode")
	}
	if !hasEmbedded && !hasCustom {
		return nil, report, fmt.Errorf("privacyengine: no TOML rules supplied")
	}

	var embedded, custom parsedRuleSet
	if config.CustomMode != CustomRulesReplace {
		if !hasEmbedded {
			return nil, report, fmt.Errorf("privacyengine: extend mode requires embedded TOML")
		}
		embedded, err = parseRuleSet(config.EmbeddedTOML, RuleSourceEmbedded, config.EmbeddedCompatibility)
		report.append(embedded.report)
		if err != nil {
			return nil, report, errWithCombinedReport(err, report)
		}
	}
	if hasCustom {
		custom, err = parseRuleSet(config.CustomTOML, RuleSourceCustom, config.CustomCompatibility)
		report.append(custom.report)
		if err != nil {
			return nil, report, errWithCombinedReport(err, report)
		}
	}

	rules := append([]secretRule(nil), embedded.rules...)
	globalAllowlists := append([]compiledAllowlist(nil), embedded.globalAllowlists...)
	if hasCustom {
		if config.CustomMode == CustomRulesReplace {
			rules = append(rules, custom.rules...)
			globalAllowlists = append(globalAllowlists, custom.globalAllowlists...)
		} else {
			ids := make(map[string]struct{}, len(rules)+len(custom.rules))
			for _, rule := range rules {
				ids[rule.id] = struct{}{}
			}
			for _, rule := range custom.rules {
				if _, duplicate := ids[rule.id]; duplicate {
					action := CompatibilityRejected
					if config.CustomCompatibility == CompatibilitySkipUnsupported {
						action = CompatibilitySkipped
					}
					report.Issues = append(report.Issues, CompatibilityIssue{
						Source: RuleSourceCustom, RuleID: rule.id, Feature: "rule.id",
						Action: action, Detail: "custom rule id duplicates an embedded rule",
					})
					report.RulesLoaded--
					if action == CompatibilitySkipped {
						report.RulesSkipped++
						continue
					}
					return nil, report, &RulesCompatibilityError{Report: report}
				}
				ids[rule.id] = struct{}{}
				rules = append(rules, rule)
			}
			globalAllowlists = append(globalAllowlists, custom.globalAllowlists...)
		}
	}

	engine := &Engine{
		rules:            rules,
		globalAllowlists: globalAllowlists,
		limits:           limits,
		phoneRegions:     phoneRegions,
		report:           cloneReport(report),
	}
	return engine, cloneReport(report), nil
}

func validCompatibilityPolicy(policy CompatibilityPolicy) bool {
	return policy == CompatibilityError || policy == CompatibilitySkipUnsupported
}

func errWithCombinedReport(err error, report CompatibilityReport) error {
	if _, ok := err.(*RulesCompatibilityError); ok {
		return &RulesCompatibilityError{Report: cloneReport(report)}
	}
	return err
}

func cloneReport(report CompatibilityReport) CompatibilityReport {
	cloned := report
	cloned.Issues = append([]CompatibilityIssue(nil), report.Issues...)
	return cloned
}

// CompatibilityReport returns a defensive copy of the construction report.
func (e *Engine) CompatibilityReport() CompatibilityReport {
	if e == nil {
		return CompatibilityReport{}
	}
	return cloneReport(e.report)
}

// Stats returns loaded and skipped whole-rule counts.
func (e *Engine) Stats() (loaded, skipped int) {
	if e == nil {
		return 0, 0
	}
	return e.report.RulesLoaded, e.report.RulesSkipped
}

// Detect returns sorted, disjoint findings whose offsets index text. It never
// stores matched plaintext in a Finding.
func (e *Engine) Detect(ctx context.Context, text string, options RequestOptions) (findings []Finding, err error) {
	defer func() {
		if recover() != nil {
			findings = nil
			err = ErrInternalFailure
		}
	}()
	return e.detect(ctx, text, options)
}

func (e *Engine) detect(ctx context.Context, text string, options RequestOptions) ([]Finding, error) {
	if ctx == nil {
		return nil, ErrNilContext
	}
	if e == nil {
		return nil, ErrNilEngine
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	budget := options.Budget
	if budget == nil {
		budget = newBudgetUnchecked(e.limits)
	}
	if err := budget.takeNode(len(text)); err != nil {
		return nil, err
	}

	if options.PreservePlaceholder {
		return nil, nil
	}

	collector := newSpanCollector(len(text), budget.remainingFindings(), options.PreferredRuleIDs)
	if !credentialFieldApplies(options.FieldContext) || !isCredentialPlaceholder(text) {
		if err := detectCredentialField(text, collector, options.FieldContext); err != nil {
			return nil, err
		}
	}
	if err := detectPII(ctx, text, e.phoneRegions, collector); err != nil {
		return nil, err
	}
	if err := e.detectSecrets(ctx, text, collector); err != nil {
		return nil, err
	}
	findings := collector.findings()
	if err := budget.takeFindings(len(findings)); err != nil {
		return nil, err
	}
	return findings, nil
}

// Redact detects and replaces spans in one pass. A renderer failure returns the
// original input and no partially rebuilt text.
func (e *Engine) Redact(ctx context.Context, text string, options RequestOptions) (result Redaction, err error) {
	result.Redacted = text
	defer func() {
		if recover() != nil {
			result = Redaction{Redacted: text}
			err = ErrInternalFailure
		}
	}()

	findings, err := e.detect(ctx, text, options)
	if err != nil {
		return result, err
	}
	result.Findings = findings
	if len(findings) == 0 {
		return result, nil
	}

	renderer := options.Renderer
	if renderer == nil {
		renderer = DefaultRenderer()
	}
	replacements := make([]string, len(findings))
	for i, finding := range findings {
		if err := ctx.Err(); err != nil {
			return Redaction{Redacted: text, Findings: findings}, err
		}
		if finding.Start < 0 || finding.Start >= finding.End || finding.End > len(text) {
			return Redaction{Redacted: text}, ErrInternalFailure
		}
		replacement, renderErr := renderer.Render(ctx, finding, text[finding.Start:finding.End])
		if renderErr != nil {
			return Redaction{Redacted: text, Findings: findings}, fmt.Errorf("privacyengine: renderer failed")
		}
		replacements[i] = replacement
	}

	var builder strings.Builder
	previous := 0
	for i, finding := range findings {
		builder.WriteString(text[previous:finding.Start])
		builder.WriteString(replacements[i])
		previous = finding.End
	}
	builder.WriteString(text[previous:])
	result.Redacted = builder.String()
	return result, nil
}

type span struct {
	start  int
	end    int
	kind   Kind
	ruleID string
}

// spanCollector incrementally unions overlapping spans, preserving the
// metadata of the first accepted detector layer. This prevents a wider later
// finding from leaving a sensitive suffix visible while keeping the output
// sorted and disjoint.
type spanCollector struct {
	textLen   int
	max       int
	preferred map[string]struct{}
	spans     []span
}

func newSpanCollector(textLen, maxFindings int, preferred map[string]struct{}) *spanCollector {
	if maxFindings < 0 {
		maxFindings = 0
	}
	return &spanCollector{textLen: textLen, max: maxFindings, preferred: preferred}
}

func (c *spanCollector) add(candidate span) error {
	if candidate.start < 0 || candidate.start >= candidate.end || candidate.end > c.textLen {
		return nil
	}
	i := sort.Search(len(c.spans), func(i int) bool { return c.spans[i].end > candidate.start })
	j := i
	merged := candidate
	metadataPreferred := c.isPreferred(merged.ruleID)
	for j < len(c.spans) && c.spans[j].start < merged.end {
		existing := c.spans[j]
		existingPreferred := c.isPreferred(existing.ruleID)
		if (j == i && !metadataPreferred) || (!metadataPreferred && existingPreferred) {
			merged.kind = existing.kind
			merged.ruleID = existing.ruleID
			metadataPreferred = existingPreferred
		}
		if existing.start < merged.start {
			merged.start = existing.start
		}
		if existing.end > merged.end {
			merged.end = existing.end
		}
		j++
	}
	newCount := len(c.spans) + 1 - (j - i)
	if newCount > c.max {
		return &LimitError{Resource: ResourceFindings, Limit: c.max, Used: len(c.spans), Requested: 1}
	}
	if j == i {
		c.spans = append(c.spans, span{})
		copy(c.spans[i+1:], c.spans[i:])
		c.spans[i] = merged
		return nil
	}
	c.spans[i] = merged
	copy(c.spans[i+1:], c.spans[j:])
	c.spans = c.spans[:newCount]
	return nil
}

func (c *spanCollector) isPreferred(ruleID string) bool {
	_, ok := c.preferred[ruleID]
	return ok
}

func (c *spanCollector) findings() []Finding {
	if len(c.spans) == 0 {
		return nil
	}
	findings := make([]Finding, len(c.spans))
	for i, item := range c.spans {
		findings[i] = Finding{Kind: item.kind, RuleID: item.ruleID, Start: item.start, End: item.end}
	}
	return findings
}
