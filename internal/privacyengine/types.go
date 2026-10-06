package privacyengine

import (
	"context"
	"errors"
	"fmt"
)

// Kind classifies a finding and selects its typed placeholder.
type Kind string

const (
	KindEmail    Kind = "email"
	KindPhone    Kind = "phone"
	KindBankCard Kind = "bank_card"
	KindIBAN     Kind = "iban"
	KindIP       Kind = "ip"
	KindSecret   Kind = "secret"
)

const (
	rulePIIEmail         = "pii.email"
	rulePIIPhone         = "pii.phone"
	rulePIIBankCard      = "pii.bank-card"
	rulePIIIPv4          = "pii.ipv4"
	rulePIIIPv6          = "pii.ipv6"
	rulePIIIBAN          = "pii.iban"
	rulePIIURLCredential = "pii.url-credential"
	ruleContextSecret    = "builtin.context-secret"
	ruleHighEntropy      = "builtin.high-entropy"
	ruleCredentialField  = "builtin.credential-field"
)

// Finding describes a sensitive byte span. Start is inclusive and End is
// exclusive. Finding intentionally has no field containing the matched text;
// callers that explicitly need it can use source[Start:End] while processing
// the result and avoid retaining another plaintext copy.
type Finding struct {
	Kind   Kind   `json:"kind"`
	RuleID string `json:"rule_id"`
	Start  int    `json:"start"`
	End    int    `json:"end"`
}

// Redaction is the result of Redact. Findings refer to byte offsets in the
// original input, not in Redacted.
type Redaction struct {
	Redacted string    `json:"redacted"`
	Findings []Finding `json:"findings,omitempty"`
}

// Hit reports whether any span was redacted.
func (r Redaction) Hit() bool { return len(r.Findings) != 0 }

// Renderer produces a replacement for one finding. Plaintext is passed only
// for the duration of this call; it is not retained in Finding or by the
// engine. A request-scoped renderer may use that value to maintain a reversible
// map, while the default renderer ignores it and emits a typed placeholder.
type Renderer interface {
	Render(ctx context.Context, finding Finding, plaintext string) (string, error)
}

// RendererFunc adapts a function to Renderer.
type RendererFunc func(context.Context, Finding, string) (string, error)

// Render implements Renderer.
func (f RendererFunc) Render(ctx context.Context, finding Finding, plaintext string) (string, error) {
	if f == nil {
		return "", ErrNilRenderer
	}
	return f(ctx, finding, plaintext)
}

// ToolScope identifies whether a structured string came from recognized tool
// input or output. Empty means no tool scope and disables credential-field
// whole-value matching.
type ToolScope string

const (
	ToolScopeInput  ToolScope = "tool-input"
	ToolScopeOutput ToolScope = "tool-output"
)

const MaxFieldContextAncestors = 4

// FieldContext contains bounded field names and semantic flags only. It must
// never contain request values or complete paths.
type FieldContext struct {
	ImmediateKey  string
	Ancestors     [MaxFieldContextAncestors]string
	AncestorCount uint8
	ToolScope     ToolScope
	Structured    bool
	Encoded       bool
}

// RequestOptions carries request-scoped state. Reuse one Budget across all
// text nodes in a request so byte, finding, and node limits are cumulative.
// Renderer is consulted only by Redact and may itself hold request-scoped
// pseudonym state. PreferredRuleIDs preserves action-bearing rule metadata when
// its span overlaps another detector's finding.
type RequestOptions struct {
	Budget           *Budget
	Renderer         Renderer
	PreferredRuleIDs map[string]struct{}
	FieldContext     FieldContext
	// PreservePlaceholder marks a renderer-produced configured placeholder. It
	// carries no request value and still consumes the ordinary node/byte budget.
	PreservePlaceholder bool
}

var (
	// ErrNilContext is returned instead of dereferencing a nil context.
	ErrNilContext = errors.New("privacyengine: nil context")
	// ErrNilEngine is returned when an exported method is called on a nil engine.
	ErrNilEngine = errors.New("privacyengine: nil engine")
	// ErrNilRenderer is returned for a typed-nil RendererFunc.
	ErrNilRenderer = errors.New("privacyengine: nil renderer")
	// ErrBudgetExceeded identifies a request that exhausted a configured limit.
	ErrBudgetExceeded = errors.New("privacyengine: resource budget exceeded")
	// ErrInternalFailure is a defense-in-depth result if an internal or custom
	// renderer panic reaches an API boundary. Panic values are intentionally not
	// included because they may contain request plaintext.
	ErrInternalFailure = errors.New("privacyengine: internal failure")
	// ErrIncompatibleRules identifies unsupported or invalid TOML semantics.
	ErrIncompatibleRules = errors.New("privacyengine: incompatible rules")
)

// Resource identifies one budget dimension.
type Resource string

const (
	ResourceBytes    Resource = "bytes"
	ResourceFindings Resource = "findings"
	ResourceNodes    Resource = "nodes"
)

// LimitError reports a budget refusal without including request content.
type LimitError struct {
	Resource  Resource
	Limit     int
	Used      int
	Requested int
}

func (e *LimitError) Error() string {
	if e == nil {
		return ErrBudgetExceeded.Error()
	}
	return fmt.Sprintf("%s: %s limit %d (used %d, requested %d)", ErrBudgetExceeded, e.Resource, e.Limit, e.Used, e.Requested)
}

// Unwrap makes errors.Is(err, ErrBudgetExceeded) work.
func (e *LimitError) Unwrap() error { return ErrBudgetExceeded }
