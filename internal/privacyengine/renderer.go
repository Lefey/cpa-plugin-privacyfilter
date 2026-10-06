package privacyengine

import (
	"context"
	"fmt"
)

var defaultPlaceholders = map[Kind]string{
	KindEmail:    "[邮箱]",
	KindPhone:    "[电话]",
	KindBankCard: "[银行卡]",
	KindIBAN:     "[IBAN]",
	KindIP:       "[IP]",
	KindSecret:   "[密钥]",
}

// PlaceholderRenderer emits one typed placeholder per Kind. Its map is copied
// at construction, so a renderer can safely be shared by concurrent scans.
type PlaceholderRenderer struct {
	placeholders map[Kind]string
}

// NewPlaceholderRenderer starts with the package's existing typed labels and
// applies the supplied overrides. An empty replacement is valid and removes a
// matched value.
func NewPlaceholderRenderer(overrides map[Kind]string) *PlaceholderRenderer {
	placeholders := make(map[Kind]string, len(defaultPlaceholders))
	for kind, placeholder := range defaultPlaceholders {
		placeholders[kind] = placeholder
	}
	for kind, placeholder := range overrides {
		placeholders[kind] = placeholder
	}
	return &PlaceholderRenderer{placeholders: placeholders}
}

// DefaultRenderer returns a renderer for the existing PII and secret labels.
func DefaultRenderer() Renderer { return NewPlaceholderRenderer(nil) }

// Render implements Renderer. It deliberately ignores plaintext.
func (r *PlaceholderRenderer) Render(ctx context.Context, finding Finding, _ string) (string, error) {
	if ctx == nil {
		return "", ErrNilContext
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if r == nil {
		return "", ErrNilRenderer
	}
	placeholder, ok := r.placeholders[finding.Kind]
	if !ok {
		return "", fmt.Errorf("privacyengine: no placeholder for finding kind %q", finding.Kind)
	}
	return placeholder, nil
}
