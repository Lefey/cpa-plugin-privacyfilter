package privacyengine

import (
	"context"
	"testing"
)

func FuzzNoPanic(f *testing.F) {
	engine := customEngine(f, `
[[rules]]
id = "fuzz-capture"
regex = '''api[ _-]?key[=: ]*([A-Za-z0-9+/=_-]{4,})'''
keywords = ["api"]
`)
	for _, seed := range []string{
		"",
		"api keyABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"前缀 token=abcDEF1234567890/xyzABC4567890== 后缀",
		string([]byte{0xff, 0xfe, 'a', 'p', 'i', ' ', 'k', 'e', 'y'}),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 {
			t.Skip()
		}
		_, _ = engine.Detect(context.Background(), input, RequestOptions{})
		_, _ = engine.Redact(context.Background(), input, RequestOptions{})
	})
}

func FuzzPIIDetectorsNoPanic(f *testing.F) {
	engine := piiEngine(f, "RU", "CN", "US")
	for _, seed := range []string{
		"",
		"+7 (914) 999-66-66 8 914 999 66 66 +(",
		"4111 1111 1111 1111 3782 822463 10005 1-2-3",
		"DE89 3704 0044 0532 0130 00 GB82WEST12345698765432 NO93",
		"::1 2001:db8::1. ::ffff:192.0.2.1: a::b",
		"иван@почта.рф +00 000 0",
		"postgres://u:p@h ://:@ https://a:b@[::1] x://u:${P}@h",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64<<10 {
			t.Skip()
		}
		findings, err := engine.Detect(context.Background(), input, RequestOptions{})
		if err != nil {
			return
		}
		previous := 0
		for _, finding := range findings {
			if finding.Start < previous || finding.Start >= finding.End || finding.End > len(input) {
				t.Fatalf("finding out of order or out of bounds: %+v", finding)
			}
			previous = finding.End
		}
	})
}
