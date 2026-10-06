package privacyengine

import (
	"context"
	"regexp"
	"sort"
	"strings"
)

// reURLUserinfo matches the "scheme://user:password@" prefix of a URL. The
// user part stops at the first ":" (RFC 3986 says the separator is the first
// colon) and may be empty, as in "redis://:password@host"; the password may
// contain further colons and runs up to the "@" that introduces the host.
// Neither part may contain whitespace, "/" or "@", and a host must follow so
// that "a:b@" at the end of a line is not accepted.
var reURLUserinfo = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://([^\s/@:]*):([^\s/@]+)@[^\s/@:]`)

// detectURLCredentials finds the password of a URL written in the form
// scheme://user:password@host. Only the password is a finding, so a database
// DSN or a Git remote keeps its scheme, user name, host, port and path and
// stays recognisable to the model; the token or placeholder sits exactly where
// the password was.
//
// It returns the ascending offsets of the "@" that ends each reported
// password. The email detector skips an address whose "@" is one of them:
// "p4ss@host.example.com" inside "https://user:p4ss@host.example.com" is the
// password and the host, not an address. Only a reported password suppresses
// an address, so nothing this detector declines can hide behind it.
func detectURLCredentials(ctx context.Context, text string, collector *spanCollector) ([]int, error) {
	if !strings.Contains(text, "://") {
		return nil, nil
	}
	var passwordEnds []int
	err := forEachSubmatchIndex(ctx, reURLUserinfo, text, func(indices []int) error {
		if len(indices) < 6 || indices[4] < 0 || indices[5] <= indices[4] || indices[5] > len(text) {
			return nil
		}
		start, end := indices[4], indices[5]
		// Documentation writes "user:password@host" with an obvious stand-in
		// such as ${DB_PASSWORD}, <password>, REPLACE_ME or "****".
		if isCredentialPlaceholder(text[start:end]) {
			return nil
		}
		if err := collector.add(span{start: start, end: end, kind: KindSecret, ruleID: rulePIIURLCredential}); err != nil {
			return err
		}
		passwordEnds = append(passwordEnds, end)
		return nil
	})
	return passwordEnds, err
}

// containsOffset reports whether the ascending offsets include offset.
func containsOffset(offsets []int, offset int) bool {
	i := sort.SearchInts(offsets, offset)
	return i < len(offsets) && offsets[i] == offset
}
