package privacyengine

import (
	"context"
	"regexp"
)

// reURLUserinfo matches the "scheme://user:password@" prefix of a URL. The
// user part stops at the first ":" (RFC 3986 says the separator is the first
// colon); the password may contain further colons and runs up to the "@" that
// introduces the host. Neither part may contain whitespace, "/" or "@", and a
// host must follow so that "a:b@" at the end of a line is not accepted.
var reURLUserinfo = regexp.MustCompile(`[A-Za-z][A-Za-z0-9+.\-]*://([^\s/@:]+):([^\s/@]+)@[A-Za-z0-9\[]`)

// detectURLCredentials finds the password of a URL written in the form
// scheme://user:password@host. Only the password is a finding, so a database
// DSN or a Git remote keeps its scheme, user name, host, port and path and
// stays recognisable to the model; the token or placeholder sits exactly where
// the password was.
func detectURLCredentials(ctx context.Context, text string, collector *spanCollector) error {
	return forEachSubmatchIndex(ctx, reURLUserinfo, text, func(indices []int) error {
		if len(indices) < 6 || indices[4] < 0 || indices[5] <= indices[4] || indices[5] > len(text) {
			return nil
		}
		start, end := indices[4], indices[5]
		// Documentation writes "user:password@host" with an obvious stand-in
		// such as ${DB_PASSWORD}, <password>, REPLACE_ME or "****".
		if isCredentialPlaceholder(text[start:end]) {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindSecret, ruleID: rulePIIURLCredential})
	})
}

// isURLUserinfoAt reports whether the "@" at text[at] ends the user:password
// part of a URL, i.e. "scheme://" and a user name with a colon precede it. The
// email detector uses it so that "p4ss@host.example.com" inside
// "https://user:p4ss@host.example.com" is not taken for an address.
func isURLUserinfoAt(text string, at int) bool {
	if at < 0 || at >= len(text) || text[at] != '@' {
		return false
	}
	sawColon := false
	i := at - 1
	for i >= 0 && (isURLUserinfoByte(text[i]) || text[i] == ':') {
		sawColon = sawColon || text[i] == ':'
		i--
	}
	return sawColon && i >= 2 && text[i] == '/' && text[i-1] == '/' && text[i-2] == ':'
}

func isURLUserinfoByte(b byte) bool {
	switch b {
	case ' ', '\t', '\r', '\n', '/', '@', ':':
		return false
	}
	return true
}
