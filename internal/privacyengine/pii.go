package privacyengine

// PII detection in this file is derived from packyme/privacy-filter/filter/pii.go
// at commit 64b8de3c2060. See LICENSE in this directory.

import (
	"context"
	"net/netip"
	"regexp"
	"strings"
)

// Letters of scripts that separate words with spaces. CJK is left out on
// purpose: in text without spaces it would pull the neighbouring words into
// the address.
const emailLetters = `\p{Latin}\p{Cyrillic}\p{Greek}`

var (
	reEmail = regexp.MustCompile(`[` + emailLetters + `0-9._%+\-]+@[` + emailLetters + `0-9.\-]+\.[` + emailLetters + `]{2,}`)
	reIPv4  = regexp.MustCompile(`(?:(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])`)
	// A generous IPv6 candidate; net/netip decides.
	reIPv6 = regexp.MustCompile(`[0-9A-Fa-f:.]{3,45}`)
)

var sshCommands = []string{"ssh ", "scp ", "rsync ", "sftp ", "ssh-copy-id ", "ssh-keygen "}

func isInSSHCommandContext(text string, emailStart int) bool {
	if emailStart < 0 || emailStart > len(text) {
		return false
	}
	lineStart := strings.LastIndexByte(text[:emailStart], '\n') + 1
	line := text[lineStart:emailStart]
	for _, command := range sshCommands {
		if strings.Contains(line, command) {
			return true
		}
	}
	return false
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func ipBounded(text string, start, end int) bool {
	if start < 0 || start > end || end > len(text) {
		return false
	}
	if start > 0 && (isDigit(text[start-1]) || text[start-1] == '.') {
		return false
	}
	if end < len(text) && (isDigit(text[end]) || text[end] == '.') {
		return false
	}
	return true
}

func detectPII(ctx context.Context, text string, phoneRegions []phoneRegion, collector *spanCollector) error {
	// A URL password is added before the email detector so that the password
	// span, not a "password@host" address, decides the finding.
	if err := detectURLCredentials(ctx, text, collector); err != nil {
		return err
	}
	if err := forEachMatchIndex(ctx, reEmail, text, func(start, end int) error {
		if end < len(text) && text[end] == ':' && end+1 < len(text) && text[end+1] != ' ' && text[end+1] != '\t' {
			return nil
		}
		if isInSSHCommandContext(text, start) {
			return nil
		}
		if isURLUserinfoAt(text, start+strings.IndexByte(text[start:end], '@')) {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindEmail, ruleID: rulePIIEmail})
	}); err != nil {
		return err
	}
	hasDigit := false
	for i := 0; i < len(text); i++ {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if isDigit(text[i]) {
			hasDigit = true
			break
		}
	}
	if !hasDigit {
		return nil
	}

	if err := forEachMatchIndex(ctx, reIPv4, text, func(start, end int) error {
		if !ipBounded(text, start, end) {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindIP, ruleID: rulePIIIPv4})
	}); err != nil {
		return err
	}
	if err := detectIPv6(ctx, text, collector); err != nil {
		return err
	}
	// An IBAN is added before the card and phone detectors so that digit groups
	// inside it keep the IBAN kind when their spans are merged.
	if err := detectIBAN(ctx, text, collector); err != nil {
		return err
	}
	if err := detectBankCards(ctx, text, collector); err != nil {
		return err
	}
	return detectPhones(ctx, text, phoneRegions, collector)
}

func isASCIIWordByte(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || b == '_'
}

// detectIPv6 accepts a candidate only if it parses as an IPv6 address and
// contains a digit. The digit requirement keeps scope operators between
// hexadecimal-looking identifiers ("fade::bed") out.
func detectIPv6(ctx context.Context, text string, collector *spanCollector) error {
	if strings.Count(text, ":") < 2 {
		return nil
	}
	return forEachMatchIndex(ctx, reIPv6, text, func(start, end int) error {
		if start > 0 && (isASCIIWordByte(text[start-1]) || text[start-1] == ':' || text[start-1] == '.') {
			return nil
		}
		if end < len(text) && isASCIIWordByte(text[end]) {
			return nil
		}
		// Sentence punctuation after the address is not part of it.
		for end > start && text[end-1] == '.' {
			end--
		}
		if end-start >= 2 && text[end-1] == ':' && text[end-2] != ':' {
			end--
		}
		candidate := text[start:end]
		if strings.Count(candidate, ":") < 2 || strings.IndexAny(candidate, "0123456789") < 0 {
			return nil
		}
		addr, err := netip.ParseAddr(candidate)
		if err != nil || !addr.Is6() {
			return nil
		}
		return collector.add(span{start: start, end: end, kind: KindIP, ruleID: rulePIIIPv6})
	})
}

type digitGroup struct{ start, end int }

// maxCardGroups is the largest number of groups in a written card number
// (4-4-4-4-3).
const maxCardGroups = 5

// detectBankCards finds Luhn-valid card numbers of 13 to 19 digits that start
// with a payment-network digit, written either without separators or in a
// usual card layout with single spaces or hyphens. Requiring a layout keeps
// dates, timestamps and other separated numbers from being tested against the
// checksum at all.
func detectBankCards(ctx context.Context, text string, collector *spanCollector) error {
	var groups []digitGroup
	var separators []byte
	flush := func() error {
		defer func() { groups, separators = groups[:0], separators[:0] }()
		for i := 0; i < len(groups); {
			// Digits after a "+" are a phone number in international format,
			// even if they happen to satisfy the card checksum.
			if i == 0 && groups[0].start > 0 && text[groups[0].start-1] == '+' {
				i++
				continue
			}
			// Every payment network issues from major industry identifiers 2
			// to 6 (Mir and Mastercard 2, Amex, Diners and JCB 3, Visa 4,
			// Mastercard and Maestro 5, Discover, UnionPay and Maestro 6).
			// Other leading digits keep amounts such as "1000 2000 3000 4000"
			// that happen to satisfy the checksum from being reported.
			if first := text[groups[i].start]; first < '2' || first > '6' {
				i++
				continue
			}
			matched := false
			last := i + maxCardGroups - 1
			if last >= len(groups) {
				last = len(groups) - 1
			}
			for j := last; j >= i; j-- {
				if !cardLayout(groups[i:j+1], separators[i:j]) || !luhnGroups(text, groups[i:j+1]) {
					continue
				}
				if err := collector.add(span{start: groups[i].start, end: groups[j].end, kind: KindBankCard, ruleID: rulePIIBankCard}); err != nil {
					return err
				}
				i, matched = j+1, true
				break
			}
			if !matched {
				i++
			}
		}
		return nil
	}
	for i := 0; i < len(text); {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if !isDigit(text[i]) {
			i++
			continue
		}
		start := i
		for i < len(text) && isDigit(text[i]) {
			i++
		}
		groups = append(groups, digitGroup{start, i})
		if i+1 < len(text) && (text[i] == ' ' || text[i] == '-') && isDigit(text[i+1]) {
			separators = append(separators, text[i])
			i++
			continue
		}
		if err := flush(); err != nil {
			return err
		}
	}
	return nil
}

// cardLayout reports whether the groups are one unbroken number, groups of
// four with a shorter last group, or the 4-6-5 and 4-6-4 layouts, joined by
// one and the same separator.
func cardLayout(groups []digitGroup, separators []byte) bool {
	digits := 0
	for _, group := range groups {
		digits += group.end - group.start
	}
	if digits < 13 || digits > 19 {
		return false
	}
	if len(groups) == 1 {
		return true
	}
	for _, separator := range separators[1:] {
		if separator != separators[0] {
			return false
		}
	}
	size := func(i int) int { return groups[i].end - groups[i].start }
	if len(groups) == 3 && size(0) == 4 && size(1) == 6 && (size(2) == 5 || size(2) == 4) {
		return true
	}
	for i := 0; i < len(groups)-1; i++ {
		if size(i) != 4 {
			return false
		}
	}
	return size(len(groups)-1) <= 4
}

func luhnGroups(text string, groups []digitGroup) bool {
	sum := 0
	double := false
	for g := len(groups) - 1; g >= 0; g-- {
		for i := groups[g].end - 1; i >= groups[g].start; i-- {
			digit := int(text[i] - '0')
			if double {
				digit *= 2
				if digit > 9 {
					digit -= 9
				}
			}
			sum += digit
			double = !double
		}
	}
	return sum%10 == 0
}
