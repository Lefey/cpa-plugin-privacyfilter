package privacyengine

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/nyaruka/phonenumbers"
)

const (
	// A written phone number rarely has more groups than "+33 1 23 45 67 89".
	maxPhoneGroups = 8
	minPhoneDigits = 7
	// E.164 allows 15 digits; a national trunk prefix can add a few more.
	maxPhoneDigits = 17
)

// normalizePhoneRegions validates ISO 3166-1 alpha-2 region codes against the
// phone metadata and returns them upper-cased, in order, without duplicates.
func normalizePhoneRegions(regions []string) ([]phoneRegion, error) {
	if len(regions) == 0 {
		return nil, nil
	}
	supported := phonenumbers.GetSupportedRegions()
	out := make([]phoneRegion, 0, len(regions))
	seen := make(map[string]struct{}, len(regions))
	for _, region := range regions {
		code := strings.ToUpper(strings.TrimSpace(region))
		if !supported[code] {
			return nil, fmt.Errorf("privacyengine: unsupported phone region %q", region)
		}
		if _, duplicate := seen[code]; duplicate {
			return nil, fmt.Errorf("privacyengine: duplicate phone region %q", region)
		}
		seen[code] = struct{}{}
		out = append(out, phoneRegion{
			code:        code,
			callingCode: int32(phonenumbers.GetCountryCodeForRegion(code)),
			trunkPrefix: phonenumbers.GetNddPrefixForRegion(code, true),
		})
	}
	return out, nil
}

func isPhoneSeparator(b byte) bool {
	return b == ' ' || b == '\t' || b == '.' || b == '-' || b == '(' || b == ')'
}

// phoneHead reports whether a phone candidate may start at i: a "+" or the
// first digit of a digit group that is not the continuation of a word or of a
// larger numeric token such as a date, a version or a decimal fraction.
func phoneHead(text string, i int) (plus, ok bool) {
	switch {
	case text[i] == '+':
		j := i + 1
		if j < len(text) && text[j] == '(' {
			j++
		}
		if j >= len(text) || !isDigit(text[j]) {
			return false, false
		}
		if i > 0 && (isASCIIWordByte(text[i-1]) || text[i-1] == '+') {
			return false, false
		}
		return true, true
	case isDigit(text[i]):
		if i == 0 {
			return false, true
		}
		previous := text[i-1]
		if isASCIIWordByte(previous) || previous == '+' {
			return false, false
		}
		if i > 1 && isDigit(text[i-2]) && (previous == '.' || previous == ',' || previous == '-' || previous == '/' || previous == ':') {
			return false, false
		}
		return false, true
	default:
		return false, false
	}
}

// detectPhones validates candidates with the libphonenumber metadata. A number
// in international format ("+" and a country code) is recognised for every
// country. A number in national format is recognised only for the configured
// regions, because the same digits are a phone number in one country and an
// ordinary number in another.
func detectPhones(ctx context.Context, text string, regions []phoneRegion, collector *spanCollector) error {
	if len(regions) == 0 && strings.IndexByte(text, '+') < 0 {
		return nil
	}
	var ends [maxPhoneGroups]int
	var digits [maxPhoneGroups]int
	for i := 0; i < len(text); i++ {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		plus, ok := phoneHead(text, i)
		if !ok || (!plus && len(regions) == 0) {
			if isDigit(text[i]) {
				// Not a head: skip the rest of this digit group.
				for i+1 < len(text) && isDigit(text[i+1]) {
					i++
				}
			}
			continue
		}

		// Collect up to maxPhoneGroups digit groups joined by one separator.
		groups, total := 0, 0
		j := i
		if plus {
			j++
		}
		for groups < maxPhoneGroups {
			k := j
			if k < len(text) && isPhoneSeparator(text[k]) {
				k++
				// A second separator only next to a bracket: ") " or " (".
				if k < len(text) && isPhoneSeparator(text[k]) && (text[k] == '(' || text[k-1] == ')' || text[k-1] == '(') {
					k++
				}
			}
			if k >= len(text) || !isDigit(text[k]) || (groups == 0 && k != j && !(k == j+1 && text[j] == '(')) {
				break
			}
			first := k
			for k < len(text) && isDigit(text[k]) {
				k++
			}
			// A lone digit is a country or trunk code, or the area code right
			// after one; further on it is a column of unrelated numbers.
			if k-first == 1 && groups >= 2 {
				break
			}
			total += k - first
			ends[groups], digits[groups] = k, total
			groups++
			j = k
		}
		if groups == 0 {
			continue
		}

		matchedEnd := -1
		for g := groups - 1; g >= 0 && digits[g] >= minPhoneDigits; g-- {
			end := ends[g]
			if digits[g] > maxPhoneDigits || (end < len(text) && isASCIIWordByte(text[end])) {
				continue
			}
			if validPhone(text[i:end], plus, regions) {
				matchedEnd = end
				break
			}
		}
		if matchedEnd < 0 {
			// Let the next group be a head of its own.
			i = ends[0] - 1
			continue
		}
		if err := collector.add(span{start: i, end: matchedEnd, kind: KindPhone, ruleID: rulePIIPhone}); err != nil {
			return err
		}
		i = matchedEnd - 1
	}
	return nil
}

// phoneRegion is the part of the metadata needed to read a number written in
// a region's national format.
type phoneRegion struct {
	code        string
	callingCode int32
	// trunkPrefix is the national dialling prefix ("8" in RU, "0" in most of
	// Europe) that is written before the number but is not part of it.
	trunkPrefix string
}

// callingCodes maps a country calling code to the trunk prefix of its main
// region. Calling codes are prefix-free, so at most one of the first one, two
// or three digits of an international number is a key.
var callingCodes = sync.OnceValue(func() map[int32]string {
	codes := make(map[int32]string)
	for region := range phonenumbers.GetSupportedRegions() {
		code := int32(phonenumbers.GetCountryCodeForRegion(region))
		if _, seen := codes[code]; !seen {
			codes[code] = phonenumbers.GetNddPrefixForRegion(phonenumbers.GetRegionCodeForCountryCode(int(code)), true)
		}
	}
	return codes
})

// validPhone checks the digits of a candidate against the metadata directly.
// phonenumbers.Parse would do the same after its own, far more expensive,
// lexical analysis, which the caller has already done.
func validPhone(candidate string, plus bool, regions []phoneRegion) bool {
	var buffer [maxPhoneDigits]byte
	digits := buffer[:0]
	for i := 0; i < len(candidate); i++ {
		if isDigit(candidate[i]) {
			digits = append(digits, candidate[i])
		}
	}
	if !plus {
		for i := range regions {
			region := &regions[i]
			if validNationalNumber(region.callingCode, region.code, region.trunkPrefix, digits) {
				return true
			}
		}
		return false
	}
	codes := callingCodes()
	code := int32(0)
	for i := 0; i < 3 && i < len(digits); i++ {
		code = code*10 + int32(digits[i]-'0')
		if trunkPrefix, known := codes[code]; known {
			return validNationalNumber(code, "", trunkPrefix, digits[i+1:])
		}
	}
	return false
}

// validNationalNumber accepts the digits as written or without the trunk
// prefix. An empty region means any region that shares the calling code.
func validNationalNumber(callingCode int32, region, trunkPrefix string, digits []byte) bool {
	if validSignificantNumber(callingCode, region, digits) {
		return true
	}
	if trunkPrefix == "" || !strings.HasPrefix(string(digits), trunkPrefix) {
		return false
	}
	return validSignificantNumber(callingCode, region, digits[len(trunkPrefix):])
}

func validSignificantNumber(callingCode int32, region string, digits []byte) bool {
	if len(digits) < 4 || len(digits) > 15 {
		return false
	}
	// A leading zero that belongs to the number (Italy) is carried separately
	// because the number itself is stored as an integer.
	zeros := 0
	for zeros < len(digits)-1 && digits[zeros] == '0' {
		zeros++
	}
	var national uint64
	for _, digit := range digits {
		national = national*10 + uint64(digit-'0')
	}
	number := &phonenumbers.PhoneNumber{CountryCode: &callingCode, NationalNumber: &national}
	if zeros > 0 {
		leadingZero, count := true, int32(zeros)
		number.ItalianLeadingZero, number.NumberOfLeadingZeros = &leadingZero, &count
	}
	if region == "" {
		return phonenumbers.IsValidNumber(number)
	}
	return phonenumbers.IsValidNumberForRegion(number, region)
}
