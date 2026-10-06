package privacyengine

import "context"

// ibanLengths is the total IBAN length per country from the SWIFT IBAN
// registry. The length is fixed per country, so a candidate needs no trimming:
// it either has exactly this many characters or it is not an IBAN.
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
	"BH": 22, "BI": 27, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24,
	"DE": 22, "DJ": 27, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
	"FK": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27,
	"GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27,
	"JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20,
	"LV": 21, "LY": 25, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MN": 20, "MR": 27,
	"MT": 31, "MU": 30, "NI": 28, "NL": 18, "NO": 15, "OM": 23, "PK": 24, "PL": 28,
	"PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "RU": 33, "SA": 24, "SC": 31,
	"SD": 18, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "SO": 23, "ST": 25, "SV": 28,
	"TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20, "YE": 30,
}

func isUpper(b byte) bool { return b >= 'A' && b <= 'Z' }

func isASCIIAlnum(b byte) bool {
	return isDigit(b) || isUpper(b) || (b >= 'a' && b <= 'z')
}

// detectIBAN finds an upper-case country code and two check digits, followed
// by exactly the country's number of characters with optional single spaces,
// and accepts it when the ISO 7064 mod 97-10 checksum holds.
func detectIBAN(ctx context.Context, text string, collector *spanCollector) error {
	var compact [34]byte
	for i := 0; i+15 <= len(text); i++ {
		if i&4095 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if !isUpper(text[i]) || !isUpper(text[i+1]) || !isDigit(text[i+2]) || !isDigit(text[i+3]) {
			continue
		}
		if i > 0 && isASCIIAlnum(text[i-1]) {
			continue
		}
		want, known := ibanLengths[text[i:i+2]]
		if !known {
			continue
		}
		n, j := 0, i
		for n < want && j < len(text) {
			if text[j] == ' ' && n > 0 && j+1 < len(text) && isASCIIAlnum(text[j+1]) {
				j++
			}
			if !isASCIIAlnum(text[j]) {
				break
			}
			compact[n] = text[j]
			n++
			j++
		}
		if n != want || (j < len(text) && isASCIIAlnum(text[j])) || !ibanChecksum(compact[:n]) {
			continue
		}
		if err := collector.add(span{start: i, end: j, kind: KindIBAN, ruleID: rulePIIIBAN}); err != nil {
			return err
		}
		i = j - 1
	}
	return nil
}

// ibanChecksum moves the first four characters to the end, reads letters as
// 10 to 35 and checks that the number is 1 modulo 97.
func ibanChecksum(iban []byte) bool {
	remainder := 0
	for i := 0; i < len(iban); i++ {
		c := iban[(i+4)%len(iban)]
		switch {
		case isDigit(c):
			remainder = (remainder*10 + int(c-'0')) % 97
		case isUpper(c):
			remainder = (remainder*100 + int(c-'A') + 10) % 97
		default:
			remainder = (remainder*100 + int(c-'a') + 10) % 97
		}
	}
	return remainder == 1
}
