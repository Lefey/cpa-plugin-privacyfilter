package privacyengine

import (
	"context"
	"reflect"
	"testing"
)

func piiEngine(t testing.TB, regions ...string) *Engine {
	t.Helper()
	engine, report, err := New(Config{
		CustomTOML:   []byte("[[rules]]\nid = \"never\"\nregex = '''NEVER_MATCH_THIS_VALUE'''\nkeywords = [\"NEVER_MATCH\"]\n"),
		CustomMode:   CustomRulesReplace,
		PhoneRegions: regions,
	})
	if err != nil {
		t.Fatalf("New: %v (report=%+v)", err, report)
	}
	return engine
}

// found returns "kind:text" for every finding.
func found(t *testing.T, engine *Engine, text string) []string {
	t.Helper()
	findings, err := engine.Detect(context.Background(), text, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, finding := range findings {
		out = append(out, string(finding.Kind)+":"+text[finding.Start:finding.End])
	}
	return out
}

func checkFound(t *testing.T, engine *Engine, cases map[string][]string) {
	t.Helper()
	for text, want := range cases {
		if want == nil {
			want = []string{}
		}
		if got := found(t, engine, text); !reflect.DeepEqual(got, want) {
			t.Errorf("%q:\n got  %q\n want %q", text, got, want)
		}
	}
}

func TestPhoneInternationalFormatNeedsNoRegion(t *testing.T) {
	checkFound(t, piiEngine(t), map[string][]string{
		"мой телефон +79149996666 в обратном порядке": {"phone:+79149996666"},
		"call +7 (914) 999-66-66.":         {"phone:+7 (914) 999-66-66"},
		"office: +44 20 7946 0958, ext 12": {"phone:+44 20 7946 0958"},
		// 8613812345678 satisfies the card checksum; the "+" decides.
		"+1 650-253-0000 or +8613812345678":              {"phone:+1 650-253-0000", "phone:+8613812345678"},
		"+7 914 999 66 66 12 34 trailing groups":         {"phone:+7 914 999 66 66"},
		"UK +44 (0)20 7946 0958 and IT +39 02 1234 5678": {"phone:+44 (0)20 7946 0958", "phone:+39 02 1234 5678"},
		// National formats stay ordinary numbers without phone_regions.
		"89149996666, 8 (914) 999-66-66 and 13812345678": nil,
		// Not a number in any country, or glued to other text.
		"+1234 and +0000000000 and a+79149996666":  nil,
		"+79149996666123 and +79149996666abc":      nil,
		"x = y +79149996666670 * 2; C++14; +-12.5": nil,
	})
}

func TestPhoneNationalFormatForConfiguredRegions(t *testing.T) {
	checkFound(t, piiEngine(t, "ru", "CN"), map[string][]string{
		"звоните 8 (914) 999-66-66 или 89149996666": {"phone:8 (914) 999-66-66", "phone:89149996666"},
		"заказ 12345 8 914 999 66 66 доставка":      {"phone:8 914 999 66 66"},
		"тел.914-999-66-66":                         {"phone:914-999-66-66"},
		"01.02.2026 8 914 999 66 66 12 записан":     {"phone:8 914 999 66 66"},
		"1 2 3 4 5 6 7 8 9 1 4 9 9 9 6 6 6 6":       nil,
		"手机13812345678。":                            {"phone:13812345678"},
		// Longer digit runs, fractions, dates and versions are not candidates.
		"89149996666123 3.14159265358 2026-10-05 v8.914.999.66.66": nil,
		"id_89149996666 and x89149996666":                          nil,
	})
	if _, _, err := New(Config{CustomTOML: []byte("[[rules]]\nid = \"n\"\nregex = '''N'''\n"), CustomMode: CustomRulesReplace, PhoneRegions: []string{"XX"}}); err == nil {
		t.Error("an unknown phone region was accepted")
	}
	if _, _, err := New(Config{CustomTOML: []byte("[[rules]]\nid = \"n\"\nregex = '''N'''\n"), CustomMode: CustomRulesReplace, PhoneRegions: []string{"RU", "ru"}}); err == nil {
		t.Error("a duplicate phone region was accepted")
	}
}

func TestBankCardWithSeparators(t *testing.T) {
	checkFound(t, piiEngine(t), map[string][]string{
		"card 4111111111111111.":                   {"bank_card:4111111111111111"},
		"card 4111 1111 1111 1111 exp 12/27":       {"bank_card:4111 1111 1111 1111"},
		"4111-1111-1111-1111 12/27":                {"bank_card:4111-1111-1111-1111"},
		"amex 3782 822463 10005":                   {"bank_card:3782 822463 10005"},
		"n 12 4111 1111 1111 1111 77":              {"bank_card:4111 1111 1111 1111"},
		"4111 1111 1111 1112 and 4111111111111112": nil,
		// Mixed separators and layouts that are not a card.
		"4111 1111-1111 1111":                       nil,
		"41 11 11 11 11 11 11 11":                   nil,
		"2026-10-05 18-14-04 and 20261005 181404 0": nil,
		"1411111111111111a 14111111111111118":       nil,
	})
}

func TestBankCardLeadingDigit(t *testing.T) {
	checkFound(t, piiEngine(t), map[string][]string{
		// One Luhn-valid number per issuing network: Mir, JCB, Visa,
		// Mastercard, UnionPay.
		"2200 2460 0000 0003": {"bank_card:2200 2460 0000 0003"},
		"3530 1113 3330 0000": {"bank_card:3530 1113 3330 0000"},
		"4111111111111111":    {"bank_card:4111111111111111"},
		"5555-5555-5555-4444": {"bank_card:5555-5555-5555-4444"},
		"6200 0000 0000 0005": {"bank_card:6200 0000 0000 0005"},
		// Fuel cards and national schemes outside 2 to 6: a fuel card, RuPay,
		// Belkart and Troy.
		"7005 0000 0000 0000": {"bank_card:7005 0000 0000 0000"},
		"8100 0000 0000 0002": {"bank_card:8100 0000 0000 0002"},
		"9112 0000 0000 0006": {"bank_card:9112 0000 0000 0006"},
		"9792000000000003":    {"bank_card:9792000000000003"},
		// Airline cards under 1 have 15 digits.
		"UATP 1000 000000 00009 ok": {"bank_card:1000 000000 00009"},
		// No issuer has a leading 0, and none has a leading 1 at another
		// length, so these checksum-valid amounts are not cards.
		"сумма 1000 2000 3000 4000 руб":            nil,
		"1000200030004000 and 1000 0000 0000 0008": nil,
		"0000 0000 0000 0000 and 0000000000000000": nil,
		// The leading digit of the whole number decides, not of a later
		// group: the card inside still starts with 4.
		"n 10 4111 1111 1111 1111 77": {"bank_card:4111 1111 1111 1111"},
	})
}

func TestIBAN(t *testing.T) {
	checkFound(t, piiEngine(t), map[string][]string{
		"IBAN DE89 3704 0044 0532 0130 00 und weiter":  {"iban:DE89 3704 0044 0532 0130 00"},
		"pay GB82WEST12345698765432, thanks":           {"iban:GB82WEST12345698765432"},
		"FR14 2004 1010 0505 0001 3M02 606.":           {"iban:FR14 2004 1010 0505 0001 3M02 606"},
		"(NO9386011117947)":                            {"iban:NO9386011117947"},
		"DE89 3704 0044 0532 0130 02":                  nil,
		"de89 3704 0044 0532 0130 00":                  nil,
		"XDE89370400440532013000 DE893704004405320130": nil,
		"DE89370400440532013000X ZZ89370400440532013":  nil,
	})
}

func TestIPv6(t *testing.T) {
	checkFound(t, piiEngine(t), map[string][]string{
		"host 2001:db8::1.":                                               {"ip:2001:db8::1"},
		"[2001:db8::8a2e:370:7334]:8080":                                  {"ip:2001:db8::8a2e:370:7334"},
		"link fe80::1ff:fe23:4567:890a ok":                                {"ip:fe80::1ff:fe23:4567:890a"},
		"listen ::1 and ::ffff:192.0.2.1":                                 {"ip:::1", "ip:::ffff:192.0.2.1"},
		"std::string a::b fade::bed :: at 12:30:45 mac 00:1a:2b:3c:4d:5e": nil,
		"x2001:db8::1 2001:db8::1x 1:2:3":                                 nil,
	})
}

func TestEmailInNonLatinScripts(t *testing.T) {
	checkFound(t, piiEngine(t), map[string][]string{
		"почта иван@почта.рф, спасибо":    {"email:иван@почта.рф"},
		"Mail an müller@example.de bitte": {"email:müller@example.de"},
		"邮箱ggagsa@gmail.com，响应我":          {"email:ggagsa@gmail.com"},
	})
}

func TestMergedKindsAndRetiredChineseRules(t *testing.T) {
	engine := piiEngine(t)
	// Digit groups inside an IBAN are not reported as a card or a phone.
	checkFound(t, engine, map[string][]string{
		"GB82 WEST 1234 5698 7654 32": {"iban:GB82 WEST 1234 5698 7654 32"},
		// A bare mainland mobile number and an 18-character resident ID are
		// no longer special.
		"13812345678 and 11010519491231002X": nil,
	})
}

func TestURLCredentials(t *testing.T) {
	checkFound(t, piiEngine(t), map[string][]string{
		// Only the password is reported; scheme, user, host, port and path stay.
		"DSN postgres://admin:S3cretPass@db.internal:5432/prod":         {"secret:S3cretPass"},
		"mongodb+srv://u:pw@cluster0.abc.mongodb.net/?retryWrites=true": {"secret:pw"},
		"git clone https://oauth2:glpat-x1y2z3@gitlab.com/g/p.git":      {"secret:glpat-x1y2z3"},
		"redis://:hunter2pass@cache:6379/0":                             {"secret:hunter2pass"},
		"redis://:hunter2pass@redis.example.com:6379":                   {"secret:hunter2pass"},
		"http://u:иван@почта.рф/x":                                      {"secret:иван"},
		"amqp://guest:gu:es:t@rabbit.local":                             {"secret:gu:es:t"},
		"ftp://user:p%40ss%2Fword@[2001:db8::1]:21/":                    {"secret:p%40ss%2Fword", "ip:2001:db8::1"},
		// The password must not be mistaken for an email address.
		"https://user:p4ss@host.example.com/api":        {"secret:p4ss"},
		"https://user:S3cret!Pass@host.example.com/api": {"secret:S3cret!Pass"},
		// A user name without a password is still an address, as before.
		"ssh://git@github.com/org/repo.git and mail bob@host.example.com": {"email:git@github.com", "email:bob@host.example.com"},
		"https://alice@host.example.com/":                                 {"email:alice@host.example.com"},
		// Documentation stand-ins.
		"postgres://user:${DB_PASSWORD}@db/app": nil,
		"postgres://user:<password>@db/app":     nil,
		"postgres://user:REPLACE_ME@db/app":     nil,
		"postgres://user:****@db/app":           nil,
		// Not a URL: no scheme, a host must follow, no whitespace inside. The
		// email detector then reads "x@host.example.com" as it always did.
		"user:pass@host.example.com": {"email:pass@host.example.com"},
		"scheme://user:pass@":        nil,
		// An address is skipped only where a URL password was reported. What
		// the URL detector declines stays with the email detector: no scheme,
		// a scheme that starts with a digit, a form feed in the password, and
		// a password that is a documentation stand-in.
		"://a:alice@corp.com":                 {"email:alice@corp.com"},
		"1://a:alice@corp.com":                {"email:alice@corp.com"},
		"http://a:b\falice@corp.com":          {"email:alice@corp.com"},
		"x://a:todo@corp.com":                 {"email:todo@corp.com"},
		"https://user:pa ss@host.example.com": {"email:ss@host.example.com"},
	})
}
