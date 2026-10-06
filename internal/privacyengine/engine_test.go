package privacyengine

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
)

func customEngine(t testing.TB, rules string) *Engine {
	t.Helper()
	engine, report, err := New(Config{
		CustomTOML: []byte(rules),
		CustomMode: CustomRulesReplace,
	})
	if err != nil {
		t.Fatalf("New(custom): %v (report=%+v)", err, report)
	}
	return engine
}

func embeddedEngine(t testing.TB) (*Engine, CompatibilityReport) {
	t.Helper()
	rules, err := os.ReadFile("../../rules/gitleaks.toml")
	if err != nil {
		t.Fatalf("read embedded snapshot: %v", err)
	}
	engine, report, err := New(Config{
		EmbeddedTOML:          rules,
		EmbeddedCompatibility: CompatibilitySkipUnsupported,
	})
	if err != nil {
		t.Fatalf("New(embedded): %v (report=%+v)", err, report)
	}
	return engine, report
}

func TestEmbeddedSnapshotAndCaptureSelection(t *testing.T) {
	engine, report := embeddedEngine(t)
	if report.RulesSeen != 222 || report.RulesLoaded != 217 || report.RulesSkipped != 5 {
		t.Fatalf("unexpected compatibility counts: %+v", report)
	}

	input := "alibaba=LTAIABCDEFGHIJKLMNOPQRST "
	result, err := engine.Redact(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Redacted != "alibaba=[密钥] " {
		t.Fatalf("automatic first capture was not used: redacted_len=%d findings=%d", len(result.Redacted), len(result.Findings))
	}
	if len(result.Findings) != 1 || result.Findings[0].RuleID != "alibaba-access-key-id" {
		t.Fatalf("unexpected finding: %+v", result.Findings)
	}

	// The pinned AWS rule's per-rule allowlist must suppress documented
	// EXAMPLE credentials, while a same-shape non-example remains detectable.
	allowed, err := engine.Detect(context.Background(), "AKIA"+"IOSFODNN7EXAMPLE", RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed) != 0 {
		t.Fatalf("AWS EXAMPLE credential was not allowlisted: %+v", allowed)
	}
	detected, err := engine.Detect(context.Background(), "AKIA"+"IOSFODNN7EXAMPLF", RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(detected) != 1 || detected[0].RuleID != "aws-access-token" {
		t.Fatalf("AWS non-example not detected by pinned rule: %+v", detected)
	}
}

func TestStructuredCredentialFieldsRedactWholeShortValues(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "never"
regex = '''NEVER_MATCH_THIS_VALUE'''
keywords = ["NEVER_MATCH"]
`)
	shortValue := strings.Join([]string{"q", "7", "q", "q", "2"}, "")
	cases := []struct {
		name    string
		context FieldContext
	}{
		{name: "AK", context: FieldContext{ImmediateKey: "AK", ToolScope: ToolScopeInput, Structured: true}},
		{name: "SK", context: FieldContext{ImmediateKey: "sK", ToolScope: ToolScopeOutput, Structured: true}},
		{name: "API hyphen", context: FieldContext{ImmediateKey: "API-KEY", ToolScope: ToolScopeInput, Structured: true, Encoded: true}},
		{name: "API camel", context: FieldContext{ImmediateKey: "apiKey", ToolScope: ToolScopeInput, Structured: true}},
		{name: "access key", context: FieldContext{ImmediateKey: "access_key", ToolScope: ToolScopeInput, Structured: true}},
		{name: "access camel", context: FieldContext{ImmediateKey: "accessKey", ToolScope: ToolScopeInput, Structured: true}},
		{name: "secret key", context: FieldContext{ImmediateKey: "secret-key", ToolScope: ToolScopeInput, Structured: true}},
		{name: "secret camel", context: FieldContext{ImmediateKey: "secretKey", ToolScope: ToolScopeInput, Structured: true}},
		{name: "secret access camel", context: FieldContext{ImmediateKey: "secretAccessKey", ToolScope: ToolScopeInput, Structured: true}},
		{name: "access key id camel", context: FieldContext{ImmediateKey: "accessKeyId", ToolScope: ToolScopeInput, Structured: true}},
		{name: "AWS secret access", context: FieldContext{ImmediateKey: "AWS_SECRET_ACCESS_KEY", ToolScope: ToolScopeInput, Structured: true}},
		{name: "AWS access id", context: FieldContext{ImmediateKey: "aws-access-key-id", ToolScope: ToolScopeInput, Structured: true}},
		{name: "client secret", context: FieldContext{ImmediateKey: "client_secret", ToolScope: ToolScopeInput, Structured: true}},
		{name: "private key", context: FieldContext{ImmediateKey: "privateKey", ToolScope: ToolScopeInput, Structured: true}},
		{name: "token", context: FieldContext{ImmediateKey: "TOKEN", ToolScope: ToolScopeOutput, Structured: true}},
		{name: "access token", context: FieldContext{ImmediateKey: "access-token", ToolScope: ToolScopeOutput, Structured: true}},
		{name: "access token camel", context: FieldContext{ImmediateKey: "accessToken", ToolScope: ToolScopeOutput, Structured: true}},
		{name: "api token", context: FieldContext{ImmediateKey: "api_token", ToolScope: ToolScopeInput, Structured: true}},
		{name: "api token camel", context: FieldContext{ImmediateKey: "apiToken", ToolScope: ToolScopeInput, Structured: true}},
		{name: "API secret key", context: FieldContext{ImmediateKey: "apiSecretKey", ToolScope: ToolScopeInput, Structured: true}},
		{name: "session token", context: FieldContext{ImmediateKey: "session_token", ToolScope: ToolScopeInput, Structured: true}},
		{name: "ID token", context: FieldContext{ImmediateKey: "idToken", ToolScope: ToolScopeInput, Structured: true}},
		{name: "client token", context: FieldContext{ImmediateKey: "client_token", ToolScope: ToolScopeInput, Structured: true}},
		{name: "secret token", context: FieldContext{ImmediateKey: "secretToken", ToolScope: ToolScopeInput, Structured: true}},
		{name: "bearer token", context: FieldContext{ImmediateKey: "bearer_token", ToolScope: ToolScopeInput, Structured: true}},
		{name: "OAuth token", context: FieldContext{ImmediateKey: "oauthToken", ToolScope: ToolScopeInput, Structured: true}},
		{name: "password", context: FieldContext{ImmediateKey: "Password", ToolScope: ToolScopeInput, Structured: true}},
		{name: "passwd", context: FieldContext{ImmediateKey: "passwd", ToolScope: ToolScopeInput, Structured: true}},
		{name: "pwd", context: FieldContext{ImmediateKey: "pwd", ToolScope: ToolScopeInput, Structured: true}},
		{name: "credential", context: FieldContext{ImmediateKey: "credential", ToolScope: ToolScopeOutput, Structured: true}},
		{name: "secrets", context: FieldContext{ImmediateKey: "secrets", ToolScope: ToolScopeOutput, Structured: true}},
		{name: "array ancestor", context: FieldContext{
			Ancestors: [MaxFieldContextAncestors]string{"password"}, AncestorCount: 1,
			ToolScope: ToolScopeInput, Structured: true,
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			input := " " + shortValue + " "
			result, err := engine.Detect(context.Background(), input, RequestOptions{FieldContext: testCase.context})
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if len(result) != 1 || result[0].RuleID != ruleCredentialField ||
				result[0].Kind != KindSecret || result[0].Start != 0 || result[0].End != len(input) {
				t.Fatalf("credential-field finding metadata mismatch: count=%d", len(result))
			}
		})
	}

	credentialContext := FieldContext{ImmediateKey: "credential", ToolScope: ToolScopeInput, Structured: true}
	for index, input := range []string{
		strings.Join([]string{"sec", "ret"}, ""),
		strings.Join([]string{"actual", "TODO", "7"}, ""),
	} {
		findings, err := engine.Detect(context.Background(), input, RequestOptions{FieldContext: credentialContext})
		if err != nil {
			t.Fatalf("non-template value %d: %v", index, err)
		}
		if len(findings) != 1 || findings[0].RuleID != ruleCredentialField {
			t.Fatalf("non-template value %d finding mismatch: count=%d", index, len(findings))
		}
	}
}

func TestStructuredCredentialFieldsDoNotMatchUntrustedContextsOrPlaceholders(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "never"
regex = '''NEVER_MATCH_THIS_VALUE'''
keywords = ["NEVER_MATCH"]
`)
	shortValue := strings.Join([]string{"q", "7", "q", "q", "2"}, "")
	negativeContexts := []FieldContext{
		{ImmediateKey: "monkey", ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "token_id", ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "api_key_name", ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "secret_name", ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "client_id", ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "auth", ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "authentication_method", ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "api key", ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "token", ToolScope: ToolScopeInput},
		{ImmediateKey: "token", Structured: true},
		{ImmediateKey: "id", ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "name", ToolScope: ToolScopeOutput, Structured: true},
		{ImmediateKey: "role", ToolScope: ToolScopeOutput, Structured: true},
		{ImmediateKey: "signature", ToolScope: ToolScopeOutput, Structured: true},
		{ImmediateKey: "schema", ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "value", Ancestors: [MaxFieldContextAncestors]string{"AK"}, AncestorCount: 1, ToolScope: ToolScopeInput, Structured: true},
		{ImmediateKey: "value", Ancestors: [MaxFieldContextAncestors]string{"sk"}, AncestorCount: 1, ToolScope: ToolScopeOutput, Structured: true},
		{ToolScope: ToolScopeInput, Structured: true},
	}
	for index, fieldContext := range negativeContexts {
		findings, err := engine.Detect(context.Background(), shortValue, RequestOptions{FieldContext: fieldContext})
		if err != nil {
			t.Fatalf("negative context %d: %v", index, err)
		}
		if len(findings) != 0 {
			t.Fatalf("negative context %d produced %d findings", index, len(findings))
		}
	}

	credentialContext := FieldContext{ImmediateKey: "api_key", ToolScope: ToolScopeInput, Structured: true}
	placeholders := []string{
		"", "   ", "${API_KEY}", "$API_KEY", "$env:API_KEY", "$(API_KEY)",
		"{{API_KEY}}", "${{ secrets.API_KEY }}", "%API_KEY%", "<API_KEY>",
		"[密钥]", "[密钥#2]", "[邮箱]", "[电话#2]", "[身份证]", "[银行卡]", "[IP#2]",
		"[REDACTED]", "YOUR_API_KEY", "******", "xxxx",
	}
	for index, placeholder := range placeholders {
		findings, err := engine.Detect(context.Background(), placeholder, RequestOptions{FieldContext: credentialContext})
		if err != nil {
			t.Fatalf("placeholder %d: %v", index, err)
		}
		if len(findings) != 0 {
			t.Fatalf("placeholder %d produced %d findings", index, len(findings))
		}
	}

	embedded, _ := embeddedEngine(t)
	for index, placeholder := range placeholders {
		findings, err := embedded.Detect(context.Background(), placeholder, RequestOptions{FieldContext: credentialContext})
		if err != nil {
			t.Fatalf("embedded placeholder %d: %v", index, err)
		}
		if len(findings) != 0 {
			t.Fatalf("embedded placeholder %d produced %d findings", index, len(findings))
		}
	}
}

func TestCredentialPlaceholderLikeWrappersDoNotBypassWholeValueRedaction(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "never"
regex = '''NEVER_MATCH_THIS_VALUE'''
keywords = ["NEVER_MATCH"]
`)
	fieldContext := FieldContext{ImmediateKey: "api_key", ToolScope: ToolScopeInput, Structured: true}
	values := []string{
		"{{" + strings.Join([]string{"sk", "live", "real", "secret"}, "-") + "}}",
		"<" + strings.Join([]string{"Super", "Secret", "123!"}, "") + ">",
		"YOUR_" + strings.Join([]string{"Super", "Secret", "123"}, ""),
		"$(" + strings.Join([]string{"secret", "value"}, "-") + ")",
		"REPLACE_WITH_" + strings.Join([]string{"live", "value"}, "_"),
	}
	for index, value := range values {
		findings, err := engine.Detect(context.Background(), value, RequestOptions{FieldContext: fieldContext})
		if err != nil {
			t.Fatalf("placeholder-like credential %d: %v", index, err)
		}
		if len(findings) != 1 || findings[0].RuleID != ruleCredentialField ||
			findings[0].Start != 0 || findings[0].End != len(value) {
			t.Fatalf("placeholder-like credential %d finding mismatch: count=%d", index, len(findings))
		}
	}
}

func TestCredentialPlaceholderStillRunsGenericSecretDetectors(t *testing.T) {
	engine, _ := embeddedEngine(t)
	credential := strings.Join([]string{"AKIA", "IOSFODNN7EXAMPLF"}, "")
	value := "${" + credential + "}"
	findings, err := engine.Detect(context.Background(), value, RequestOptions{FieldContext: FieldContext{
		ImmediateKey: "api_key",
		ToolScope:    ToolScopeInput,
		Structured:   true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID != "aws-access-token" {
		t.Fatalf("generic secret detector finding mismatch: count=%d", len(findings))
	}
}

func TestPreservedConfiguredPlaceholderStillConsumesBudget(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "never"
regex = '''NEVER_MATCH_THIS_VALUE'''
keywords = ["NEVER_MATCH"]
`)
	budget, err := NewBudget(Limits{MaxBytes: 32, MaxNodes: 1, MaxFindings: 1})
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	findings, err := engine.Detect(context.Background(), "[CUSTOM]", RequestOptions{
		Budget:              budget,
		PreservePlaceholder: true,
	})
	if err != nil || len(findings) != 0 {
		t.Fatalf("preserved placeholder = findings %d, err %v", len(findings), err)
	}
	if _, err = engine.Detect(context.Background(), "x", RequestOptions{Budget: budget}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("second Detect error = %v, want ErrBudgetExceeded", err)
	}
}

func TestCredentialFieldMetadataPrecedesContainedPII(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "never"
regex = '''NEVER_MATCH_THIS_VALUE'''
keywords = ["NEVER_MATCH"]
`)
	input := strings.Join([]string{"person", "@", "example", ".", "com"}, "")
	findings, err := engine.Detect(context.Background(), input, RequestOptions{FieldContext: FieldContext{
		ImmediateKey: "credential",
		ToolScope:    ToolScopeOutput,
		Structured:   true,
	}})
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != ruleCredentialField ||
		findings[0].Start != 0 || findings[0].End != len(input) {
		t.Fatalf("credential field did not retain whole-value metadata: count=%d", len(findings))
	}
}

func TestIssue3OverlapRegression(t *testing.T) {
	engine, _ := embeddedEngine(t)
	const input = "api keyABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result, err := engine.Redact(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatalf("Redact overlap input: %v", err)
	}
	if !result.Hit() || !strings.Contains(result.Redacted, "[密钥]") {
		t.Fatalf("overlap input was not safely redacted: hit=%t redacted_len=%d findings=%d", result.Hit(), len(result.Redacted), len(result.Findings))
	}
}

func TestPreferredRuleMetadataSurvivesOverlappingPII(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "block-email"
regex = '''[a-z]+@example\.com'''
keywords = ["@example."]
`)
	const input = "test@example.com"

	baseline, err := engine.Detect(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline) != 1 || baseline[0].RuleID != rulePIIEmail {
		t.Fatalf("baseline overlap metadata = %+v", baseline)
	}

	preferred, err := engine.Detect(context.Background(), input, RequestOptions{
		PreferredRuleIDs: map[string]struct{}{"block-email": {}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(preferred) != 1 || preferred[0].RuleID != "block-email" {
		t.Fatalf("preferred overlap metadata = %+v", preferred)
	}
}

func TestStrongContextLookbackBoundaries(t *testing.T) {
	candidate := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	atBoundary := strings.Repeat("x", contextLookback-len("token = ")) + "token = " + candidate
	start := strings.Index(atBoundary, candidate)
	if start != contextLookback || !hasStrongSecretContext(atBoundary, start, len(atBoundary)) {
		t.Fatalf("context at exact %d-byte boundary was missed", contextLookback)
	}

	outside := "token=" + strings.Repeat("x", contextLookback) + candidate
	start = strings.Index(outside, candidate)
	if hasStrongSecretContext(outside, start, len(outside)) {
		t.Fatal("context outside lookback unexpectedly matched")
	}
	for _, bounds := range [][2]int{{-1, 1}, {2, 1}, {0, len(candidate) + 1}} {
		if hasStrongSecretContext(candidate, bounds[0], bounds[1]) {
			t.Fatalf("invalid bounds %v unexpectedly matched", bounds)
		}
	}
}

func TestLargeIssue3Regression(t *testing.T) {
	if testing.Short() {
		t.Skip("large regression")
	}
	engine, _ := embeddedEngine(t)
	const size = 490 * 1024
	input := strings.Repeat("ordinary prose line\n", size/len("ordinary prose line\n")+1)
	input = input[:size-len("api keyABCDEFGHIJKLMNOPQRSTUVWXYZ")] + "api keyABCDEFGHIJKLMNOPQRSTUVWXYZ"
	result, err := engine.Redact(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatalf("Redact(%d bytes): %v", len(input), err)
	}
	if len(result.Redacted) == 0 || !result.Hit() {
		t.Fatal("large regression input produced no redaction")
	}
}

func TestFindingIsSpanOnlyUTF8AndRedactionIsIdempotent(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "never"
regex = '''NEVER_MATCH_THIS_VALUE'''
keywords = ["NEVER_MATCH"]
`)
	input := "前alice@example.com后 +79149996666 192.168.1.1 卡4111111111111111"
	findings, err := engine.Detect(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 4 {
		t.Fatalf("got %d findings: %+v", len(findings), findings)
	}
	if findings[0].Start != len("前") || input[findings[0].Start:findings[0].End] != "alice@example.com" {
		t.Fatalf("offset is not a UTF-8 byte span: %+v", findings[0])
	}
	findingType := reflect.TypeOf(Finding{})
	if _, ok := findingType.FieldByName("Text"); ok {
		t.Fatal("Finding must not retain plaintext Text")
	}

	first, err := engine.Redact(context.Background(), input, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Redact(context.Background(), first.Redacted, RequestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if second.Redacted != first.Redacted || second.Hit() {
		t.Fatalf("redaction is not idempotent: first_len=%d second_len=%d second_findings=%d", len(first.Redacted), len(second.Redacted), len(second.Findings))
	}
}

func TestCustomAllowlistsAndStrictCaptureValidation(t *testing.T) {
	engine := customEngine(t, `
[allowlist]
regexes = ['''^GLOBALALLOW$''']
stopwords = ["stopme"]

[[rules]]
id = "token-rule"
regex = '''token=([A-Z]{10,12})'''
keywords = ["token="]

[[rules.allowlists]]
regexTarget = "match"
regexes = ['''^token=LOCALALLOW$''']

[[rules.allowlists]]
condition = "AND"
regexTarget = "line"
regexes = ['''SAFE-LINE''']
stopwords = ["permit"]
`)
	for _, input := range []string{
		"token=GLOBALALLOW",
		"token=STOPMESTOPME",
		"token=LOCALALLOW",
		"SAFE-LINE token=PERMITAAAA",
	} {
		findings, err := engine.Detect(context.Background(), input, RequestOptions{})
		if err != nil {
			t.Fatalf("Detect input_len=%d: %v", len(input), err)
		}
		if len(findings) != 0 {
			t.Errorf("allowlist failed for input_len=%d: findings=%d", len(input), len(findings))
		}
	}

	_, report, err := New(Config{
		CustomMode: CustomRulesReplace,
		CustomTOML: []byte(`
[[rules]]
id = "bad-group"
regex = '''(x)'''
secretGroup = 2
`),
	})
	if !errors.Is(err, ErrIncompatibleRules) || report.Compatible() {
		t.Fatalf("invalid capture group accepted: err=%v report=%+v", err, report)
	}

	_, _, err = New(Config{
		CustomMode: CustomRulesReplace,
		CustomTOML: []byte(`
[[rules]]
id = "unknown"
regex = '''x'''
mystery = true
`),
	})
	if !errors.Is(err, ErrIncompatibleRules) {
		t.Fatalf("unknown custom semantic accepted: %v", err)
	}
}

func TestCustomExtendAndReplace(t *testing.T) {
	embedded := []byte(`
[[rules]]
id = "embedded"
regex = '''EMBEDDED_SECRET'''
`)
	custom := []byte(`
[[rules]]
id = "custom"
regex = '''CUSTOM_SECRET'''
`)
	extended, _, err := New(Config{EmbeddedTOML: embedded, CustomTOML: custom, CustomMode: CustomRulesExtend})
	if err != nil {
		t.Fatal(err)
	}
	findings, err := extended.Detect(context.Background(), "EMBEDDED_SECRET CUSTOM_SECRET", RequestOptions{})
	if err != nil || len(findings) != 2 {
		t.Fatalf("extend mode: findings=%+v err=%v", findings, err)
	}
	replaced, _, err := New(Config{EmbeddedTOML: embedded, CustomTOML: custom, CustomMode: CustomRulesReplace})
	if err != nil {
		t.Fatal(err)
	}
	findings, err = replaced.Detect(context.Background(), "EMBEDDED_SECRET CUSTOM_SECRET", RequestOptions{})
	if err != nil || len(findings) != 1 || findings[0].RuleID != "custom" {
		t.Fatalf("replace mode: findings=%+v err=%v", findings, err)
	}
}

func TestBudgetCancellationAndRequestRenderer(t *testing.T) {
	engine := customEngine(t, `
[[rules]]
id = "never"
regex = '''NEVER_MATCH'''
`)

	bytesBudget, _ := NewBudget(Limits{MaxBytes: 3, MaxFindings: 10, MaxNodes: 10})
	if _, err := engine.Detect(context.Background(), "four", RequestOptions{Budget: bytesBudget}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("byte limit: %v", err)
	}

	nodeBudget, _ := NewBudget(Limits{MaxBytes: 100, MaxFindings: 10, MaxNodes: 1})
	if _, err := engine.Detect(context.Background(), "clean", RequestOptions{Budget: nodeBudget}); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Detect(context.Background(), "clean", RequestOptions{Budget: nodeBudget}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("node limit: %v", err)
	}

	findingBudget, _ := NewBudget(Limits{MaxBytes: 1000, MaxFindings: 1, MaxNodes: 10})
	if _, err := engine.Detect(context.Background(), "a@example.com b@example.com", RequestOptions{Budget: findingBudget}); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("finding limit: %v", err)
	}

	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Detect(cancelled, "a@example.com", RequestOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}

	seenPlaintext := ""
	renderer := RendererFunc(func(_ context.Context, finding Finding, plaintext string) (string, error) {
		seenPlaintext = plaintext
		return "<" + string(finding.Kind) + ">", nil
	})
	result, err := engine.Redact(context.Background(), "mail a@example.com", RequestOptions{Renderer: renderer})
	if err != nil {
		t.Fatal(err)
	}
	if seenPlaintext != "a@example.com" || result.Redacted != "mail <email>" {
		t.Fatalf("request renderer mismatch: plaintext_len=%d redacted_len=%d findings=%d", len(seenPlaintext), len(result.Redacted), len(result.Findings))
	}
}
