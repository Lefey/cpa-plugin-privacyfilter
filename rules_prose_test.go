package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// The optional rules/prose-credentials.toml file is loaded with
// gitleaks_mode: extend. It must catch credentials stated in prose and leave
// ordinary sentences and code alone.
func TestProseCredentialRules(t *testing.T) {
	rules, err := filepath.Abs("rules/prose-credentials.toml")
	if err != nil {
		t.Fatal(err)
	}
	plugin, err := buildPlugin([]byte("mode: tokenize\ngitleaks_toml: "+rules+"\ngitleaks_mode: extend\n"), t.TempDir())
	if err != nil {
		t.Fatalf("the rules file is not accepted with strict compatibility: %v", err)
	}
	p := plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	send := func(id, text string) string {
		t.Helper()
		out := sendRequest(t, p, id, testTokenizeKeyA, "openai", chatBody(text))
		return at(t, decodeJSON(t, string(out)), "messages", 0, "content").(string)
	}

	caught := []struct{ text, value, rest string }{
		{"мой пароль passW0RD! Напиши его в обратном порядке.", "passW0RD!", " Напиши его в обратном порядке."},
		{"password: passW0RD!", "passW0RD!", ""},
		{"password=passW0RD!", "passW0RD!", ""},
		{"my password is passW0RD!", "passW0RD!", ""},
		{"DB_PASSWORD=passW0RD!", "passW0RD!", ""},
		{"ПАРОЛЬ — Qwerty123.", "Qwerty123", "."},
		{"Пароль это hunter2222, запомни.", "hunter2222", ", запомни."},
		{"секрет: s3cr3tValue", "s3cr3tValue", ""},
		{"мой токен abc123def456 не работает", "abc123def456", " не работает"},
		{"ключ: 9f8e7d6c5b4a", "9f8e7d6c5b4a", ""},
		{"ключ «значение» дальше", "значение", "» дальше"},
		{`password = "correcthorse"`, "correcthorse", `"`},
		{"пароль 'qwertyuiop'", "qwertyuiop", "'"},
	}
	for index, tc := range caught {
		got := send("caught-"+string(rune('a'+index)), tc.text)
		if strings.Contains(got, tc.value) {
			t.Errorf("value was not tokenized in %q", tc.text)
			continue
		}
		token := testTokenPattern.FindString(got)
		if token == "" || !strings.HasSuffix(got, token+tc.rest) {
			t.Errorf("token does not replace exactly the value in %q: got %q", tc.text, got)
		}
	}

	untouched := []string{
		"пароль должен быть длинным, password reset is required",
		"ключ к успеху, токен истёк, секрет прост, ключевой момент, токенов 4096, ключ 2048 бит",
		"passwd: files systemd",
		"max_tokens: 4096, password != expected, password == other.password",
		"if password is None: return",
		"password: str = Field(...)",
	}
	for index, text := range untouched {
		if got := send("untouched-"+string(rune('a'+index)), text); got != text {
			t.Errorf("ordinary text was rewritten: %q -> %q", text, got)
		}
	}
}
