package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// combinedRulesFile joins the optional rule files the way a deployment does:
// one file that gitleaks_toml points to.
func combinedRulesFile(t *testing.T) string {
	t.Helper()
	var combined []byte
	for _, name := range []string{"rules/prose-credentials.toml", "rules/team-roster.toml"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		combined = append(append(combined, data...), '\n')
	}
	path := filepath.Join(t.TempDir(), "privacyfilter-rules.toml")
	if err := os.WriteFile(path, combined, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestTeamRosterRules(t *testing.T) {
	plugin, err := buildPlugin([]byte("mode: tokenize\ngitleaks_toml: "+combinedRulesFile(t)+"\ngitleaks_mode: extend\n"), t.TempDir())
	if err != nil {
		t.Fatalf("the combined rules file is not accepted with strict compatibility: %v", err)
	}
	p := plugin.Capabilities.RequestInterceptor.(*privacyFilterPlugin)
	send := func(id, text string) string {
		t.Helper()
		out := sendRequest(t, p, id, testTokenizeKeyA, "openai", chatBody(text))
		return at(t, decodeJSON(t, string(out)), "messages", 0, "content").(string)
	}

	prompt := "Сегодня: 2026-10-02 (пятница).\nАвтор сообщения: id 1.\nКоманда:\n" +
		"- id 1: Ivan, @ivan_handle, Discord: Ivan\n" +
		"- id 2: Petr Sidorov, @sidorov_petr\n" +
		"  - id 3: Anna Maria Lopez, @anna_lopez, Discord: anna lopez\n\n" +
		"Сообщение:\n@ivan_handle Мой e-mail alice@example.com, мой пароль passW0RD! Спроси у @sidorov_petr."
	got := send("roster", prompt)
	for _, leaked := range []string{"Ivan", "ivan_handle", "Petr", "Sidorov", "sidorov_petr", "Anna", "Lopez", "anna_lopez", "anna lopez", "alice@example.com", "passW0RD!"} {
		if strings.Contains(got, leaked) {
			t.Errorf("roster or message value reached the provider: %q", leaked)
		}
	}
	for _, kept := range []string{"Сегодня: 2026-10-02 (пятница).", "Автор сообщения: id 1.", "Команда:", "- id 1: ", "- id 2: ", "- id 3: ", ", Discord: ", "Сообщение:", "Спроси у @"} {
		if !strings.Contains(got, kept) {
			t.Errorf("prompt structure was damaged: %q is missing", kept)
		}
	}
	lines := strings.Split(got, "\n")
	// The same person keeps one token wherever the name or handle appears, so
	// the model can still connect the roster with the message.
	first := testTokenPattern.FindAllString(lines[3], -1)
	if len(first) != 3 || first[0] != first[2] || first[0] == first[1] {
		t.Fatalf("roster line tokens = %v, want name, handle, same name", first)
	}
	if !strings.HasPrefix(lines[8], "@"+first[1]+" ") {
		t.Errorf("the mention does not reuse the roster handle token: %q", lines[8])
	}
	if got := testTokenPattern.FindAllString(lines[4], -1); len(got) != 2 {
		t.Errorf("second roster line tokens = %d, want 2", len(got))
	}
	if got := testTokenPattern.FindAllString(lines[5], -1); len(got) != 3 {
		t.Errorf("third roster line tokens = %d, want 3", len(got))
	}

	untouched := []string{
		"id 5: это не строка состава, а Discord: мессенджер",
		"@property\ndef name(self): ...\n@dataclass\nclass A: ...\n@pytest.fixture\ndef f(): ...",
		"npm i @types/node @anthropic-ai/sdk и CSS @media (min-width: 10px)",
		"почта user@example, путь /srv/@cache_dir, a@b",
		"короткое @abc и @x1",
	}
	for index, text := range untouched {
		if got := send("untouched-"+string(rune('a'+index)), text); got != text {
			t.Errorf("ordinary text was rewritten: %q -> %q", text, got)
		}
	}
}
