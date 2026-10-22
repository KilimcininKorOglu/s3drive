package webui

import "testing"

func TestLanguageKeyParity(t *testing.T) {
	for key := range en.messages {
		if _, ok := tr.messages[key]; !ok {
			t.Errorf("Turkish translation missing %q", key)
		}
	}
	for key := range tr.messages {
		if _, ok := en.messages[key]; !ok {
			t.Errorf("English translation missing %q", key)
		}
	}
}

func TestLanguageDateLayouts(t *testing.T) {
	if en.date == tr.date {
		t.Fatal("Turkish and English date layouts should differ")
	}
	if tr.dateTime == "" || tr.date == "" {
		t.Fatal("Turkish date layouts are empty")
	}
}
