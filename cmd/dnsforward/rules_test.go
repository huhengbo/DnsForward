package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndMergeRulesFailsWhenRuleSetCannotLoad(t *testing.T) {
	rules := []Rule{
		{Type: "DOMAIN", Value: "example.com", Target: "192.0.2.10"},
		{Type: "RULE-SET", Value: filepath.Join(t.TempDir(), "missing.list"), Target: "192.0.2.20"},
	}

	if _, err := loadAndMergeRules(rules, nil, 1); err == nil {
		t.Fatal("expected RULE-SET load failure to abort merge")
	}
}

func TestLoadAndMergeRulesMergesLocalRuleSet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.list")
	content := "DOMAIN,one.example\nDOMAIN-SUFFIX,two.example\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	rules := []Rule{
		{Type: "DOMAIN", Value: "base.example", Target: "192.0.2.10"},
		{Type: "RULE-SET", Value: path, Target: "192.0.2.20"},
	}

	merged, err := loadAndMergeRules(rules, nil, 1)
	if err != nil {
		t.Fatalf("unexpected merge error: %v", err)
	}
	if len(merged) != 3 {
		t.Fatalf("expected 3 merged rules, got %d", len(merged))
	}
	if merged[1].Target != "192.0.2.20" || merged[2].Target != "192.0.2.20" {
		t.Fatal("expected RULE-SET target to be applied to parsed rules")
	}
}
