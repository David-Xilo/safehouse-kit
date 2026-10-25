package redact_test

import (
	"encoding/json"
	"math/rand/v2"
	"regexp"
	"strings"
	"testing"

	"github.com/David-Xilo/safehouse-kit/contract"
	"github.com/David-Xilo/safehouse-kit/go/redact"
)

type cases struct {
	RuleCount int `json:"rule_count"`
	Fill      map[string]struct {
		Prefix   string `json:"prefix"`
		Alphabet string `json:"alphabet"`
		Length   int    `json:"length"`
	} `json:"fill"`
	Redacted  [][2]string `json:"redacted"`
	Exact     [][2]string `json:"exact"`
	Unchanged []string    `json:"unchanged"`
}

const alnum = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

// TestSharedCases runs contract/rules/cases.json, which the Rust loader runs too.
// Secrets are generated here, so none is committed.
func TestSharedCases(t *testing.T) {
	data, err := contract.Files.ReadFile("rules/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var c cases
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	r, err := redact.Load()
	if err != nil {
		t.Fatal(err)
	}
	if r.RuleCount() != c.RuleCount {
		t.Fatalf("RuleCount %d, want %d", r.RuleCount(), c.RuleCount)
	}

	rng := rand.New(rand.NewPCG(0x5eed, 0x1234))
	var pairs []string
	for name, f := range c.Fill {
		alphabet := f.Alphabet
		if alphabet == "alnum" {
			alphabet = alnum
		}
		var b strings.Builder
		b.WriteString(f.Prefix)
		for range f.Length {
			b.WriteByte(alphabet[rng.IntN(len(alphabet))])
		}
		pairs = append(pairs, "{"+name+"}", b.String())
	}
	fill := strings.NewReplacer(pairs...)
	marker := regexp.MustCompile(`\[REDACTED:[^\]]+\]`)

	for _, tc := range c.Redacted {
		in := fill.Replace(tc[0])
		if got := marker.ReplaceAllString(r.Text(in), "[R]"); got != tc[1] {
			t.Errorf("%s:\n got %s\nwant %s", tc[0], got, tc[1])
		}
	}
	for _, tc := range c.Exact {
		if got := r.Text(tc[0]); got != tc[1] {
			t.Errorf("%s:\n got %s\nwant %s", tc[0], got, tc[1])
		}
	}
	for _, in := range c.Unchanged {
		if got := r.Text(in); got != in {
			t.Errorf("changed an ordinary command line: %s -> %s", in, got)
		}
	}
}

func TestIDsAreTheCommandLineRules(t *testing.T) {
	ids, err := redact.IDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 8 || ids[0] != "argv-secret-flag" {
		t.Fatalf("IDs() = %v", ids)
	}
}
