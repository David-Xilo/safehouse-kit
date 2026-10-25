// Package redact replaces secrets in command lines and other text with
// "[REDACTED:<rule-id>]", using the shared rule data in contract/rules.
//
// It reproduces gitleaks' matching semantics, as the Rust loader in rust/ does: keyword
// prefilter, secret group, entropy threshold and allowlists. contract/rules/README.md
// states the rules; contract/rules/cases.json is the test both loaders pass.
package redact

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/David-Xilo/safehouse-kit/contract"
)

// Redactor holds the compiled rules. It is safe for concurrent use.
type Redactor struct {
	rules  []rule
	global []allowlist
}

type rule struct {
	id          string
	re          *regexp.Regexp
	keywords    []string // lower case
	entropy     float64  // 0: no threshold
	secretGroup int
	allowlists  []allowlist
}

type target int

const (
	targetSecret target = iota
	targetMatch
	targetLine
)

type allowlist struct {
	regexes   []*regexp.Regexp
	target    target
	stopwords []string // lower case
	all       bool     // condition "AND"
}

type ruleFile struct {
	Allowlist *allowlistDef `toml:"allowlist"`
	Rules     []ruleDef     `toml:"rules"`
}

type ruleDef struct {
	ID          string         `toml:"id"`
	Regex       *string        `toml:"regex"`
	Keywords    []string       `toml:"keywords"`
	Entropy     float64        `toml:"entropy"`
	SecretGroup int            `toml:"secretGroup"`
	Path        *string        `toml:"path"`
	Allowlists  []allowlistDef `toml:"allowlists"`
}

type allowlistDef struct {
	Regexes     []string `toml:"regexes"`
	RegexTarget string   `toml:"regexTarget"`
	Stopwords   []string `toml:"stopwords"`
	Condition   string   `toml:"condition"`
}

// Load compiles the embedded rule sets. Our command-line rules come first, so their ids
// win when a gitleaks rule finds the same span. Rules on file paths are skipped.
func Load() (*Redactor, error) {
	sniff, err := parse("rules/sniff.toml")
	if err != nil {
		return nil, err
	}
	gitleaks, err := parse("rules/gitleaks.toml")
	if err != nil {
		return nil, err
	}
	r := &Redactor{}
	for _, def := range append(sniff.Rules, gitleaks.Rules...) {
		if def.Regex == nil || def.Path != nil {
			continue
		}
		re, err := regexp.Compile(*def.Regex)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", def.ID, err)
		}
		ru := rule{id: def.ID, re: re, secretGroup: def.SecretGroup}
		if def.Entropy > 0 {
			ru.entropy = def.Entropy
		}
		for _, k := range def.Keywords {
			ru.keywords = append(ru.keywords, strings.ToLower(k))
		}
		for _, a := range def.Allowlists {
			al, err := newAllowlist(a, def.ID)
			if err != nil {
				return nil, err
			}
			ru.allowlists = append(ru.allowlists, al)
		}
		r.rules = append(r.rules, ru)
	}
	for _, def := range []*allowlistDef{gitleaks.Allowlist, sniff.Allowlist} {
		if def == nil {
			continue
		}
		al, err := newAllowlist(*def, "global")
		if err != nil {
			return nil, err
		}
		r.global = append(r.global, al)
	}
	return r, nil
}

// RuleCount is the number of rules loaded; tests pin it so a rules update shows.
func (r *Redactor) RuleCount() int { return len(r.rules) }

// IDs returns the rule ids of contract/rules/sniff.toml, the command-line rules.
func IDs() ([]string, error) {
	f, err := parse("rules/sniff.toml")
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(f.Rules))
	for _, d := range f.Rules {
		ids = append(ids, d.ID)
	}
	return ids, nil
}

type span struct{ start, end, rule int }

// Text returns text with every detected secret replaced by "[REDACTED:<rule-id>]".
func (r *Redactor) Text(text string) string {
	lower := strings.ToLower(text)
	var spans []span
	for i := range r.rules {
		ru := &r.rules[i]
		if !ru.active(lower) {
			continue
		}
		for _, m := range ru.re.FindAllStringSubmatchIndex(text, -1) {
			if s, e, ok := r.secret(ru, m, text); ok {
				spans = append(spans, span{s, e, i})
			}
		}
	}
	if len(spans) == 0 {
		return text
	}
	// Earliest start first; on a tie the longest span, then the first-loaded rule.
	sort.Slice(spans, func(a, b int) bool {
		x, y := spans[a], spans[b]
		if x.start != y.start {
			return x.start < y.start
		}
		if x.end != y.end {
			return x.end > y.end
		}
		return x.rule < y.rule
	})
	merged := spans[:1]
	for _, s := range spans[1:] {
		last := &merged[len(merged)-1]
		if s.start < last.end {
			last.end = max(last.end, s.end)
			continue
		}
		merged = append(merged, s)
	}
	var b strings.Builder
	cursor := 0
	for _, s := range merged {
		b.WriteString(text[cursor:s.start])
		b.WriteString("[REDACTED:")
		b.WriteString(r.rules[s.rule].id)
		b.WriteString("]")
		cursor = s.end
	}
	b.WriteString(text[cursor:])
	return b.String()
}

// active is gitleaks' prefilter: a rule runs only if one of its keywords occurs
// (ignoring ASCII case) or it has none.
func (ru *rule) active(lower string) bool {
	if len(ru.keywords) == 0 {
		return true
	}
	for _, k := range ru.keywords {
		if strings.Contains(lower, k) {
			return true
		}
	}
	return false
}

// secret applies gitleaks semantics to one match m (submatch index pairs): the
// configured secret group, else the first non-empty group, else the whole match.
func (r *Redactor) secret(ru *rule, m []int, text string) (int, int, bool) {
	ws, we := m[0], m[1]
	s, e := ws, we
	if ru.secretGroup > 0 {
		if 2*ru.secretGroup+1 >= len(m) || m[2*ru.secretGroup] < 0 {
			return 0, 0, false
		}
		s, e = m[2*ru.secretGroup], m[2*ru.secretGroup+1]
	} else {
		for g := 1; 2*g+1 < len(m); g++ {
			if m[2*g] >= 0 && m[2*g+1] > m[2*g] {
				s, e = m[2*g], m[2*g+1]
				break
			}
		}
	}
	if s == e {
		return 0, 0, false
	}
	secret := text[s:e]
	if ru.entropy > 0 && shannon(secret) <= ru.entropy {
		return 0, 0, false
	}
	line := lineAround(text, ws, we)
	for _, lists := range [][]allowlist{ru.allowlists, r.global} {
		for _, a := range lists {
			if a.allows(secret, text[ws:we], line) {
				return 0, 0, false
			}
		}
	}
	return s, e, true
}

func newAllowlist(def allowlistDef, owner string) (allowlist, error) {
	a := allowlist{all: strings.EqualFold(def.Condition, "and")}
	switch def.RegexTarget {
	case "match":
		a.target = targetMatch
	case "line":
		a.target = targetLine
	}
	for _, p := range def.Regexes {
		re, err := regexp.Compile(p)
		if err != nil {
			return allowlist{}, fmt.Errorf("%s allowlist: %w", owner, err)
		}
		a.regexes = append(a.regexes, re)
	}
	for _, w := range def.Stopwords {
		a.stopwords = append(a.stopwords, strings.ToLower(w))
	}
	return a, nil
}

func (a allowlist) allows(secret, whole, line string) bool {
	if len(a.regexes) == 0 && len(a.stopwords) == 0 {
		return false
	}
	t := secret
	switch a.target {
	case targetMatch:
		t = whole
	case targetLine:
		t = line
	}
	regexHit := false
	for _, re := range a.regexes {
		if re.MatchString(t) {
			regexHit = true
			break
		}
	}
	lower := strings.ToLower(secret)
	stopHit := false
	for _, w := range a.stopwords {
		if strings.Contains(lower, w) {
			stopHit = true
			break
		}
	}
	if a.all {
		return (len(a.regexes) == 0 || regexHit) && (len(a.stopwords) == 0 || stopHit)
	}
	return regexHit || stopHit
}

func parse(name string) (ruleFile, error) {
	data, err := contract.Files.ReadFile(name)
	if err != nil {
		return ruleFile{}, err
	}
	var f ruleFile
	if _, err := toml.Decode(string(data), &f); err != nil {
		return ruleFile{}, fmt.Errorf("%s: %w", name, err)
	}
	return f, nil
}

// lineAround returns the line of text holding text[start:end].
func lineAround(text string, start, end int) string {
	ls := strings.LastIndexByte(text[:start], '\n') + 1
	le := len(text)
	if i := strings.IndexByte(text[end:], '\n'); i >= 0 {
		le = end + i
	}
	return text[ls:le]
}

// shannon is gitleaks' entropy: character frequencies over the byte length.
func shannon(s string) float64 {
	counts := map[rune]int{}
	for _, c := range s {
		counts[c]++
	}
	inv := 1 / float64(len(s))
	var h float64
	for _, n := range counts {
		p := float64(n) * inv
		h -= p * math.Log2(p)
	}
	return h
}
