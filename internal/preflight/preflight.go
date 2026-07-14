// Preflight checks a rule's query against the live Elasticsearch mapping
// before dac-sync ever PUTs it to Kibana. This is the enforcement the rule
// header comments in rules/ have always claimed ("proven via _field_caps")
// but that, until now, ran once by hand and never again.
package preflight

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"

	"dac-sync/internal/elastic"
	"dac-sync/internal/rule"

	"gopkg.in/yaml.v3"
)

// Contract maps a field name to its expected Elasticsearch type, loaded from
// schema/field-contract.yaml.
type Contract map[string]string

func LoadContract(path string) (Contract, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read field contract %s: %w", path, err)
	}
	var doc struct {
		Fields map[string]string `yaml:"fields"`
	}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse field contract %s: %w", path, err)
	}
	return Contract(doc.Fields), nil
}

// quotedStringRE strips double-quoted string literals before field
// extraction, so a value that happens to contain "word:" (e.g. a URL) isn't
// mistaken for a field reference.
var quotedStringRE = regexp.MustCompile(`"(?:[^"\\]|\\.)*"`)

// fieldRE is a pragmatic KQL field extractor, not a KQL parser: it matches
// any dotted identifier immediately followed by ':', which is how every
// field:value clause in KQL is written. Known limitations, deliberately not
// handled because a full parser is out of scope:
//   - doesn't understand KQL range syntax (field >= value) or nested groups
//     beyond simple field:value/field:(a or b)
//   - a value with an *unquoted* colon (rare in these rules) would be
//     misread as a field reference
//   - "and"/"or"/"not" are stripped as a keyword denylist, not because the
//     grammar is understood
var fieldRE = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_.]*)\s*:`)

var kqlKeywords = map[string]bool{"and": true, "or": true, "not": true}

// ExtractFields returns the distinct field names referenced in a KQL query,
// in first-seen order.
func ExtractFields(query string) []string {
	stripped := quotedStringRE.ReplaceAllString(query, `""`)
	seen := map[string]bool{}
	var fields []string
	for _, m := range fieldRE.FindAllStringSubmatch(stripped, -1) {
		f := m[1]
		if kqlKeywords[strings.ToLower(f)] {
			continue
		}
		if seen[f] {
			continue
		}
		seen[f] = true
		fields = append(fields, f)
	}
	return fields
}

// indexPatterns reads the rule's "index" field, which may be a single string
// or a list of strings.
func indexPatterns(payload map[string]any) ([]string, error) {
	raw, ok := payload["index"]
	if !ok {
		return nil, fmt.Errorf(`rule has no "index" field`)
	}
	switch v := raw.(type) {
	case string:
		if v == "" {
			return nil, fmt.Errorf(`rule "index" field is empty`)
		}
		return []string{v}, nil
	case []any:
		var out []string
		for _, item := range v {
			s, ok := item.(string)
			if !ok || s == "" {
				return nil, fmt.Errorf(`rule "index" entry %v is not a non-empty string`, item)
			}
			out = append(out, s)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf(`rule "index" field is an empty list`)
		}
		return out, nil
	default:
		return nil, fmt.Errorf(`rule "index" field has unsupported type %T`, raw)
	}
}

// RuleResult holds the outcome of preflighting one rule. Errors fail the
// overall run; Warnings are reported but don't.
type RuleResult struct {
	RuleID   string
	Errors   []string
	Warnings []string
}

func (r RuleResult) OK() bool { return len(r.Errors) == 0 }

// CheckRule extracts the fields a rule's query references, resolves them
// against the live mapping for the rule's index patterns (combined into one
// _field_caps call, so a type conflict *between* patterns is caught, not
// just within one), and validates each field against contract, existence,
// and (in strict mode) population.
func CheckRule(ctx context.Context, es *elastic.Client, contract Contract, r *rule.Rule, strict bool) RuleResult {
	res := RuleResult{RuleID: r.RuleID}

	query, _ := r.Payload["query"].(string)
	if strings.TrimSpace(query) == "" {
		// Not every rule type has a KQL "query" (e.g. threshold/EQL/ML
		// rules use different fields entirely) -- nothing to extract.
		return res
	}

	fields := ExtractFields(query)
	if len(fields) == 0 {
		return res
	}

	patterns, err := indexPatterns(r.Payload)
	if err != nil {
		res.Errors = append(res.Errors, err.Error())
		return res
	}
	combined := strings.Join(patterns, ",")

	caps, err := es.FieldCaps(ctx, combined, fields)
	if err != nil {
		res.Errors = append(res.Errors, fmt.Sprintf("_field_caps against %q: %v", combined, err))
		return res
	}

	for _, f := range fields {
		typeBuckets, present := caps.Fields[f]
		if !present || len(typeBuckets) == 0 {
			res.Errors = append(res.Errors, fmt.Sprintf("field %q is unmapped in %q", f, combined))
			continue
		}
		if len(typeBuckets) > 1 {
			types := make([]string, 0, len(typeBuckets))
			for t := range typeBuckets {
				types = append(types, t)
			}
			sort.Strings(types)
			res.Errors = append(res.Errors, fmt.Sprintf("field %q has conflicting types %v across indices matching %q", f, types, combined))
			continue
		}

		var actualType string
		for t := range typeBuckets {
			actualType = t
		}
		if expected, ok := contract[f]; ok && expected != actualType {
			res.Errors = append(res.Errors, fmt.Sprintf("field %q is type %q in %q, contract (schema/field-contract.yaml) expects %q", f, actualType, combined, expected))
			continue
		}

		count, err := es.ExistsCount(ctx, combined, f)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Sprintf("exists count for %q against %q: %v", f, combined, err))
			continue
		}
		if count == 0 {
			msg := fmt.Sprintf("field %q is mapped but never populated in %q -- a rule querying it can never match (dead rule)", f, combined)
			if strict {
				res.Errors = append(res.Errors, msg)
			} else {
				res.Warnings = append(res.Warnings, msg)
			}
		}
	}

	return res
}

// CheckAll runs CheckRule for every rule, logs each result, and returns
// whether every rule passed (no Errors -- Warnings don't fail the run).
func CheckAll(ctx context.Context, es *elastic.Client, contract Contract, rules []*rule.Rule, strict bool, logger *log.Logger) bool {
	ok := true
	for _, r := range rules {
		res := CheckRule(ctx, es, contract, r, strict)
		for _, w := range res.Warnings {
			logger.Printf("[PREFLIGHT WARN] %s: %s", res.RuleID, w)
		}
		for _, e := range res.Errors {
			logger.Printf("[PREFLIGHT FAIL] %s: %s", res.RuleID, e)
		}
		if !res.OK() {
			ok = false
		}
	}
	return ok
}
