package preflight

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"dac-sync/internal/elastic"
	"dac-sync/internal/rule"
)

func TestExtractFields(t *testing.T) {
	cases := []struct {
		name  string
		query string
		want  []string
	}{
		{
			name:  "simple and/or",
			query: `(event.category: "process" and event.type: "start") and (process.name: "powershell.exe" or process.name: "pwsh.exe")`,
			want:  []string{"event.category", "event.type", "process.name"},
		},
		{
			name:  "dotted multi-field",
			query: `process.command_line.text: "enc" or process.command_line.text: "encodedcommand"`,
			want:  []string{"process.command_line.text"},
		},
		{
			name:  "not keyword and cidr value",
			query: `event.category: "network" and not destination.ip: (10.0.0.0/8 or 172.16.0.0/12)`,
			want:  []string{"event.category", "destination.ip"},
		},
		{
			name:  "colon inside a quoted value is not a field",
			query: `process.command_line.text: "http://evil.example.com:8080/x"`,
			want:  []string{"process.command_line.text"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ExtractFields(tc.query)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ExtractFields(%q) = %v, want %v", tc.query, got, tc.want)
			}
		})
	}
}

func TestLoadContract(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/contract.yaml"
	if err := writeFile(path, "fields:\n  event.category: keyword\n  process.pid: long\n"); err != nil {
		t.Fatal(err)
	}
	c, err := LoadContract(path)
	if err != nil {
		t.Fatalf("LoadContract: %v", err)
	}
	if c["event.category"] != "keyword" || c["process.pid"] != "long" {
		t.Fatalf("contract = %+v", c)
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o644)
}

// fakeES serves canned _field_caps and _count responses keyed by field name,
// so each test controls exactly what the "live mapping" looks like.
type fakeES struct {
	fieldTypes map[string][]string // field -> type buckets present (empty/absent = unmapped)
	existsZero map[string]bool     // fields whose _count exists query should return 0
}

func newFakeES(t *testing.T, es *fakeES) *elastic.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/_field_caps"):
			fields := strings.Split(r.URL.Query().Get("fields"), ",")
			out := map[string]map[string]elastic.FieldCapability{}
			for _, f := range fields {
				types, ok := es.fieldTypes[f]
				if !ok {
					continue // unmapped -- omit entirely, matching real ES behavior
				}
				bucket := map[string]elastic.FieldCapability{}
				for _, ty := range types {
					bucket[ty] = elastic.FieldCapability{Type: ty, Searchable: true, Aggregatable: true}
				}
				out[f] = bucket
			}
			resp := elastic.FieldCapsResponse{Indices: []string{"forge-windows-ecs"}, Fields: out}
			_ = json.NewEncoder(w).Encode(resp)

		case strings.HasSuffix(r.URL.Path, "/_count"):
			body, _ := io.ReadAll(r.Body)
			var q struct {
				Query struct {
					Exists struct {
						Field string `json:"field"`
					} `json:"exists"`
				} `json:"query"`
			}
			_ = json.Unmarshal(body, &q)
			count := 1
			if es.existsZero[q.Query.Exists.Field] {
				count = 0
			}
			_ = json.NewEncoder(w).Encode(map[string]int{"count": count})

		default:
			t.Errorf("unexpected request: %s", r.URL.Path)
		}
	}))
	t.Cleanup(srv.Close)
	return elastic.New(srv.URL, "elastic", "changeme", 5*time.Second, false)
}

func testRule(query string, index any) *rule.Rule {
	return &rule.Rule{
		RuleID: "test-rule",
		Name:   "Test Rule",
		Path:   "test.yml",
		Payload: map[string]any{
			"rule_id": "test-rule",
			"name":    "Test Rule",
			"type":    "query",
			"query":   query,
			"index":   index,
		},
	}
}

func TestCheckRule_Passes(t *testing.T) {
	es := newFakeES(t, &fakeES{
		fieldTypes: map[string][]string{
			"event.category": {"keyword"},
			"process.name":   {"keyword"},
		},
	})
	contract := Contract{"event.category": "keyword", "process.name": "keyword"}
	r := testRule(`event.category: "process" and process.name: "powershell.exe"`, "forge-windows-ecs*")

	res := CheckRule(context.Background(), es, contract, r, false)
	if !res.OK() {
		t.Fatalf("expected pass, got errors: %v", res.Errors)
	}
}

// Negative test: a rule referencing a field that doesn't exist anywhere in
// the mapping must fail preflight, naming the field.
func TestCheckRule_UnmappedFieldFails(t *testing.T) {
	es := newFakeES(t, &fakeES{
		fieldTypes: map[string][]string{
			"event.category": {"keyword"},
		},
	})
	contract := Contract{"event.category": "keyword"}
	r := testRule(`event.category: "process" and process.nonexistent_field: "x"`, "forge-windows-ecs*")

	res := CheckRule(context.Background(), es, contract, r, false)
	if res.OK() {
		t.Fatal("expected failure for unmapped field, got pass")
	}
	if !anyContains(res.Errors, "process.nonexistent_field") || !anyContains(res.Errors, "unmapped") {
		t.Fatalf("errors don't clearly name the unmapped field: %v", res.Errors)
	}
}

func TestCheckRule_TypeMismatchFails(t *testing.T) {
	es := newFakeES(t, &fakeES{
		fieldTypes: map[string][]string{
			"winlog.event_id": {"keyword"}, // contract expects long
		},
	})
	contract := Contract{"winlog.event_id": "long"}
	r := testRule(`winlog.event_id: "4688"`, "forge-windows-ecs*")

	res := CheckRule(context.Background(), es, contract, r, false)
	if res.OK() {
		t.Fatal("expected failure for type mismatch, got pass")
	}
	if !anyContains(res.Errors, "winlog.event_id") {
		t.Fatalf("errors don't name the mismatched field: %v", res.Errors)
	}
}

func TestCheckRule_CrossIndexConflictFails(t *testing.T) {
	es := newFakeES(t, &fakeES{
		fieldTypes: map[string][]string{
			"winlog.event_id": {"keyword", "long"}, // conflicting types across matched indices
		},
	})
	contract := Contract{"winlog.event_id": "long"}
	r := testRule(`winlog.event_id: "4688"`, []any{"forge-windows-ecs*", "winlogbeat-*"})

	res := CheckRule(context.Background(), es, contract, r, false)
	if res.OK() {
		t.Fatal("expected failure for cross-index type conflict, got pass")
	}
	if !anyContains(res.Errors, "conflicting types") {
		t.Fatalf("errors don't mention the conflict: %v", res.Errors)
	}
}

func TestCheckRule_MappedButEmpty_WarnsByDefault_FailsStrict(t *testing.T) {
	es := newFakeES(t, &fakeES{
		fieldTypes: map[string][]string{"destination.ip": {"ip"}},
		existsZero: map[string]bool{"destination.ip": true},
	})
	contract := Contract{"destination.ip": "ip"}
	r := testRule(`destination.ip: "198.51.100.10"`, "forge-windows-ecs*")

	nonStrict := CheckRule(context.Background(), es, contract, r, false)
	if !nonStrict.OK() {
		t.Fatalf("non-strict mode should warn, not fail: %v", nonStrict.Errors)
	}
	if len(nonStrict.Warnings) == 0 {
		t.Fatal("expected a warning about the mapped-but-empty field")
	}

	strict := CheckRule(context.Background(), es, contract, r, true)
	if strict.OK() {
		t.Fatal("strict mode should fail on a mapped-but-empty field")
	}
}

func TestCheckAll_ReturnsFalseOnAnyFailure(t *testing.T) {
	es := newFakeES(t, &fakeES{
		fieldTypes: map[string][]string{"event.category": {"keyword"}},
	})
	contract := Contract{"event.category": "keyword"}
	rules := []*rule.Rule{
		testRule(`event.category: "process"`, "forge-windows-ecs*"),
		testRule(`event.category: "process" and bogus.field: "x"`, "forge-windows-ecs*"),
	}

	ok := CheckAll(context.Background(), es, contract, rules, false, log.New(io.Discard, "", 0))
	if ok {
		t.Fatal("expected CheckAll to return false when one rule fails")
	}
}

func anyContains(list []string, substr string) bool {
	for _, s := range list {
		if strings.Contains(s, substr) {
			return true
		}
	}
	return false
}
