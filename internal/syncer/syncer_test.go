package syncer

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"dac-sync/internal/kibana"
	"dac-sync/internal/rule"
)

// Verifies headers, rule_id-based existence check, POST/PUT routing, and the resulting Summary against a fake Kibana.
func TestRun_CreateAndUpdate(t *testing.T) {
	var posts, puts int

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("kbn-xsrf") == "" {
			t.Errorf("%s %s: missing kbn-xsrf header", r.Method, r.URL)
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "elastic" || p != "changeme" {
			t.Errorf("%s %s: bad basic auth", r.Method, r.URL)
		}

		switch r.Method {
		case http.MethodGet:
			if r.URL.Query().Get("rule_id") == "existing-rule" {
				w.Write([]byte(`{}`))
				return
			}
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(`{"message":"rule not found","status_code":404}`))

		case http.MethodPost:
			posts++
			body, _ := io.ReadAll(r.Body)
			var m map[string]any
			if err := json.Unmarshal(body, &m); err != nil {
				t.Errorf("POST body is not JSON: %v", err)
			}
			if m["rule_id"] != "new-rule" {
				t.Errorf("POST for wrong rule: %v", m["rule_id"])
			}
			w.Write([]byte(`{}`))

		case http.MethodPut:
			puts++
			body, _ := io.ReadAll(r.Body)
			var m map[string]any
			_ = json.Unmarshal(body, &m)
			if m["rule_id"] != "existing-rule" {
				t.Errorf("PUT for wrong rule: %v", m["rule_id"])
			}
			w.Write([]byte(`{}`))

		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	}))
	defer srv.Close()

	c := kibana.New(srv.URL, "elastic", "changeme", 5*time.Second, false)
	rules := []*rule.Rule{
		{RuleID: "existing-rule", Name: "Existing", Path: "t1.yml",
			Payload: map[string]any{"rule_id": "existing-rule", "name": "Existing", "type": "query"}},
		{RuleID: "new-rule", Name: "New", Path: "t2.yml",
			Payload: map[string]any{"rule_id": "new-rule", "name": "New", "type": "query"}},
	}

	sum := Run(context.Background(), c, rules, false, log.New(io.Discard, "", 0))

	if sum.Created != 1 || sum.Updated != 1 || sum.Failed != 0 {
		t.Fatalf("summary = %+v, want created=1 updated=1 failed=0", sum)
	}
	if posts != 1 || puts != 1 {
		t.Fatalf("posts=%d puts=%d, want 1 and 1", posts, puts)
	}
}

// Verifies dry-run still checks existence but never issues a write.
func TestRun_DryRunMutatesNothing(t *testing.T) {
	var writes int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writes++
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`{"message":"rule not found","status_code":404}`))
	}))
	defer srv.Close()

	c := kibana.New(srv.URL, "elastic", "changeme", 5*time.Second, false)
	rules := []*rule.Rule{
		{RuleID: "r1", Name: "R1", Path: "r1.yml",
			Payload: map[string]any{"rule_id": "r1", "name": "R1", "type": "query"}},
	}

	sum := Run(context.Background(), c, rules, true, log.New(io.Discard, "", 0))

	if writes != 0 {
		t.Fatalf("dry-run issued %d write request(s)", writes)
	}
	if sum.Created != 1 || sum.Failed != 0 {
		t.Fatalf("summary = %+v, want planned created=1 failed=0", sum)
	}
}
