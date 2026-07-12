// Loads detection rule files from disk and validates the handful of fields the syncer needs.
package rule

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Rule struct {
	RuleID  string
	Name    string
	Path    string
	Payload map[string]any
}

func (r *Rule) JSON() ([]byte, error) {
	b, err := json.Marshal(r.Payload)
	if err != nil {
		return nil, fmt.Errorf("%s: marshal: %w", r.Path, err)
	}
	return b, nil
}

func LoadDir(dir string) ([]*Rule, error) {
	var rules []*Rule
	seen := map[string]string{} // rule_id -> defining file

	walk := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".json" && ext != ".yaml" && ext != ".yml" {
			return nil
		}

		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}

		payload := map[string]any{}
		switch ext {
		case ".json":
			if err := json.Unmarshal(raw, &payload); err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
		default:
			if err := yaml.Unmarshal(raw, &payload); err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
		}

		r, err := build(path, payload)
		if err != nil {
			return err
		}
		if prev, dup := seen[r.RuleID]; dup {
			return fmt.Errorf("duplicate rule_id %q: %s and %s", r.RuleID, prev, path)
		}
		seen[r.RuleID] = path
		rules = append(rules, r)
		return nil
	}

	if err := filepath.WalkDir(dir, walk); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rule files (.json/.yaml/.yml) found under %s", dir)
	}
	return rules, nil
}

func build(path string, payload map[string]any) (*Rule, error) {
	id, err := stringField(payload, "rule_id")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	name, err := stringField(payload, "name")
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if _, err := stringField(payload, "type"); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &Rule{RuleID: id, Name: name, Path: path, Payload: payload}, nil
}

func stringField(m map[string]any, key string) (string, error) {
	v, ok := m[key]
	if !ok {
		return "", fmt.Errorf("missing required field %q", key)
	}
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", fmt.Errorf("field %q must be a non-empty string", key)
	}
	return s, nil
}
