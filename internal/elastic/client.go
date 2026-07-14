// Minimal HTTP client for the Elasticsearch APIs the preflight check needs: _field_caps and _count.
// Separate from internal/kibana, which talks to the Detection Engine API on Kibana, not ES directly.
package elastic

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxErrBody = 64 << 10

type Client struct {
	baseURL string
	user    string
	pass    string
	http    *http.Client
}

func New(baseURL, user, pass string, timeout time.Duration, insecureTLS bool) *Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		user:    user,
		pass:    pass,
		http:    &http.Client{Timeout: timeout, Transport: tr},
	}
}

// FieldCapability is one type bucket for a field, as returned by _field_caps.
type FieldCapability struct {
	Type         string `json:"type"`
	Searchable   bool   `json:"searchable"`
	Aggregatable bool   `json:"aggregatable"`
}

// FieldCapsResponse mirrors GET <index>/_field_caps?fields=... . Fields maps
// field name -> ES type name -> capability. More than one key in the inner
// map means the field has conflicting types across the matched indices.
type FieldCapsResponse struct {
	Indices []string                              `json:"indices"`
	Fields  map[string]map[string]FieldCapability `json:"fields"`
}

// FieldCaps resolves indexPattern (may include wildcards, e.g. "forge-windows-ecs*")
// against the fields listed. A field absent from the returned Fields map is
// unmapped in every matched index.
func (c *Client) FieldCaps(ctx context.Context, indexPattern string, fields []string) (*FieldCapsResponse, error) {
	path := fmt.Sprintf("/%s/_field_caps?fields=%s", url.PathEscape(indexPattern), url.QueryEscape(strings.Join(fields, ",")))
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, apiError(resp)
	}

	var out FieldCapsResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode _field_caps response: %w", err)
	}
	return &out, nil
}

// Count runs a _count query and returns the number of matching documents.
func (c *Client) Count(ctx context.Context, indexPattern string, query map[string]any) (int, error) {
	body, err := json.Marshal(map[string]any{"query": query})
	if err != nil {
		return 0, fmt.Errorf("marshal count query: %w", err)
	}

	path := fmt.Sprintf("/%s/_count", url.PathEscape(indexPattern))
	resp, err := c.do(ctx, http.MethodPost, path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, apiError(resp)
	}

	var out struct {
		Count int `json:"count"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return 0, fmt.Errorf("decode _count response: %w", err)
	}
	return out.Count, nil
}

// ExistsCount is a convenience wrapper for the "is this field ever populated" check.
func (c *Client) ExistsCount(ctx context.Context, indexPattern, field string) (int, error) {
	return c.Count(ctx, indexPattern, map[string]any{"exists": map[string]any{"field": field}})
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.SetBasicAuth(c.user, c.pass)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w", method, path, err)
	}
	return resp, nil
}

func apiError(resp *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrBody))
	var e struct {
		Error struct {
			Reason string `json:"reason"`
			Type   string `json:"type"`
		} `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error.Reason != "" {
		return fmt.Errorf("elasticsearch: HTTP %d: %s: %s", resp.StatusCode, e.Error.Type, e.Error.Reason)
	}
	return fmt.Errorf("elasticsearch: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
}
