// Minimal HTTP client for the Kibana Detection Engine rules API: check existence by rule_id, then POST or PUT.
package kibana

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

const (
	rulesPath  = "/api/detection_engine/rules"
	apiVersion = "2023-10-31"
	maxErrBody = 64 << 10
)

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

func (c *Client) RuleExists(ctx context.Context, ruleID string) (bool, error) {
	resp, err := c.do(ctx, http.MethodGet, rulesPath+"?rule_id="+url.QueryEscape(ruleID), nil)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		drain(resp.Body)
		return true, nil
	case http.StatusNotFound:
		drain(resp.Body)
		return false, nil
	default:
		return false, apiError(resp)
	}
}

func (c *Client) CreateRule(ctx context.Context, body []byte) error {
	return c.write(ctx, http.MethodPost, body)
}

func (c *Client) UpdateRule(ctx context.Context, body []byte) error {
	return c.write(ctx, http.MethodPut, body)
}

func (c *Client) write(ctx context.Context, method string, body []byte) error {
	resp, err := c.do(ctx, method, rulesPath, bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 == 2 {
		drain(resp.Body)
		return nil
	}
	return apiError(resp)
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.SetBasicAuth(c.user, c.pass)
	req.Header.Set("kbn-xsrf", "true")
	req.Header.Set("elastic-api-version", apiVersion)
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
		Message string `json:"message"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Message != "" {
		return fmt.Errorf("kibana: HTTP %d: %s", resp.StatusCode, e.Message)
	}
	return fmt.Errorf("kibana: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
}

func drain(r io.Reader) { _, _ = io.Copy(io.Discard, io.LimitReader(r, maxErrBody)) }
