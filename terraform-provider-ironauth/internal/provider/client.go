// SPDX-License-Identifier: MIT OR Apache-2.0

// Package provider implements the IronAuth Terraform provider (issue #51).
package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a thin management-API client. It is deliberately hand written rather
// than generated: the provider touches a small, stable slice of the surface, and a
// generated client would drag the whole management contract into a binary that
// needs six endpoints.
type Client struct {
	Endpoint string
	Token    string
	HTTP     *http.Client
}

// NewClient builds a client against endpoint with a sane timeout. A provider that
// hangs blocks a whole plan, so the timeout is short and explicit rather than the
// Go default of none at all.
func NewClient(endpoint, token string) *Client {
	return &Client{
		Endpoint: strings.TrimRight(endpoint, "/"),
		Token:    token,
		HTTP:     &http.Client{Timeout: 30 * time.Second},
	}
}

// APIError carries the status and the server's own body, which is what makes a
// failed apply diagnosable. Swallowing the body and reporting "request failed" is
// the single most common way a provider wastes an operator's afternoon.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("management API returned %d: %s", e.Status, e.Body)
}

// NotFound reports whether the error is a 404, which Terraform needs to
// distinguish so a resource deleted out of band is REMOVED FROM STATE rather than
// failing every subsequent plan.
func NotFound(err error) bool {
	var apiErr *APIError
	if e, ok := err.(*APIError); ok {
		apiErr = e
	}
	return apiErr != nil && apiErr.Status == http.StatusNotFound
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any, idempotencyKey string) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, c.Endpoint+path, reader)
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	request.Header.Set("authorization", "Bearer "+c.Token)
	if body != nil {
		request.Header.Set("content-type", "application/json")
	}
	// Every management POST honours Idempotency-Key. Terraform retries, and a retry
	// that created a SECOND tenant would leave an orphan nothing in state points at.
	if idempotencyKey != "" {
		request.Header.Set("idempotency-key", idempotencyKey)
	}
	response, err := c.HTTP.Do(request)
	if err != nil {
		return fmt.Errorf("calling %s %s: %w", method, path, err)
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return &APIError{Status: response.StatusCode, Body: string(payload)}
	}
	if out != nil && len(payload) > 0 {
		if err := json.Unmarshal(payload, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

// Tenant is the slice of a tenant the provider manages.
type Tenant struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
}

// tenantCreated is the create ENVELOPE. Creating a tenant also creates its first
// environment, so the response is `{tenant, environment}` rather than a bare tenant.
// Decoding it as a bare tenant silently yields empty fields, and Terraform then
// rejects the apply with "provider produced inconsistent result": the acceptance
// test caught exactly that, which is what an acceptance test is for.
type tenantCreated struct {
	Tenant Tenant `json:"tenant"`
}

// CreateTenant creates a tenant. idempotencyKey must be stable for one logical
// create so a Terraform retry replays rather than duplicating.
func (c *Client) CreateTenant(ctx context.Context, displayName, idempotencyKey string) (*Tenant, error) {
	var created tenantCreated
	body := map[string]string{"display_name": displayName}
	if err := c.do(ctx, http.MethodPost, "/v1/tenants", body, &created, idempotencyKey); err != nil {
		return nil, err
	}
	return &created.Tenant, nil
}

// GetTenant reads one tenant. A 404 comes back as an *APIError so the caller can
// tell "gone" from "broken"; conflating them makes a provider either wedge on a
// deleted resource or silently recreate one during an outage.
func (c *Client) GetTenant(ctx context.Context, id string) (*Tenant, error) {
	var found Tenant
	if err := c.do(ctx, http.MethodGet, "/v1/tenants/"+id, nil, &found, ""); err != nil {
		return nil, err
	}
	return &found, nil
}

// UpdateTenant renames a tenant.
func (c *Client) UpdateTenant(ctx context.Context, id, displayName string) (*Tenant, error) {
	var updated Tenant
	body := map[string]string{"display_name": displayName}
	if err := c.do(ctx, http.MethodPatch, "/v1/tenants/"+id, body, &updated, ""); err != nil {
		return nil, err
	}
	return &updated, nil
}

// DeleteTenant removes a tenant. A 404 is treated as success: destroy is meant to
// converge on absence, and failing because something else already deleted it
// leaves an operator unable to run `destroy` at all.
func (c *Client) DeleteTenant(ctx context.Context, id string) error {
	err := c.do(ctx, http.MethodDelete, "/v1/tenants/"+id, nil, nil, "")
	if err != nil && NotFound(err) {
		return nil
	}
	return err
}
