// SPDX-License-Identifier: MIT OR Apache-2.0
package management_test

import (
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/ELares/ironauth/sdks/go/management"
)

type captureTransport func(*http.Request) (*http.Response, error)

func (f captureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"X-Request-Id": {"request-1"}}, Body: io.NopCloser(strings.NewReader(body))}
}

func readResponse(t *testing.T, r *http.Response, err error, status int, body string) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	got, err := io.ReadAll(r.Body)
	if err != nil || r.StatusCode != status || string(got) != body || r.Header.Get("X-Request-Id") != "request-1" {
		t.Fatalf("response changed: status=%d body=%q err=%v headers=%v", r.StatusCode, got, err, r.Header)
	}
}

func TestBackupCallerKeySurvivesExplicitRetryAndHTTPFailures(t *testing.T) {
	statuses := []int{503, 202, 422, 401}
	bodies := []string{`{"error":"temporarily_unavailable"}`, `{"request_id":"saved"}`, `{"error":"idempotency_key_conflict"}`, `{"error":"unauthorized"}`}
	key := "Backup-Operation.A_17:retry"
	calls := 0
	client := management.New("https://management.example/", "operator-token")
	client.HTTP = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.String() != "https://management.example/v1/tenants/tenant/environments/environment/backups" || r.ContentLength != 0 {
			t.Fatalf("backup request changed: %s %s length=%d", r.Method, r.URL, r.ContentLength)
		}
		if got := r.Header.Values("Idempotency-Key"); !reflect.DeepEqual(got, []string{key}) {
			t.Fatalf("caller key changed: %q", got)
		}
		if r.Header.Get("Authorization") != "Bearer operator-token" {
			t.Fatal("authentication changed")
		}
		result := response(statuses[calls], bodies[calls])
		calls++
		return result, nil
	})}
	operation := client.WithIdempotencyKey(key)
	for i := range statuses {
		r, err := operation.TriggerBackup("tenant", "environment", nil)
		readResponse(t, r, err, statuses[i], bodies[i])
		if calls != i+1 {
			t.Fatal("the SDK must not retry or replace a caller's operation key")
		}
	}
}

func TestKeyedClientsAreIndependentAndOriginalRemainsUnchanged(t *testing.T) {
	var keys []string
	client := management.New("https://management.example", "operator-token")
	client.HTTP = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		if r.Header.Get("Idempotency-Key") == "" && r.Header.Values("Idempotency-Key") != nil {
			t.Fatal("an empty key must omit the header")
		}
		return response(202, "accepted"), nil
	})}
	original := *client
	first := client.WithIdempotencyKey("first")
	second := first.WithIdempotencyKey("second")
	cleared := first.WithIdempotencyKey("")
	other := management.New(client.BaseURL, client.Token)
	other.HTTP = client.HTTP
	otherOperation := other.WithIdempotencyKey("other")
	for _, c := range []*management.Client{first, second, client, otherOperation, first, cleared, second, other} {
		r, err := c.TriggerBackup("tenant", "environment", nil)
		readResponse(t, r, err, 202, "accepted")
	}
	if want := []string{"first", "second", "", "other", "first", "", "second", ""}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("keys leaked between clients: got %q want %q", keys, want)
	}
	if *client != original || first == client || first == second || first.HTTP != original.HTTP {
		t.Fatal("builder mutated the original or did not preserve its transport")
	}
}

func TestBackupTransportErrorIsReturnedWithoutAutomaticRetry(t *testing.T) {
	want := errors.New("connection interrupted")
	calls := 0
	client := management.New("https://management.example", "operator-token")
	client.HTTP = &http.Client{Transport: captureTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Header.Get("Idempotency-Key") != "persisted-operation-key" {
			t.Fatal("missing caller key")
		}
		return nil, want
	})}
	operation := client.WithIdempotencyKey("persisted-operation-key")
	for i := 1; i <= 2; i++ {
		r, err := operation.TriggerBackup("tenant", "environment", nil)
		if r != nil || !errors.Is(err, want) || calls != i {
			t.Fatalf("transport failure changed: response=%v err=%v calls=%d", r, err, calls)
		}
	}
}
