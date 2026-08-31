// SPDX-License-Identifier: MIT OR Apache-2.0

// Sign a user in from Go with the device flow, and VERIFY the token (issue #116).
//
// Read alongside docs/quickstart-go.md. No dependencies at all: Go's standard library has
// crypto/ed25519, so the signature check below is visible rather than hidden behind a library
// call -- which is the part of this worth reading.
//
// A token that arrived over TLS from the right host is not a verified token. TLS says who sent
// it; the signature says who MINTED it, and those are different questions the moment anything
// sits between you and the issuer.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "quickstart: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	issuer := os.Getenv("ISSUER")
	clientID := os.Getenv("CLIENT_ID")
	if issuer == "" || clientID == "" {
		return fmt.Errorf("ISSUER and CLIENT_ID must be set")
	}
	// The protocol endpoints live at the DEPLOYMENT ROOT while the issuer is per environment.
	root := issuer
	if at := strings.Index(issuer, "/t/"); at >= 0 {
		root = issuer[:at]
	}

	user := envOr("DEV_USER", "dev@example.test")
	password := envOr("DEV_PASSWORD", "dev-password-not-for-production")

	// REDIRECTS ARE NOT FOLLOWED. The login POST answers 303 to /authorize, which answers 303 to
	// the client's registered redirect_uri -- http://127.0.0.1/callback, where nothing listens.
	// Following the chain turns a working login into a connection error from a host this program
	// never meant to contact. What it wants from /login is the session cookie on the 303 itself.
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	// 1. Start the device grant. A public client, so no secret travels.
	grant := map[string]any{}
	if err := postJSON(client, root+"/device_authorization", url.Values{
		"client_id": {clientID},
		"scope":     {"openid"},
	}, nil, &grant); err != nil {
		return fmt.Errorf("the grant did not start: %w", err)
	}
	deviceCode, _ := grant["device_code"].(string)
	userCode, _ := grant["user_code"].(string)
	interval := 5.0
	if value, ok := grant["interval"].(float64); ok {
		interval = value
	}
	fmt.Printf("quickstart: visit %v and enter %s\n", grant["verification_uri"], userCode)

	// 2. Approve it, as the user's second device would. Scripted here so CI runs unattended.
	resume := "/authorize?response_type=code&client_id=" + url.QueryEscape(clientID) +
		"&redirect_uri=http://127.0.0.1/callback&scope=openid"
	jar, err := postForm(client, root+"/login", url.Values{
		"identifier": {user},
		"password":   {password},
		"return_to":  {resume},
	}, nil)
	if err != nil {
		return fmt.Errorf("the approving user could not sign in: %w", err)
	}
	page, more, err := postRaw(client, issuer+"/device", url.Values{"user_code": {userCode}}, jar)
	if err != nil {
		return err
	}
	for name, value := range more {
		jar[name] = value
	}
	handle := regexp.MustCompile(`name="device_code_id"[^>]*value="([^"]+)"`).FindSubmatch(page)
	if handle == nil {
		return fmt.Errorf("the approval page carried no flow handle")
	}
	if _, _, err := postRaw(client, issuer+"/device", url.Values{
		"decision":       {"allow"},
		"device_code_id": {string(handle[1])},
		"user_code":      {userCode},
	}, jar); err != nil {
		return err
	}

	// 3. Poll, honouring the advertised interval.
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Duration(interval) * time.Second)
		token := map[string]any{}
		err := postJSON(client, root+"/token", url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {deviceCode},
			"client_id":   {clientID},
		}, nil, &token)
		if err == nil {
			idToken, _ := token["id_token"].(string)
			claims, err := verify(issuer, idToken, clientID)
			if err != nil {
				return err
			}
			fmt.Printf("quickstart: signed in as %v\n", claims["sub"])
			return nil
		}
		if failure, ok := token["error"].(string); ok &&
			(failure == "authorization_pending" || failure == "slow_down") {
			continue
		}
		return fmt.Errorf("the grant failed: %v", token)
	}
	return fmt.Errorf("timed out waiting for approval")
}

// verify checks an EdDSA ID token against the environment's published JWKS.
//
// Every check here is one a real verifier must do, and the ORDER matters: the algorithm comes
// from what the ISSUER publishes, the key from the published set, and the token's own header is
// only ever matched against them. A verifier that took alg from the header can be talked into
// "none", which is the oldest JOSE bug there is.
func verify(issuer, idToken, audience string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("not a compact JWS")
	}
	header, err := decodeSegment(parts[0])
	if err != nil {
		return nil, err
	}
	claims, err := decodeSegment(parts[1])
	if err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("the signature is not base64url")
	}

	response, err := http.Get(issuer + "/jwks.json")
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(response.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	if header["alg"] != "EdDSA" {
		return nil, fmt.Errorf("this environment publishes EdDSA, token says %v", header["alg"])
	}
	kid, _ := header["kid"].(string)
	var public ed25519.PublicKey
	for _, key := range jwks.Keys {
		if key["kid"] == kid {
			raw, err := base64.RawURLEncoding.DecodeString(key["x"])
			if err != nil {
				return nil, fmt.Errorf("the published key is not base64url")
			}
			public = ed25519.PublicKey(raw)
		}
	}
	if public == nil {
		return nil, fmt.Errorf("no published key for kid %q", kid)
	}
	// NOT OPTIONAL. A quickstart that skipped this would teach that the signature is optional,
	// which is the one thing it must not teach.
	if !ed25519.Verify(public, []byte(parts[0]+"."+parts[1]), signature) {
		return nil, fmt.Errorf("the signature does not verify")
	}

	if claims["iss"] != issuer {
		return nil, fmt.Errorf("wrong issuer %v", claims["iss"])
	}
	if !hasAudience(claims["aud"], audience) {
		return nil, fmt.Errorf("wrong audience %v", claims["aud"])
	}
	exp, _ := claims["exp"].(float64)
	if int64(exp) <= time.Now().Unix() {
		return nil, fmt.Errorf("the token has expired")
	}
	return claims, nil
}

// hasAudience handles `aud` being a string OR an array, which RFC 7519 section 4.1.3 allows. A
// verifier that handled only the string form rejects every multi-audience token an issuer may
// legitimately mint.
func hasAudience(value any, wanted string) bool {
	switch typed := value.(type) {
	case string:
		return typed == wanted
	case []any:
		for _, entry := range typed {
			if entry == wanted {
				return true
			}
		}
	}
	return false
}

func decodeSegment(segment string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, fmt.Errorf("a segment is not base64url")
	}
	out := map[string]any{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("a segment is not JSON")
	}
	return out, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func postRaw(client *http.Client, target string, form url.Values, jar map[string]string) ([]byte, map[string]string, error) {
	request, err := http.NewRequest("POST", target, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, nil, err
	}
	request.Header.Set("content-type", "application/x-www-form-urlencoded")
	if len(jar) > 0 {
		pairs := make([]string, 0, len(jar))
		for name, value := range jar {
			pairs = append(pairs, name+"="+value)
		}
		request.Header.Set("cookie", strings.Join(pairs, "; "))
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, nil, err
	}
	cookies := map[string]string{}
	for _, cookie := range response.Cookies() {
		cookies[cookie.Name] = cookie.Value
	}
	if response.StatusCode >= 400 {
		return body, cookies, fmt.Errorf("%s answered %d: %s", target, response.StatusCode, body)
	}
	return body, cookies, nil
}

func postForm(client *http.Client, target string, form url.Values, jar map[string]string) (map[string]string, error) {
	_, cookies, err := postRaw(client, target, form, jar)
	return cookies, err
}

func postJSON(client *http.Client, target string, form url.Values, jar map[string]string, into *map[string]any) error {
	body, _, err := postRaw(client, target, form, jar)
	// The body is decoded even on an error status, because the token endpoint's
	// `authorization_pending` arrives as a 400 and the caller has to read it.
	if len(body) > 0 {
		_ = json.Unmarshal(body, into)
	}
	return err
}
