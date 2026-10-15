package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

func TestTokenStoreRotationRevocationAndRestart(t *testing.T) {
	path := t.TempDir() + "/tokens.json"
	store, err := newTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	first, err := store.rotate("google-sub-a")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(first, "hrs_") {
		t.Fatalf("token prefix = %q", first)
	}
	if data, err := os.ReadFile(path); err != nil {
		t.Fatal(err)
	} else if strings.Contains(string(data), first) {
		t.Fatal("token file contains plaintext token")
	}
	if info, err := store.verify(context.Background(), first, nil); err != nil || info.UserID != "google-sub-a" {
		t.Fatalf("verify first token = %#v, %v", info, err)
	}

	restarted, err := newTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.verify(context.Background(), first, nil); err != nil {
		t.Fatalf("restarted store rejected token: %v", err)
	}
	second, err := restarted.rotate("google-sub-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.verify(context.Background(), first, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("rotated token error = %v, want ErrInvalidToken", err)
	}
	if info, err := restarted.verify(context.Background(), second, nil); err != nil || info.UserID != "google-sub-a" {
		t.Fatalf("verify rotated token = %#v, %v", info, err)
	}
	if _, err := restarted.verify(context.Background(), second+"x", nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("malformed token error = %v, want ErrInvalidToken", err)
	}
	if err := restarted.revoke("google-sub-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.verify(context.Background(), second, nil); !errors.Is(err, auth.ErrInvalidToken) {
		t.Fatalf("revoked token error = %v, want ErrInvalidToken", err)
	}
}

func TestTokenStoreDiskFailurePreservesCurrentToken(t *testing.T) {
	path := t.TempDir() + "/tokens.json"
	store, err := newTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := store.rotate("subject")
	if err != nil {
		t.Fatal(err)
	}
	store.path = t.TempDir() + "/missing-dir/tokens.json"
	if _, err := store.rotate("subject"); err == nil {
		t.Fatal("rotation unexpectedly succeeded with unwritable token path")
	}
	if _, err := store.verify(context.Background(), token, nil); err != nil {
		t.Fatalf("failed rotation invalidated current token: %v", err)
	}
	if err := store.revoke("subject"); err == nil {
		t.Fatal("revocation unexpectedly succeeded with unwritable token path")
	}
	if _, err := store.verify(context.Background(), token, nil); err != nil {
		t.Fatalf("failed revocation invalidated current token: %v", err)
	}
}

func TestTokenStoreRejectsCorruptPersistence(t *testing.T) {
	path := t.TempDir() + "/tokens.json"
	if err := os.WriteFile(path, []byte(`{"tokens":{"subject":"not-a-digest"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newTokenStore(path); err == nil {
		t.Fatal("corrupt token store accepted")
	}
}

type fixedOIDCFixture struct {
	server *httptest.Server
	key    *rsa.PrivateKey
	codes  map[string]struct {
		challenge string
		nonce     string
	}
}

func newFixedOIDCFixture(t *testing.T) *fixedOIDCFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &fixedOIDCFixture{key: key, codes: make(map[string]struct {
		challenge string
		nonce     string
	})}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":                 googleIssuer,
				"authorization_endpoint": fixture.server.URL + "/authorize",
				"token_endpoint":         fixture.server.URL + "/token",
				"jwks_uri":               fixture.server.URL + "/jwks",
			})
		case "/authorize":
			state, nonce := r.URL.Query().Get("state"), r.URL.Query().Get("nonce")
			challenge, redirect := r.URL.Query().Get("code_challenge"), r.URL.Query().Get("redirect_uri")
			if state == "" || nonce == "" || challenge == "" || redirect == "" {
				http.Error(w, "invalid authorization request", http.StatusBadRequest)
				return
			}
			code := "fixture-code-" + state
			fixture.codes[code] = struct {
				challenge string
				nonce     string
			}{challenge: challenge, nonce: nonce}
			callback, err := url.Parse(redirect)
			if err != nil {
				http.Error(w, "invalid redirect", http.StatusBadRequest)
				return
			}
			query := callback.Query()
			query.Set("state", state)
			query.Set("code", code)
			callback.RawQuery = query.Encode()
			http.Redirect(w, r, callback.String(), http.StatusFound)
		case "/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid token request", http.StatusBadRequest)
				return
			}
			code := r.Form.Get("code")
			entry, ok := fixture.codes[code]
			if !ok {
				http.Error(w, "invalid code", http.StatusBadRequest)
				return
			}
			verifier := r.Form.Get("code_verifier")
			sum := sha256.Sum256([]byte(verifier))
			if want := base64.RawURLEncoding.EncodeToString(sum[:]); verifier == "" || want != entry.challenge {
				http.Error(w, "invalid PKCE", http.StatusBadRequest)
				return
			}
			idToken := signedIDToken(t, fixture.key, map[string]any{
				"iss":            googleIssuer,
				"aud":            "client-id",
				"sub":            "google-sub",
				"email":          "person@example.com",
				"email_verified": true,
				"hd":             "example.com",
				"nonce":          entry.nonce,
				"iat":            time.Now().Unix(),
				"exp":            time.Now().Add(5 * time.Minute).Unix(),
			})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"access_token": "fixture-access-token",
				"token_type":   "Bearer",
				"id_token":     idToken,
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key:       &fixture.key.PublicKey,
				KeyID:     "fixture",
				Algorithm: string(jose.RS256),
				Use:       "sig",
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

type rewriteTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (t rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	if clone.URL.Host == "accounts.google.com" {
		u := *clone.URL
		u.Scheme, u.Host = t.target.Scheme, t.target.Host
		clone.URL = &u
	}
	return t.base.RoundTrip(clone)
}

func newFixtureAuthentication(t *testing.T, fixture *fixedOIDCFixture) *authentication {
	t.Helper()
	secretPath := t.TempDir() + "/secret"
	if err := os.WriteFile(secretPath, []byte("fixture-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseURL, err := url.Parse(fixture.server.URL)
	if err != nil {
		t.Fatal(err)
	}
	c := config{Auth: authConfig{
		ResourceURL:            "http://127.0.0.1:8080/mcp",
		WorkspaceDomain:        "example.com",
		GoogleClientID:         "client-id",
		GoogleClientSecretFile: secretPath,
		TokenFile:              t.TempDir() + "/tokens.json",
	}}
	authentication, err := newAuthenticationWithHTTPClient(context.Background(), c, &http.Client{Transport: rewriteTransport{target: baseURL, base: http.DefaultTransport}})
	if err != nil {
		t.Fatal(err)
	}
	return authentication
}

func signedIDToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	object, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := object.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestGoogleIDTokenChecksNonceDomainEmailAndAudience(t *testing.T) {
	fixture := newFixedOIDCFixture(t)
	a := newFixtureAuthentication(t, fixture)
	pending := pendingLogin{nonce: "nonce"}
	claims := map[string]any{
		"iss":            googleIssuer,
		"aud":            "client-id",
		"sub":            "google-sub",
		"email":          "person@example.com",
		"email_verified": true,
		"hd":             "example.com",
		"nonce":          "nonce",
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(5 * time.Minute).Unix(),
	}
	valid := signedIDToken(t, fixture.key, claims)
	if got, err := a.verifyGoogleIDToken(context.Background(), valid, pending); err != nil || got.Subject != "google-sub" {
		t.Fatalf("valid ID token = %#v, %v", got, err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"wrong domain":     func(c map[string]any) { c["hd"] = "other.example" },
		"unverified email": func(c map[string]any) { c["email_verified"] = false },
		"wrong nonce":      func(c map[string]any) { c["nonce"] = "other" },
		"wrong issuer":     func(c map[string]any) { c["iss"] = "https://accounts.example.invalid" },
		"wrong audience":   func(c map[string]any) { c["aud"] = "other-client" },
		"expired":          func(c map[string]any) { c["exp"] = time.Now().Add(-time.Minute).Unix() },
		"missing subject":  func(c map[string]any) { delete(c, "sub") },
	} {
		t.Run(name, func(t *testing.T) {
			mutate(claims)
			if _, err := a.verifyGoogleIDToken(context.Background(), signedIDToken(t, fixture.key, claims), pending); err == nil {
				t.Fatal("invalid ID token accepted")
			}
			claims["iss"] = googleIssuer
			claims["exp"] = time.Now().Add(5 * time.Minute).Unix()
			claims["sub"] = "google-sub"
			claims["hd"] = "example.com"
			claims["email_verified"] = true
			claims["nonce"] = "nonce"
			claims["aud"] = "client-id"
		})
	}
}

func TestLoginStatePKCEAndBrowserBinding(t *testing.T) {
	fixture := newFixedOIDCFixture(t)
	a := newFixtureAuthentication(t, fixture)

	startResponse := httptest.NewRecorder()
	a.handler().ServeHTTP(startResponse, httptest.NewRequest(http.MethodGet, "/auth/google/start", nil))
	if startResponse.Code != http.StatusFound {
		t.Fatalf("start status = %d", startResponse.Code)
	}
	startLocation, err := url.Parse(startResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var stateCookie *http.Cookie
	for _, cookie := range startResponse.Result().Cookies() {
		if cookie.Name == a.stateCookieName() {
			stateCookie = cookie
			break
		}
	}
	if stateCookie == nil {
		t.Fatal("start response omitted browser-bound state cookie")
	}

	authorizeResponse := httptest.NewRecorder()
	fixture.server.Config.Handler.ServeHTTP(authorizeResponse, httptest.NewRequest(http.MethodGet, startLocation.String(), nil))
	if authorizeResponse.Code != http.StatusFound {
		t.Fatalf("authorize status = %d", authorizeResponse.Code)
	}
	callbackURL := authorizeResponse.Header().Get("Location")
	callbackRequest := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	callbackRequest.AddCookie(stateCookie)
	callbackResponse := httptest.NewRecorder()
	a.handler().ServeHTTP(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusFound || callbackResponse.Header().Get("Location") != "/" {
		t.Fatalf("callback status/location = %d %q", callbackResponse.Code, callbackResponse.Header().Get("Location"))
	}
	var sessionCookie *http.Cookie
	for _, cookie := range callbackResponse.Result().Cookies() {
		if cookie.Name == a.sessionCookieName() && cookie.Value != "" {
			sessionCookie = cookie
			break
		}
	}
	if sessionCookie == nil {
		t.Fatal("callback response omitted browser session cookie")
	}
	accountRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	accountRequest.AddCookie(sessionCookie)
	accountResponse := httptest.NewRecorder()
	a.handler().ServeHTTP(accountResponse, accountRequest)
	if !strings.Contains(accountResponse.Body.String(), "person@example.com") || !strings.Contains(accountResponse.Body.String(), "google-sub") {
		t.Fatal("authenticated account page omitted verified identity")
	}

	replayRequest := httptest.NewRequest(http.MethodGet, callbackURL, nil)
	replayRequest.AddCookie(stateCookie)
	replayResponse := httptest.NewRecorder()
	a.handler().ServeHTTP(replayResponse, replayRequest)
	if replayResponse.Code != http.StatusBadRequest {
		t.Fatalf("callback replay status = %d, want 400", replayResponse.Code)
	}

	startResponse = httptest.NewRecorder()
	a.handler().ServeHTTP(startResponse, httptest.NewRequest(http.MethodGet, "/auth/google/start", nil))
	secondLocation, err := url.Parse(startResponse.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var secondCookie *http.Cookie
	for _, cookie := range startResponse.Result().Cookies() {
		if cookie.Name == a.stateCookieName() {
			secondCookie = cookie
			break
		}
	}
	authorizeResponse = httptest.NewRecorder()
	fixture.server.Config.Handler.ServeHTTP(authorizeResponse, httptest.NewRequest(http.MethodGet, secondLocation.String(), nil))
	wrongBrowser := httptest.NewRequest(http.MethodGet, authorizeResponse.Header().Get("Location"), nil)
	wrongBrowser.AddCookie(stateCookie)
	wrongResponse := httptest.NewRecorder()
	a.handler().ServeHTTP(wrongResponse, wrongBrowser)
	if wrongResponse.Code != http.StatusBadRequest {
		t.Fatalf("wrong-browser callback status = %d, want 400", wrongResponse.Code)
	}
	rightBrowser := httptest.NewRequest(http.MethodGet, authorizeResponse.Header().Get("Location"), nil)
	rightBrowser.AddCookie(secondCookie)
	rightResponse := httptest.NewRecorder()
	a.handler().ServeHTTP(rightResponse, rightBrowser)
	if rightResponse.Code != http.StatusFound {
		t.Fatalf("right-browser callback status = %d, want 302", rightResponse.Code)
	}
}

func TestAccountActionsRequireOriginAndSessionCSRF(t *testing.T) {
	policyPath := t.TempDir() + "/policy.json"
	if err := os.WriteFile(policyPath, []byte(`{"subjects":{},"catalogs":{"alpha":["*"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := newTokenStore(t.TempDir() + "/tokens.json")
	if err != nil {
		t.Fatal(err)
	}
	a := &authentication{
		cfg: config{PolicyFile: policyPath}, origin: "http://127.0.0.1:8080", tokens: store,
		pending: make(map[string]pendingLogin), sessions: map[string]browserSession{
			"session-a": {subject: "subject-a", email: "a@example.com", csrf: "csrf-a", expires: time.Now().Add(time.Hour)},
			"session-b": {subject: "subject-b", email: "b@example.com", csrf: "csrf-b", expires: time.Now().Add(time.Hour)},
		}, now: time.Now,
	}
	req := httptest.NewRequest(http.MethodPost, "/tokens/rotate", strings.NewReader("csrf=csrf-a"))
	req.Header.Set("Origin", a.origin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "hr_session", Value: "session-a"})
	response := httptest.NewRecorder()
	a.handler().ServeHTTP(response, req)
	if response.Code != http.StatusOK {
		t.Fatalf("workspace account without individual membership cannot rotate: %d", response.Code)
	}
	token := regexp.MustCompile(`hrs_[A-Za-z0-9_-]{43}`).FindString(response.Body.String())
	if info, err := store.verify(context.Background(), token, req); err != nil || info.UserID != "subject-a" {
		t.Fatal("account response did not contain a usable personal token")
	}
	if strings.Contains(response.Body.String(), "subject-b") {
		t.Fatal("account page exposed another subject")
	}

	anonymous := httptest.NewRequest(http.MethodPost, "/tokens/rotate", strings.NewReader("csrf=csrf-a"))
	anonymous.Header.Set("Origin", a.origin)
	anonymous.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	anonymousResponse := httptest.NewRecorder()
	a.handler().ServeHTTP(anonymousResponse, anonymous)
	if anonymousResponse.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous rotation status = %d, want 401", anonymousResponse.Code)
	}

	badOrigin := httptest.NewRequest(http.MethodPost, "/tokens/revoke", strings.NewReader("csrf=csrf-a"))
	badOrigin.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	badOrigin.AddCookie(&http.Cookie{Name: "hr_session", Value: "session-a"})
	badResponse := httptest.NewRecorder()
	a.handler().ServeHTTP(badResponse, badOrigin)
	if badResponse.Code != http.StatusForbidden {
		t.Fatalf("missing Origin status = %d, want 403", badResponse.Code)
	}

	wrongCSRF := httptest.NewRequest(http.MethodPost, "/tokens/revoke", strings.NewReader("csrf=csrf-b"))
	wrongCSRF.Header.Set("Origin", a.origin)
	wrongCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongCSRF.AddCookie(&http.Cookie{Name: "hr_session", Value: "session-a"})
	wrongResponse := httptest.NewRecorder()
	a.handler().ServeHTTP(wrongResponse, wrongCSRF)
	if wrongResponse.Code != http.StatusForbidden {
		t.Fatalf("wrong CSRF status = %d, want 403", wrongResponse.Code)
	}
}
