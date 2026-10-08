package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"golang.org/x/oauth2"
)

const (
	googleIssuer         = "https://accounts.google.com"
	discoveryHTTPTimeout = 10 * time.Second
	pendingLoginTTL      = 10 * time.Minute
	browserSessionTTL    = 8 * time.Hour
	maxPendingLogins     = 1024
	maxBrowserSessions   = 1024
	maxTokenFileBytes    = 1 << 20
	maxTokenRecords      = 4096
	maxOAuthCodeBytes    = 16 << 10
	maxFormBytes         = 8 << 10
	maxSecretBytes       = 16 << 10
)

// tokenStore persists only SHA-256 digests. The plaintext token exists only in
// the response that created it and in the caller that presents it.
type tokenStore struct {
	path     string
	mu       sync.Mutex
	tokens   map[string]string // Google subject -> hex SHA-256 digest
	byDigest map[string]string // hex SHA-256 digest -> Google subject
}

type tokenStoreFile struct {
	Tokens map[string]string `json:"tokens"`
}

func newTokenStore(path string) (*tokenStore, error) {
	if path == "" {
		return nil, errors.New("token file is required")
	}
	store := &tokenStore{
		path:     path,
		tokens:   make(map[string]string),
		byDigest: make(map[string]string),
	}
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return store, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxTokenFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read token file: %w", err)
	}
	if len(data) > maxTokenFileBytes {
		return nil, errors.New("token file exceeds size limit")
	}
	var onDisk tokenStoreFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&onDisk); err != nil {
		return nil, fmt.Errorf("decode token file: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("token file contains multiple JSON documents")
	}
	if onDisk.Tokens == nil {
		return nil, errors.New("token file has no token map")
	}
	if len(onDisk.Tokens) > maxTokenRecords {
		return nil, errors.New("token file has too many token records")
	}
	for subject, digest := range onDisk.Tokens {
		if subject == "" || len(subject) > 512 || len(digest) != sha256.Size*2 {
			return nil, errors.New("token file contains invalid token record")
		}
		if _, err := hex.DecodeString(digest); err != nil || strings.ToLower(digest) != digest {
			return nil, errors.New("token file contains invalid token digest")
		}
		if _, exists := store.byDigest[digest]; exists {
			return nil, errors.New("token file contains duplicate token digest")
		}
		store.tokens[subject] = digest
		store.byDigest[digest] = subject
	}
	return store, nil
}

func cloneTokenMap(tokens map[string]string) map[string]string {
	copy := make(map[string]string, len(tokens)+1)
	for subject, digest := range tokens {
		copy[subject] = digest
	}
	return copy
}

func (s *tokenStore) persist(tokens map[string]string) error {
	data, err := json.Marshal(tokenStoreFile{Tokens: tokens})
	if err != nil {
		return err
	}
	if len(data) > maxTokenFileBytes {
		return errors.New("token file exceeds size limit")
	}
	if err := atomicReplace(s.path, data); err != nil {
		return fmt.Errorf("write token file: %w", err)
	}
	return nil
}

func randomBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

func randomURLToken(size int) (string, error) {
	data, err := randomBytes(size)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func tokenDigest(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func (s *tokenStore) rotate(subject string) (string, error) {
	if subject == "" || len(subject) > 512 {
		return "", errors.New("invalid subject")
	}
	random, err := randomURLToken(32)
	if err != nil {
		return "", err
	}
	token := "hrs_" + random
	digest := tokenDigest(token)

	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.tokens) >= maxTokenRecords {
		if _, exists := s.tokens[subject]; !exists {
			return "", errors.New("token store is full")
		}
	}
	next := cloneTokenMap(s.tokens)
	next[subject] = digest
	if err := s.persist(next); err != nil {
		return "", err
	}
	if s.byDigest == nil {
		s.byDigest = make(map[string]string, len(next))
	}
	if old := s.tokens[subject]; old != "" {
		delete(s.byDigest, old)
	}
	s.byDigest[digest] = subject
	s.tokens = next
	return token, nil
}

func (s *tokenStore) revoke(subject string) error {
	if subject == "" || len(subject) > 512 {
		return errors.New("invalid subject")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	digest, ok := s.tokens[subject]
	if !ok {
		return nil
	}
	next := cloneTokenMap(s.tokens)
	delete(next, subject)
	if err := s.persist(next); err != nil {
		return err
	}
	delete(s.byDigest, digest)
	s.tokens = next
	return nil
}

func (s *tokenStore) verify(_ context.Context, rawToken string, _ *http.Request) (*auth.TokenInfo, error) {
	if len(rawToken) != len("hrs_")+43 || !strings.HasPrefix(rawToken, "hrs_") {
		return nil, auth.ErrInvalidToken
	}
	encoded := rawToken[len("hrs_"):]
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 {
		return nil, auth.ErrInvalidToken
	}
	digest := tokenDigest(rawToken)
	s.mu.Lock()
	defer s.mu.Unlock()
	subject := s.byDigest[digest]
	if subject == "" {
		return nil, auth.ErrInvalidToken
	}
	return &auth.TokenInfo{UserID: subject, Scopes: []string{readScope}}, nil
}

type pendingLogin struct {
	verifier string
	nonce    string
	expires  time.Time
}

type browserSession struct {
	subject string
	email   string
	csrf    string
	expires time.Time
}

type googleClaims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	HostedDomain  string `json:"hd"`
	Nonce         string `json:"nonce"`
}

type authentication struct {
	cfg          config
	oauth        oauth2.Config
	verifier     *oidc.IDTokenVerifier
	tokens       *tokenStore
	origin       string
	cookieSecure bool
	client       *http.Client
	now          func() time.Time

	mu       sync.Mutex
	pending  map[string]pendingLogin
	sessions map[string]browserSession
}

func boundedHTTPClient(base *http.Client) *http.Client {
	if base == nil {
		base = &http.Client{}
	}
	client := *base
	if client.Timeout <= 0 || client.Timeout > discoveryHTTPTimeout {
		client.Timeout = discoveryHTTPTimeout
	}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		if err := validateEndpoint(req.URL.String()); err != nil {
			return err
		}
		return nil
	}
	return &client
}

func readClientSecret(path string) (string, error) {
	if path == "" {
		return "", errors.New("google client secret file is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open Google client secret: %w", err)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSecretBytes+1))
	if err != nil {
		return "", fmt.Errorf("read Google client secret: %w", err)
	}
	if len(data) > maxSecretBytes {
		return "", errors.New("Google client secret exceeds size limit")
	}
	secret := strings.TrimSpace(string(data))
	if secret == "" || strings.ContainsAny(secret, "\r\n") {
		return "", errors.New("Google client secret is empty or malformed")
	}
	return secret, nil
}

func resourceOrigin(raw string) (string, bool, error) {
	if err := validateEndpoint(raw); err != nil {
		return "", false, err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Path != "/mcp" || u.RawQuery != "" || u.Fragment != "" {
		return "", false, errors.New("resource_url must be /mcp without query or fragment")
	}
	loopback := u.Scheme == "http" && (u.Hostname() == "localhost" || func() bool {
		ip := net.ParseIP(u.Hostname())
		return ip != nil && ip.IsLoopback()
	}())
	return u.Scheme + "://" + u.Host, !loopback, nil
}

func newAuthentication(ctx context.Context, c config) (*authentication, error) {
	return newAuthenticationWithHTTPClient(ctx, c, nil)
}

// newAuthenticationWithHTTPClient is an unexported test seam. Production always
// discovers the fixed Google issuer; tests can route its HTTP client to a local
// signed OIDC fixture without changing that issuer.
func newAuthenticationWithHTTPClient(ctx context.Context, c config, baseClient *http.Client) (*authentication, error) {
	origin, secureCookie, err := resourceOrigin(c.Auth.ResourceURL)
	if err != nil {
		return nil, fmt.Errorf("resource_url: %w", err)
	}
	if c.Auth.WorkspaceDomain == "" {
		return nil, errors.New("workspace_domain is required")
	}
	if c.Auth.GoogleClientID == "" {
		return nil, errors.New("google_client_id is required")
	}
	clientSecret, err := readClientSecret(c.Auth.GoogleClientSecretFile)
	if err != nil {
		return nil, err
	}
	tokens, err := newTokenStore(c.Auth.TokenFile)
	if err != nil {
		return nil, err
	}
	client := boundedHTTPClient(baseClient)
	discoveryContext := oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(discoveryContext, googleIssuer)
	if err != nil {
		return nil, fmt.Errorf("Google OIDC discovery failed: %w", err)
	}
	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil || metadata.JWKSURL == "" {
		return nil, errors.New("Google OIDC discovery omitted JWKS endpoint")
	}
	if err := validateEndpoint(metadata.JWKSURL); err != nil {
		return nil, fmt.Errorf("Google JWKS endpoint: %w", err)
	}
	endpoint := provider.Endpoint()
	if err := validateEndpoint(endpoint.AuthURL); err != nil {
		return nil, fmt.Errorf("Google authorization endpoint: %w", err)
	}
	if err := validateEndpoint(endpoint.TokenURL); err != nil {
		return nil, fmt.Errorf("Google token endpoint: %w", err)
	}
	verifier := provider.VerifierContext(
		oidc.ClientContext(context.Background(), client),
		&oidc.Config{ClientID: c.Auth.GoogleClientID},
	)
	return &authentication{
		cfg: c,
		oauth: oauth2.Config{
			ClientID:     c.Auth.GoogleClientID,
			ClientSecret: clientSecret,
			Endpoint:     endpoint,
			RedirectURL:  origin + "/auth/google/callback",
			Scopes:       []string{oidc.ScopeOpenID, "email"},
		},
		verifier:     verifier,
		tokens:       tokens,
		origin:       origin,
		cookieSecure: secureCookie,
		client:       client,
		now:          time.Now,
		pending:      make(map[string]pendingLogin),
		sessions:     make(map[string]browserSession),
	}, nil
}

func (a *authentication) currentTime() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func (a *authentication) pruneLocked(now time.Time) {
	for state, pending := range a.pending {
		if !pending.expires.After(now) {
			delete(a.pending, state)
		}
	}
	for sessionID, session := range a.sessions {
		if !session.expires.After(now) {
			delete(a.sessions, sessionID)
		}
	}
}

func (a *authentication) newPending() (string, pendingLogin, error) {
	state, err := randomURLToken(32)
	if err != nil {
		return "", pendingLogin{}, err
	}
	nonce, err := randomURLToken(32)
	if err != nil {
		return "", pendingLogin{}, err
	}
	verifier, err := randomURLToken(32)
	if err != nil {
		return "", pendingLogin{}, err
	}
	pending := pendingLogin{verifier: verifier, nonce: nonce, expires: a.currentTime().Add(pendingLoginTTL)}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(a.currentTime())
	if len(a.pending) >= maxPendingLogins {
		return "", pendingLogin{}, errors.New("too many pending logins")
	}
	if a.pending == nil {
		a.pending = make(map[string]pendingLogin)
	}
	a.pending[state] = pending
	return state, pending, nil
}

func (a *authentication) takePending(state string) (pendingLogin, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(a.currentTime())
	pending, ok := a.pending[state]
	if ok {
		delete(a.pending, state)
	}
	return pending, ok
}

func (a *authentication) createSession(subject, email string) (string, browserSession, error) {
	sessionID, err := randomURLToken(32)
	if err != nil {
		return "", browserSession{}, err
	}
	csrf, err := randomURLToken(32)
	if err != nil {
		return "", browserSession{}, err
	}
	session := browserSession{subject: subject, email: email, csrf: csrf, expires: a.currentTime().Add(browserSessionTTL)}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(a.currentTime())
	if len(a.sessions) >= maxBrowserSessions {
		return "", browserSession{}, errors.New("too many browser sessions")
	}
	if a.sessions == nil {
		a.sessions = make(map[string]browserSession)
	}
	a.sessions[sessionID] = session
	return sessionID, session, nil
}

func (a *authentication) sessionCookieName() string {
	if a.cookieSecure {
		return "__Host-hr_session"
	}
	return "hr_session"
}

func (a *authentication) stateCookieName() string {
	if a.cookieSecure {
		return "__Host-hr_oauth_state"
	}
	return "hr_oauth_state"
}

func (a *authentication) session(r *http.Request) (string, browserSession, bool) {
	cookie, err := r.Cookie(a.sessionCookieName())
	if err != nil || cookie.Value == "" || len(cookie.Value) > 128 {
		return "", browserSession{}, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pruneLocked(a.currentTime())
	session, ok := a.sessions[cookie.Value]
	return cookie.Value, session, ok
}

func (a *authentication) setSessionCookie(w http.ResponseWriter, sessionID string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.sessionCookieName(),
		Value:    sessionID,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *authentication) setStateCookie(w http.ResponseWriter, state string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     a.stateCookieName(),
		Value:    state,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *authentication) deleteSession(sessionID string) {
	if sessionID == "" {
		return
	}
	a.mu.Lock()
	delete(a.sessions, sessionID)
	a.mu.Unlock()
}

func (a *authentication) sameOrigin(r *http.Request) bool {
	return r.Header.Get("Origin") == a.origin
}

func formCSRF(w http.ResponseWriter, r *http.Request) (string, error) {
	if r.URL.RawQuery != "" || r.ContentLength > maxFormBytes {
		return "", errors.New("invalid form")
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/x-www-form-urlencoded" {
		return "", errors.New("invalid form")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		return "", errors.New("invalid form")
	}
	if len(r.PostForm) != 1 || len(r.PostForm["csrf"]) != 1 || r.PostForm["csrf"][0] == "" {
		return "", errors.New("invalid form")
	}
	return r.PostForm["csrf"][0], nil
}

func (a *authentication) requirePostSession(w http.ResponseWriter, r *http.Request) (string, browserSession, bool) {
	if r.Method != http.MethodPost || !a.sameOrigin(r) {
		http.Error(w, "not allowed", http.StatusForbidden)
		return "", browserSession{}, false
	}
	sessionID, session, ok := a.session(r)
	if !ok {
		http.Error(w, "sign in required", http.StatusUnauthorized)
		return "", browserSession{}, false
	}
	csrf, err := formCSRF(w, r)
	if err != nil || len(csrf) != len(session.csrf) || subtle.ConstantTimeCompare([]byte(csrf), []byte(session.csrf)) != 1 {
		http.Error(w, "invalid request", http.StatusForbidden)
		return "", browserSession{}, false
	}
	return sessionID, session, true
}

func (a *authentication) verifyGoogleIDToken(ctx context.Context, raw string, pending pendingLogin) (googleClaims, error) {
	if raw == "" || len(raw) > maxOAuthCodeBytes {
		return googleClaims{}, errors.New("invalid identity token")
	}
	idToken, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		return googleClaims{}, errors.New("invalid identity token")
	}
	var claims googleClaims
	if err := idToken.Claims(&claims); err != nil || claims.Subject == "" || claims.Email == "" || !claims.EmailVerified || claims.HostedDomain != a.cfg.Auth.WorkspaceDomain || claims.Nonce != pending.nonce {
		return googleClaims{}, errors.New("invalid identity token")
	}
	return claims, nil
}

func (a *authentication) start(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, pending, err := a.newPending()
	if err != nil {
		http.Error(w, "sign in unavailable", http.StatusServiceUnavailable)
		return
	}
	challenge := sha256.Sum256([]byte(pending.verifier))
	challengeText := base64.RawURLEncoding.EncodeToString(challenge[:])
	location := a.oauth.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challengeText),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", pending.nonce),
	)
	a.setStateCookie(w, state, int(pendingLoginTTL.Seconds()))
	http.Redirect(w, r, location, http.StatusFound)
}

func (a *authentication) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	state, code := r.URL.Query().Get("state"), r.URL.Query().Get("code")
	if len(state) == 0 || len(state) > 128 {
		http.Error(w, "invalid sign in response", http.StatusBadRequest)
		return
	}
	stateCookie, err := r.Cookie(a.stateCookieName())
	if err != nil || len(stateCookie.Value) != len(state) || subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(state)) != 1 {
		http.Error(w, "invalid sign in response", http.StatusBadRequest)
		return
	}
	pending, ok := a.takePending(state)
	if !ok {
		http.Error(w, "invalid or expired sign in response", http.StatusBadRequest)
		return
	}
	a.setStateCookie(w, "", -1)
	if oauthError := r.URL.Query().Get("error"); oauthError != "" {
		http.Error(w, "sign in cancelled", http.StatusBadRequest)
		return
	}
	if len(code) == 0 || len(code) > maxOAuthCodeBytes {
		http.Error(w, "invalid sign in response", http.StatusBadRequest)
		return
	}
	exchangeContext := r.Context()
	if a.client != nil {
		exchangeContext = context.WithValue(exchangeContext, oauth2.HTTPClient, a.client)
	}
	token, err := a.oauth.Exchange(exchangeContext, code, oauth2.VerifierOption(pending.verifier))
	if err != nil {
		http.Error(w, "sign in failed", http.StatusBadRequest)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		http.Error(w, "sign in failed", http.StatusBadRequest)
		return
	}
	claims, err := a.verifyGoogleIDToken(r.Context(), rawIDToken, pending)
	if err != nil {
		http.Error(w, "sign in failed", http.StatusBadRequest)
		return
	}
	sessionID, _, err := a.createSession(claims.Subject, claims.Email)
	if err != nil {
		http.Error(w, "sign in unavailable", http.StatusServiceUnavailable)
		return
	}
	if previous, _, ok := a.session(r); ok {
		a.deleteSession(previous)
	}
	a.setSessionCookie(w, sessionID, int(browserSessionTTL.Seconds()))
	http.Redirect(w, r, "/", http.StatusFound)
}

type accountPage struct {
	SignedIn bool
	Email    string
	Subject  string
	CSRF     string
	Catalogs []string
	Token    string
	Error    string
}

var accountTemplate = template.Must(template.New("account").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>hr-skills account</title></head>
<body><main><h1>hr-skills account</h1>
{{if .SignedIn}}<p>Signed in as <strong>{{.Email}}</strong>.</p><dl><dt>Google subject</dt><dd><code>{{.Subject}}</code></dd></dl>
{{if .Catalogs}}<h2>Catalog access</h2><ul>{{range .Catalogs}}<li>{{.}}</li>{{end}}</ul>
{{else}}<p>You are verified, but no catalog access has been granted. Ask an administrator to add policy for this Google subject.</p>{{end}}
<h2>MCP token</h2><p>Tokens do not expire until you rotate or revoke them. Browser sessions expire after 8 hours.</p>
{{if .Catalogs}}<form method="post" action="/tokens/rotate"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">Generate or rotate token</button></form>{{end}}
<form method="post" action="/tokens/revoke"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">Revoke token</button></form>
{{if .Token}}<section aria-live="polite"><h2>New token</h2><p>Copy it now. It will not be shown again.</p><p><code>{{.Token}}</code></p></section>{{end}}
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="/sign-out"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">Sign out</button></form>
{{else}}<p><a href="/auth/google/start">Sign in with Google</a></p>{{end}}
</main></body></html>`))

func writeSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// Preserve Origin on same-origin HTML forms; no-referrer makes Chrome send null.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
}

func (a *authentication) allowed(subject string) ([]string, error) {
	catalogs, err := allowedCatalogs(a.cfg.PolicyFile, subject)
	if err != nil {
		return nil, err
	}
	sort.Strings(catalogs)
	return catalogs, nil
}

func (a *authentication) renderAccount(w http.ResponseWriter, r *http.Request, token, message string) {
	writeSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, session, ok := a.session(r)
	page := accountPage{SignedIn: ok, Token: token, Error: message}
	if ok {
		page.Email, page.Subject = session.email, session.subject
		page.CSRF = session.csrf
		catalogs, err := a.allowed(session.subject)
		page.Catalogs = catalogs
		if err != nil {
			page.Error = "Account access could not be loaded."
		}
	}
	if err := accountTemplate.Execute(w, page); err != nil {
		// The response may already have started; log only the template error.
		slog.Error("account page rendering failed", "error", err)
	}
}

func (a *authentication) account(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	a.renderAccount(w, r, "", "")
}

func (a *authentication) rotate(w http.ResponseWriter, r *http.Request) {
	_, session, ok := a.requirePostSession(w, r)
	if !ok {
		return
	}
	catalogs, err := a.allowed(session.subject)
	if err != nil {
		http.Error(w, "account unavailable", http.StatusInternalServerError)
		return
	}
	if len(catalogs) == 0 {
		http.Error(w, "no catalog access", http.StatusForbidden)
		return
	}
	token, err := a.tokens.rotate(session.subject)
	if err != nil {
		http.Error(w, "token unavailable", http.StatusInternalServerError)
		return
	}
	a.renderAccount(w, r, token, "")
}

func (a *authentication) revoke(w http.ResponseWriter, r *http.Request) {
	_, session, ok := a.requirePostSession(w, r)
	if !ok {
		return
	}
	if err := a.tokens.revoke(session.subject); err != nil {
		http.Error(w, "token unavailable", http.StatusInternalServerError)
		return
	}
	a.renderAccount(w, r, "", "Token revoked.")
}

func (a *authentication) signOut(w http.ResponseWriter, r *http.Request) {
	sessionID, _, ok := a.requirePostSession(w, r)
	if !ok {
		return
	}
	a.deleteSession(sessionID)
	a.setSessionCookie(w, "", -1)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *authentication) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", a.account)
	mux.HandleFunc("/auth/google/start", a.start)
	mux.HandleFunc("/auth/google/callback", a.callback)
	mux.HandleFunc("/tokens/rotate", a.rotate)
	mux.HandleFunc("/tokens/revoke", a.revoke)
	mux.HandleFunc("/sign-out", a.signOut)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp" {
			writeSecurityHeaders(w)
		}
		mux.ServeHTTP(w, r)
	})
}
