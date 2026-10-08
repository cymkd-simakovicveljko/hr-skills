package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

type localOIDCFixture struct {
	server   *httptest.Server
	private  *rsa.PrivateKey
	wrongKey *rsa.PrivateKey
	issuer   string
	resource string
}

func newLocalOIDCFixture(t *testing.T) *localOIDCFixture {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	fixture := &localOIDCFixture{private: private, wrongKey: wrongKey}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   fixture.issuer,
				"jwks_uri": fixture.issuer + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key:       &fixture.private.PublicKey,
				KeyID:     "test-key",
				Algorithm: string(jose.RS256),
				Use:       "sig",
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fixture.server.Close)
	fixture.issuer = fixture.server.URL
	fixture.resource = fixture.server.URL + "/mcp"
	return fixture
}

func (f *localOIDCFixture) verifier(t *testing.T) auth.TokenVerifier {
	t.Helper()
	verifier, err := newTokenVerifier(context.Background(), authConfig{
		Issuer:          f.issuer,
		ResourceURL:     f.resource,
		WorkspaceDomain: "example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func accessTokenClaims(issuer, audience, domain string) map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":   issuer,
		"aud":   audience,
		"sub":   "user@example.com",
		"scope": "skills:read  profile",
		"hd":    domain,
		"exp":   now.Add(10 * time.Minute).Unix(),
		"nbf":   now.Add(-time.Minute).Unix(),
	}
}

func signedAccessToken(t *testing.T, key any, algorithm jose.SignatureAlgorithm, typ string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: algorithm, Key: key}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func TestNewTokenVerifierAcceptsRFC9068AccessToken(t *testing.T) {
	fixture := newLocalOIDCFixture(t)
	verifier := fixture.verifier(t)

	info, err := verifier(context.Background(), signedAccessToken(t, fixture.private, jose.RS256, "AT+JWT", accessTokenClaims(fixture.issuer, fixture.resource, "example.com")), nil)
	if err != nil {
		t.Fatalf("valid access token rejected: %v", err)
	}
	if info.UserID != "user@example.com" {
		t.Fatalf("UserID = %q, want user@example.com", info.UserID)
	}
	if !reflect.DeepEqual(info.Scopes, []string{"skills:read", "profile"}) {
		t.Fatalf("Scopes = %#v", info.Scopes)
	}
	if !info.Expiration.After(time.Now()) {
		t.Fatalf("Expiration = %v, want future expiry", info.Expiration)
	}
}

func TestNewTokenVerifierRejectsInvalidAccessTokens(t *testing.T) {
	fixture := newLocalOIDCFixture(t)
	verifier := fixture.verifier(t)

	tests := []struct {
		name      string
		key       any
		algorithm jose.SignatureAlgorithm
		typ       string
		mutate    func(map[string]any)
	}{
		{
			name:      "wrong signature",
			key:       fixture.wrongKey,
			algorithm: jose.RS256,
			typ:       "at+jwt",
		},
		{
			name:      "wrong issuer",
			key:       fixture.private,
			algorithm: jose.RS256,
			typ:       "at+jwt",
			mutate:    func(claims map[string]any) { claims["iss"] = "http://other.example" },
		},
		{
			name:      "wrong audience",
			key:       fixture.private,
			algorithm: jose.RS256,
			typ:       "at+jwt",
			mutate:    func(claims map[string]any) { claims["aud"] = fixture.issuer + "/other" },
		},
		{
			name:      "expired",
			key:       fixture.private,
			algorithm: jose.RS256,
			typ:       "at+jwt",
			mutate:    func(claims map[string]any) { claims["exp"] = time.Now().Add(-time.Minute).Unix() },
		},
		{
			name:      "future nbf",
			key:       fixture.private,
			algorithm: jose.RS256,
			typ:       "at+jwt",
			mutate:    func(claims map[string]any) { claims["nbf"] = time.Now().Add(10 * time.Minute).Unix() },
		},
		{
			name:      "ID token type",
			key:       fixture.private,
			algorithm: jose.RS256,
			typ:       "JWT",
		},
		{
			name:      "wrong workspace domain",
			key:       fixture.private,
			algorithm: jose.RS256,
			typ:       "at+jwt",
			mutate:    func(claims map[string]any) { claims["hd"] = "other.example" },
		},
		{
			name:      "HMAC algorithm",
			key:       []byte("not-a-provider-secret-but-long-enough-for-hs256"),
			algorithm: jose.HS256,
			typ:       "at+jwt",
		},
		{
			name:      "missing subject",
			key:       fixture.private,
			algorithm: jose.RS256,
			typ:       "at+jwt",
			mutate:    func(claims map[string]any) { delete(claims, "sub") },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			claims := accessTokenClaims(fixture.issuer, fixture.resource, "example.com")
			if test.mutate != nil {
				test.mutate(claims)
			}
			_, err := verifier(context.Background(), signedAccessToken(t, test.key, test.algorithm, test.typ, claims), nil)
			if !errors.Is(err, auth.ErrInvalidToken) {
				t.Fatalf("error = %v, want sanitized ErrInvalidToken", err)
			}
		})
	}
}

func TestNewTokenVerifierRejectsUnsafeDiscoveredJWKS(t *testing.T) {
	fixture := newLocalOIDCFixture(t)
	fixture.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			_ = json.NewEncoder(w).Encode(map[string]string{
				"issuer":   fixture.issuer,
				"jwks_uri": "http://public.example.invalid/jwks",
			})
			return
		}
		http.NotFound(w, r)
	})

	_, err := newTokenVerifier(context.Background(), authConfig{
		Issuer:          fixture.issuer,
		ResourceURL:     fixture.resource,
		WorkspaceDomain: "example.com",
	})
	if err == nil {
		t.Fatal("newTokenVerifier accepted an unsafe discovered JWKS URL")
	}
}
