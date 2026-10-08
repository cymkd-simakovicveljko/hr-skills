package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/auth"
)

var supportedAccessTokenAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.EdDSA,
}

const discoveryHTTPTimeout = 10 * time.Second

type tokenClaims struct {
	Subject   string       `json:"sub"`
	Scope     string       `json:"scope"`
	Domain    string       `json:"hd"`
	Expiry    *json.Number `json:"exp"`
	NotBefore *json.Number `json:"nbf"`
}

// newTokenVerifier discovers the fixed issuer's keys once and returns a
// verifier for RFC 9068 access tokens. Token headers never choose an issuer or
// JWKS URL: jku is ignored, and iss is checked against the configured issuer.
func newTokenVerifier(ctx context.Context, c authConfig) (auth.TokenVerifier, error) {
	if err := validateEndpoint(c.Issuer); err != nil {
		return nil, fmt.Errorf("issuer: %w", err)
	}
	if err := validateEndpoint(c.ResourceURL); err != nil {
		return nil, fmt.Errorf("resource_url: %w", err)
	}
	if c.WorkspaceDomain == "" {
		return nil, fmt.Errorf("workspace_domain is required")
	}

	client := &http.Client{
		Timeout: discoveryHTTPTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			// Discovery and JWKS requests may use loopback HTTP for local
			// deployment/tests, but must never follow a public insecure redirect.
			return validateEndpoint(req.URL.String())
		},
	}

	supportedSigningAlgs := make([]string, len(supportedAccessTokenAlgorithms))
	for i, algorithm := range supportedAccessTokenAlgorithms {
		supportedSigningAlgs[i] = string(algorithm)
	}
	discoveryContext := oidc.ClientContext(ctx, client)
	provider, err := oidc.NewProvider(discoveryContext, c.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery failed: %w", err)
	}

	var metadata struct {
		JWKSURL string `json:"jwks_uri"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, fmt.Errorf("oidc discovery claims failed: %w", err)
	}
	if err := validateEndpoint(metadata.JWKSURL); err != nil {
		return nil, fmt.Errorf("jwks_uri: %w", err)
	}

	// Use a background context for the long-lived remote key set. The client
	// timeout still bounds every discovery/JWKS request; request cancellation
	// remains effective while each token is being verified.
	verifier := provider.VerifierContext(
		oidc.ClientContext(context.Background(), client),
		&oidc.Config{
			ClientID:             c.ResourceURL,
			SupportedSigningAlgs: supportedSigningAlgs,
		},
	)

	return func(verifyContext context.Context, rawToken string, _ *http.Request) (*auth.TokenInfo, error) {
		return verifyAccessToken(verifyContext, verifier, c, rawToken)
	}, nil
}

func verifyAccessToken(ctx context.Context, verifier *oidc.IDTokenVerifier, c authConfig, rawToken string) (*auth.TokenInfo, error) {
	parsed, err := jose.ParseSigned(rawToken, supportedAccessTokenAlgorithms)
	if err != nil || len(parsed.Signatures) != 1 {
		return nil, auth.ErrInvalidToken
	}
	signature := parsed.Signatures[0]
	typ, ok := signature.Protected.ExtraHeaders[jose.HeaderType].(string)
	if !ok || !strings.EqualFold(typ, "at+jwt") {
		return nil, auth.ErrInvalidToken
	}

	verified, err := verifier.Verify(ctx, rawToken)
	if err != nil || verified.Issuer != c.Issuer {
		return nil, auth.ErrInvalidToken
	}

	var claims tokenClaims
	if err := verified.Claims(&claims); err != nil || claims.Subject == "" || claims.Expiry == nil {
		return nil, auth.ErrInvalidToken
	}
	// The external OAuth provider must enforce Google Workspace login and copy
	// Google's verified hd claim into this signed access token. This is not
	// direct Google token passthrough: Google ID tokens and client-audience
	// tokens are rejected by the fixed issuer/audience checks above.
	if claims.Domain != c.WorkspaceDomain {
		return nil, auth.ErrInvalidToken
	}
	if claims.NotBefore != nil {
		nbf, err := numericDate(*claims.NotBefore)
		if err != nil || nbf.After(time.Now()) {
			return nil, auth.ErrInvalidToken
		}
	}

	return &auth.TokenInfo{
		UserID:     claims.Subject,
		Scopes:     strings.Fields(claims.Scope),
		Expiration: verified.Expiry,
	}, nil
}

func numericDate(number json.Number) (time.Time, error) {
	seconds, err := number.Float64()
	if err != nil || math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < math.MinInt64 || seconds >= math.MaxInt64 {
		return time.Time{}, fmt.Errorf("invalid numeric date")
	}
	whole, fractional := math.Modf(seconds)
	return time.Unix(int64(whole), int64(fractional*1e9)), nil
}
