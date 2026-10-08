package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
)

const skillsExtension = "io.modelcontextprotocol/skills"
const readScope = "skills:read"

type skillListParams struct {
	mcp.ParamsBase
	Cursor string `json:"cursor,omitempty"`
}

type skillGetParams struct {
	mcp.ParamsBase
	URI string `json:"uri"`
}

type skillListResult struct {
	mcp.ResultBase
	mcp.Cacheable
	ResultType string       `json:"resultType,omitempty"`
	Skills     []skillEntry `json:"skills"`
}

type skillGetResult struct {
	mcp.ResultBase
	mcp.Cacheable
	ResultType string     `json:"resultType,omitempty"`
	Skill      skillEntry `json:"skill"`
}

type accessKey struct{}
type requestAccess struct {
	catalogs   []string
	resultType string
}

func newMCPServer(c config) (*mcp.Server, error) {
	store := &catalogStore{root: c.Store}
	server := mcp.NewServer(&mcp.Implementation{Name: "hr-skills", Version: "0.1.0"}, &mcp.ServerOptions{
		Instructions: "Discover authorized skills with skills/list, inspect a manifest with skills/get, and load files with resources/read. A skill URI pins its published revision. Loading instructions does not activate them; approval, activation, and execution belong to the client.",
		Capabilities: &mcp.ServerCapabilities{
			Resources:  &mcp.ResourceCapabilities{},
			Extensions: map[string]any{skillsExtension: map[string]any{}},
		},
		SetCacheable: func(_ context.Context, _ mcp.Request, cache *mcp.Cacheable) { *cache = privateCache() },
	})
	// Custom skills methods and resource reads share the same per-request grants.
	// No session or pinned revision is an authorization cache.
	server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			extra := req.GetExtra()
			if extra == nil || extra.TokenInfo == nil || extra.TokenInfo.UserID == "" {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidRequest, Message: "authentication required"}
			}
			allowed, err := allowedCatalogs(c.PolicyFile, extra.TokenInfo.UserID)
			if err != nil {
				return nil, catalogError(err)
			}
			access := requestAccess{catalogs: allowed}
			if versioned, ok := req.(interface{ ProtocolVersion() string }); ok && versioned.ProtocolVersion() >= "2026-07-28" {
				access.resultType = "complete"
			}
			ctx = context.WithValue(ctx, accessKey{}, access)
			result, err := next(ctx, method, req)
			// Keep unknown and forbidden URIs indistinguishable, including SDK misses.
			var rpcErr *jsonrpc.Error
			if method == "resources/read" && errors.As(err, &rpcErr) && rpcErr.Code == mcp.CodeResourceNotFound {
				return nil, catalogError(errNotFound)
			}
			// Discovery stays in authorized skills/list manifests, not wildcard templates.
			if templates, ok := result.(*mcp.ListResourceTemplatesResult); err == nil && ok {
				templates.ResourceTemplates = []*mcp.ResourceTemplate{}
			}
			return result, err
		}
	})
	server.AddResourceTemplate(&mcp.ResourceTemplate{URITemplate: "skill://{+path}", Name: "skill"}, func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		access := ctx.Value(accessKey{}).(requestAccess)
		content, err := store.read(req.Params.URI, access.catalogs)
		if err != nil {
			return nil, catalogError(err)
		}
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{content}}, nil
	})
	if err := mcp.AddReceivingCustomMethod(server, "skills/list", func(ctx context.Context, _ *mcp.ServerSession, p *skillListParams) (*skillListResult, error) {
		if p != nil && p.Cursor != "" {
			return nil, invalidParams("invalid cursor")
		}
		access := ctx.Value(accessKey{}).(requestAccess)
		skills, err := store.list(access.catalogs)
		if err != nil {
			return nil, catalogError(err)
		}
		if skills == nil {
			skills = []skillEntry{}
		}
		return &skillListResult{Cacheable: privateCache(), ResultType: access.resultType, Skills: skills}, nil
	}); err != nil {
		return nil, err
	}
	if err := mcp.AddReceivingCustomMethod(server, "skills/get", func(ctx context.Context, _ *mcp.ServerSession, p *skillGetParams) (*skillGetResult, error) {
		if p == nil {
			return nil, invalidParams("skill URI required")
		}
		access := ctx.Value(accessKey{}).(requestAccess)
		skill, err := store.get(p.URI, access.catalogs)
		if err != nil {
			return nil, catalogError(err)
		}
		return &skillGetResult{Cacheable: privateCache(), ResultType: access.resultType, Skill: skill}, nil
	}); err != nil {
		return nil, err
	}
	return server, nil
}

func privateCache() mcp.Cacheable { return mcp.Cacheable{TTLMs: 0, CacheScope: "private"} }

func invalidParams(message string) error {
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: message}
}

func catalogError(err error) error {
	if errors.Is(err, errNotFound) {
		return invalidParams("resource not found")
	}
	slog.Error("catalog request failed", "error", err)
	return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "catalog unavailable"}
}

func newHTTPHandler(c config, verifier auth.TokenVerifier) (http.Handler, error) {
	server, err := newMCPServer(c)
	if err != nil {
		return nil, err
	}
	resource, err := url.Parse(c.Auth.ResourceURL)
	if err != nil {
		return nil, err
	}
	origin := resource.Scheme + "://" + resource.Host
	metadataPath := "/.well-known/oauth-protected-resource/mcp"
	transport := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server }, &mcp.StreamableHTTPOptions{
		Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 1 << 20,
		// Exact public Host is checked below, including requests from a local TLS proxy.
		DisableLocalhostProtection: true, PropagateRequestCancellation: true,
	})
	protected := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: origin + metadataPath, Scopes: []string{readScope},
	})(transport)
	mux := http.NewServeMux()
	mux.Handle(metadataPath, auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource: c.Auth.ResourceURL, AuthorizationServers: []string{c.Auth.Issuer},
		ScopesSupported: []string{readScope}, BearerMethodsSupported: []string{"header"},
		ResourceName: "hr-skills",
	}))
	mux.Handle("/mcp", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, no-store")
		if requestOrigin := r.Header.Get("Origin"); requestOrigin != "" && requestOrigin != origin {
			http.Error(w, "origin not allowed", http.StatusForbidden)
			return
		}
		if len(r.Header.Values("Authorization")) > 1 {
			http.Error(w, "invalid authorization", http.StatusBadRequest)
			return
		}
		protected.ServeHTTP(&privateResponseWriter{ResponseWriter: w}, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if !strings.EqualFold(r.Host, resource.Host) {
			http.Error(w, "host not allowed", http.StatusMisdirectedRequest)
			return
		}
		mux.ServeHTTP(w, r)
	}), nil
}

// The SDK sets transport cache headers; enforce private, non-storable content
// at the last write so shared proxies cannot retain authorized skill content.
type privateResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
}

func (w *privateResponseWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *privateResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *privateResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
