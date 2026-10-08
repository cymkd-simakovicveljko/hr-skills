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

type skillSummary struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	URI         string `json:"uri"`
}

type listSkillsOutput struct {
	Skills []skillSummary `json:"skills"`
}

type skillURIInput struct {
	URI string `json:"uri" jsonschema:"Revision-pinned URI returned by list_skills or load_skill"`
}

type loadedSkill struct {
	URI          string          `json:"uri"`
	Instructions string          `json:"instructions"`
	Resources    []skillResource `json:"resources"`
}

type accessKey struct{}
type requestAccess struct {
	catalogs   []string
	resultType string
}

func newMCPServer(c config) (*mcp.Server, error) {
	store := &catalogStore{root: c.Store}
	server := mcp.NewServer(&mcp.Implementation{Name: "hr-skills", Version: "0.1.0"}, &mcp.ServerOptions{
		Instructions: "Discover authorized skill metadata with list_skills, then load selected instructions with load_skill. Read supporting files with read_skill_resource or resources/read only when needed. A skill URI pins its published revision. Loading does not activate or execute a skill; respect its frontmatter restrictions and client approval policy. Native skills clients may use skills/list and skills/get.",
		Capabilities: &mcp.ServerCapabilities{
			Tools:      &mcp.ToolCapabilities{},
			Resources:  &mcp.ResourceCapabilities{},
			Extensions: map[string]any{skillsExtension: map[string]any{}},
		},
		SetCacheable: func(_ context.Context, _ mcp.Request, cache *mcp.Cacheable) { *cache = privateCache() },
	})
	// Discovery, tool calls and resource reads share the same per-request grants.
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
			// Discovery stays in authorized skill lists, not wildcard templates.
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
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_skills",
		Description: "List authorized skill names, descriptions and revision-pinned URIs without loading instructions. Select skills relevant to the user's task, then call load_skill.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, listSkillsOutput, error) {
		access := ctx.Value(accessKey{}).(requestAccess)
		skills, err := store.list(access.catalogs)
		if err != nil {
			return nil, listSkillsOutput{}, catalogError(err)
		}
		summaries := make([]skillSummary, len(skills))
		for i, skill := range skills {
			name, _ := skill.Frontmatter["name"].(string)
			description, _ := skill.Frontmatter["description"].(string)
			summaries[i] = skillSummary{Name: name, Description: description, URI: skill.URI}
		}
		return nil, listSkillsOutput{Skills: summaries}, nil
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "load_skill",
		Description: "Load a selected SKILL.md and links to supporting files. Read only needed files with read_skill_resource or resources/read. Respect frontmatter activation restrictions; loading does not activate or execute the skill.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input skillURIInput) (*mcp.CallToolResult, loadedSkill, error) {
		access := ctx.Value(accessKey{}).(requestAccess)
		skill, err := store.get(input.URI, access.catalogs)
		if err != nil {
			return nil, loadedSkill{}, catalogError(err)
		}
		content, err := store.read(skill.URI, access.catalogs)
		if err != nil {
			return nil, loadedSkill{}, catalogError(err)
		}
		resources := make([]skillResource, 0, len(skill.Resources))
		for _, resource := range skill.Resources {
			if resource.URI != skill.URI {
				resources = append(resources, resource)
			}
		}
		return nil, loadedSkill{URI: skill.URI, Instructions: content.Text, Resources: resources}, nil
	})
	mcp.AddTool(server, &mcp.Tool{
		Name:        "read_skill_resource",
		Description: "Read one revision-pinned supporting file linked by load_skill, only when needed for the task. Returns UTF-8 text or a base64 blob; never executes scripts.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
		// SDK inference treats []byte as an array; MCP blobs are base64 strings.
		OutputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"uri":  map[string]string{"type": "string"},
				"text": map[string]string{"type": "string"},
				"blob": map[string]string{"type": "string", "contentEncoding": "base64"},
			},
			"required": []string{"uri"},
		},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, input skillURIInput) (*mcp.CallToolResult, *mcp.ResourceContents, error) {
		access := ctx.Value(accessKey{}).(requestAccess)
		content, err := store.read(input.URI, access.catalogs)
		if err != nil {
			return nil, nil, catalogError(err)
		}
		return nil, content, nil
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
