package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// This scenario defends the HTTP authorization seam, including grants changed
// after discovery. A cached session or manifest must never preserve a grant.
func TestHTTPIsolationPublicationAndRevocation(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(version, func(t *testing.T) {
			issuer := newLocalOIDCFixture(t)
			root := t.TempDir()
			c := config{
				Store: filepath.Join(root, "store"), PolicyFile: filepath.Join(root, "policy.json"),
				Auth:     authConfig{Issuer: issuer.issuer, ResourceURL: issuer.resource, WorkspaceDomain: "example.com"},
				Catalogs: []catalogConfig{{Name: "engineering", Path: filepath.Join(root, "engineering")}, {Name: "finance", Path: filepath.Join(root, "finance")}},
			}
			writeSkill := func(catalog, body string) {
				t.Helper()
				dir := filepath.Join(root, catalog, "review")
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "SKILL.md"), []byte("---\nname: review\ndescription: Review work\n---\n"+body), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("supporting evidence"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			writeSkill("engineering", "engineering-v1")
			writeSkill("finance", "finance-confidential")
			for name, data := range map[string][]byte{"data.bin": {0xff, 0x80}, "empty.txt": {}} {
				if err := os.WriteFile(filepath.Join(root, "engineering", "review", name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := publishCatalogs(c); err != nil {
				t.Fatal(err)
			}
			p := policy{Subjects: map[string][]string{"alice": {"developers"}, "bob": {"accountants"}}, Catalogs: map[string][]string{"engineering": {"developers"}, "finance": {"accountants"}}}
			writePolicy := func() {
				t.Helper()
				data, err := json.Marshal(p)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(c.PolicyFile+".new", data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(c.PolicyFile+".new", c.PolicyFile); err != nil {
					t.Fatal(err)
				}
			}
			writePolicy()
			verifier, err := newTokenVerifier(context.Background(), c.Auth)
			if err != nil {
				t.Fatal(err)
			}
			handler, err := newHTTPHandler(c, verifier)
			if err != nil {
				t.Fatal(err)
			}
			httpServer := httptest.NewServer(handler)
			defer httpServer.Close()
			resource, _ := url.Parse(c.Auth.ResourceURL)
			tokenFor := func(subject, scope string) string {
				claims := accessTokenClaims(issuer.issuer, issuer.resource, "example.com")
				claims["sub"], claims["scope"] = subject, scope
				return signedAccessToken(t, issuer.private, jose.RS256, "at+jwt", claims)
			}
			alice, bob := tokenFor("alice", readScope), tokenFor("bob", readScope)
			request := func(method, path, token string, body []byte, headers map[string]string) (int, http.Header, []byte) {
				t.Helper()
				r, err := http.NewRequest(method, httpServer.URL+path, bytes.NewReader(body))
				if err != nil {
					t.Fatal(err)
				}
				r.Host = resource.Host
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Accept", "application/json, text/event-stream")
				r.Header.Set("MCP-Protocol-Version", version)
				if token != "" {
					r.Header.Set("Authorization", "Bearer "+token)
				}
				for k, v := range headers {
					r.Header.Set(k, v)
				}
				response, err := httpServer.Client().Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				data, err := io.ReadAll(response.Body)
				if err != nil {
					t.Fatal(err)
				}
				return response.StatusCode, response.Header, data
			}
			rpc := func(token, method string, params map[string]any) map[string]json.RawMessage {
				t.Helper()
				if version >= "2026-07-28" {
					params["_meta"] = map[string]any{mcp.MetaKeyProtocolVersion: version, mcp.MetaKeyClientCapabilities: map[string]any{"extensions": map[string]any{skillsExtension: map[string]any{}}}}
				}
				body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
				if err != nil {
					t.Fatal(err)
				}
				requestHeaders := map[string]string{"Mcp-Method": method}
				if method == "resources/read" {
					requestHeaders["Mcp-Name"] = params["uri"].(string)
				}
				status, headers, data := request("POST", "/mcp", token, body, requestHeaders)
				if (status != http.StatusOK && status != http.StatusBadRequest && status != http.StatusInternalServerError) || headers.Get("Cache-Control") != "private, no-store" {
					t.Fatalf("RPC status=%d headers=%v body=%s", status, headers, data)
				}
				var result map[string]json.RawMessage
				if err := json.Unmarshal(data, &result); err != nil {
					t.Fatalf("RPC response: %s: %v", data, err)
				}
				if status != http.StatusOK && result["error"] == nil {
					t.Fatalf("HTTP %d without RPC error: %s", status, data)
				}
				return result
			}
			resultType := ""
			if version >= "2026-07-28" {
				resultType = "complete"
			} else {
				res := rpc(alice, "initialize", map[string]any{
					"protocolVersion": version,
					"capabilities":    map[string]any{"extensions": map[string]any{skillsExtension: map[string]any{}}},
					"clientInfo":      map[string]any{"name": "test", "version": "1"},
				})
				if res["error"] != nil {
					t.Fatalf("initialize error: %s", res["error"])
				}
			}
			list := func(token string) []skillEntry {
				t.Helper()
				res := rpc(token, "skills/list", map[string]any{})
				if res["error"] != nil {
					t.Fatalf("list error: %s", res["error"])
				}
				var result skillListResult
				if err := json.Unmarshal(res["result"], &result); err != nil {
					t.Fatal(err)
				}
				if result.CacheScope != "private" || result.TTLMs != 0 || result.ResultType != resultType {
					t.Fatalf("incorrect authorized caching/result fields: %+v", result)
				}
				return result.Skills
			}
			readContent := func(token, uri string) string {
				t.Helper()
				res := rpc(token, "resources/read", map[string]any{"uri": uri})
				if res["error"] != nil {
					t.Fatalf("read error: %s", res["error"])
				}
				var result struct {
					mcp.Cacheable
					ResultType string                  `json:"resultType"`
					Contents   []*mcp.ResourceContents `json:"contents"`
				}
				if err := json.Unmarshal(res["result"], &result); err != nil {
					t.Fatal(err)
				}
				if result.CacheScope != "private" || result.TTLMs != 0 || result.ResultType != resultType {
					t.Fatalf("incorrect resource caching/result fields: %+v", result)
				}
				if len(result.Contents) != 1 {
					t.Fatalf("unexpected resource contents: %+v", result)
				}
				return result.Contents[0].Text
			}
			status, headers, _ := request("POST", "/mcp", "", []byte(`{}`), nil)
			if status != 401 || !strings.Contains(headers.Get("WWW-Authenticate"), "/.well-known/oauth-protected-resource/mcp") {
				t.Fatalf("missing OAuth discovery challenge: %d %v", status, headers)
			}
			status, _, metadata := request("GET", "/.well-known/oauth-protected-resource/mcp", "", nil, nil)
			if status != 200 || !bytes.Contains(metadata, []byte(issuer.issuer)) {
				t.Fatalf("metadata: %d %s", status, metadata)
			}
			status, _, _ = request("POST", "/mcp", tokenFor("alice", "profile"), []byte(`{}`), nil)
			if status != 403 {
				t.Fatalf("missing scope status=%d", status)
			}
			status, _, _ = request("POST", "/mcp", alice, []byte(`{}`), map[string]string{"Origin": "https://evil.example"})
			if status != 403 {
				t.Fatalf("untrusted Origin status=%d", status)
			}
			aliceSkills, bobSkills := list(alice), list(bob)
			if len(aliceSkills) != 1 || !strings.HasPrefix(aliceSkills[0].URI, "skill://engineering/") {
				t.Fatalf("alice visibility: %+v", aliceSkills)
			}
			if len(bobSkills) != 1 || !strings.HasPrefix(bobSkills[0].URI, "skill://finance/") {
				t.Fatalf("bob visibility: %+v", bobSkills)
			}
			if got := list(tokenFor("unlisted", readScope)); len(got) != 0 {
				t.Fatalf("unlisted user sees skills: %+v", got)
			}
			oldURI := aliceSkills[0].URI
			oldContent := readContent(alice, oldURI)
			if !strings.HasSuffix(oldContent, "engineering-v1") {
				t.Fatalf("wrong content: %q", oldContent)
			}
			if got := readContent(alice, strings.TrimSuffix(oldURI, "SKILL.md")+"notes.txt"); got != "supporting evidence" {
				t.Fatalf("supporting file=%q", got)
			}
			for name, want := range map[string][]byte{"data.bin": {0xff, 0x80}, "empty.txt": {}} {
				res := rpc(alice, "resources/read", map[string]any{"uri": strings.TrimSuffix(oldURI, "SKILL.md") + name})
				var result mcp.ReadResourceResult
				if err := json.Unmarshal(res["result"], &result); err != nil {
					t.Fatal(err)
				}
				if len(result.Contents) != 1 || result.Contents[0].Blob == nil || !bytes.Equal(result.Contents[0].Blob, want) {
					t.Fatalf("%s lost binary/empty content: %+v", name, result.Contents)
				}
			}
			templates := rpc(alice, "resources/templates/list", map[string]any{})
			var templateList mcp.ListResourceTemplatesResult
			if err := json.Unmarshal(templates["result"], &templateList); err != nil {
				t.Fatal(err)
			}
			if len(templateList.ResourceTemplates) != 0 {
				t.Fatalf("discovery escaped authorized skill manifests: %+v", templateList.ResourceTemplates)
			}
			if res := rpc(alice, "resources/templates/list", map[string]any{"cursor": "invalid"}); res["error"] == nil {
				t.Fatal("invalid template cursor was accepted")
			}
			for _, method := range []string{"skills/get", "resources/read"} {
				denied := rpc(alice, method, map[string]any{"uri": bobSkills[0].URI})
				unknown := rpc(alice, method, map[string]any{"uri": "skill://absent/unknown/SKILL.md"})
				if denied["error"] == nil || !bytes.Equal(denied["error"], unknown["error"]) {
					t.Fatalf("%s leaked existence: denied=%s unknown=%s", method, denied["error"], unknown["error"])
				}
				unmatched := rpc(alice, method, map[string]any{"uri": "https://unknown.example/skill"})
				if !bytes.Equal(denied["error"], unmatched["error"]) {
					t.Fatalf("%s distinguishes unmatched URIs from denied resources: %s", method, unmatched["error"])
				}
			}
			writeSkill("engineering", "engineering-v2")
			if _, err := publishCatalogs(c); err != nil {
				t.Fatal(err)
			}
			newURI := list(alice)[0].URI
			if newURI == oldURI || !strings.HasSuffix(readContent(alice, newURI), "engineering-v2") {
				t.Fatal("new publication not visible")
			}
			if readContent(alice, oldURI) != oldContent {
				t.Fatal("pinned revision changed")
			}
			delete(p.Subjects, "alice")
			writePolicy()
			if len(list(alice)) != 0 {
				t.Fatal("revoked membership still listed")
			}
			for _, uri := range []string{oldURI, newURI} {
				for _, method := range []string{"skills/get", "resources/read"} {
					if res := rpc(alice, method, map[string]any{"uri": uri}); res["error"] == nil {
						t.Fatalf("revoked membership still accesses pinned resource via %s", method)
					}
				}
			}
			if err := os.WriteFile(c.PolicyFile, []byte(`{broken`), 0600); err != nil {
				t.Fatal(err)
			}
			if res := rpc(bob, "skills/list", map[string]any{}); res["error"] == nil {
				t.Fatal("invalid policy did not fail closed")
			}
		})
	}
}
