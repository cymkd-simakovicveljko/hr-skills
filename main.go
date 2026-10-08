package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const usage = `Usage: hr-skills <publish|serve> -config config.json

publish  Validate checked-out skill catalogs and atomically publish snapshots.
         Run after a trusted Git checkout or CI update. No server rebuild or
         restart is needed; previous revision URIs remain readable.
serve    Serve authenticated Streamable HTTP MCP at /mcp.

Configuration paths are relative to the configuration file. See
config.example.json and policy.example.json. The publisher needs write access
only to the store; the server needs read access to the store and policy file.
Run one publisher per store. No Git credentials are needed by the server.
Publish only trusted, quiescent checkouts; every file beneath a skill directory
is distributed, including nested skills and hidden files (except .git).

Authentication deployment contract:
  Configure an external OAuth authorization server with Google Workspace login,
  authorization-code + PKCE S256, and MCP-client registration support (registered
  client IDs, dynamic registration, or client ID metadata documents as needed).
  It must publish OIDC discovery/JWKS and issue RFC 9068 JWT access tokens with:
    typ: at+jwt; iss: auth.issuer; aud: auth.resource_url; sub; exp; iat;
    scope: skills:read; hd: the verified upstream Google Workspace domain.
  Enforce the configured Workspace domain upstream. Do not copy an unverified
  user-editable domain attribute into hd. Google ID/API tokens are not accepted.
  Tokens must be asymmetric-signed. The provider handles login, consent, token
  issuance/refresh, and client redirects; this server only verifies tokens.

Policy subjects are stable OAuth issuer sub values, not emails or Google group
names. Memberships are admin-managed; no Google Directory sync is implied.
For example, add "provider-subject-id": ["engineering"] under subjects to grant
that identity access to catalogs whose reader groups include engineering.
Replace the policy file atomically to change grants; it is reread on every MCP
request, including reads of old revisions. Invalid policy fails closed.

Put HTTPS in front of serve, preserve the public Host, and keep the HTTP listener
private (loopback by default). Browser cross-origin MCP requests are rejected.
The OAuth metadata endpoint permits public cross-origin discovery. Do not expose
the store, policy, source checkouts, or signing credentials over static HTTP.
MCP clients can use list_skills (metadata) and load_skill (instructions and
reference URIs). Fetch only needed references with read_skill_resource or
resources/read; resources/list does not enumerate files. Native skills clients
may use io.modelcontextprotocol/skills. The server does not run scripts or
automatically activate skills in a model's context.
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		slog.Error("hr-skills stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, err := io.WriteString(out, usage)
		return err
	}
	if args[0] != "publish" && args[0] != "serve" {
		return fmt.Errorf("unknown command %q; use --help", args[0])
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(errOut)
	path := flags.String("config", "config.json", "configuration file")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	c, err := loadConfig(*path)
	if err != nil {
		return fmt.Errorf("configuration: %w", err)
	}
	if args[0] == "publish" {
		revisions, err := publishCatalogs(c)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(revisions)
	}
	if _, err := allowedCatalogs(c.PolicyFile, ""); err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	catalogNames := make([]string, 0, len(c.Catalogs))
	for _, catalog := range c.Catalogs {
		catalogNames = append(catalogNames, catalog.Name)
	}
	if _, err := (&catalogStore{root: c.Store}).list(catalogNames); err != nil {
		return fmt.Errorf("publish catalogs before serving: %w", err)
	}
	verifier, err := newTokenVerifier(ctx, c.Auth)
	if err != nil {
		return fmt.Errorf("authentication: %w", err)
	}
	handler, err := newHTTPHandler(c, verifier)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second,
		IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
	}
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				_ = server.Close()
			}
		case <-finished:
		}
	}()
	slog.Info("serving skills", "listen", listener.Addr().String(), "resource", c.Auth.ResourceURL)
	if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
