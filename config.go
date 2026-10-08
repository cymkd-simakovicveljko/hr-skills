package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
)

type authConfig struct {
	ResourceURL            string `json:"resource_url"`
	WorkspaceDomain        string `json:"workspace_domain"`
	GoogleClientID         string `json:"google_client_id"`
	GoogleClientSecretFile string `json:"google_client_secret_file"`
	TokenFile              string `json:"token_file"`
}

type catalogConfig struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

type config struct {
	Listen     string          `json:"listen"`
	Store      string          `json:"store"`
	PolicyFile string          `json:"policy_file"`
	Auth       authConfig      `json:"auth"`
	Catalogs   []catalogConfig `json:"catalogs"`
}

// Memberships are administered here, keyed by verified Google subject, not email.
type policy struct {
	Subjects map[string][]string `json:"subjects"`
	Catalogs map[string][]string `json:"catalogs"`
}

var catalogNamePattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

func validCatalogName(name string) bool {
	return len(name) <= 64 && catalogNamePattern.MatchString(name)
}

func decodeFile(path string, value any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if err != nil {
		return err
	}
	if len(data) > 1<<20 {
		return fmt.Errorf("configuration exceeds 1 MiB")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(value); err != nil {
		return err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("expected one JSON document")
	}
	return nil
}

func loadConfig(path string) (config, error) {
	var c config
	if err := decodeFile(path, &c); err != nil {
		return c, err
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8080"
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return c, fmt.Errorf("listen: %w", err)
	}
	if c.Store == "" || c.PolicyFile == "" {
		return c, fmt.Errorf("store and policy_file are required")
	}
	base, err := filepath.Abs(filepath.Dir(path))
	if err != nil {
		return c, err
	}
	resolve := func(p string) string {
		if filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	c.Store, c.PolicyFile = resolve(c.Store), resolve(c.PolicyFile)
	if c.Auth.TokenFile == "" {
		return c, fmt.Errorf("auth.token_file is required")
	}
	c.Auth.TokenFile = resolve(c.Auth.TokenFile)
	if c.Auth.GoogleClientSecretFile != "" {
		c.Auth.GoogleClientSecretFile = resolve(c.Auth.GoogleClientSecretFile)
	}
	if within(c.Store, c.Auth.TokenFile) || c.Auth.TokenFile == c.PolicyFile || c.Auth.TokenFile == c.Auth.GoogleClientSecretFile {
		return c, fmt.Errorf("token_file must be separate from the catalog store, policy, and Google secret")
	}
	seen := map[string]bool{}
	for i := range c.Catalogs {
		v := &c.Catalogs[i]
		if !validCatalogName(v.Name) || seen[v.Name] || v.Path == "" {
			return c, fmt.Errorf("invalid or duplicate catalog %q", v.Name)
		}
		seen[v.Name] = true
		v.Path = resolve(v.Path)
		if within(v.Path, c.Store) || within(c.Store, v.Path) {
			return c, fmt.Errorf("catalog source and store must not overlap")
		}
		if within(v.Path, c.Auth.TokenFile) || (c.Auth.GoogleClientSecretFile != "" && within(v.Path, c.Auth.GoogleClientSecretFile)) {
			return c, fmt.Errorf("authentication files must not be inside a catalog source")
		}
	}
	if len(c.Catalogs) == 0 {
		return c, fmt.Errorf("at least one catalog is required")
	}
	if err := validateEndpoint(c.Auth.ResourceURL); err != nil {
		return c, fmt.Errorf("resource_url: %w", err)
	}
	u, _ := url.Parse(c.Auth.ResourceURL)
	if u.Path != "/mcp" {
		return c, fmt.Errorf("resource_url path must be /mcp")
	}
	if c.Auth.WorkspaceDomain == "" {
		return c, fmt.Errorf("workspace_domain is required")
	}
	return c, nil
}

func within(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && filepath.IsLocal(rel)
}

func validateEndpoint(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("expected an absolute URL without credentials, query, or fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && (u.Hostname() == "localhost" || (ip != nil && ip.IsLoopback())) {
		return nil
	}
	return fmt.Errorf("HTTPS is required except on loopback")
}

func allowedCatalogs(path, subject string) ([]string, error) {
	var p policy
	if err := decodeFile(path, &p); err != nil {
		return nil, err
	}
	groups := map[string]bool{}
	for _, group := range p.Subjects[subject] {
		if group != "" {
			groups[group] = true
		}
	}
	allowed := []string{}
	for catalog, readers := range p.Catalogs {
		if !validCatalogName(catalog) {
			return nil, fmt.Errorf("invalid catalog in policy")
		}
		for _, group := range readers {
			if groups[group] {
				allowed = append(allowed, catalog)
				break
			}
		}
	}
	return allowed, nil
}
