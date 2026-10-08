# hr-skills

An authenticated MCP server for distributing versioned skill catalogs. Agents discover skill metadata, load selected instructions, and fetch supporting files only when needed.

The server distributes content; it does not execute scripts, install local skills, or automatically activate instructions. Developers connect their MCP client to the hosted service—no local server or catalog checkout is required.

## Connect to the development/staging service

| Setting | Value |
| --- | --- |
| Account page | <https://hr-skills.34.205.105.168.sslip.io/> |
| MCP endpoint | `https://hr-skills.34.205.105.168.sslip.io/mcp` |
| Transport | Streamable HTTP |
| Authentication | `Authorization: Bearer <your-hr-skills-token>` |
| Google Workspace | `recombo.ai` |

### 1. Sign in and obtain access

Open the account page and sign in with Google. If no catalog access is listed, give an administrator the **Google subject** shown on that page. Signing in verifies your identity; it does not automatically grant catalog access.

Once access is granted, select **Generate or rotate token**. Treat the displayed token as a secret. Google ID tokens, Google API tokens, browser cookies, and tokens from other applications cannot authenticate MCP requests.

Google login here is for the account page. Automatic MCP-client OAuth login is **not implemented**: the client uses the separate bearer token you generate.

### 2. Store the token locally

For OMP, keep the token outside the repository in an owner-only file. This Bash command prompts without echoing the token or putting it in shell history:

```bash
bash -c '
  set -eu
  install -d -m 700 "$HOME/.omp/agent/secrets"
  read -r -s -p "Paste hr-skills token: " token </dev/tty
  printf "\n" >/dev/tty
  test -n "$token"
  umask 077
  printf "Bearer %s\n" "$token" > "$HOME/.omp/agent/secrets/hr-skills.authorization"
  chmod 600 "$HOME/.omp/agent/secrets/hr-skills.authorization"
'
```

The file contains the complete `Bearer ...` header value. Never commit it, paste it into a chat, or put it in shared project configuration.

### 3. Configure OMP once per user/profile

Merge this entry into `~/.omp/agent/mcp.json`; preserve any existing servers:

```json
{
  "mcpServers": {
    "hr-skills": {
      "type": "http",
      "url": "https://hr-skills.34.205.105.168.sslip.io/mcp",
      "headers": {
        "Authorization": "!cat \"$HOME/.omp/agent/secrets/hr-skills.authorization\""
      }
    }
  }
}
```

OMP resolves the `!cat` command locally when connecting. The token is used as an HTTP header, not as model instructions. The configuration contains only the secret file's path.

User-level setup applies across projects in the default OMP profile. Named profiles use `~/.omp/profiles/<name>/agent/mcp.json` instead; use a matching private secret location if you want separate local credential storage. A project-level definition or disable override can supersede the user entry.

An alternative is `"Authorization": "Bearer ${HR_SKILLS_TOKEN}"` if your environment/secret manager already provides that variable to OMP. The file-backed setup above requires no shell environment changes.

Other clients need the same URL, HTTP transport, and bearer header, but their configuration and secret-resolution syntax may differ. OMP's `!cat` syntax is not portable to every MCP client.

### 4. Reload and verify

In an already-open OMP session:

```text
/mcp reload
/mcp list
/mcp test hr-skills
```

Then ask the agent:

> List the skills available from hr-skills, then load a relevant skill without executing anything.

Success means the configured client returns authorized skill metadata and can load a returned revision-pinned URI. An empty catalog may reflect your access policy; it does not prove the server is disconnected.

New default-profile OMP sessions discover this connection automatically. You do not need to sign in or paste the token again for each session.

## What enters the agent's context?

Connection, discovery, and instruction loading are separate operations:

| Event | What the agent receives |
| --- | --- |
| Session starts and MCP connects | Access to the MCP tools and their descriptions; not the full skill catalog. |
| `list_skills` is called | Authorized skill names, descriptions, and revision-pinned URIs. |
| `load_skill` is called with a returned URI | That skill's complete `SKILL.md` and links to its supporting files. |
| `read_skill_resource` is called with a returned URI | One requested file, as UTF-8 text or a base64 blob. |

OMP can expose the tools through its discoverable `xd://` tool surface. Runtime names are sanitized; for example, `list_skills` appears as `mcp__hr_skills_list_skills`. Use the client's exposed tool names rather than assuming every client uses the same naming convention.

Connecting makes these tools available; it does **not** guarantee the agent will call them. Loading a skill also does not override its frontmatter activation restrictions, client approval rules, or higher-priority instructions.

### Bootstrap discovery without another skill

Use a short instruction in an **always-loaded instruction file**, not a skill that itself has to be discovered. For OMP, append the following to the effective `APPEND_SYSTEM.md` for your user/profile or project. The default user location is `~/.omp/agent/APPEND_SYSTEM.md`; preserve its existing contents. Project-level or explicit CLI prompt overrides may take precedence.

```text
Once per session, call the hr-skills server's list_skills tool. Before work
that matches an available skill, load that skill and follow its applicable
instructions and activation restrictions. Fetch supporting files only as
needed. If hr-skills is unavailable, report that and continue without claiming
its skills were applied.
```

This is an onboarding instruction to add explicitly. Connecting the server or reading this README does not install it automatically.

The flow is: **one local instruction → remote catalog metadata → selected skill instructions**. The bootstrap stays fixed as the catalog grows. No rule needs to preload every skill or copy the catalog into each repository.

## Token lifecycle and troubleshooting

- **One current token per Google subject.** Generating a new token immediately replaces the previous one. If several clients use that identity's token, update them all after rotation.
- **Tokens remain valid until rotated or revoked.** Only SHA-256 digests are stored by the server. Browser sessions expire after eight hours and are cleared on server restart; MCP tokens are independent of those sessions.
- **After rotation:** replace the local authorization file, then restart OMP. OMP caches successful `!command` results for the process lifetime, so `/mcp reload` alone may retain the old header.
- **Lost or exposed token:** revoke it on the account page, generate a replacement, and update the affected clients.
- **401:** check that the header contains `Bearer ` followed by the current hr-skills token. A revoked token, another application's token, or a browser session is not sufficient.
- **Verified login but no access:** ask an administrator to grant catalog access to the Google subject shown on the account page. Email addresses are not policy subject keys.
- **Server absent from OMP:** check the active profile, JSON validity, project overrides, and `/mcp list`. Use `/mcp reload` after changing configuration.
- **Server connected but skills unused:** add the bootstrap instruction above or explicitly ask the agent to discover skills.
- **No files in `resources/list`:** intentional. Use `list_skills`, then `load_skill`, then `read_skill_resource`. Do not depend on a client-wide resource browser to enumerate the catalog.

## Run your own server

This section is for operators. Consumers of the hosted service can stop above.

### Build and configure

Use Go 1.26 or newer:

```bash
go build -o hr-skills .
cp config.example.json config.json
cp policy.example.json policy.json
```

Edit the copies before serving. Paths in the configuration are relative to the configuration file. See [config.example.json](config.example.json), [policy.example.json](policy.example.json), and `./hr-skills --help` for the configuration contract.

1. Register a **separate Google OAuth Web application client** for this service. Its redirect URI is the origin of `auth.resource_url` plus `/auth/google/callback`, for example `https://hr-skills.example.com/auth/google/callback`.
2. Set `auth.google_client_id`, `auth.workspace_domain`, and the public HTTPS `auth.resource_url` ending in `/mcp`.
3. Store only the client secret—not the downloaded Google JSON—in `auth.google_client_secret_file`. Restrict access to the service account. Never reuse another application's client secret or MCP token.
4. Choose `auth.token_file` in a private, writable directory outside the source catalogs and published store. Give the runtime user access only to the files it needs.
5. Point each catalog at a trusted, stable checkout containing `SKILL.md` files and their supporting files. Keep credentials out of those directories.

### Publish and serve

```bash
./hr-skills publish -config config.json
./hr-skills serve -config config.json
```

Publish before starting the server. The publisher validates catalogs and atomically updates the published snapshots. After a trusted catalog update, run `publish` again; the running server does not need rebuilding or restarting. Old revision-pinned URIs remain readable, subject to the caller's current access policy.

Every file beneath a skill directory is distributed, including nested skills and hidden files except `.git`. Publish only reviewed, quiescent checkouts; do not point a catalog at an arbitrary working directory containing secrets.

Run one publisher per catalog store and one server per token file. The publisher needs write access to the store. The runtime reads the store, policy, and Google client secret, and writes its token file; it does not need Git credentials.

### Grant access

The example configuration calls its catalog `shared`. Its policy permits the `engineering` group to read that catalog. After a user signs in, add their verified Google subject to the policy:

```json
{
  "subjects": {
    "GOOGLE_SUB_FROM_ACCOUNT_PAGE": ["engineering"]
  },
  "catalogs": {
    "shared": ["engineering"]
  }
}
```

Catalog keys must match your configuration; the hosted staging catalog is named `engineering`, while the example above uses `shared`.

Membership is admin-managed; Google Workspace group synchronization is not provided. Replace policy files atomically. Policy is reread for every MCP request, including old revisions, and invalid policy fails closed. For offboarding, remove access grants and revoke the user's token.

### HTTPS and operational boundaries

Put an HTTPS reverse proxy in front of `serve`, preserve the public `Host`, and keep the HTTP listener private. Loopback is appropriate for a host-local proxy; a containerized proxy needs a reachable private interface instead of its own loopback.

Expose only the application routes. Never serve the catalog store, source checkout, policy, token file, or Google client secret as static files. Do not log authorization headers.

The MCP endpoint uses Streamable HTTP. Standard tool clients use the three tools above; clients supporting the `io.modelcontextprotocol/skills` extension can use native skill discovery. The service distributes instructions and resources, not a remote code-execution environment.

## Development checks

```bash
go test -race -count=1 ./...
go vet ./...
```
