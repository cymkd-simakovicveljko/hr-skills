# hr-skills

An authenticated MCP server for distributing versioned skill catalogs. Agents discover skill metadata, load selected instructions, and fetch supporting files only when needed.

The server distributes content; it does not execute scripts, install local skills, or automatically activate instructions. Developers connect their MCP client to the hosted service—no local server or catalog checkout is required.

## Developer setup

Start with [Connect OMP to the company workflow](QUICKSTART.md): get a personal token, connect MCP, enable the workflow bootstrap, and verify it in a fresh session. The guide targets the development/staging service and requires no local server or catalog checkout.

### Client configuration notes

The quick start uses OMP's default user profile. Named profiles use `~/.omp/profiles/<name>/agent/mcp.json` instead; use a matching private secret location if you want separate local credential storage. A project-level definition or disable override can supersede the user entry.

OMP resolves `!cat` locally when connecting; the token becomes an HTTP header, not model instructions. An alternative is `"Authorization": "Bearer ${HR_SKILLS_TOKEN}"` if your environment/secret manager already provides that variable to OMP. The file-backed setup requires no shell environment changes.

Other clients need the same URL, Streamable HTTP transport and bearer header, but their configuration and secret-resolution syntax may differ. OMP's `!cat` syntax is not portable to every MCP client. Google login is for the account page; automatic MCP-client OAuth login is not implemented.

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

### Bootstrap the company workflow

Use a short instruction in an **always-loaded instruction file**, not another skill that itself has to be discovered. The [workflow setup step](QUICKSTART.md#3-enable-the-company-workflow) owns the copyable bootstrap and OMP installation instructions. Project-level or explicit CLI prompt overrides may take precedence.

For other clients, put the same bootstrap in their supported always-loaded project or managed instructions; OMP's filename and configuration syntax are not portable. Team rollout requires configuring and checking each supported client, not only publishing the catalog. Each developer keeps their own credentials.

The flow is **client bootstrap → catalog metadata → `using-agent-skills` → selected procedures and resources**. The bootstrap stays fixed as routing evolves. The [catalog](https://github.com/cymkd-simakovicveljko/hr-skills-catalog) contains all 25 Osmani SDLC skills and five supplements: the Osmani skills and three risk-specific supplements support model invocation, while `grill-me` and pstack `tdd` require explicit selection as alternatives to `interview-me` and `test-driven-development`. The server preserves these restrictions in the delivered instructions; it does not execute or enforce the workflow.

The router supplies all nine lifecycle modes as MCP-readable resources: spec, plan, build (including auto/all), test, review, code-simplify, constraints (including check/guard/ratchet), ship, and webperf (quick/deep). Ask in natural language, such as “run the build auto workflow.” This does not install native slash commands, named agents, hooks or browser tooling. Full-plan execution still needs plan approval; release readiness is not deployment authorization. Verify the published catalog through `list_skills` rather than assuming the server already has a local catalog edit.

Add the bootstrap explicitly, then start a fresh session so the client reads it. Publishing the router does not update already-loaded sessions. Keep the skill URIs and verification evidence in the existing task or PR record; required CI checks and approval controls remain authoritative.

## Token lifecycle and troubleshooting

- **One current token per Google subject.** Generating a new token immediately replaces the previous one. If several clients use that identity's token, update them all after rotation.
- **Tokens remain valid until rotated or revoked.** Only SHA-256 digests are stored by the server. Browser sessions expire after eight hours and are cleared on server restart; MCP tokens are independent of those sessions.
- **After rotation:** replace the local authorization file, then restart OMP. OMP caches successful `!command` results for the process lifetime, so `/mcp reload` alone may retain the old header.
- **Lost or exposed token:** revoke it on the account page, generate a replacement, and update the affected clients.
- **401:** check that the header contains `Bearer ` followed by the current hr-skills token. A revoked token, another application's token, or a browser session is not sufficient.
- **Verified login but no access:** the hosted service grants `engineering` access to every verified `recombo.ai` account. Ask an administrator to check the workspace-wide catalog policy; no individual grant is required.
- **Server absent from OMP:** check the active profile, JSON validity, project overrides, and `/mcp list`. Use `/mcp reload` after changing configuration.
- **Server connected but skills unused:** follow the [workflow setup step](QUICKSTART.md#3-enable-the-company-workflow), start a fresh session, and verify discovery plus router loading in the tool activity.
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

### Hosted catalog automation

The Lightsail deployment pulls the private [hr-skills-catalog](https://github.com/cymkd-simakovicveljko/hr-skills-catalog) repository's `main` branch approximately every 15 minutes, with an initial check one minute after boot. [deploy/publish-catalog.sh](deploy/publish-catalog.sh) fetches and checks out the latest observed commit without running repository hooks, then publishes it. It records the commit only after successful publication; unchanged commits are skipped and failures are retried by the next timer run.

[deploy/hr-skills-publish.service](deploy/hr-skills-publish.service) and [deploy/hr-skills-publish.timer](deploy/hr-skills-publish.timer) provide serialization, boot activation, and journal logs. Use the service—not concurrent direct script invocations—for manual publishing. No inbound webhook, GitHub Actions server credential, or application restart is needed.

The installed layout is deployment-specific:

- Publisher script: `/opt/hr-skills/publish-catalog.sh`.
- Root-owned source checkout: `/opt/hr-skills/catalogs/repository`; `engineering` maps to its `engineering/` directory in `/etc/hr-skills/config.json`.
- Read-only, repository-scoped GitHub deploy key: `/etc/credstore.encrypted/hr-skills-catalog.github-deploy-key`, encrypted with systemd credential name `github-deploy-key`. Only the publisher receives the decrypted credential.
- GitHub SSH host keys: `/etc/hr-skills/github_known_hosts`, pinned from GitHub's HTTPS `/meta` API; unknown host keys fail closed.
- Successful commit marker: `/var/lib/hr-skills-catalog/published-commit`. Documentation-only commits can advance this marker without changing the content-addressed catalog revision.
- Catalog store: owned by `hr-skills:hr-skills`. The root publisher drops to this UID before publishing so newly created private files are immediately readable by the server. The HTTP service retains `ProtectSystem=strict` with only `/var/lib/hr-skills/auth` writable, keeping its catalog store read-only. Preserve this sandbox if changing the service unit.

To install updated publisher files on this host, copy the script to its path above and the two units to `/etc/systemd/system/`, then run `sudo systemctl daemon-reload` and `sudo systemctl enable --now hr-skills-publish.timer`. Provision the listed credential, host keys, source directory, store ownership, and catalog mapping before a first installation.

Operational checks on Lightsail:

```bash
sudo systemctl start hr-skills-publish.service
sudo systemctl is-active hr-skills-publish.timer hr-skills.service
sudo journalctl -u hr-skills-publish.service -n 30 --no-pager
sudo cat /var/lib/hr-skills-catalog/published-commit
test "$(sudo cat /var/lib/hr-skills-catalog/published-commit)" = "$(sudo git -C /opt/hr-skills/catalogs/repository rev-parse HEAD)"
```

Compare the recorded commit with GitHub `main`. A failed fetch or invalid catalog does not replace the last good published catalog. To roll back content, revert the relevant commit in the catalog repository and push to `main`. Clients must discover and load the new revision; instructions already loaded into a conversation do not change automatically.

### Grant access

The example configuration calls its catalog `shared`. A reader of `"*"` grants that catalog to every authenticated account from the configured Google Workspace domain, without a per-person membership entry:

```json
{
  "subjects": {},
  "catalogs": {
    "shared": ["*"]
  }
}
```

Catalog keys must match your configuration. The hosted staging service uses `"engineering": ["*"]` and the workspace domain `recombo.ai`. This does not permit anonymous access: Google verification is still required to issue a personal token, and MCP requests still require a valid token.

For a restricted catalog, replace `"*"` with group names and assign those groups in `subjects`, keyed by verified Google subject rather than email. Google Workspace group synchronization is not provided. Replace policy files atomically. Policy is reread for every MCP request, including old revisions, and invalid policy fails closed.

Workspace membership is checked at login, not on each MCP request. Disabling a Google account does not invalidate an existing MCP token or browser session. For offboarding, disable the Workspace account, revoke its MCP token, and clear surviving browser sessions (currently by restarting the service).

### HTTPS and operational boundaries

Put an HTTPS reverse proxy in front of `serve`, preserve the public `Host`, and keep the HTTP listener private. Loopback is appropriate for a host-local proxy; a containerized proxy needs a reachable private interface instead of its own loopback.

Expose only the application routes. Never serve the catalog store, source checkout, policy, token file, or Google client secret as static files. Do not log authorization headers.

The MCP endpoint uses Streamable HTTP. Standard tool clients use the three tools above; clients supporting the `io.modelcontextprotocol/skills` extension can use native skill discovery. The service distributes instructions and resources, not a remote code-execution environment.

## Development checks

```bash
go test -race -count=1 ./...
go vet ./...
```
