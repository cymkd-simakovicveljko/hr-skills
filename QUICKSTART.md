# Connect OMP to the company workflow

Connect once, then let your agent load the relevant engineering skills as needed. No local server, catalog clone or per-project skill installation is required.

**For:** developers with OMP installed, using its default profile and a Bash terminal. This guide connects to the **development/staging service**, not a declared production endpoint. For named profiles or other clients, see [configuration notes](README.md#client-configuration-notes).

## 1. Get your personal token

Open the [account page](https://hr-skills.34.205.105.168.sslip.io/) and sign in with your `recombo.ai` Google account.

- Every verified `recombo.ai` account automatically gets `engineering` catalog access. No individual invitation or administrator grant is needed.
- Select **Generate or rotate token**. This replaces your previous token, so update any other clients using it too.
- Keep the token private. Never paste it into an agent chat, repository or shared configuration. The client needs this hr-skills token, not a Google token.

## 2. Connect OMP

Run this in your terminal, then paste the token value at the prompt—not the `Bearer ` prefix. Input is hidden and stays out of shell history:

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

Open `~/.omp/agent/mcp.json` in your editor. Create it with the following content if absent; otherwise back it up and merge the `hr-skills` entry into its existing `mcpServers` object. Preserve other servers and settings.

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

The configuration references your private token file; it does not contain the token itself.

## 3. Enable the company workflow

Connecting MCP makes tools available. This bootstrap tells the agent when to use them.

Open `~/.omp/agent/APPEND_SYSTEM.md`. Create it if absent; otherwise back it up and preserve its contents. Append this block once, unless it is already present:

```text
At the start of an engineering task, call hr-skills list_skills and load
using-agent-skills using its returned revision-pinned URI. Reuse an identical
URI already loaded. Follow its applicable routing and activation rules; load
only the procedures and supporting resources needed for the task. Retain the
selected revision for that task. Use the host's exposed tool names.
If the server or router is unavailable or ambiguous, report the gap. Continue
only independently justified work under existing instructions; pause steps
that depend on missing safety guidance. Do not claim the shared workflow ran.
Loading instructions does not authorize commits, pushes, publication,
deployment, destructive actions, or bypassing host approvals.
```

## 4. Restart and verify

Fully exit and reopen OMP, then start a fresh session so it reads both the connection and bootstrap. In OMP, run:

```text
/mcp list
/mcp test hr-skills
```

Then ask:

> Discover hr-skills, load using-agent-skills, and explain which procedure you would use for a failing unit test with a cheap local reproduction. Do not change files or execute a repair.

**You are connected when:** the MCP check succeeds, tool activity shows catalog discovery and the router actually loading, and the agent selects `debugging-and-error-recovery` plus `test-driven-development` without starting a repair. A connected server alone does not prove the workflow was loaded.

Setup is per user/profile, not per project. You do not need to sign in again each session or reinstall skills when the catalog changes; already-loaded instructions stay on their selected revision for the current task.

## If something fails

- **Signed in, but no catalog access:** confirm you used your `recombo.ai` Google account, then ask an administrator to check the service's workspace-wide catalog policy. Individual grants are not required.
- **401 or token problems:** follow [token troubleshooting](README.md#token-lifecycle-and-troubleshooting). After replacing a token, fully restart OMP; reload alone may retain the old header.
- **Connected, but skills unused:** check step 3 and start a fresh session. Project settings or explicit prompt overrides may supersede user configuration; see [configuration notes](README.md#client-configuration-notes).
