#!/bin/sh
set -eu

repo=/opt/hr-skills/catalogs/repository
state=/var/lib/hr-skills-catalog
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
export GIT_SSH_COMMAND="ssh -i ${CREDENTIALS_DIRECTORY:?}/github-deploy-key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/hr-skills/github_known_hosts"

if [ ! -d "$repo/.git" ]; then
    git -c core.hooksPath=/dev/null init "$repo"
    git -C "$repo" remote add origin git@github.com:cymkd-simakovicveljko/hr-skills-catalog.git
fi

git -C "$repo" -c core.hooksPath=/dev/null fetch --no-tags --depth=1 origin refs/heads/main
commit=$(git -C "$repo" rev-parse --verify 'FETCH_HEAD^{commit}')
if [ -f "$state/published-commit" ] && [ "$(cat "$state/published-commit")" = "$commit" ]; then
    printf 'Already published %s\n' "$commit"
    exit 0
fi

git -C "$repo" -c core.hooksPath=/dev/null -c core.fsmonitor=false checkout --detach --force "$commit"
chown -hR root:hr-skills "$repo"
chmod -R u=rwX,g=rX,o= "$repo"
chmod 700 "$repo/.git"

# Publish as the reader's UID so new private objects are readable immediately.
# The HTTP service's sandbox keeps its catalog-store mount read-only.
runuser -u hr-skills -- /opt/hr-skills/current/hr-skills publish -config /etc/hr-skills/config.json
printf '%s\n' "$commit" > "$state/published-commit.next"
mv "$state/published-commit.next" "$state/published-commit"
printf 'Published catalog commit %s\n' "$commit"
