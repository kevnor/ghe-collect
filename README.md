# ghe-collect

Read-only configuration collection from **GitHub Enterprise Cloud with data residency (GHE.com)**, for security reviews.

One run exports enterprise, organization and repository settings, the audit log and workflow files into a folder you can analyse offline. Nothing in the target enterprise is changed.

## Safety properties

- **Read-only.** Every REST call is `GET`. GraphQL is query-only, and the script refuses to send anything containing `mutation`.
- **The token is never written to disk.** It is read from `GH_TOKEN` or a hidden prompt. (With an OAuth token, `gh auth login` stores it in the keychain or gh's config. See [OAuth token](#oauth-token-when-classic-pats-are-blocked).)
- **No secret values.** The API never returns secret values, only names. Actions variable values are redacted by default (name and length are kept). Secret scanning alerts are fetched with `hide_secret=true`, and any `secret` field is removed as well.
- **Traceable.** `meta/run.json` records the user, token type, token scopes, token expiry, start and finish time, number of API calls and the SHA-256 of the script.
- **Tested.** `tests/run-tests.sh` checks these guarantees against a fake API on every change, on Linux (bash 5) and macOS (bash 3.2).

## What it collects

| Level | Content |
| --- | --- |
| Enterprise | Owners, policies, IP allow list, identity provider (OIDC/SAML), Actions policies, runner groups, security configurations, custom properties, audit log streams, licenses, Copilot seats |
| Audit log | Web/API events for the last 90 days and git events for the last 7 days, as NDJSON |
| Organization | Owners, members, outside collaborators, organization roles, teams and IdP groups, rulesets with bypass lists, bypass events for the last 30 days, custom properties, GitHub Apps, webhooks, Actions settings, runners, secret names, variables, OIDC sub claim, security configurations, open security alerts |
| Repository | Settings, direct collaborators, teams, rulesets (including inherited) and effective rules on the default branch, classic branch protection, webhooks, deploy keys, environments with branch policies and secret names, Actions permissions, Dependabot status, CODEOWNERS, `dependabot.yml`, workflow files |

## Requirements

- bash 3.2 or newer (the macOS default works), `gh` 2.48 or newer, `jq` 1.6 or newer, `tar`
- Network access that satisfies the enterprise's IP allow list and Conditional Access. In practice, run it from the customer's network or device.

### macOS without Homebrew

```bash
bash scripts/install-tools-macos.sh
export PATH="$HOME/bin:$PATH"
```

This installs `gh` (and `jq` if it is missing or too old) into `~/bin` without admin rights, and verifies the SHA-256 checksums of both downloads. Clean up afterwards with `rm -rf ~/ghe-tools ~/bin/gh ~/bin/jq`.

If macOS says **operation not permitted**, the file is quarantined or in a protected folder:

```bash
xattr -d com.apple.quarantine ghe-collect.sh   # or copy it out of Documents/Desktop/iCloud
```

### Linux / WSL

Install `gh` and `jq` from your package manager. On WSL, run from your Linux home folder, not from `/mnt/c`.

## Access

The token has the same access as your account.

1. **Enterprise owner** (or a role with read access to enterprise settings) covers the enterprise level.
2. **Organization owner** is needed for full organization and repository coverage. Enterprise owners can join organizations from `https://SUBDOMAIN.ghe.com/enterprises/SLUG/organizations` → gear menu → **Join as an organization owner**. This is a change that appears in the audit log, so agree on it with the customer first, and leave the organizations when you are done.

## Token

Use a **classic PAT** with a short lifetime (7 days or less). Fine-grained PATs cannot read enterprise endpoints.

Pre-filled form (replace `SUBDOMAIN`):

```
https://SUBDOMAIN.ghe.com/settings/tokens/new?description=ghe-collect&scopes=repo,read:org,read:enterprise,read:audit_log,read:repo_hook
```

| Scope | Need | Without it |
| --- | --- | --- |
| `repo` | Required | Repository settings, rulesets, files and alerts are missing |
| `read:org` | Required | Organizations, members and teams are missing |
| `read:enterprise` | Required | Enterprise settings are missing |
| `read:audit_log` | Required | Audit log is missing |
| `read:repo_hook` | Required | Repository webhooks are missing |
| `admin:org` | Optional, needs customer approval | Organization Actions settings, runner groups, secret names and code security are missing |
| `admin:org_hook` | Optional, needs customer approval | Organization webhooks are missing |

`repo`, `admin:org` and `admin:org_hook` also grant write access. The script only reads, but the customer must accept the scopes. The script warns about any scope beyond this list.

Enterprise Actions policies and runners, audit log streams, the IP allow list, the identity provider and verified domains require `admin:enterprise`. Do not request that scope; take screenshots in the UI instead. Without it the script skips those calls and records them as `SKIP` in `index.tsv`.

Classic PATs can be blocked by the enterprise (Enterprise → Policies → Personal access tokens) **or by each organization** (Org → Settings → Personal access tokens). A blocked organization returns 403 with "forbids access via a personal access token (classic)", and gh suggests the `admin:org` scope, which does not help. The script reports blocked organizations under `ACTION NEEDED` in `summary.txt`. Ask the customer for a time-limited exception rather than changing it yourself, then rerun with `--resume`. Check this before the run if you can, or use an OAuth token instead (below).

### OAuth token (when classic PATs are blocked)

The classic-PAT block does not apply to OAuth apps, and `gh auth login` gets an OAuth token (`gho_...`) with the same scopes, so every call works as with a classic PAT:

```bash
gh auth login --hostname SUBDOMAIN.ghe.com --web --scopes read:enterprise,read:audit_log,read:repo_hook
GH_TOKEN="$(gh auth token --hostname SUBDOMAIN.ghe.com)" bash ghe-collect.sh --host SUBDOMAIN.ghe.com --enterprise SLUG
```

- gh always requests `repo`, `read:org` and `gist`. The script accepts `gist` for OAuth tokens.
- OAuth tokens do not expire, and gh stores the token on the device (keychain or `hosts.yml`). Log out and revoke it right after the run:
  `gh auth logout --hostname SUBDOMAIN.ghe.com`, then revoke **GitHub CLI** under `https://SUBDOMAIN.ghe.com/settings/applications`.
- If an organization restricts OAuth app access, an org owner must approve GitHub CLI once. With SAML SSO, authorize the organizations during the browser flow.

## Usage

```bash
# Short test first: one organization, three repositories, no audit log
bash ghe-collect.sh --host SUBDOMAIN.ghe.com --enterprise SLUG --orgs ORG --repo-limit 3 --no-audit-log

# Full run
bash ghe-collect.sh --host SUBDOMAIN.ghe.com --enterprise SLUG

# Resume after an interruption or rate limit
bash ghe-collect.sh --host SUBDOMAIN.ghe.com --enterprise SLUG --out ./ghe-collect-SLUG-TIMESTAMP --resume
```

- **SLUG** is the part after `/enterprises/` in the enterprise URL.
- **ORG** is an organization name as it appears in `https://SUBDOMAIN.ghe.com/ORG`. Without `--orgs`, all organizations in the enterprise are collected.

Other options: `--skip-archived`, `--no-alerts`, `--no-workflows`, `--no-git-events`, `--audit-days N`, `--keep-variable-values`, `--no-archive`. See `--help`.

Expect 25–35 API calls per repository. The script waits automatically when the rate limit (5,000 calls per hour) runs low, so a few hundred repositories can take a couple of hours.

## Output

```
ghe-collect-SLUG-TIMESTAMP/
├── meta/           run.json, user.json
├── enterprise/     policies, IP allow list, IdP, Actions, audit-log-*.ndjson
├── orgs/ORG/       organization settings, rulesets/, teams/, repos/REPO/
├── workflows/      ORG/REPO/*.yml  (ready for zizmor)
├── index.tsv       every call with its status
├── errors.log      failed calls with the error message
└── summary.txt     summary and coverage per organization
ghe-collect-SLUG-TIMESTAMP.tar.gz (+ .sha256)
```

Read `summary.txt` first. `owner-view: no` for an organization means the token user is not an organization owner there, and much will be missing.

## After the run

- [ ] Revoke the PAT, or for an OAuth token: `gh auth logout` and revoke GitHub CLI under Settings → Applications
- [ ] Move the `.tar.gz` and `.sha256` to the engagement storage, and delete the copy on the device
- [ ] Record the run in the activity log (from `meta/run.json`)
- [ ] Run zizmor offline on the workflows: `zizmor --offline workflows/`
- [ ] Compare `audit-log-web.ndjson` with the customer's SIEM for the same period to test whether audit log streaming is complete
- [ ] Review `errors.log` and decide what to collect manually (screenshots)

**Never commit collected output to this repository.** `.gitignore` excludes the default output names, but check before you push.

## Moving the tool to another device

Prefer a release bundle over cloning when the target device cannot reach this repository:

```bash
# On your own machine, from a tagged commit
git archive --format=tar.gz --prefix=ghe-collect-1.1.0/ -o ghe-collect-1.1.0.tar.gz v1.1.0
shasum -a 256 ghe-collect-1.1.0.tar.gz > ghe-collect-1.1.0.tar.gz.sha256
```

Send both files through an approved channel, then on the target device:

```bash
shasum -a 256 -c ghe-collect-1.1.0.tar.gz.sha256
tar xzf ghe-collect-1.1.0.tar.gz && cd ghe-collect-1.1.0
```

## Limitations

- Fine-grained PATs and PAT requests can only be listed with a GitHub App. Check them in the UI.
- SCIM data is not collected. The mapping from IdP groups to teams is in `teams/*-external-groups.json`; check the rest in the IdP.
- Some endpoints are new or in preview (enterprise rulesets, audit log streams, enterprise teams) and may return 404 on GHE.com. They are marked optional and do not stop the run.
- The audit log API has its own rate limit and can stop part-way on busy enterprises. What was fetched is kept in `*.partial`; the SIEM is an alternative source.
- Only GHE.com is supported. GitHub Enterprise Server and github.com enterprises are not targeted.

## Development

```bash
bash tests/run-tests.sh                                  # run with the default bash
TEST_BASH=/bin/bash bash tests/run-tests.sh              # on macOS: test with bash 3.2
shellcheck -e SC2016 ghe-collect.sh scripts/*.sh tests/*.sh
```

The tests use `tests/fake-gh`, a stand-in for the `gh` CLI that logs every call and returns canned responses. When you add an endpoint, add a matching response there if the new code path needs one, and a check in `tests/run-tests.sh` for any new guarantee.

CI (`.github/workflows/ci.yml`) runs shellcheck and the tests on Ubuntu and macOS for every push and pull request.

Releasing: update `SCRIPT_VERSION` and `CHANGELOG.md`, commit, tag `vX.Y.Z`, and build the bundle as described above.
