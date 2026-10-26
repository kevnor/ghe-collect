#!/usr/bin/env bash
#
# ghe-collect.sh
#
# Read-only configuration collection from GitHub Enterprise Cloud with data residency (GHE.com).
#
# The script ONLY makes GET requests to the REST API and read queries to GraphQL. It changes nothing.
# The token is never written to disk. Secret values are never collected (the API does not return them),
# Actions variable values are redacted by default, and secret scanning alerts are fetched without the secret.
#
# Usage: ./ghe-collect.sh --host SUBDOMAIN.ghe.com --enterprise SLUG [options]
#        ./ghe-collect.sh --help
#
# Requires: bash 3.2+, gh >= 2.48, jq >= 1.6, tar
#
set -uo pipefail
umask 077

readonly SCRIPT_VERSION="1.1.0"
readonly API_VERSION="2022-11-28"
readonly MIN_GH_VERSION="2.48.0"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
HOST=""
ENTERPRISE=""
ORGS_ARG=""
OUT=""
AUDIT_DAYS=90
GIT_EVENT_DAYS=7
SKIP_ARCHIVED=0
REPO_LIMIT=0
COLLECT_ALERTS=1
COLLECT_AUDIT=1
COLLECT_GIT_EVENTS=1
COLLECT_WORKFLOWS=1
KEEP_VAR_VALUES=0
RESUME=0
NO_ARCHIVE=0

usage() {
  cat <<'EOF'
Usage: ghe-collect.sh --host SUBDOMAIN.ghe.com --enterprise SLUG [options]

Required:
  --host HOST              GHE.com host, e.g. example.ghe.com (without api.)
  --enterprise SLUG        Enterprise slug

Options:
  --orgs a,b,c             Only these organizations (default: all organizations in the enterprise)
  --out DIR                Output directory (default: ./ghe-collect-SLUG-TIMESTAMP)
  --resume                 Continue an interrupted run in --out. Existing files are skipped
  --audit-days N           Days of audit log (web/API events). Default 90, max 180
  --no-audit-log           Do not collect the audit log
  --no-git-events          Do not collect git events (last 7 days)
  --no-alerts              Do not collect open security alerts (secret scanning, Dependabot, code scanning)
  --no-workflows           Do not download workflow files
  --skip-archived          Skip archived repositories
  --repo-limit N           Max repositories per organization (for testing)
  --keep-variable-values   Keep Actions variable values (default: redacted)
  --no-archive             Do not create a tar.gz at the end
  --version                Print version
  -h, --help               Show this help

The token is read from GH_TOKEN. If it is not set, the script prompts without echoing input.
Use a short-lived classic PAT. See README.md for required scopes.
EOF
}

log()  { printf '[%s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }
warn() { log "WARNING: $*"; }
die()  { log "ERROR: $*"; exit 1; }

need_arg() { [[ $# -ge 2 && -n "$2" ]] || die "$1 requires a value"; }

while (($#)); do
  case "$1" in
    --host)                 need_arg "$@"; HOST="$2"; shift 2 ;;
    --enterprise)           need_arg "$@"; ENTERPRISE="$2"; shift 2 ;;
    --orgs)                 need_arg "$@"; ORGS_ARG="$2"; shift 2 ;;
    --out)                  need_arg "$@"; OUT="$2"; shift 2 ;;
    --audit-days)           need_arg "$@"; AUDIT_DAYS="$2"; shift 2 ;;
    --repo-limit)           need_arg "$@"; REPO_LIMIT="$2"; shift 2 ;;
    --resume)               RESUME=1; shift ;;
    --no-audit-log)         COLLECT_AUDIT=0; shift ;;
    --no-git-events)        COLLECT_GIT_EVENTS=0; shift ;;
    --no-alerts)            COLLECT_ALERTS=0; shift ;;
    --no-workflows)         COLLECT_WORKFLOWS=0; shift ;;
    --skip-archived)        SKIP_ARCHIVED=1; shift ;;
    --keep-variable-values) KEEP_VAR_VALUES=1; shift ;;
    --no-archive)           NO_ARCHIVE=1; shift ;;
    --version)              echo "ghe-collect ${SCRIPT_VERSION}"; exit 0 ;;
    -h|--help)              usage; exit 0 ;;
    *)                      die "Unknown argument: $1 (see --help)" ;;
  esac
done

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
HOST="${HOST#https://}"; HOST="${HOST#api.}"; HOST="${HOST%%/*}"
HOST="$(printf '%s' "$HOST" | tr '[:upper:]' '[:lower:]')"
[[ "$HOST" =~ ^[a-z0-9][a-z0-9-]*\.ghe\.com$ ]] || die "--host must look like SUBDOMAIN.ghe.com (got: '${HOST}')"
[[ "$ENTERPRISE" =~ ^[A-Za-z0-9][A-Za-z0-9-]*$ ]] || die "--enterprise is missing or invalid"
if ! [[ "$AUDIT_DAYS" =~ ^[0-9]+$ ]] || (( AUDIT_DAYS < 1 || AUDIT_DAYS > 180 )); then die "--audit-days must be 1-180"; fi
[[ "$REPO_LIMIT" =~ ^[0-9]+$ ]] || die "--repo-limit must be a number"
if [[ -n "$ORGS_ARG" && ! "$ORGS_ARG" =~ ^[A-Za-z0-9-]+(,[A-Za-z0-9-]+)*$ ]]; then die "--orgs must be comma-separated organization names"; fi
(( BASH_VERSINFO[0] >= 3 && (BASH_VERSINFO[0] > 3 || BASH_VERSINFO[1] >= 2) )) || die "Requires bash 3.2 or newer"

for cmd in gh jq tar mktemp date; do
  command -v "$cmd" >/dev/null 2>&1 || die "'$cmd' not found in PATH"
done

GH_VER="$(gh --version 2>/dev/null | head -n1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
[[ -n "$GH_VER" ]] || die "Could not read gh version"
if [[ "$(awk -v a="$GH_VER" -v b="$MIN_GH_VERSION" 'BEGIN { split(a, x, "."); split(b, y, ".");
      for (i = 1; i <= 3; i++) { if (x[i]+0 > y[i]+0) { print 1; exit } if (x[i]+0 < y[i]+0) { print 0; exit } } print 1 }')" != "1" ]]; then
  die "gh $GH_VER is too old. Requires $MIN_GH_VERSION or newer (for --slurp)"
fi
jq -n '[1] | walk(.)' >/dev/null 2>&1 || die "jq has no walk(). Requires jq 1.6 or newer"

if command -v sha256sum >/dev/null 2>&1; then SHA_CMD=(sha256sum); else SHA_CMD=(shasum -a 256); fi

# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------
if [[ -z "${GH_TOKEN:-}" ]]; then
  [[ -t 0 ]] || die "GH_TOKEN is not set and there is no terminal to prompt in"
  read -rsp "Classic PAT for ${HOST} (input hidden): " GH_TOKEN; echo >&2
fi
[[ -n "${GH_TOKEN:-}" ]] || die "Empty token"
case "$GH_TOKEN" in
  ghp_*)        ;;
  github_pat_*) die "Fine-grained PATs cannot read enterprise endpoints. Use a classic PAT" ;;
  *)            warn "Token does not look like a classic PAT (ghp_...). Continuing anyway" ;;
esac
export GH_TOKEN
export GH_ENTERPRISE_TOKEN="$GH_TOKEN"
export GH_HOST="$HOST"
export GH_PROMPT_DISABLED=1 GH_NO_UPDATE_NOTIFIER=1 GH_PAGER=cat NO_COLOR=1 CLICOLOR=0
unset GITHUB_TOKEN GITHUB_ENTERPRISE_TOKEN

# ---------------------------------------------------------------------------
# Output directory
# ---------------------------------------------------------------------------
STARTED="$(date -u +%FT%TZ)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUT:-./ghe-collect-${ENTERPRISE}-${STAMP}}"
OUT="${OUT%/}"
if [[ -d "$OUT" && -n "$(ls -A "$OUT" 2>/dev/null)" ]] && (( ! RESUME )); then
  die "Directory '$OUT' exists and is not empty. Use --resume or a different --out"
fi
mkdir -p "$OUT"/{meta,enterprise,orgs,workflows} || die "Could not create '$OUT'"
INDEX="$OUT/index.tsv"
ERRLOG="$OUT/errors.log"
[[ -f "$INDEX" ]] || printf 'time\tstatus\tcategory\tendpoint\tfile\n' > "$INDEX"
touch "$ERRLOG"
exec 2> >(tee -a "$OUT/run.log" >&2)

trap 'warn "Interrupted. Resume with: $0 --host $HOST --enterprise $ENTERPRISE --out \"$OUT\" --resume"; exit 130' INT TERM

CALLS=0
LAST_STATUS=""
IP_WARNED=0
LOGIN=""
SCOPES=""
TOKEN_EXPIRY=""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
uri()  { jq -rn --arg s "$1" '$s|@uri'; }
safe() { printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '_'; }

rate_guard() {
  (( CALLS % 50 == 0 )) || return 0
  local line rem reset wait
  line="$(gh api --hostname "$HOST" rate_limit --jq '.resources.core | "\(.remaining) \(.reset)"' 2>/dev/null)" || return 0
  read -r rem reset <<<"$line"
  [[ "$rem" =~ ^[0-9]+$ && "$reset" =~ ^[0-9]+$ ]] || return 0
  if (( rem < 200 )); then
    wait=$(( reset - $(date +%s) + 5 )); (( wait < 5 )) && wait=5
    log "Rate limit: $rem calls left. Waiting ${wait}s for reset"
    sleep "$wait"
  fi
}

record() { # status category endpoint file
  printf '%s\t%s\t%s\t%s\t%s\n' "$(date -u +%FT%TZ)" "$1" "$2" "$3" "${4#"$OUT"/}" >> "$INDEX"
}

handle_error() { # errfile endpoint
  local s
  s="$(grep -oE 'HTTP [0-9]{3}' "$1" | tail -n1 | cut -d' ' -f2)"
  LAST_STATUS="${s:-ERR}"
  printf '%s\t%s\t%s\n' "$LAST_STATUS" "$2" "$(head -c 400 "$1" | tr '\n\r' '  ')" >> "$ERRLOG"
  if (( ! IP_WARNED )) && grep -qiE 'IP allow list|conditional access' "$1"; then
    IP_WARNED=1
    warn "Blocked by IP allow list / Conditional Access. Run from the customer's network"
  fi
}

# api_get <category> <endpoint> <outfile> [paginate 0|1] [jq post-filter]
# A category ending in ':optional' means 403/404 is expected in some setups.
api_get() {
  local cat="$1" ep="$2" out="$3" pag="${4:-0}" post="${5:-}"
  if (( RESUME )) && [[ -s "$out" ]]; then LAST_STATUS="cached"; return 0; fi
  mkdir -p "$(dirname "$out")"
  rate_guard
  local -a args=(api --hostname "$HOST" --method GET
    -H "Accept: application/vnd.github+json" -H "X-GitHub-Api-Version: ${API_VERSION}")
  (( pag )) && args+=(--paginate --slurp)
  local tmp err rc filter
  tmp="$(mktemp)"; err="$(mktemp)"
  gh "${args[@]}" "$ep" >"$tmp" 2>"$err"; rc=$?
  CALLS=$((CALLS + 1))
  if (( rc == 0 )); then
    if [[ ! -s "$tmp" ]]; then
      LAST_STATUS=204
      printf '{"_http_status":204}\n' > "$out"
    else
      LAST_STATUS=200
      filter='.'
      # --slurp returns a list of pages. A list of lists is flattened into one list.
      (( pag )) && filter='if type=="array" and length>0 and all(.[]; type=="array") then (add // []) else . end'
      [[ -n "$post" ]] && filter="${filter} | ${post}"
      if ! jq "$filter" "$tmp" > "$out" 2>>"$err"; then
        LAST_STATUS="PARSE"
        printf '%s\t%s\t%s\n' "PARSE" "$ep" "$(head -c 400 "$err" | tr '\n\r' '  ')" >> "$ERRLOG"
        rm -f "$out"
      fi
    fi
  else
    handle_error "$err" "$ep"
    rm -f "$out"
  fi
  record "$LAST_STATUS" "$cat" "$ep" "$out"
  rm -f "$tmp" "$err"
  [[ "$LAST_STATUS" == 2* ]]
}

# api_raw <category> <endpoint> <outfile>  (file contents, e.g. workflows and CODEOWNERS)
api_raw() {
  local cat="$1" ep="$2" out="$3"
  if (( RESUME )) && [[ -s "$out" ]]; then LAST_STATUS="cached"; return 0; fi
  mkdir -p "$(dirname "$out")"
  rate_guard
  local tmp err rc
  tmp="$(mktemp)"; err="$(mktemp)"
  gh api --hostname "$HOST" --method GET \
    -H "Accept: application/vnd.github.raw+json" -H "X-GitHub-Api-Version: ${API_VERSION}" \
    "$ep" >"$tmp" 2>"$err"; rc=$?
  CALLS=$((CALLS + 1))
  if (( rc == 0 )); then
    LAST_STATUS=200; mv "$tmp" "$out"
  else
    handle_error "$err" "$ep"; rm -f "$tmp"
  fi
  record "$LAST_STATUS" "$cat" "$ep" "$out"
  rm -f "$err"
  [[ "$LAST_STATUS" == 2* ]]
}

# gql <category> <name> <outfile> <query> [paginate 0|1]
gql() {
  local cat="$1" name="$2" out="$3" q="$4" pag="${5:-0}"
  if grep -qiE '(^|[^A-Za-z_])mutation([^A-Za-z_]|$)' <<<"$q"; then die "Internal error: GraphQL mutation blocked"; fi
  if (( RESUME )) && [[ -s "$out" ]]; then LAST_STATUS="cached"; return 0; fi
  mkdir -p "$(dirname "$out")"
  rate_guard
  local -a args=(api graphql --hostname "$HOST" -f "query=${q}" -f "slug=${ENTERPRISE}")
  (( pag )) && args+=(--paginate --slurp)
  local tmp err rc
  tmp="$(mktemp)"; err="$(mktemp)"
  gh "${args[@]}" >"$tmp" 2>"$err"; rc=$?
  CALLS=$((CALLS + 1))
  if (( rc == 0 )) && jq . "$tmp" > "$out" 2>/dev/null; then
    LAST_STATUS=200
    if jq -e 'if type=="array" then any(.[]; has("errors")) else has("errors") end' "$out" >/dev/null 2>&1; then
      LAST_STATUS="GQLERR"
      printf '%s\t%s\t%s\n' "GQLERR" "graphql:${name}" "$(jq -c '[.. | objects | select(has("errors")) | .errors[]?.message]' "$out" | head -c 400)" >> "$ERRLOG"
    fi
  elif grep -qE 'HTTP [0-9]{3}' "$err"; then
    handle_error "$err" "graphql:${name}"
    rm -f "$out"
  else
    LAST_STATUS="GQLERR"
    printf '%s\t%s\t%s\n' "GQLERR" "graphql:${name}" "$(head -c 400 "$err" | tr '\n\r' '  ')" >> "$ERRLOG"
    rm -f "$out"
  fi
  record "$LAST_STATUS" "$cat" "graphql:${name}" "$out"
  rm -f "$tmp" "$err"
  [[ "$LAST_STATUS" == 2* ]]
}

# Post-processing filters
REDACT_VARS='walk(if type=="object" and has("name") and has("value") and (.value|type)=="string" then .value = "<redacted: \(.value|length) chars>" else . end)'
STRIP_SECRETS='walk(if type=="object" then del(.secret) else . end)'
var_filter() { (( KEEP_VAR_VALUES )) && printf '' || printf '%s' "$REDACT_VARS"; }

# ---------------------------------------------------------------------------
# Identity, scopes and manifest
# ---------------------------------------------------------------------------
whoami_and_scopes() {
  local hdr err
  hdr="$(mktemp)"; err="$(mktemp)"
  if ! gh api --hostname "$HOST" --method GET -i /user >"$hdr" 2>"$err"; then
    cat "$err" >&2
    rm -f "$hdr" "$err"
    die "Could not authenticate to ${HOST}. Check token, network and IP allow list"
  fi
  SCOPES="$(grep -i '^x-oauth-scopes:' "$hdr" | head -n1 | cut -d: -f2- | tr -d ' \r')"
  TOKEN_EXPIRY="$(grep -i '^github-authentication-token-expiration:' "$hdr" | head -n1 | cut -d: -f2- | sed 's/^ *//' | tr -d '\r')"
  rm -f "$hdr" "$err"
  api_get meta "/user" "$OUT/meta/user.json" || die "Could not fetch /user"
  LOGIN="$(jq -r '.login // empty' "$OUT/meta/user.json")"
  log "Authenticated as ${LOGIN} on ${HOST}"
  if [[ -n "$TOKEN_EXPIRY" ]]; then log "Token expires: ${TOKEN_EXPIRY}"; else warn "Token has no expiry date. Use a short lifetime"; fi
}

has_scope() { # scope -> 0 if covered (directly or by a parent scope)
  local have=",${SCOPES},"
  case "$1" in
    read:org)        [[ $have == *",read:org,"* || $have == *",write:org,"* || $have == *",admin:org,"* ]] ;;
    read:enterprise) [[ $have == *",read:enterprise,"* || $have == *",admin:enterprise,"* || $have == *",manage_billing:enterprise,"* ]] ;;
    read:repo_hook)  [[ $have == *",read:repo_hook,"* || $have == *",write:repo_hook,"* || $have == *",admin:repo_hook,"* ]] ;;
    *)               [[ $have == *",$1,"* ]] ;;
  esac
}

check_scopes() {
  if [[ -z "$SCOPES" ]]; then
    warn "No X-OAuth-Scopes header found. Is this a classic PAT? Many calls may fail"
    return
  fi
  log "Token scopes: ${SCOPES}"
  local s
  for s in repo read:org read:enterprise read:audit_log read:repo_hook; do
    has_scope "$s" || warn "Missing scope '${s}'. Related data will not be collected"
  done
  has_scope admin:org || log "Optional scope 'admin:org' missing. Org Actions settings, runner groups, secret names and code security are skipped"
  has_scope admin:org_hook || log "Optional scope 'admin:org_hook' missing. Org webhooks are skipped"
  local IFS=','
  for s in $SCOPES; do
    case "$s" in
      repo|read:org|read:enterprise|read:audit_log|read:repo_hook|admin:org|admin:org_hook) ;;
      *) warn "Unnecessary scope '${s}'. Consider a new token without it" ;;
    esac
  done
}

write_manifest() { # start|end
  local f="$OUT/meta/run.json" script_sha
  script_sha="$("${SHA_CMD[@]}" "$0" 2>/dev/null | cut -d' ' -f1)"
  if [[ "$1" == "start" ]]; then
    jq -n --arg v "$SCRIPT_VERSION" --arg sha "$script_sha" --arg host "$HOST" --arg ent "$ENTERPRISE" \
      --arg login "$LOGIN" --arg scopes "$SCOPES" --arg exp "$TOKEN_EXPIRY" --arg started "$STARTED" \
      --arg gh "$GH_VER" --arg orgs "$ORGS_ARG" --argjson audit_days "$AUDIT_DAYS" \
      --argjson resume "$RESUME" --argjson alerts "$COLLECT_ALERTS" --argjson keep_vars "$KEEP_VAR_VALUES" \
      '{script_version:$v, script_sha256:$sha, host:$host, enterprise:$ent, user:$login,
        token_scopes:($scopes|split(",")), token_expiry:$exp, gh_version:$gh,
        params:{orgs:$orgs, audit_days:$audit_days, resume:($resume==1), alerts:($alerts==1), keep_variable_values:($keep_vars==1)},
        started:$started, finished:null, api_calls:null}' > "$f"
  else
    local tmp; tmp="$(mktemp)"
    jq --arg fin "$(date -u +%FT%TZ)" --argjson calls "$CALLS" '.finished=$fin | .api_calls=$calls' "$f" > "$tmp" && mv "$tmp" "$f"
  fi
}

# ---------------------------------------------------------------------------
# Enterprise
# ---------------------------------------------------------------------------
collect_enterprise() {
  local E="$OUT/enterprise" ent="$ENTERPRISE"
  log "Enterprise: ${ent}"

  gql enterprise basics "$E/graphql-basics.json" \
    'query($slug:String!){ enterprise(slug:$slug){ id databaseId slug name url createdAt viewerIsAdmin members(first:1){ totalCount } } }'
  gql enterprise organizations "$E/graphql-organizations.json" \
    'query($slug:String!,$endCursor:String){ enterprise(slug:$slug){ organizations(first:100, after:$endCursor){ pageInfo{ hasNextPage endCursor } nodes{ login name databaseId createdAt } } } }' 1
  gql enterprise admins "$E/graphql-admins.json" \
    'query($slug:String!,$endCursor:String){ enterprise(slug:$slug){ ownerInfo{ admins(first:100, after:$endCursor){ pageInfo{ hasNextPage endCursor } edges{ role node{ login name } } } } } }' 1
  gql enterprise policies "$E/graphql-policies.json" \
    'query($slug:String!){ enterprise(slug:$slug){ ownerInfo{ defaultRepositoryPermissionSetting membersCanCreateRepositoriesSetting membersCanChangeRepositoryVisibilitySetting membersCanDeleteRepositoriesSetting membersCanInviteCollaboratorsSetting allowPrivateRepositoryForkingSetting membersCanUpdateProtectedBranchesSetting twoFactorRequiredSetting } } }'
  gql enterprise:optional policies-extra "$E/graphql-policies-extra.json" \
    'query($slug:String!){ enterprise(slug:$slug){ ownerInfo{ membersCanDeleteIssuesSetting membersCanMakePurchasesSetting membersCanViewDependencyInsightsSetting organizationProjectsSetting repositoryProjectsSetting teamDiscussionsSetting notificationDeliveryRestrictionEnabledSetting } } }'
  gql enterprise ip-allow-list "$E/graphql-ip-allow-list.json" \
    'query($slug:String!,$endCursor:String){ enterprise(slug:$slug){ ownerInfo{ ipAllowListEnabledSetting ipAllowListForInstalledAppsEnabledSetting ipAllowListEntries(first:100, after:$endCursor){ pageInfo{ hasNextPage endCursor } nodes{ allowListValue name isActive createdAt updatedAt } } } } }' 1
  gql enterprise identity-provider "$E/graphql-identity-provider.json" \
    'query($slug:String!){ enterprise(slug:$slug){ ownerInfo{ oidcProvider{ id providerType tenantId } samlIdentityProvider{ id issuer ssoUrl } } } }'
  gql enterprise:optional counts "$E/graphql-counts.json" \
    'query($slug:String!){ enterprise(slug:$slug){ ownerInfo{ outsideCollaborators(first:1){ totalCount } pendingAdminInvitations(first:1){ totalCount } pendingMemberInvitations(first:1){ totalCount } } } }'
  gql enterprise:optional domains "$E/graphql-domains.json" \
    'query($slug:String!){ enterprise(slug:$slug){ ownerInfo{ domains(first:100){ nodes{ domain isVerified isApproved } } } } }'

  local b="/enterprises/${ent}"
  api_get enterprise          "$b/actions/permissions"                          "$E/actions-permissions.json"
  api_get enterprise:optional "$b/actions/permissions/selected-actions"         "$E/actions-selected-actions.json"
  api_get enterprise          "$b/actions/permissions/workflow"                 "$E/actions-workflow-permissions.json"
  api_get enterprise:optional "$b/actions/permissions/fork-pr-contributor-approval" "$E/actions-fork-pr-approval.json"
  api_get enterprise:optional "$b/actions/permissions/self-hosted-runners"      "$E/actions-self-hosted-runners-policy.json"
  api_get enterprise          "$b/actions/runner-groups?per_page=100"           "$E/actions-runner-groups.json" 1
  api_get enterprise          "$b/actions/runners?per_page=100"                 "$E/actions-runners.json" 1
  api_get enterprise          "$b/code-security/configurations?per_page=100"    "$E/code-security-configurations.json" 1
  api_get enterprise:optional "$b/code-security/configurations/defaults"         "$E/code-security-defaults.json"
  api_get enterprise:optional "$b/properties/schema"                            "$E/custom-properties-schema.json"
  api_get enterprise:optional "$b/audit-log/streams"                            "$E/audit-log-streams.json"
  api_get enterprise:optional "$b/consumed-licenses?per_page=100"               "$E/consumed-licenses.json" 1
  api_get enterprise:optional "$b/copilot/billing/seats?per_page=100"           "$E/copilot-seats.json" 1
  api_get enterprise:optional "$b/teams?per_page=100"                           "$E/enterprise-teams.json" 1

  # Runner groups restricted to selected organizations
  if [[ -s "$E/actions-runner-groups.json" ]]; then
    local id
    while read -r id; do
      [[ -n "$id" ]] || continue
      api_get enterprise:optional "$b/actions/runner-groups/${id}/organizations?per_page=100" "$E/runner-groups/${id}-organizations.json" 1
    done < <(jq -r '.[]?.runner_groups[]? | select(.visibility=="selected") | .id' "$E/actions-runner-groups.json")
  fi
}

# Audit log is streamed to NDJSON (one event per line)
collect_audit_stream() { # name include days
  local name="$1" include="$2" days="$3" since out part err rc
  since="$(date -u -d "-${days} days" +%F 2>/dev/null || date -u -v-"${days}"d +%F)"
  out="$OUT/enterprise/audit-log-${name}.ndjson"
  part="${out}.partial"
  if (( RESUME )) && [[ -s "$out" ]]; then return 0; fi
  local ep="/enterprises/${ENTERPRISE}/audit-log?phrase=created%3A%3E%3D${since}&include=${include}&order=asc&per_page=100"
  log "Audit log (${name}) since ${since}. This may take a while"
  err="$(mktemp)"
  gh api --hostname "$HOST" --method GET -H "X-GitHub-Api-Version: ${API_VERSION}" \
    --paginate --jq '.[] | tojson' "$ep" >"$part" 2>"$err"; rc=$?
  CALLS=$((CALLS + 1))
  if (( rc == 0 )); then
    mv "$part" "$out"; LAST_STATUS=200
    log "Audit log (${name}): $(wc -l < "$out" | tr -d ' ') events"
  else
    handle_error "$err" "$ep"
    warn "Audit log (${name}) failed (${LAST_STATUS}). Partial data is in $(basename "$part"). Consider exporting from the SIEM or UI"
    out="$part"
  fi
  record "$LAST_STATUS" enterprise "$ep" "$out"
  rm -f "$err"
}

collect_audit_log() {
  collect_audit_stream web web "$AUDIT_DAYS"
  (( COLLECT_GIT_EVENTS )) && collect_audit_stream git git "$GIT_EVENT_DAYS"
}

# ---------------------------------------------------------------------------
# Organization
# ---------------------------------------------------------------------------
collect_org() {
  local org="$1" O="$OUT/orgs/$1" b="/orgs/$1" id slug
  log "Org: ${org}"

  if ! api_get org "$b" "$O/org.json"; then
    warn "Could not fetch org ${org} (${LAST_STATUS}). Skipping"
    return 0
  fi
  if [[ "$(jq -r 'has("default_repository_permission")' "$O/org.json")" != "true" ]]; then
    warn "Owner-only fields not visible in org ${org}. The token user is probably not an org owner. Expect many 403/404"
  fi

  # Members, roles and teams
  api_get org          "$b/members?role=admin&per_page=100"           "$O/owners.json" 1
  api_get org          "$b/members?per_page=100"                      "$O/members.json" 1
  api_get org          "$b/outside_collaborators?per_page=100"        "$O/outside-collaborators.json" 1
  api_get org:optional "$b/failed_invitations?per_page=100"           "$O/failed-invitations.json" 1
  if api_get org "$b/organization-roles" "$O/org-roles.json"; then
    while read -r id; do
      [[ -n "$id" ]] || continue
      api_get org:optional "$b/organization-roles/${id}/users?per_page=100" "$O/org-roles/${id}-users.json" 1
      api_get org:optional "$b/organization-roles/${id}/teams?per_page=100" "$O/org-roles/${id}-teams.json" 1
    done < <(jq -r '.roles[]?.id' "$O/org-roles.json")
  fi
  if api_get org "$b/teams?per_page=100" "$O/teams.json" 1; then
    while read -r slug; do
      [[ -n "$slug" ]] || continue
      api_get org          "$b/teams/${slug}/members?per_page=100"  "$O/teams/${slug}-members.json" 1
      api_get org:optional "$b/teams/${slug}/external-groups"       "$O/teams/${slug}-external-groups.json"
    done < <(jq -r '.[]?.slug' "$O/teams.json")
  fi
  api_get org:optional "$b/external-groups?per_page=100" "$O/external-groups.json"

  # Rulesets and custom properties
  if api_get org "$b/rulesets?per_page=100" "$O/rulesets.json" 1; then
    while read -r id; do
      [[ -n "$id" ]] || continue
      api_get org "$b/rulesets/${id}" "$O/rulesets/${id}.json"
    done < <(jq -r '.[]?.id' "$O/rulesets.json")
  fi
  api_get org:optional "$b/rulesets/rule-suites?time_period=month&rule_suite_result=bypass&per_page=100" "$O/rule-suites-bypass-30d.json" 1
  api_get org          "$b/properties/schema"                   "$O/custom-properties-schema.json"
  api_get org          "$b/properties/values?per_page=100"      "$O/custom-properties-values.json" 1

  # Apps and webhooks
  api_get org          "$b/installations?per_page=100"          "$O/app-installations.json" 1
  api_get org          "$b/hooks?per_page=100"                  "$O/webhooks.json" 1

  # Actions
  api_get org          "$b/actions/permissions"                  "$O/actions-permissions.json"
  api_get org:optional "$b/actions/permissions/selected-actions" "$O/actions-selected-actions.json"
  api_get org          "$b/actions/permissions/workflow"         "$O/actions-workflow-permissions.json"
  api_get org:optional "$b/actions/permissions/repositories?per_page=100" "$O/actions-enabled-repositories.json" 1
  api_get org:optional "$b/actions/permissions/fork-pr-contributor-approval" "$O/actions-fork-pr-approval.json"
  api_get org:optional "$b/actions/oidc/customization/sub"      "$O/actions-oidc-sub-claim.json"
  if api_get org "$b/actions/runner-groups?per_page=100" "$O/actions-runner-groups.json" 1; then
    while read -r id; do
      [[ -n "$id" ]] || continue
      api_get org:optional "$b/actions/runner-groups/${id}/repositories?per_page=100" "$O/runner-groups/${id}-repositories.json" 1
    done < <(jq -r '.[]?.runner_groups[]? | select(.visibility=="selected") | .id' "$O/actions-runner-groups.json")
  fi
  api_get org          "$b/actions/runners?per_page=100"         "$O/actions-runners.json" 1
  api_get org          "$b/actions/secrets?per_page=100"         "$O/actions-secrets.json" 1
  api_get org          "$b/actions/variables?per_page=30"        "$O/actions-variables.json" 1 "$(var_filter)"
  api_get org:optional "$b/dependabot/secrets?per_page=100"      "$O/dependabot-secrets.json" 1
  api_get org:optional "$b/private-registries"                   "$O/private-registries.json"
  api_get org:optional "$b/settings/network-configurations"      "$O/network-configurations.json"

  # Code security and Copilot
  api_get org          "$b/code-security/configurations?per_page=100" "$O/code-security-configurations.json" 1
  api_get org:optional "$b/code-security/configurations/defaults"     "$O/code-security-defaults.json"
  api_get org:optional "$b/copilot/billing"                           "$O/copilot-billing.json"
  api_get org:optional "$b/copilot/billing/seats?per_page=100"        "$O/copilot-seats.json" 1

  # Open security alerts
  if (( COLLECT_ALERTS )); then
    api_get org:optional "$b/secret-scanning/alerts?state=open&hide_secret=true&per_page=100" "$O/alerts-secret-scanning-open.json" 1 "$STRIP_SECRETS"
    api_get org:optional "$b/dependabot/alerts?state=open&per_page=100"    "$O/alerts-dependabot-open.json" 1
    api_get org:optional "$b/code-scanning/alerts?state=open&per_page=100" "$O/alerts-code-scanning-open.json" 1
  fi

  # Repositories
  if ! api_get org "$b/repos?type=all&per_page=100" "$O/repos.json" 1; then
    warn "Could not list repositories in ${org}"
    return 0
  fi
  local total n=0 name archived branch
  total="$(jq 'length' "$O/repos.json")"
  log "Org ${org}: ${total} repositories"
  while IFS=$'\t' read -r name archived branch; do
    [[ -n "$name" ]] || continue
    if (( SKIP_ARCHIVED )) && [[ "$archived" == "true" ]]; then continue; fi
    n=$((n + 1))
    if (( REPO_LIMIT > 0 && n > REPO_LIMIT )); then log "Reached --repo-limit ${REPO_LIMIT} in ${org}"; break; fi
    log "  [${n}/${total}] ${org}/${name}"
    collect_repo "$org" "$name" "$branch" "$archived"
  done < <(jq -r '.[] | [.name, (.archived|tostring), (.default_branch // "")] | @tsv' "$O/repos.json")
}

# ---------------------------------------------------------------------------
# Repository
# ---------------------------------------------------------------------------
collect_repo() {
  local org="$1" repo="$2" branch="$3" archived="$4"
  local R="$OUT/orgs/${org}/repos/${repo}" b="/repos/${org}/${repo}" eb="" id src env envu envs f

  api_get repo "$b"                                      "$R/repo.json"
  api_get repo "$b/collaborators?affiliation=direct&per_page=100" "$R/collaborators-direct.json" 1
  api_get repo "$b/teams?per_page=100"                   "$R/teams.json" 1
  api_get repo "$b/properties/values"                    "$R/custom-properties.json"
  [[ "$archived" == "true" ]] && return 0

  # Rulesets (including inherited) and effective rules on the default branch
  if api_get repo "$b/rulesets?includes_parents=true&per_page=100" "$R/rulesets.json" 1; then
    while IFS=$'\t' read -r id src; do
      [[ -n "$id" ]] || continue
      case "$src" in
        Repository) api_get repo "$b/rulesets/${id}" "$R/rulesets/${id}.json" ;;
        Enterprise) [[ -s "$OUT/enterprise/rulesets/${id}.json" ]] || api_get enterprise "$b/rulesets/${id}" "$OUT/enterprise/rulesets/${id}.json" ;;
        *) ;; # Organization: collected at org level
      esac
    done < <(jq -r '.[]? | [(.id|tostring), (.source_type // "")] | @tsv' "$R/rulesets.json")
  fi
  if [[ -n "$branch" ]]; then
    eb="$(uri "$branch")"
    api_get repo          "$b/rules/branches/${eb}?per_page=100" "$R/effective-rules-default-branch.json" 1
    api_get repo:optional "$b/branches/${eb}/protection"         "$R/branch-protection-default-branch.json"
  fi

  # Access into the repository
  api_get repo:optional "$b/hooks?per_page=100"     "$R/webhooks.json" 1
  api_get repo          "$b/keys?per_page=100"      "$R/deploy-keys.json" 1

  # Environments
  if api_get repo "$b/environments?per_page=100" "$R/environments.json" 1; then
    while read -r env; do
      [[ -n "$env" ]] || continue
      envu="$(uri "$env")"; envs="$(safe "$env")"
      api_get repo:optional "$b/environments/${envu}/deployment-branch-policies?per_page=100" "$R/environments/${envs}-branch-policies.json" 1
      api_get repo:optional "$b/environments/${envu}/secrets?per_page=100"   "$R/environments/${envs}-secrets.json" 1
      api_get repo:optional "$b/environments/${envu}/variables?per_page=30"  "$R/environments/${envs}-variables.json" 1 "$(var_filter)"
    done < <(jq -r '.[]?.environments[]?.name' "$R/environments.json")
  fi

  # Actions
  api_get repo          "$b/actions/permissions"            "$R/actions-permissions.json"
  api_get repo:optional "$b/actions/permissions/workflow"   "$R/actions-workflow-permissions.json"
  api_get repo:optional "$b/actions/permissions/access"     "$R/actions-access.json"
  api_get repo          "$b/actions/secrets?per_page=100"   "$R/actions-secrets.json" 1
  api_get repo          "$b/actions/variables?per_page=30"  "$R/actions-variables.json" 1 "$(var_filter)"
  api_get repo:optional "$b/actions/runners?per_page=100"   "$R/actions-runners.json" 1

  # Code security. vulnerability-alerts: 204 = enabled, 404 = disabled
  api_get repo:optional "$b/code-security-configuration"    "$R/code-security-configuration.json"
  api_get repo:optional "$b/vulnerability-alerts"           "$R/dependabot-alerts-enabled.json" \
    || printf '{"_http_status":%s}\n' "\"${LAST_STATUS}\"" > "$R/dependabot-alerts-enabled.json"
  api_get repo:optional "$b/automated-security-fixes"       "$R/dependabot-security-updates.json"

  # Files: workflows, CODEOWNERS, dependabot.yml
  [[ -n "$branch" ]] || return 0
  local ref="?ref=${eb}"
  if (( COLLECT_WORKFLOWS )); then
    if api_get repo:optional "$b/contents/.github/workflows${ref}" "$R/workflows-list.json"; then
      while read -r f; do
        [[ -n "$f" && "$f" != */* && "$f" != ".." ]] || continue
        api_raw repo "$b/contents/.github/workflows/$(uri "$f")${ref}" "$OUT/workflows/${org}/${repo}/${f}"
      done < <(jq -r 'if type=="array" then .[] | select(.type=="file") | .name | select(test("\\.ya?ml$")) else empty end' "$R/workflows-list.json")
    fi
  fi
  for f in .github/CODEOWNERS CODEOWNERS docs/CODEOWNERS; do
    api_raw repo:optional "$b/contents/${f}${ref}" "$R/CODEOWNERS" && break
  done
  api_get repo:optional "$b/codeowners/errors${ref}" "$R/codeowners-errors.json"
  api_raw repo:optional "$b/contents/.github/dependabot.yml${ref}" "$R/dependabot.yml" \
    || api_raw repo:optional "$b/contents/.github/dependabot.yaml${ref}" "$R/dependabot.yml"
}

# ---------------------------------------------------------------------------
# Summary and packaging
# ---------------------------------------------------------------------------
write_summary() {
  local S="$OUT/summary.txt" org
  {
    echo "ghe-collect ${SCRIPT_VERSION}"
    echo "Host:        ${HOST}"
    echo "Enterprise:  ${ENTERPRISE}"
    echo "User:        ${LOGIN}"
    echo "Scopes:      ${SCOPES}"
    echo "Started:     ${STARTED}"
    echo "Finished:    $(date -u +%FT%TZ)"
    echo "API calls:   ${CALLS} (this run)"
    echo
    echo "Status for all calls:"
    awk -F'\t' 'NR>1 {c[$2]++} END {for (k in c) printf "  %-8s %d\n", k, c[k]}' "$INDEX" | sort
    echo
    echo "Failures on non-optional calls (grouped by endpoint):"
    awk -F'\t' 'NR>1 && $2 !~ /^(2|cached)/ && $3 !~ /:optional$/ {
        ep=$4; sub(/\?.*/, "", ep)
        gsub(/\/contents\/.*/, "/contents/{path}", ep)
        gsub(/\/repos\/[^\/]+\/[^\/]+/, "/repos/{owner}/{repo}", ep)
        gsub(/\/orgs\/[^\/]+/, "/orgs/{org}", ep)
        gsub(/\/teams\/[^\/]+/, "/teams/{team}", ep)
        gsub(/\/environments\/[^\/]+/, "/environments/{env}", ep)
        gsub(/\/branches\/[^\/]+/, "/branches/{branch}", ep)
        gsub(/\/[0-9]+/, "/{id}", ep)
        c[$2 "  " ep]++
      } END {for (k in c) printf "  %4d x %s\n", c[k], k}' "$INDEX" | sort -k3
    echo
    echo "Organizations:"
    for org in ${ORGS[@]+"${ORGS[@]}"}; do
      local repos="-" owner="no"
      [[ -s "$OUT/orgs/${org}/repos.json" ]] && repos="$(jq 'length' "$OUT/orgs/${org}/repos.json")"
      [[ -s "$OUT/orgs/${org}/org.json" ]] && [[ "$(jq -r 'has("default_repository_permission")' "$OUT/orgs/${org}/org.json")" == "true" ]] && owner="yes"
      printf '  %-30s repos: %-6s owner-view: %s\n' "$org" "$repos" "$owner"
    done
    echo
    echo "403/404 on individual calls is often expected (feature not in use, missing scope or role)."
    echo "See errors.log for details and index.tsv for every call."
  } > "$S"
  cat "$S" >&2
}

package() {
  (( NO_ARCHIVE )) && return 0
  local parent base
  parent="$(cd "$(dirname "$OUT")" && pwd)"; base="$(basename "$OUT")"
  log "Packaging ${base}.tar.gz"
  tar -czf "${parent}/${base}.tar.gz" -C "$parent" "$base" 2>/dev/null || { warn "Packaging failed"; return 0; }
  ( cd "$parent" && "${SHA_CMD[@]}" "${base}.tar.gz" > "${base}.tar.gz.sha256" )
  log "Done: ${parent}/${base}.tar.gz"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
log "ghe-collect ${SCRIPT_VERSION} against ${HOST} (enterprise ${ENTERPRISE}). Read-only"
log "Output: ${OUT}"

whoami_and_scopes
check_scopes
write_manifest start

collect_enterprise
(( COLLECT_AUDIT )) && collect_audit_log

ORGS=()
if [[ -n "$ORGS_ARG" ]]; then
  IFS=',' read -r -a ORGS <<<"$ORGS_ARG"
elif [[ -s "$OUT/enterprise/graphql-organizations.json" ]]; then
  while IFS= read -r o; do
    [[ -n "$o" ]] && ORGS+=("$o")
  done < <(jq -r '.[]?.data.enterprise.organizations.nodes[]?.login // empty' "$OUT/enterprise/graphql-organizations.json")
fi
(( ${#ORGS[@]} > 0 )) || warn "No organizations found. Pass them with --orgs"
log "Organizations: ${ORGS[*]:-none}"

for o in ${ORGS[@]+"${ORGS[@]}"}; do
  collect_org "$o"
done

write_manifest end
write_summary
package
log "Remember: revoke the token now, and store the output only in the engagement folder"
