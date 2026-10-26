#!/usr/bin/env bash
#
# Runs ghe-collect.sh against tests/fake-gh and checks the important guarantees.
#
# Usage: bash tests/run-tests.sh
#        TEST_BASH=/path/to/bash-3.2 bash tests/run-tests.sh   # test with another bash
#
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/ghe-collect.sh"
TEST_BASH="${TEST_BASH:-bash}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$WORK/bin"
cp "$ROOT/tests/fake-gh" "$WORK/bin/gh"
chmod +x "$WORK/bin/gh"
export PATH="$WORK/bin:$PATH"
export FAKE_GH_LOG="$WORK/calls.log"
export GH_TOKEN="ghp_testtoken"

PASS=0; FAIL=0
ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); printf '  FAIL  %s\n' "$1"; }
check() { local desc="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$desc"; else fail "$desc"; fi; }

run() { "$TEST_BASH" "$SCRIPT" --host test.ghe.com --enterprise test "$@" >"$WORK/last.log" 2>&1; }

echo "Using: $("$TEST_BASH" --version | head -n1)"

echo "Full run"
rm -f "$FAKE_GH_LOG"
run --out "$WORK/out"
O="$WORK/out"
check "exits and writes summary"           test -s "$O/summary.txt"
check "creates archive and checksum"       test -s "$WORK/out.tar.gz.sha256"
check "only GET for REST calls"            python3 -c "
import json,sys
for l in open('$FAKE_GH_LOG'):
    a=json.loads(l)
    if a[:1]==['api'] and a[1]!='graphql' and 'rate_limit' not in a:
        if not ('--method' in a and a[a.index('--method')+1]=='GET'): sys.exit(1)"
check "no GraphQL mutations"               bash -c "! grep -qi 'mutation' '$FAKE_GH_LOG'"
check "variable values redacted"           bash -c "grep -q '<redacted: 11 chars>' '$O/orgs/test-org/actions-variables.json' && ! grep -rq supersecret '$O'"
check "secret scanning value stripped"     bash -c "! grep -rq AKIAFAKE '$O'"
check "token never written to output"      bash -c "! grep -rq ghp_testtoken '$O' '$WORK/out.tar.gz'"
check "workflow yaml downloaded"           test -s "$O/workflows/test-org/app1/ci.yml"
check "non-yaml workflow entry skipped"    test ! -e "$O/workflows/test-org/app1/README.md"
check "enterprise ruleset fetched via repo" test -s "$O/enterprise/rulesets/20.json"
check "repo ruleset fetched"               test -s "$O/orgs/test-org/repos/app1/rulesets/30.json"
check "environment name sanitized"         test -s "$O/orgs/test-org/repos/app1/environments/prod_env_1-secrets.json"
check "CODEOWNERS found in fallback path"  test -s "$O/orgs/test-org/repos/app1/CODEOWNERS"
check "dependabot disabled recorded"       grep -q '"404"' "$O/orgs/test-org/repos/app1/dependabot-alerts-enabled.json"
check "204 recorded"                       grep -q 204 "$O/orgs/test-org/repos/app1/code-security-configuration.json"
check "archived repo: no rulesets"         test ! -e "$O/orgs/test-org/repos/old/rulesets.json"
check "audit log as NDJSON"                test "$(wc -l < "$O/enterprise/audit-log-web.ndjson" | tr -d ' ')" = 2
check "GraphQL error logged as GQLERR"     grep -q '^GQLERR' "$O/errors.log"
check "admin:enterprise calls skipped"     bash -c "grep -q 'SKIP	enterprise	/enterprises/test/actions/permissions	' '$O/index.tsv' && ! grep -q 'enterprises/test/actions/permissions\"' '$FAKE_GH_LOG'"
check "skipped calls not listed as failures" bash -c "! grep -q '/enterprises/test/actions' '$O/summary.txt'"
check "manifest has version and scopes"    bash -c "jq -e '.script_version and (.token_scopes|length>0) and .finished' '$O/meta/run.json'"
check "unnecessary scope warned"           grep -q "Unnecessary scope 'workflow'" "$WORK/last.log"

echo "Resume"
before="$(wc -l < "$FAKE_GH_LOG")"
run --out "$WORK/out" --resume --no-archive
after="$(wc -l < "$FAKE_GH_LOG")"
check "resume retries only failed calls"   test $((after - before)) -lt 15

echo "Options"
run --out "$WORK/out2" --orgs test-org --repo-limit 1 --no-audit-log --no-archive
check "--orgs and --repo-limit"            bash -c "grep -q 'Reached --repo-limit 1' '$WORK/last.log' && test ! -e '$WORK/out2/enterprise/audit-log-web.ndjson'"
FAKE_GH_SCOPES="repo, read:org, read:enterprise, read:audit_log, read:repo_hook, admin:enterprise" \
  run --out "$WORK/out4" --orgs test-org --repo-limit 1 --no-audit-log --no-archive
check "admin:enterprise calls made when granted" grep -q '403  /enterprises/test/actions/permissions' "$WORK/out4/summary.txt"
FAKE_GH_CLASSIC_BLOCK=1 run --out "$WORK/out5" --no-audit-log --no-archive
check "classic PAT block explained"        bash -c "grep -q 'Org test-org blocks classic PATs' '$WORK/last.log' && grep -A1 'ACTION NEEDED' '$WORK/out5/summary.txt' | grep -q test-org"
FAKE_GH_CLASSIC_BLOCK=1 run --out "$WORK/out6" --orgs test-org --no-audit-log --no-archive
check "blocked org skipped with fix"       bash -c "grep -q 'blocks classic PATs. Skipping. Ask an org owner' '$WORK/last.log' && test \$(grep -c 'blocks classic PATs. Adding scopes' '$WORK/last.log') = 1"
FAKE_GH_NO_ORGS=1 run --out "$WORK/out3" --no-audit-log --no-archive
check "no organizations does not crash"    bash -c "grep -q 'No organizations found' '$WORK/last.log' && test -s '$WORK/out3/summary.txt'"

echo "OAuth token"
GH_TOKEN="gho_testtoken" FAKE_GH_SCOPES="repo, read:org, gist, read:enterprise, read:audit_log, read:repo_hook" \
  run --out "$WORK/out7" --orgs test-org --repo-limit 1 --no-audit-log --no-archive
check "OAuth token accepted without warning" bash -c "! grep -q 'does not look like' '$WORK/last.log'"
check "gist scope allowed for OAuth"       bash -c "! grep -q \"Unnecessary scope 'gist'\" '$WORK/last.log'"
check "OAuth revoke reminder"              grep -q "gh auth logout --hostname test.ghe.com" "$WORK/last.log"
check "manifest records token type"        bash -c "jq -e '.token_type==\"oauth\"' '$WORK/out7/meta/run.json'"
check "OAuth token never written to output" bash -c "! grep -rq gho_testtoken '$WORK/out7'"
check "gist still warned for classic PAT"  bash -c "FAKE_GH_SCOPES='repo, gist' GH_TOKEN=ghp_testtoken '$TEST_BASH' '$SCRIPT' --host test.ghe.com --enterprise test --orgs test-org --repo-limit 1 --no-audit-log --no-archive --out '$WORK/out8' 2>&1 | grep -q \"Unnecessary scope 'gist'\""

echo "Validation"
"$TEST_BASH" "$SCRIPT" --host github.com --enterprise test >"$WORK/v.log" 2>&1
check "rejects non-ghe.com host"           grep -q 'must look like SUBDOMAIN.ghe.com' "$WORK/v.log"
GH_TOKEN=github_pat_x "$TEST_BASH" "$SCRIPT" --host test.ghe.com --enterprise test --out "$WORK/v" >"$WORK/v.log" 2>&1
check "rejects fine-grained PAT"           grep -q 'Fine-grained PATs' "$WORK/v.log"
"$TEST_BASH" "$SCRIPT" --host test.ghe.com --enterprise >"$WORK/v.log" 2>&1
check "missing value is an error"          grep -q 'requires a value' "$WORK/v.log"
"$TEST_BASH" "$SCRIPT" --host test.ghe.com --enterprise test --audit-days 999 >"$WORK/v.log" 2>&1
check "audit-days range enforced"          grep -q 'audit-days must be 1-180' "$WORK/v.log"

echo
echo "Passed: ${PASS}  Failed: ${FAIL}"
(( FAIL == 0 ))
