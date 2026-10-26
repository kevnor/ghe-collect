#!/usr/bin/env python3
#
# ghe-audit.py
#
# Offline security assessment of ghe-collect output. Reads an extracted ghe-collect output
# directory, evaluates it against the rule catalog in audit/catalog.json and writes a report
# (HTML, Markdown, Word, JSON, CSV).
#
# The script never contacts GitHub or any other service. The report contains no external
# resources (no fonts, scripts or images are fetched when it is opened).
#
# Usage: python3 ghe-audit.py OUTDIR [options]
#        python3 ghe-audit.py --help
#
# Requires: Python 3.8+, standard library only
#
import argparse
import csv
import datetime as dt
import fnmatch
import html
import io
import json
import os
import re
import sys
import traceback
import zipfile
from xml.sax.saxutils import escape as _xml_escape

TOOL_VERSION = "0.1.0"
HERE = os.path.dirname(os.path.abspath(__file__))
CATALOG_PATH = os.path.join(HERE, "audit", "catalog.json")
CSS_PATH = os.path.join(HERE, "audit", "report.css")

SEVERITIES = ["critical", "high", "medium", "low", "info"]
# Rule and result statuses, most important first
STATUSES = ["fail", "review", "accepted", "pass", "info", "not_assessed"]
STATUS_LABEL = {
    "fail": "Fail", "review": "Review", "accepted": "Accepted risk", "pass": "Pass",
    "info": "Info", "not_assessed": "Not assessed",
}

# Enterprise files that need the admin:enterprise scope, which ghe-collect does not request
ADMIN_ENTERPRISE_FILES = {
    "enterprise/graphql-ip-allow-list.json", "enterprise/graphql-identity-provider.json",
    "enterprise/graphql-domains.json", "enterprise/actions-permissions.json",
    "enterprise/actions-selected-actions.json", "enterprise/actions-workflow-permissions.json",
    "enterprise/actions-fork-pr-approval.json", "enterprise/actions-self-hosted-runners-policy.json",
    "enterprise/actions-runner-groups.json", "enterprise/actions-runners.json",
    "enterprise/audit-log-streams.json",
}

REASONS = {
    "SKIP": "Not collected: needs the admin:enterprise scope, which is not requested by design",
    "403": "Access denied (403): missing scope or role, or blocked by policy",
    "404": "Not available (404): feature not in use, or missing scope or role",
    "GQLERR": "GraphQL error during collection (see errors.log)",
    "PARSE": "The collected response could not be parsed",
}


def die(msg):
    sys.stderr.write("ghe-audit: %s\n" % msg)
    sys.exit(1)


def warn(msg):
    sys.stderr.write("ghe-audit: WARNING: %s\n" % msg)


def parse_time(s):
    """ISO 8601 timestamp or epoch milliseconds -> aware datetime, or None."""
    if s is None or s == "":
        return None
    if isinstance(s, (int, float)):
        return dt.datetime.fromtimestamp(s / 1000.0, tz=dt.timezone.utc)
    try:
        return dt.datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------
class Missing(Exception):
    """Data needed by a check is not available. The message is the reason shown in the report."""


def resolve_root(path):
    """Accept the output directory itself, or a folder that contains exactly one output directory."""
    if os.path.isfile(os.path.join(path, "meta", "run.json")):
        return path
    if os.path.isdir(path):
        subs = [os.path.join(path, d) for d in sorted(os.listdir(path))
                if os.path.isfile(os.path.join(path, d, "meta", "run.json"))]
        if len(subs) == 1:
            return subs[0]
    die("'%s' is not a ghe-collect output directory (meta/run.json not found). Extract the .tar.gz first" % path)


class OutputDir:
    def __init__(self, path):
        self.root = resolve_root(path)
        self._cache = {}
        self.index = {}       # file -> last status
        self.endpoints = {}   # endpoint -> last status
        idx = os.path.join(self.root, "index.tsv")
        if os.path.isfile(idx):
            with open(idx, encoding="utf-8", errors="replace") as fh:
                for n, line in enumerate(fh):
                    parts = line.rstrip("\n").split("\t")
                    if n == 0 or len(parts) < 5:
                        continue
                    _, status, _, endpoint, rel = parts[:5]
                    self.endpoints[endpoint] = status
                    if rel:
                        self.index[rel] = status
        self.run = self.load("meta/run.json") or {}
        self.scopes = set(self.run.get("token_scopes") or [])

    def path(self, rel):
        return os.path.join(self.root, rel)

    def exists(self, rel):
        return os.path.isfile(self.path(rel))

    def load(self, rel):
        """Parsed JSON, or None if the file is missing or unreadable."""
        if rel not in self._cache:
            data = None
            try:
                with open(self.path(rel), encoding="utf-8") as fh:
                    data = json.load(fh)
            except (OSError, ValueError):
                pass
            self._cache[rel] = data
        return self._cache[rel]

    def text(self, rel):
        try:
            with open(self.path(rel), encoding="utf-8", errors="replace") as fh:
                return fh.read()
        except OSError:
            return None

    def status(self, rel):
        return self.index.get(rel)

    def reason(self, rel):
        st = self.index.get(rel)
        if st is None and rel in ADMIN_ENTERPRISE_FILES and "admin:enterprise" not in self.scopes:
            st = "SKIP"
        if st is None:
            return "Not collected in this run (%s)" % rel
        if st == "cached" or st.startswith("2"):
            return "Collected file is missing or unreadable (%s)" % rel
        return "%s (%s)" % (REASONS.get(st, "Collection failed with status %s" % st), rel)

    def get(self, rel):
        data = self.load(rel)
        if data is None:
            raise Missing(self.reason(rel))
        return data

    def items(self, rel, key=None):
        """List of items from a REST file, whatever the pagination shape.

        Paginated list endpoints are stored as one flat list. Paginated wrapped endpoints
        (e.g. {"runner_groups": [...]}) are stored as a list of page objects.
        """
        data = self.get(rel)
        if isinstance(data, dict):
            return list(data.get(key) or []) if key else [data]
        if key and data and all(isinstance(p, dict) and key in p for p in data):
            out = []
            for page in data:
                out.extend(page.get(key) or [])
            return out
        return list(data)

    def gql(self, rel, *path):
        """Value at path in a GraphQL response (first page). Raises Missing on errors or absence."""
        data = self.get(rel)
        pages = data if isinstance(data, list) else [data]
        for page in pages:
            v = page
            for p in path:
                v = v.get(p) if isinstance(v, dict) else None
            if v is not None:
                return v
        if any(isinstance(p, dict) and p.get("errors") for p in pages):
            raise Missing("%s (%s)" % (REASONS["GQLERR"], rel))
        raise Missing("Field %s not present (%s)" % (".".join(path), rel))

    def gql_list(self, rel, *path):
        """Concatenated lists at path across all GraphQL pages."""
        data = self.get(rel)
        pages = data if isinstance(data, list) else [data]
        out, found = [], False
        for page in pages:
            v = page
            for p in path:
                v = v.get(p) if isinstance(v, dict) else None
            if isinstance(v, list):
                found = True
                out.extend(v)
        if not found:
            if any(isinstance(p, dict) and p.get("errors") for p in pages):
                raise Missing("%s (%s)" % (REASONS["GQLERR"], rel))
            raise Missing("Field %s not present (%s)" % (".".join(path), rel))
        return out


# ---------------------------------------------------------------------------
# Targets and results
# ---------------------------------------------------------------------------
class Target:
    def __init__(self, kind, label, base, meta=None):
        self.kind, self.label, self.base, self.meta = kind, label, base, meta or {}

    def f(self, name):
        return "%s/%s" % (self.base, name)


class Result:
    def __init__(self, status, detail="", evidence=None, target=None):
        self.status, self.detail, self.evidence, self.target = status, detail, evidence, target
        self.waiver = None

    def to_dict(self):
        d = {"target": self.target, "status": self.status, "detail": self.detail}
        if self.evidence:
            d["evidence"] = self.evidence
        if self.waiver:
            d["waiver"] = self.waiver
        return d


def PASS(detail="", evidence=None, target=None):
    return Result("pass", detail, evidence, target)


def FAIL(detail="", evidence=None, target=None):
    return Result("fail", detail, evidence, target)


def REVIEW(detail="", evidence=None, target=None):
    return Result("review", detail, evidence, target)


def INFO(detail="", evidence=None, target=None):
    return Result("info", detail, evidence, target)


def NA(detail="", evidence=None, target=None):
    return Result("not_assessed", detail, evidence, target)


def ev(rel, field, value):
    return {"file": rel, "field": field, "value": value}


def per(targets, fn):
    """Run fn for each target. Missing data becomes a not_assessed result for that target."""
    out = []
    for t in targets:
        try:
            res = fn(t)
        except Missing as e:
            res = NA(str(e))
        if res is None:
            continue
        for r in (res if isinstance(res, list) else [res]):
            if r.target is None:
                r.target = t.label
            out.append(r)
    return out


def listing(values, limit=10):
    values = [str(v) for v in values]
    if len(values) <= limit:
        return ", ".join(values)
    return "%s and %d more" % (", ".join(values[:limit]), len(values) - limit)


# ---------------------------------------------------------------------------
# Audit context
# ---------------------------------------------------------------------------
class Audit:
    def __init__(self, d, zizmor=None):
        self.d = d
        self.zizmor = zizmor
        self.rule = None
        run = d.run
        self.collected = parse_time(run.get("started")) or dt.datetime.now(dt.timezone.utc)
        self.ent = Target("enterprise", run.get("enterprise") or "enterprise", "enterprise")
        self._orgs = None
        self._repos = {}

    def param(self, name, default=None):
        return (self.rule or {}).get("params", {}).get(name, default)

    def org_names_attempted(self):
        names = set()
        for ep in self.d.endpoints:
            m = re.match(r"^/orgs/([^/?]+)$", ep)
            if m:
                names.add(m.group(1))
        base = self.d.path("orgs")
        if os.path.isdir(base):
            names.update(n for n in os.listdir(base) if os.path.isdir(os.path.join(base, n)))
        return sorted(names)

    def orgs(self):
        """Organizations whose org.json was collected."""
        if self._orgs is None:
            self._orgs = [Target("org", n, "orgs/%s" % n) for n in self.org_names_attempted()
                          if self.d.exists("orgs/%s/org.json" % n)]
        return self._orgs

    def repos(self, org, include_archived=False):
        """Repositories in an org whose repo.json was collected."""
        if org.label not in self._repos:
            listed = self.d.load(org.f("repos.json")) or []
            repos = []
            for r in listed if isinstance(listed, list) else []:
                name = r.get("name")
                base = "%s/repos/%s" % (org.base, name)
                if name and self.d.exists(base + "/repo.json"):
                    repos.append(Target("repo", "%s/%s" % (org.label, name), base, r))
            self._repos[org.label] = repos
        return [r for r in self._repos[org.label] if include_archived or not r.meta.get("archived")]

    def all_repos(self):
        out = []
        for o in self.orgs():
            out.extend(self.repos(o))
        return out

    def ent_policy(self, field):
        return self.d.gql("enterprise/graphql-policies.json", "data", "enterprise", "ownerInfo", field)

    def audit_events(self):
        """(events, note). Uses the .partial file if the full download did not finish."""
        rel = "enterprise/audit-log-web.ndjson"
        note = ""
        if not self.d.exists(rel):
            if self.d.exists(rel + ".partial"):
                rel += ".partial"
                note = " (partial download: the audit log stopped part-way)"
            else:
                raise Missing(self.d.reason(rel))
        events = []
        with open(self.d.path(rel), encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        pass
        days = (self.d.run.get("params") or {}).get("audit_days")
        return events, ("%s days of audit log%s" % (days, note) if days else "audit log" + note)


# ---------------------------------------------------------------------------
# Checks. One function per rule ID; rule text lives in audit/catalog.json.
# ---------------------------------------------------------------------------
CHECKS = {}


def check(rule_id):
    def deco(fn):
        CHECKS[rule_id] = fn
        return fn
    return deco


POLICIES = "enterprise/graphql-policies.json"


# --- Identity and access ----------------------------------------------------
@check("IAM-01")
def iam_identity_provider(a):
    rel = "enterprise/graphql-identity-provider.json"

    def fn(t):
        info = a.d.gql(rel, "data", "enterprise", "ownerInfo")
        if info.get("oidcProvider"):
            p = info["oidcProvider"]
            return PASS("OIDC identity provider (%s)" % (p.get("providerType") or "OIDC"),
                        ev(rel, "oidcProvider.providerType", p.get("providerType")))
        if info.get("samlIdentityProvider"):
            return PASS("SAML identity provider", ev(rel, "samlIdentityProvider.issuer",
                                                     info["samlIdentityProvider"].get("issuer")))
        return FAIL("No identity provider configured", ev(rel, "oidcProvider/samlIdentityProvider", None))
    return per([a.ent], fn)


@check("IAM-02")
def iam_ip_allow_list(a):
    rel = "enterprise/graphql-ip-allow-list.json"

    def fn(t):
        v = a.d.gql(rel, "data", "enterprise", "ownerInfo", "ipAllowListEnabledSetting")
        if v == "ENABLED":
            n = len(a.d.gql_list(rel, "data", "enterprise", "ownerInfo", "ipAllowListEntries", "nodes"))
            return PASS("IP allow list enabled (%d entries)" % n, ev(rel, "ipAllowListEnabledSetting", v))
        return FAIL("IP allow list not enabled", ev(rel, "ipAllowListEnabledSetting", v))
    return per([a.ent], fn)


def _owner_count(a, target, logins, rel, field):
    lo, hi = a.param("min_owners", 2), a.param("max_owners", 5)
    e = ev(rel, field, len(logins))
    if len(logins) < lo:
        return FAIL("%d owner(s); fewer than %d is a single point of failure" % (len(logins), lo), e)
    if len(logins) > hi:
        return FAIL("%d owners (recommended at most %d): %s" % (len(logins), hi, listing(logins)), e)
    return PASS("%d owners" % len(logins), e)


@check("IAM-03")
def iam_enterprise_owners(a):
    rel = "enterprise/graphql-admins.json"

    def fn(t):
        edges = a.d.gql_list(rel, "data", "enterprise", "ownerInfo", "admins", "edges")
        owners = sorted((e.get("node") or {}).get("login", "?") for e in edges if e.get("role") == "OWNER")
        return _owner_count(a, t, owners, rel, "admins[role=OWNER]")
    return per([a.ent], fn)


@check("IAM-04")
def iam_org_owners(a):
    def fn(o):
        owners = sorted(m.get("login", "?") for m in a.d.items(o.f("owners.json")))
        return _owner_count(a, o, owners, o.f("owners.json"), "length")
    return per(a.orgs(), fn)


@check("IAM-05")
def iam_direct_admins(a):
    out = []
    for o in a.orgs():
        owners = {m.get("login") for m in (a.d.load(o.f("owners.json")) or []) if isinstance(m, dict)}

        def fn(r):
            rel = r.f("collaborators-direct.json")
            admins = sorted(c.get("login", "?") for c in a.d.items(rel)
                            if ((c.get("permissions") or {}).get("admin") or c.get("role_name") == "admin")
                            and c.get("login") not in owners)
            if admins:
                return FAIL("Direct admin access: %s" % listing(admins), ev(rel, "permissions.admin", admins))
            return PASS("No direct admin collaborators")
        out += per(a.repos(o), fn)
    return out


@check("IAM-06")
def iam_outside_collaborators(a):
    def ent(t):
        rel = "enterprise/graphql-counts.json"
        n = a.d.gql(rel, "data", "enterprise", "ownerInfo", "outsideCollaborators", "totalCount")
        if n:
            return REVIEW("%d outside collaborator(s) in the enterprise" % n, ev(rel, "outsideCollaborators.totalCount", n))
        return PASS("No outside collaborators", ev(rel, "outsideCollaborators.totalCount", n))

    def org(o):
        rel = o.f("outside-collaborators.json")
        users = sorted(u.get("login", "?") for u in a.d.items(rel))
        if users:
            return REVIEW("%d outside collaborator(s): %s" % (len(users), listing(users)), ev(rel, "login", users))
        return PASS("No outside collaborators")
    return per([a.ent], ent) + per(a.orgs(), org)


# --- Enterprise and organization policies ----------------------------------
@check("POL-01")
def pol_base_permission(a):
    def ent(t):
        v = a.ent_policy("defaultRepositoryPermissionSetting")
        e = ev(POLICIES, "defaultRepositoryPermissionSetting", v)
        if v in ("NONE", "READ"):
            return PASS("Enterprise enforces base permission '%s'" % v.lower(), e)
        if v == "NO_POLICY":
            return INFO("No enterprise policy; each organization sets its own base permission", e)
        return FAIL("Enterprise enforces base permission '%s'" % v.lower(), e)

    def org(o):
        rel = o.f("org.json")
        v = a.d.get(rel).get("default_repository_permission")
        if v is None:
            raise Missing("Owner-only field not visible; the token user is not an owner of %s" % o.label)
        e = ev(rel, "default_repository_permission", v)
        return PASS("Base permission '%s'" % v, e) if v in ("none", "read") else FAIL("Base permission '%s'" % v, e)
    return per([a.ent], ent) + per(a.orgs(), org)


def _ent_toggle(a, field, allowed_text, no_policy=REVIEW):
    """Enterprise ENABLED/DISABLED/NO_POLICY setting where ENABLED is the risky choice."""
    def fn(t):
        v = a.ent_policy(field)
        e = ev(POLICIES, field, v)
        if v == "DISABLED":
            return PASS("Enterprise policy: members cannot %s" % allowed_text, e)
        if v == "ENABLED":
            return FAIL("Enterprise policy: members can %s" % allowed_text, e)
        return no_policy("No enterprise policy; each organization decides whether members can %s" % allowed_text, e)
    return per([a.ent], fn)


@check("POL-02")
def pol_visibility_change(a):
    return _ent_toggle(a, "membersCanChangeRepositoryVisibilitySetting", "change repository visibility")


@check("POL-03")
def pol_repo_deletion(a):
    return _ent_toggle(a, "membersCanDeleteRepositoriesSetting", "delete or transfer repositories")


@check("POL-04")
def pol_private_forking(a):
    # Organization settings are collected, so a missing enterprise policy is only informational here
    out = _ent_toggle(a, "allowPrivateRepositoryForkingSetting", "fork private and internal repositories", INFO)

    def org(o):
        rel = o.f("org.json")
        v = a.d.get(rel).get("members_can_fork_private_repositories")
        if v is None:
            raise Missing("Owner-only field not visible; the token user is not an owner of %s" % o.label)
        e = ev(rel, "members_can_fork_private_repositories", v)
        return FAIL("Members can fork private repositories", e) if v else PASS("Forking of private repositories disabled", e)
    return out + per(a.orgs(), org)


@check("POL-05")
def pol_invite_collaborators(a):
    return _ent_toggle(a, "membersCanInviteCollaboratorsSetting", "invite outside collaborators")


# --- Branch and ruleset protection ------------------------------------------
def protection(a, r):
    """Combined protection of the default branch from rulesets and classic branch protection."""
    if not r.meta.get("default_branch"):
        raise Missing("Empty repository (no default branch)")
    rules_rel = r.f("effective-rules-default-branch.json")
    rules = a.d.items(rules_rel)
    p = {"pr": False, "approvals": 0, "stale": False, "last_push": False, "codeowners": False,
         "no_force": False, "no_delete": False, "checks": False, "enforce_admins": None,
         "sources": [], "classic_unknown": False}
    for rule in rules:
        t, prm = rule.get("type"), rule.get("parameters") or {}
        if t == "pull_request":
            p["pr"] = True
            p["approvals"] = max(p["approvals"], int(prm.get("required_approving_review_count") or 0))
            p["stale"] |= bool(prm.get("dismiss_stale_reviews_on_push"))
            p["last_push"] |= bool(prm.get("require_last_push_approval"))
            p["codeowners"] |= bool(prm.get("require_code_owner_review"))
        elif t == "non_fast_forward":
            p["no_force"] = True
        elif t == "deletion":
            p["no_delete"] = True
        elif t == "required_status_checks":
            p["checks"] = True
    if rules:
        p["sources"].append("rulesets")
    bp_rel = r.f("branch-protection-default-branch.json")
    bp = a.d.load(bp_rel)
    if isinstance(bp, dict) and "_http_status" not in bp:
        p["sources"].append("classic branch protection")
        rev = bp.get("required_pull_request_reviews")
        if rev:
            p["pr"] = True
            p["approvals"] = max(p["approvals"], int(rev.get("required_approving_review_count") or 0))
            p["stale"] |= bool(rev.get("dismiss_stale_reviews"))
            p["last_push"] |= bool(rev.get("require_last_push_approval"))
            p["codeowners"] |= bool(rev.get("require_code_owner_reviews"))
        if not (bp.get("allow_force_pushes") or {}).get("enabled", False):
            p["no_force"] = True
        if not (bp.get("allow_deletions") or {}).get("enabled", False):
            p["no_delete"] = True
        sc = bp.get("required_status_checks") or {}
        if sc.get("contexts") or sc.get("checks"):
            p["checks"] = True
        p["enforce_admins"] = bool((bp.get("enforce_admins") or {}).get("enabled"))
    elif a.d.status(bp_rel) not in (None, "404"):
        p["classic_unknown"] = True
    return p


def _protection_rule(a, test, ok_text, fail_text):
    def fn(r):
        p = protection(a, r)
        src = ", ".join(p["sources"]) or "no protection"
        if test(p):
            return PASS("%s (%s)" % (ok_text, src))
        if p["classic_unknown"]:
            raise Missing("Rulesets do not cover this, and classic branch protection could not be read (%s)"
                          % a.d.reason(r.f("branch-protection-default-branch.json")))
        return FAIL("%s (%s)" % (fail_text(p) if callable(fail_text) else fail_text, src),
                    ev(r.f("effective-rules-default-branch.json"), "default branch", r.meta.get("default_branch")))
    return per(a.all_repos(), fn)


@check("BRP-01")
def brp_pull_request(a):
    need = a.param("min_approvals", 1)

    def failed(p):
        if not p["pr"]:
            return "Default branch does not require a pull request"
        return "Pull request required with only %d approval(s)" % p["approvals"]
    return _protection_rule(a, lambda p: p["pr"] and p["approvals"] >= need,
                            "Pull request with at least %d approval(s) required" % need, failed)


@check("BRP-02")
def brp_force_push(a):
    return _protection_rule(a, lambda p: p["no_force"], "Force pushes blocked", "Force pushes allowed on default branch")


@check("BRP-03")
def brp_deletion(a):
    return _protection_rule(a, lambda p: p["no_delete"], "Deletion blocked", "Default branch can be deleted")


@check("BRP-04")
def brp_stale_reviews(a):
    return _protection_rule(a, lambda p: p["pr"] and (p["stale"] or p["last_push"]),
                            "Approvals are invalidated by new pushes",
                            "Approvals stay valid after new commits are pushed")


@check("BRP-05")
def brp_code_owners(a):
    def fn(r):
        p = protection(a, r)
        has_file = a.d.exists(r.f("CODEOWNERS"))
        if p["codeowners"] and has_file:
            return PASS("Code owner review required")
        if p["codeowners"]:
            return FAIL("Code owner review required, but no CODEOWNERS file on the default branch")
        if p["classic_unknown"]:
            raise Missing("Classic branch protection could not be read")
        return FAIL("Code owner review not required" + ("" if has_file else "; no CODEOWNERS file"))
    return per(a.all_repos(), fn)


@check("BRP-06")
def brp_status_checks(a):
    return _protection_rule(a, lambda p: p["checks"], "Status checks required", "No required status checks")


def _rulesets(a):
    """(label, rel, ruleset) for every collected ruleset file."""
    out = []
    pattern = re.compile(r"^(enterprise|orgs/([^/]+)|orgs/([^/]+)/repos/([^/]+))/rulesets/[^/]+\.json$")
    for dirpath, _, files in os.walk(a.d.root):
        for fn in sorted(files):
            rel = os.path.relpath(os.path.join(dirpath, fn), a.d.root).replace(os.sep, "/")
            m = pattern.match(rel)
            if not m:
                continue
            rs = a.d.load(rel)
            if not isinstance(rs, dict):
                continue
            owner = "enterprise" if m.group(1) == "enterprise" else (
                m.group(2) or "%s/%s" % (m.group(3), m.group(4)))
            out.append(("%s: ruleset '%s'" % (owner, rs.get("name", rs.get("id"))), rel, rs))
    return sorted(out, key=lambda x: x[0])


@check("BRP-07")
def brp_bypass_actors(a):
    out = []
    for label, rel, rs in _rulesets(a):
        if rs.get("enforcement") != "active":
            continue
        actors = rs.get("bypass_actors") or []
        always = ["%s %s" % (b.get("actor_type"), b.get("actor_id") if b.get("actor_id") is not None else "")
                  for b in actors if b.get("bypass_mode", "always") == "always"]
        if always:
            out.append(REVIEW("Can always bypass: %s" % listing([s.strip() for s in always]),
                              ev(rel, "bypass_actors", actors), target=label))
        else:
            out.append(PASS("No unconditional bypass actors", target=label))
    for r in a.all_repos():
        bp = a.d.load(r.f("branch-protection-default-branch.json"))
        if isinstance(bp, dict) and "_http_status" not in bp and not (bp.get("enforce_admins") or {}).get("enabled"):
            out.append(REVIEW("Classic branch protection does not apply to administrators",
                              ev(r.f("branch-protection-default-branch.json"), "enforce_admins.enabled", False),
                              target=r.label))
    if not out:
        out.append(INFO("No active rulesets or classic branch protection found", target=a.ent.label))
    return out


@check("BRP-08")
def brp_bypass_events(a):
    def fn(o):
        rel = o.f("rule-suites-bypass-30d.json")
        suites = a.d.items(rel)
        if not suites:
            return PASS("No rule bypasses in the last 30 days")
        by_repo = {}
        for s in suites:
            key = s.get("repository_name") or "?"
            by_repo.setdefault(key, set()).add(s.get("actor_name") or "?")
        parts = ["%s (%s)" % (k, ", ".join(sorted(v))) for k, v in sorted(by_repo.items())]
        return REVIEW("%d push(es) bypassed rules in the last 30 days: %s" % (len(suites), listing(parts)),
                      ev(rel, "length", len(suites)))
    return per(a.orgs(), fn)


@check("BRP-09")
def brp_codeowners_errors(a):
    def fn(r):
        if not a.d.exists(r.f("CODEOWNERS")):
            return None
        rel = r.f("codeowners-errors.json")
        errors = a.d.get(rel).get("errors") or []
        if errors:
            msgs = ["line %s: %s" % (e.get("line"), e.get("kind")) for e in errors]
            return FAIL("%d error(s) in CODEOWNERS: %s" % (len(errors), listing(msgs, 5)), ev(rel, "errors", len(errors)))
        return PASS("CODEOWNERS has no errors")
    return per(a.all_repos(), fn)


# --- GitHub Actions ----------------------------------------------------------
def _actions_scopes(a):
    """Enterprise first (often not collected), then organizations."""
    return [a.ent] + a.orgs()


@check("ACT-01")
def act_allowed_actions(a):
    def fn(t):
        rel = t.f("actions-permissions.json")
        d = a.d.get(rel)
        if d.get("enabled_repositories") == "none":
            return PASS("GitHub Actions disabled", ev(rel, "enabled_repositories", "none"))
        v = d.get("allowed_actions")
        e = ev(rel, "allowed_actions", v)
        if v == "all":
            return FAIL("All actions and reusable workflows are allowed", e)
        if v == "selected":
            sel = a.d.load(t.f("actions-selected-actions.json")) or {}
            bits = []
            if sel.get("github_owned_allowed"):
                bits.append("GitHub-owned")
            if sel.get("verified_allowed"):
                bits.append("verified creators")
            if sel.get("patterns_allowed"):
                bits.append("%d pattern(s)" % len(sel["patterns_allowed"]))
            return PASS("Selected actions only" + (": " + ", ".join(bits) if bits else ""), e)
        if v == "local_only":
            return PASS("Only actions in the enterprise are allowed", e)
        raise Missing("allowed_actions not present (%s)" % rel)
    return per(_actions_scopes(a), fn)


@check("ACT-02")
def act_sha_pinning(a):
    def fn(t):
        rel = t.f("actions-permissions.json")
        d = a.d.get(rel)
        if d.get("enabled_repositories") == "none":
            return PASS("GitHub Actions disabled")
        if "sha_pinning_required" not in d:
            raise Missing("sha_pinning_required not returned by the API (%s)" % rel)
        e = ev(rel, "sha_pinning_required", d["sha_pinning_required"])
        return PASS("Actions must be pinned to a full commit SHA", e) if d["sha_pinning_required"] \
            else FAIL("Actions may be referenced by tag or branch", e)
    return per(_actions_scopes(a), fn)


def _workflow_perm_targets(a):
    out = _actions_scopes(a)
    for r in a.all_repos():
        if a.d.exists(r.f("actions-workflow-permissions.json")):
            out.append(r)
    return out


@check("ACT-03")
def act_default_token(a):
    def fn(t):
        rel = t.f("actions-workflow-permissions.json")
        v = a.d.get(rel).get("default_workflow_permissions")
        e = ev(rel, "default_workflow_permissions", v)
        if v == "read":
            return PASS("GITHUB_TOKEN is read-only by default", e)
        if v == "write":
            return FAIL("GITHUB_TOKEN has write access by default", e)
        raise Missing("default_workflow_permissions not present (%s)" % rel)
    return per(_workflow_perm_targets(a), fn)


@check("ACT-04")
def act_approve_prs(a):
    def fn(t):
        rel = t.f("actions-workflow-permissions.json")
        v = a.d.get(rel).get("can_approve_pull_request_reviews")
        if v is None:
            raise Missing("can_approve_pull_request_reviews not present (%s)" % rel)
        e = ev(rel, "can_approve_pull_request_reviews", v)
        return FAIL("GitHub Actions can create and approve pull requests", e) if v \
            else PASS("GitHub Actions cannot approve pull requests", e)
    return per(_workflow_perm_targets(a), fn)


@check("ACT-05")
def act_fork_approval(a):
    def fn(t):
        rel = t.f("actions-fork-pr-approval.json")
        v = a.d.get(rel).get("approval_policy")
        e = ev(rel, "approval_policy", v)
        if v == "all_external_contributors":
            return PASS("Approval required for all external contributors", e)
        if v is None:
            raise Missing("approval_policy not present (%s)" % rel)
        return FAIL("Approval only required for '%s'" % v.replace("_", " "), e)
    return per(_actions_scopes(a), fn)


@check("ACT-06")
def act_runner_groups(a):
    def fn(t):
        groups = a.d.items(t.f("actions-runner-groups.json"), "runner_groups")
        runners = a.d.load(t.f("actions-runners.json"))
        n_runners = 0
        if isinstance(runners, list):
            n_runners = sum(len(p.get("runners") or []) for p in runners if isinstance(p, dict))
        out = []
        for g in groups:
            name = "%s: runner group '%s'" % (t.label, g.get("name"))
            e = ev(t.f("actions-runner-groups.json"), "runner_groups[%s]" % g.get("name"),
                   {k: g.get(k) for k in ("visibility", "allows_public_repositories", "restricted_to_workflows")})
            if g.get("allows_public_repositories"):
                out.append(FAIL("Public repositories can use these self-hosted runners", e, name))
            elif g.get("visibility") == "all" and not g.get("restricted_to_workflows") and n_runners:
                out.append(REVIEW("Available to all repositories and all workflows", e, name))
            else:
                out.append(PASS("Access restricted", e, name))
        if not n_runners and not any(r.status == "fail" for r in out):
            return PASS("No self-hosted runners registered")
        return out
    return per(_actions_scopes(a), fn)


@check("ACT-07")
def act_secret_visibility(a):
    def fn(o):
        out = []
        for fname, kind in (("actions-secrets.json", "Actions"), ("dependabot-secrets.json", "Dependabot")):
            rel = o.f(fname)
            if not a.d.exists(rel):
                if kind == "Actions":
                    raise Missing(a.d.reason(rel))
                continue
            wide = sorted(s.get("name", "?") for s in a.d.items(rel, "secrets") if s.get("visibility") == "all")
            if wide:
                out.append(REVIEW("%s secrets available to all repositories: %s" % (kind, listing(wide)),
                                  ev(rel, "visibility", "all")))
        return out or PASS("No organization secrets shared with all repositories")
    return per(a.orgs(), fn)


# --- Code security -----------------------------------------------------------
def _security_feature(a, key, name):
    def fn(r):
        rel = r.f("repo.json")
        sa = a.d.get(rel).get("security_and_analysis")
        if not isinstance(sa, dict):
            raise Missing("security_and_analysis not visible; needs admin access to %s" % r.label)
        v = (sa.get(key) or {}).get("status")
        e = ev(rel, "security_and_analysis.%s.status" % key, v)
        return PASS("%s enabled" % name, e) if v == "enabled" else FAIL("%s not enabled" % name, e)
    return per(a.all_repos(), fn)


@check("SEC-01")
def sec_secret_scanning(a):
    return _security_feature(a, "secret_scanning", "Secret scanning")


@check("SEC-02")
def sec_push_protection(a):
    return _security_feature(a, "secret_scanning_push_protection", "Push protection")


@check("SEC-03")
def sec_dependabot_alerts(a):
    def fn(r):
        rel = r.f("dependabot-alerts-enabled.json")
        st = str(a.d.get(rel).get("_http_status"))
        if st == "204":
            return PASS("Dependabot alerts enabled", ev(rel, "status", 204))
        if st == "404":
            return FAIL("Dependabot alerts not enabled", ev(rel, "status", 404))
        raise Missing("Dependabot alert status could not be read (status %s)" % st)
    return per(a.all_repos(), fn)


@check("SEC-04")
def sec_dependabot_updates(a):
    def fn(r):
        rel = r.f("dependabot-security-updates.json")
        v = a.d.get(rel).get("enabled")
        if v is None:
            raise Missing("enabled not present (%s)" % rel)
        e = ev(rel, "enabled", v)
        return PASS("Dependabot security updates enabled", e) if v else FAIL("Dependabot security updates not enabled", e)
    return per(a.all_repos(), fn)


def _has_codeql_workflow(a, r):
    base = a.d.path("workflows/%s" % r.label)
    if not os.path.isdir(base):
        return False
    for fn in os.listdir(base):
        text = a.d.text("workflows/%s/%s" % (r.label, fn)) or ""
        if "github/codeql-action" in text:
            return True
    return False


@check("SEC-05")
def sec_code_scanning(a):
    def fn(r):
        cfg = a.d.load(r.f("code-security-configuration.json")) or {}
        setup = ((cfg.get("configuration") or {}).get("code_scanning_default_setup"))
        if setup == "enabled":
            return PASS("Default setup through security configuration '%s'" % cfg["configuration"].get("name"))
        if _has_codeql_workflow(a, r):
            return PASS("CodeQL workflow (advanced setup)")
        return REVIEW("No evidence of code scanning (no default setup in the attached security configuration, "
                      "no CodeQL workflow)")
    return per(a.all_repos(), fn)


@check("SEC-06")
def sec_default_configuration(a):
    def fn(t):
        rel = t.f("code-security-defaults.json")
        defaults = a.d.get(rel)
        defaults = defaults if isinstance(defaults, list) else [defaults]
        good = [d for d in defaults if d.get("default_for_new_repos") in ("all", "private_and_internal")]
        if good:
            c = good[0].get("configuration") or {}
            note = "" if c.get("enforcement") == "enforced" else " (not enforced; repositories can detach it)"
            return PASS("New repositories get '%s'%s" % (c.get("name"), note),
                        ev(rel, "default_for_new_repos", good[0].get("default_for_new_repos")))
        public = [d for d in defaults if d.get("default_for_new_repos") == "public"]
        if public:
            return FAIL("Default configuration applies to new public repositories only. Enterprise Managed Users "
                        "cannot create public repositories, so new repositories get no security configuration",
                        ev(rel, "default_for_new_repos", "public"))
        return FAIL("No default security configuration for new repositories", ev(rel, "default_for_new_repos", None))
    return per([a.ent] + a.orgs(), fn)


def _age_days(a, ts):
    t = parse_time(ts)
    return (a.collected - t).days if t else None


@check("SEC-07")
def sec_secret_alerts(a):
    def fn(o):
        rel = o.f("alerts-secret-scanning-open.json")
        alerts = a.d.items(rel)
        if not alerts:
            return PASS("No open secret scanning alerts")
        types, repos, ages = {}, set(), []
        for al in alerts:
            k = al.get("secret_type_display_name") or al.get("secret_type") or "?"
            types[k] = types.get(k, 0) + 1
            repos.add((al.get("repository") or {}).get("full_name", "?"))
            age = _age_days(a, al.get("created_at"))
            if age is not None:
                ages.append(age)
        bypassed = sum(1 for al in alerts if al.get("push_protection_bypassed"))
        detail = "%d open alert(s) in %d repositories%s. Types: %s" % (
            len(alerts), len(repos), "; oldest %d days" % max(ages) if ages else "",
            listing(["%s (%d)" % kv for kv in sorted(types.items(), key=lambda kv: -kv[1])], 6))
        if bypassed:
            detail += ". %d pushed by bypassing push protection" % bypassed
        return FAIL(detail, ev(rel, "length", len(alerts)))
    return per(a.orgs(), fn)


def _severity_counts(alerts, getter):
    counts = {}
    for al in alerts:
        s = (getter(al) or "unknown").lower()
        counts[s] = counts.get(s, 0) + 1
    return counts


def _alert_rule(a, fname, getter, name):
    def fn(o):
        rel = o.f(fname)
        alerts = a.d.items(rel)
        counts = _severity_counts(alerts, getter)
        text = ", ".join("%s %d" % (s, counts[s]) for s in ["critical", "high", "medium", "low", "unknown"] if counts.get(s))
        serious = counts.get("critical", 0) + counts.get("high", 0)
        if serious:
            repos = {}
            for al in alerts:
                if (getter(al) or "").lower() in ("critical", "high"):
                    k = (al.get("repository") or {}).get("full_name", "?")
                    repos[k] = repos.get(k, 0) + 1
            top = sorted(repos.items(), key=lambda kv: -kv[1])[:5]
            return FAIL("%d critical/high open %s alert(s) (%s). Most affected: %s" % (
                serious, name, text, listing(["%s (%d)" % kv for kv in top])), ev(rel, "severity", counts))
        if alerts:
            return INFO("Open %s alerts: %s" % (name, text), ev(rel, "severity", counts))
        return PASS("No open %s alerts" % name)
    return per(a.orgs(), fn)


@check("SEC-08")
def sec_dependabot_open(a):
    return _alert_rule(a, "alerts-dependabot-open.json",
                       lambda al: (al.get("security_advisory") or {}).get("severity")
                       or (al.get("security_vulnerability") or {}).get("severity"), "Dependabot")


@check("SEC-09")
def sec_code_scanning_open(a):
    return _alert_rule(a, "alerts-code-scanning-open.json",
                       lambda al: (al.get("rule") or {}).get("security_severity_level"), "code scanning")


# --- Integrations ------------------------------------------------------------
def _safe_url(url):
    """Scheme, host and path only: query strings in webhook URLs can hold credentials."""
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*://[^/?#@]*@?[^/?#]*)([^?#]*)", url or "")
    if not m:
        return "?"
    host = m.group(1)
    if "@" in host:
        scheme, rest = host.split("://", 1)
        host = "%s://%s" % (scheme, rest.split("@", 1)[1])
    return host + m.group(2)


@check("INT-01")
def int_webhooks(a):
    targets = list(a.orgs()) + [r for r in a.all_repos() if a.d.exists(r.f("webhooks.json"))]

    def fn(t):
        out = []
        for h in a.d.items(t.f("webhooks.json")):
            c = h.get("config") or {}
            url = c.get("url") or ""
            issues = []
            if not c.get("secret"):
                issues.append("no secret")
            if str(c.get("insecure_ssl")) == "1":
                issues.append("TLS certificate verification disabled")
            if url.lower().startswith("http://"):
                issues.append("plain HTTP")
            label = "%s: webhook %s" % (t.label, _safe_url(url))
            e = ev(t.f("webhooks.json"), "hook %s" % h.get("id"), {"active": h.get("active"), "issues": issues})
            if issues:
                out.append(FAIL(", ".join(issues).capitalize() + ("" if h.get("active", True) else " (inactive)"), e, label))
            else:
                out.append(PASS("Secret set and TLS verified", e, label))
        return out
    return per(targets, fn)


@check("INT-02")
def int_deploy_keys(a):
    def fn(r):
        rel = r.f("deploy-keys.json")
        keys = a.d.items(rel)
        rw = ["'%s' (created %s)" % (k.get("title"), (k.get("created_at") or "?")[:10])
              for k in keys if not k.get("read_only", True)]
        if rw:
            return FAIL("Deploy key(s) with write access: %s" % listing(rw), ev(rel, "read_only", False))
        if keys:
            return PASS("%d read-only deploy key(s)" % len(keys))
        return None
    return per(a.all_repos(), fn)


@check("INT-03")
def int_apps(a):
    def fn(o):
        rel = o.f("app-installations.json")
        out = []
        for inst in a.d.items(rel, "installations"):
            perms = inst.get("permissions") or {}
            strong = sorted("%s:%s" % (k, v) for k, v in perms.items() if v in ("write", "admin") and k != "metadata")
            label = "%s: app '%s'" % (o.label, inst.get("app_slug"))
            e = ev(rel, "installation %s" % inst.get("id"),
                   {"repository_selection": inst.get("repository_selection"), "write_permissions": strong})
            if inst.get("repository_selection") == "all" and strong:
                out.append(REVIEW("Installed on all repositories with %s" % listing(strong, 8), e, label))
            else:
                out.append(PASS("Scoped installation or read-only permissions", e, label))
        return out or PASS("No GitHub Apps installed")
    return per(a.orgs(), fn)


# --- Deployments -------------------------------------------------------------
@check("DEP-01")
def dep_production_envs(a):
    pattern = re.compile(a.param("production_pattern", r"(^|[^a-z])(prod|production|prd|live)([^a-z]|$)"), re.I)

    def fn(r):
        rel = r.f("environments.json")
        out = []
        for env in a.d.items(rel, "environments"):
            name = env.get("name") or ""
            if not pattern.search(name):
                continue
            types = {p.get("type") for p in env.get("protection_rules") or []}
            reviewers = "required_reviewers" in types
            branches = env.get("deployment_branch_policy") is not None
            label = "%s: environment '%s'" % (r.label, name)
            e = ev(rel, "environments[%s]" % name, {"required_reviewers": reviewers, "branch_policy": branches})
            if reviewers or branches:
                have = [x for x, ok in (("required reviewers", reviewers), ("branch policy", branches)) if ok]
                out.append(PASS("Protected by %s" % " and ".join(have), e, label))
            else:
                out.append(FAIL("Any branch can deploy without approval", e, label))
        return out or None
    return per(a.all_repos(), fn)


# --- Audit log ---------------------------------------------------------------
@check("AUD-01")
def aud_streaming(a):
    def fn(t):
        rel = "enterprise/audit-log-streams.json"
        streams = a.d.get(rel)
        streams = streams if isinstance(streams, list) else [streams]
        on = [s.get("stream_type", "?") for s in streams if s.get("enabled")]
        if on:
            return PASS("Streaming to %s" % listing(on), ev(rel, "enabled", True))
        return FAIL("No enabled audit log stream", ev(rel, "enabled", False))
    return per([a.ent], fn)


def _event_rule(a, match, describe, found_status=REVIEW):
    def fn(t):
        events, window = a.audit_events()
        hits = [e for e in events if match(e.get("action") or "", e)]
        if not hits:
            return PASS("No such events in %s" % window)
        lines = []
        for e in hits[:a.param("max_listed", 15)]:
            when = parse_time(e.get("@timestamp") or e.get("created_at"))
            change = " (%s -> %s)" % (e.get("previous_visibility") or "?", e["visibility"]) if e.get("visibility") else ""
            lines.append("%s %s%s by %s%s" % (
                when.strftime("%Y-%m-%d") if when else "?", e.get("action"), change, e.get("actor") or "?",
                (" on " + str(e.get("repo") or e.get("org"))) if (e.get("repo") or e.get("org")) else ""))
        return found_status("%d event(s) in %s. %s" % (len(hits), window, describe),
                            {"file": "enterprise/audit-log-web.ndjson", "field": "action", "value": lines})
    return per([a.ent], fn)


@check("AUD-02")
def aud_push_protection_bypass(a):
    return _event_rule(a, lambda act, e: act == "secret_scanning_push_protection.bypass",
                       "Each bypass pushed a detected secret into a repository.")


@check("AUD-03")
def aud_protection_removed(a):
    acts = {"protected_branch.destroy", "protected_branch.policy_override", "repository_ruleset.destroy"}
    return _event_rule(a, lambda act, e: act in acts or act.endswith("ruleset.destroy"),
                       "Check that each change was intended.")


SECURITY_FEATURES = ("secret_scanning", "push_protection", "dependabot", "vulnerability_alert", "code_scanning",
                     "advanced_security")


# Covers repo, org and enterprise variants, e.g. repository_secret_scanning.disable,
# org.secret_scanning_push_protection_disable, business_secret_scanning.disabled_for_new_repos
DISABLE_RE = re.compile(r"[._]disable(d_for_new_repos)?$")


@check("AUD-04")
def aud_security_disabled(a):
    return _event_rule(a, lambda act, e: bool(DISABLE_RE.search(act)) and any(s in act for s in SECURITY_FEATURES),
                       "Security features were turned off.")


@check("AUD-05")
def aud_repo_lifecycle(a):
    return _event_rule(a, lambda act, e: act in ("repo.access", "repo.destroy", "repo.transfer", "repo.transfer_outgoing"),
                       "Repository visibility changes, deletions and transfers.")


@check("AUD-06")
def aud_runner_registration(a):
    return _event_rule(a, lambda act, e: act.endswith("register_self_hosted_runner"),
                       "New self-hosted runners were registered.", found_status=INFO)


# --- Workflows -----------------------------------------------------------------
def _workflows(a):
    """(target label, rel, text without comments) for every collected workflow file."""
    out = []
    base = a.d.path("workflows")
    if not os.path.isdir(base):
        return out
    for dirpath, _, files in os.walk(base):
        for fn in sorted(files):
            if not re.search(r"\.ya?ml$", fn):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), a.d.root).replace(os.sep, "/")
            text = a.d.text(rel) or ""
            text = re.sub(r"(?m)(^|\s)#.*$", r"\1", text)
            out.append((rel[len("workflows/"):], rel, text))
    return sorted(out)


def _need_workflows(a):
    wf = _workflows(a)
    if not wf:
        raise Missing("No workflow files collected (--no-workflows, or no repositories use GitHub Actions)")
    return wf


@check("WFL-01")
def wfl_pull_request_target(a):
    out = []
    try:
        wfs = _need_workflows(a)
    except Missing as e:
        return [NA(str(e), target=a.ent.label)]
    for label, rel, text in wfs:
        if not re.search(r"\bpull_request_target\b", text):
            continue
        if re.search(r"github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref", text):
            out.append(FAIL("Runs on pull_request_target and references the pull request head",
                            ev(rel, "on", "pull_request_target"), label))
        else:
            out.append(REVIEW("Runs on pull_request_target", ev(rel, "on", "pull_request_target"), label))
    return out or [PASS("No workflows use pull_request_target", target=a.ent.label)]


USES_RE = re.compile(r"(?m)^\s*(?:-\s*)?uses\s*:\s*['\"]?([^\s'\"]+)")


@check("WFL-02")
def wfl_unpinned_actions(a):
    trusted = set(a.param("trusted_owners", ["actions", "github"]))
    out = []
    try:
        wfs = _need_workflows(a)
    except Missing as e:
        return [NA(str(e), target=a.ent.label)]
    for label, rel, text in wfs:
        bad = []
        for ref in USES_RE.findall(text):
            if ref.startswith("./") or ref.startswith("docker://"):
                continue
            owner = ref.split("/", 1)[0].lower()
            version = ref.split("@", 1)[1] if "@" in ref else ""
            if owner in trusted or re.fullmatch(r"[0-9a-f]{40}", version):
                continue
            bad.append(ref)
        if bad:
            out.append(FAIL("Third-party actions not pinned to a commit SHA: %s" % listing(sorted(set(bad)), 6),
                            ev(rel, "uses", sorted(set(bad))), label))
        else:
            out.append(PASS("All third-party actions pinned", target=label))
    return out


@check("WFL-03")
def wfl_permissions(a):
    out = []
    try:
        wfs = _need_workflows(a)
    except Missing as e:
        return [NA(str(e), target=a.ent.label)]
    for label, rel, text in wfs:
        if re.search(r"(?m)^permissions\s*:", text):
            out.append(PASS("Top-level permissions declared", target=label))
        elif re.search(r"(?m)^\s+permissions\s*:", text):
            out.append(REVIEW("Permissions declared per job only; jobs without a block get the default token permissions",
                              ev(rel, "permissions", "job level"), label))
        else:
            out.append(FAIL("No permissions block; the workflow gets the default token permissions",
                            ev(rel, "permissions", None), label))
    return out


def _zizmor_path(finding):
    """First workflow path mentioned in a zizmor finding, relative to workflows/."""
    stack = [finding]
    while stack:
        v = stack.pop()
        if isinstance(v, dict):
            for k, x in v.items():
                # verbatim_path since zizmor 1.27, given_path before
                if k in ("verbatim_path", "given_path") and isinstance(x, str):
                    p = x.replace("\\", "/")
                    return p.split("workflows/", 1)[1] if "workflows/" in p else p
                stack.append(x)
        elif isinstance(v, list):
            stack.extend(v)
    return "?"


@check("WFL-04")
def wfl_zizmor(a):
    if a.zizmor is None:
        return [NA("zizmor output not provided. Run `zizmor --offline --format json workflows/ > zizmor.json` "
                   "and pass --zizmor zizmor.json", target=a.ent.label)]
    findings = a.zizmor if isinstance(a.zizmor, list) else a.zizmor.get("findings", [])
    out = []
    for f in findings:
        if f.get("ignored"):
            continue
        sev = ((f.get("determinations") or {}).get("severity") or "unknown")
        status = FAIL if sev.lower() in ("high", "medium") else REVIEW
        out.append(status("[%s] %s: %s" % (sev, f.get("ident", "?"), f.get("desc", "")),
                          {"file": "zizmor", "field": f.get("ident"), "value": f.get("url")},
                          _zizmor_path(f)))
    return out or [PASS("zizmor reported no findings", target=a.ent.label)]


# --- Hygiene -------------------------------------------------------------------
@check("HYG-01")
def hyg_copilot_seats(a):
    days = a.param("inactive_days", 60)

    def fn(t):
        rel = "enterprise/copilot-seats.json"
        seats = a.d.items(rel, "seats")
        if not seats:
            return PASS("No Copilot seats assigned")
        idle = []
        for s in seats:
            age = _age_days(a, s.get("last_activity_at"))
            if age is None or age > days:
                idle.append((s.get("assignee") or {}).get("login", "?"))
        if idle:
            return REVIEW("%d of %d Copilot seats unused for more than %d days: %s" % (
                len(idle), len(seats), days, listing(sorted(idle))), ev(rel, "last_activity_at", len(idle)))
        return PASS("All %d Copilot seats active in the last %d days" % (len(seats), days))
    return per([a.ent], fn)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
def load_catalog(path=CATALOG_PATH):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_waivers(path, today):
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    out = []
    for w in data.get("waivers", data if isinstance(data, list) else []):
        exp = w.get("expires")
        if exp and exp < today:
            warn("Waiver for %s (%s) expired on %s; ignored" % (w.get("rule"), w.get("target", "*"), exp))
            continue
        out.append(w)
    return out


def rule_status(results):
    present = {r.status for r in results}
    for s in STATUSES:
        if s in present:
            return s
    return "not_assessed"


def evaluate(audit, catalog, waivers=(), errors=None):
    rules = []
    for meta in catalog["rules"]:
        fn = CHECKS.get(meta["id"])
        audit.rule = meta
        try:
            results = fn(audit) if fn else [NA("No check implemented", target=audit.ent.label)]
        except Missing as e:
            results = [NA(str(e), target=audit.ent.label)]
        except Exception:  # a broken check must not stop the report
            if errors is not None:
                errors.append((meta["id"], traceback.format_exc()))
            warn("Check %s failed:\n%s" % (meta["id"], traceback.format_exc()))
            results = [NA("Check failed to run (tool error)", target=audit.ent.label)]
        if meta.get("scope") in ("org", "repo"):
            # Organizations that could not be collected are not assessed, not passed
            for name in audit.org_names_attempted():
                rel = "orgs/%s/org.json" % name
                if not audit.d.exists(rel):
                    results.append(NA("Organization not collected: %s" % audit.d.reason(rel), target=name))
        if not results:
            results = [INFO("Nothing to evaluate", target=audit.ent.label)]
        for r in results:
            if r.status in ("fail", "review"):
                for w in waivers:
                    if w.get("rule") == meta["id"] and fnmatch.fnmatchcase(r.target or "", w.get("target", "*")):
                        r.status = "accepted"
                        r.waiver = {k: w.get(k) for k in ("reason", "approved_by", "expires") if w.get(k)}
                        break
        results.sort(key=lambda r: (STATUSES.index(r.status), r.target or ""))
        rule = {k: meta.get(k) for k in ("id", "area", "title", "severity", "scope", "rationale", "remediation",
                                          "manual_check", "references")}
        rule["status"] = rule_status(results)
        rule["counts"] = {s: sum(1 for r in results if r.status == s) for s in STATUSES}
        rule["results"] = [r.to_dict() for r in results]
        rules.append(rule)
    audit.rule = None
    return rules


def org_scorecard(audit, rules, areas):
    """Per organization and area: counts of fail+review / pass / not assessed."""
    rows = []
    for name in audit.org_names_attempted():
        collected = audit.d.exists("orgs/%s/org.json" % name)
        cells = {}
        for area in areas:
            c = {"issues": 0, "pass": 0, "na": 0}
            for rule in rules:
                if rule["area"] != area["id"]:
                    continue
                for r in rule["results"]:
                    t = r["target"] or ""
                    if t != name and not t.startswith(name + "/") and not t.startswith(name + ":"):
                        continue
                    if r["status"] in ("fail", "review"):
                        c["issues"] += 1
                    elif r["status"] in ("pass", "accepted"):
                        c["pass"] += 1
                    elif r["status"] == "not_assessed":
                        c["na"] += 1
            cells[area["id"]] = c
        listed = audit.d.load("orgs/%s/repos.json" % name)
        org_t = Target("org", name, "orgs/%s" % name)
        rows.append({
            "org": name, "collected": collected,
            "reason": "" if collected else audit.d.reason("orgs/%s/org.json" % name),
            "repos_listed": len(listed) if isinstance(listed, list) else None,
            "repos_assessed": len(audit.repos(org_t)) if collected else 0,
            "areas": cells,
        })
    return rows


def build_report(audit, catalog, rules, waivers):
    run = audit.d.run
    by_sev = {s: 0 for s in SEVERITIES}
    for r in rules:
        if r["status"] == "fail":
            by_sev[r["severity"]] = by_sev.get(r["severity"], 0) + 1
    top = sorted([r for r in rules if r["status"] in ("fail", "review")],
                 key=lambda r: (SEVERITIES.index(r["severity"]), r["status"] != "fail",
                                -(r["counts"]["fail"] + r["counts"]["review"])))[:5]
    coverage = []
    for r in rules:
        for res in r["results"]:
            if res["status"] == "not_assessed":
                coverage.append({"rule": r["id"], "title": r["title"], "target": res["target"],
                                 "reason": res["detail"], "manual_check": r.get("manual_check") or ""})
    errors = []
    elog = audit.d.text("errors.log") or ""
    for line in elog.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            errors.append({"status": parts[0], "endpoint": parts[1]})
    return {
        "tool": {"name": "ghe-audit", "version": TOOL_VERSION, "catalog_version": catalog.get("version")},
        "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scope": {
            "host": run.get("host"), "enterprise": run.get("enterprise"), "user": run.get("user"),
            "token_type": run.get("token_type"), "token_scopes": run.get("token_scopes"),
            "collector_version": run.get("script_version"), "collector_sha256": run.get("script_sha256"),
            "collection_started": run.get("started"), "collection_finished": run.get("finished"),
            "audit_days": (run.get("params") or {}).get("audit_days"),
            "params": run.get("params"),
        },
        "areas": catalog["areas"],
        "sources": catalog.get("sources", []),
        "summary": {
            "rules": len(rules),
            "by_status": {s: sum(1 for r in rules if r["status"] == s) for s in STATUSES},
            "failed_by_severity": by_sev,
            "top": [{"id": r["id"], "title": r["title"], "severity": r["severity"], "status": r["status"]} for r in top],
        },
        "organizations": org_scorecard(audit, rules, catalog["areas"]),
        "rules": rules,
        "coverage": coverage,
        "collection_errors": errors,
        "waivers": waivers,
    }


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def area_name(report, area_id):
    for a in report["areas"]:
        if a["id"] == area_id:
            return a["name"]
    return area_id


def ref_text(ref):
    label = ref.get("title") or ref.get("id") or ""
    return "%s: %s" % (ref.get("source"), label) if ref.get("source") else label


def evidence_text(e):
    if not e:
        return ""
    v = e.get("value")
    if isinstance(v, (dict, list)):
        v = json.dumps(v, ensure_ascii=False)
        if len(v) > 300:
            v = v[:300] + "..."
    return "%s: %s = %s" % (e.get("file"), e.get("field"), v)


def issues(rule):
    return [r for r in rule["results"] if r["status"] in ("fail", "review", "accepted")]


def render_json(report):
    return json.dumps(report, indent=2, ensure_ascii=False) + "\n"


def _csv_cell(v):
    """Neutralize spreadsheet formulas in customer-controlled text."""
    s = "" if v is None else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def render_csv(report):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["rule_id", "area", "title", "severity", "rule_status", "target", "result_status", "detail",
                "evidence", "waiver_reason"])
    for r in report["rules"]:
        for res in r["results"]:
            w.writerow([_csv_cell(x) for x in (
                r["id"], area_name(report, r["area"]), r["title"], r["severity"], r["status"], res["target"],
                res["status"], res["detail"], evidence_text(res.get("evidence")),
                (res.get("waiver") or {}).get("reason", ""))])
    return buf.getvalue()


def _md(s):
    return str(s if s is not None else "").replace("|", "\\|").replace("\n", " ")


def render_markdown(report):
    sc, sm = report["scope"], report["summary"]
    L = []
    L.append("# GitHub Enterprise security assessment: %s" % sc.get("enterprise"))
    L.append("")
    L.append("| | |\n| --- | --- |")
    for k, v in (("Host", sc.get("host")), ("Collected", sc.get("collection_started")),
                 ("Collected as", sc.get("user")), ("Token scopes", ", ".join(sc.get("token_scopes") or [])),
                 ("Collector", "%s (sha256 %s)" % (sc.get("collector_version"), (sc.get("collector_sha256") or "")[:12])),
                 ("Report generated", report["generated"]),
                 ("Rule catalog", report["tool"]["catalog_version"])):
        L.append("| %s | %s |" % (k, _md(v)))
    L.append("")
    L.append("## Summary")
    L.append("")
    bs = sm["by_status"]
    L.append("%d rules: %d fail, %d need review, %d accepted, %d pass, %d not assessed." % (
        sm["rules"], bs["fail"], bs["review"], bs["accepted"], bs["pass"], bs["not_assessed"]))
    L.append("")
    L.append("Failed rules by severity: " + ", ".join(
        "%s %d" % (s, n) for s, n in sm["failed_by_severity"].items() if n) or "none")
    L.append("")
    if sm["top"]:
        L.append("**Top risks**")
        L.append("")
        for t in sm["top"]:
            L.append("- **%s** %s (%s, %s)" % (t["id"], t["title"], t["severity"], STATUS_LABEL[t["status"]].lower()))
        L.append("")
    L.append("## Organizations")
    L.append("")
    L.append("| Organization | Repositories assessed | " + " | ".join(a["name"] for a in report["areas"]) + " |")
    L.append("| --- | --- | " + " | ".join("---" for _ in report["areas"]) + " |")
    for o in report["organizations"]:
        if not o["collected"]:
            L.append("| %s | not collected: %s |%s" % (_md(o["org"]), _md(o["reason"]), " |" * len(report["areas"])))
            continue
        cells = ["%d issues / %d ok%s" % (c["issues"], c["pass"], " / %d n/a" % c["na"] if c["na"] else "")
                 for c in (o["areas"][a["id"]] for a in report["areas"])]
        L.append("| %s | %s of %s | %s |" % (_md(o["org"]), o["repos_assessed"], o["repos_listed"], " | ".join(cells)))
    L.append("")
    L.append("## Findings")
    for area in report["areas"]:
        rules = [r for r in report["rules"] if r["area"] == area["id"] and r["status"] in ("fail", "review", "accepted")]
        if not rules:
            continue
        L.append("")
        L.append("### %s" % area["name"])
        for r in sorted(rules, key=lambda r: (SEVERITIES.index(r["severity"]), r["id"])):
            L.append("")
            L.append("#### %s %s" % (r["id"], r["title"]))
            L.append("")
            L.append("**Severity:** %s · **Status:** %s · **Affected:** %d" % (
                r["severity"].capitalize(), STATUS_LABEL[r["status"]], len(issues(r))))
            L.append("")
            L.append(r["rationale"])
            L.append("")
            L.append("| Target | Status | Detail |\n| --- | --- | --- |")
            for res in issues(r):
                d = res["detail"] + (" (accepted: %s)" % res["waiver"].get("reason") if res.get("waiver") else "")
                L.append("| %s | %s | %s |" % (_md(res["target"]), STATUS_LABEL[res["status"]], _md(d)))
            L.append("")
            L.append("**Recommendation:** " + r["remediation"])
            if r.get("references"):
                L.append("")
                L.append("**References:** " + "; ".join(
                    "[%s](%s)" % (ref_text(x), x["url"]) if x.get("url") else ref_text(x) for x in r["references"]))
    L.append("")
    L.append("## Passed checks")
    L.append("")
    for r in report["rules"]:
        if r["status"] in ("pass", "info"):
            L.append("- %s %s" % (r["id"], r["title"]))
    L.append("")
    L.append("## Not assessed")
    L.append("")
    L.append("These checks could not be evaluated from the collected data. Verify them manually.")
    L.append("")
    L.append("| Rule | Target | Reason | Manual check |\n| --- | --- | --- | --- |")
    for c in report["coverage"]:
        L.append("| %s %s | %s | %s | %s |" % (c["rule"], _md(c["title"]), _md(c["target"]), _md(c["reason"]),
                                             _md(c["manual_check"])))
    L.append("")
    L.append("## Method")
    L.append("")
    L.append(METHOD_TEXT)
    L.append("")
    for s in report["sources"]:
        L.append("- [%s](%s)" % (s["name"], s["url"]))
    return "\n".join(L) + "\n"


METHOD_TEXT = (
    "Configuration was collected read-only with ghe-collect and evaluated offline with ghe-audit against a rule "
    "catalog based on GitHub's documentation, OpenSSF Scorecard and SCM best practices, and Legitify policies. "
    "GHE.com enterprises use Enterprise Managed Users: authentication and MFA are enforced by the identity provider, "
    "so they are outside this assessment and must be verified in the IdP. \"Review\" means the setting is not wrong "
    "in itself but needs a decision by the customer. \"Not assessed\" means the data was not available to the "
    "collecting account; it is not a pass.")


def _h(s):
    return html.escape("" if s is None else str(s))


def render_html(report, css):
    sc, sm = report["scope"], report["summary"]
    out = []
    w = out.append
    w("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">")
    w("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
    w("<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\">")
    w("<title>Security assessment: %s</title><style>%s</style></head><body><main>" % (_h(sc.get("enterprise")), css))
    w("<header><p class=\"eyebrow\">GitHub Enterprise security assessment</p><h1>%s</h1>" % _h(sc.get("enterprise")))
    w("<dl class=\"meta\">")
    for k, v in (("Host", sc.get("host")), ("Collected", sc.get("collection_started")),
                 ("Collected as", sc.get("user")), ("Token scopes", ", ".join(sc.get("token_scopes") or [])),
                 ("Collector", "%s, sha256 %s" % (sc.get("collector_version"), (sc.get("collector_sha256") or "")[:12])),
                 ("Generated", report["generated"]), ("Rule catalog", report["tool"]["catalog_version"])):
        w("<div><dt>%s</dt><dd>%s</dd></div>" % (_h(k), _h(v)))
    w("</dl></header>")

    w("<section><h2>Summary</h2><div class=\"tiles\">")
    for s in SEVERITIES[:4]:
        w("<div class=\"tile sev-%s\"><span class=\"n\">%d</span><span>%s</span></div>" % (
            s, sm["failed_by_severity"].get(s, 0), s.capitalize()))
    bs = sm["by_status"]
    w("</div><p>%d rules evaluated: <b>%d fail</b>, %d need review, %d accepted, %d pass, %d not assessed. "
      "Tiles count failed rules by severity.</p>" % (
          sm["rules"], bs["fail"], bs["review"], bs["accepted"], bs["pass"], bs["not_assessed"]))
    if sm["top"]:
        w("<h3>Top risks</h3><ol class=\"top\">")
        for t in sm["top"]:
            w("<li><a href=\"#%s\">%s %s</a> <span class=\"badge sev-%s\">%s</span> <span class=\"badge st-%s\">%s</span></li>" % (
                _h(t["id"]), _h(t["id"]), _h(t["title"]), t["severity"], t["severity"].capitalize(),
                t["status"], STATUS_LABEL[t["status"]]))
        w("</ol>")
    w("</section>")

    w("<section><h2>Organizations</h2><div class=\"scroll\"><table><thead><tr><th>Organization</th><th>Repositories</th>")
    for a in report["areas"]:
        w("<th>%s</th>" % _h(a["name"]))
    w("</tr></thead><tbody>")
    for o in report["organizations"]:
        if not o["collected"]:
            w("<tr><td>%s</td><td colspan=\"%d\" class=\"muted\">Not collected: %s</td></tr>" % (
                _h(o["org"]), len(report["areas"]) + 1, _h(o["reason"])))
            continue
        w("<tr><td>%s</td><td>%s of %s</td>" % (_h(o["org"]), o["repos_assessed"], _h(o["repos_listed"])))
        for a in report["areas"]:
            c = o["areas"][a["id"]]
            cls = "bad" if c["issues"] else ("good" if c["pass"] else "muted")
            w("<td class=\"%s\">%d / %d%s</td>" % (cls, c["issues"], c["pass"], " (%d n/a)" % c["na"] if c["na"] else ""))
        w("</tr>")
    w("</tbody></table></div><p class=\"muted\">Cells: issues / passed results per area.</p></section>")

    w("<section><h2>Findings</h2>")
    for area in report["areas"]:
        rules = [r for r in report["rules"] if r["area"] == area["id"] and r["status"] in ("fail", "review", "accepted")]
        if not rules:
            continue
        w("<h3>%s</h3>" % _h(area["name"]))
        for r in sorted(rules, key=lambda r: (SEVERITIES.index(r["severity"]), r["id"])):
            iss = issues(r)
            w("<article class=\"finding\" id=\"%s\"><h4>%s %s</h4>" % (_h(r["id"]), _h(r["id"]), _h(r["title"])))
            w("<p><span class=\"badge sev-%s\">%s</span> <span class=\"badge st-%s\">%s</span> "
              "<span class=\"muted\">%d affected, %d passed, %d not assessed</span></p>" % (
                  r["severity"], r["severity"].capitalize(), r["status"], STATUS_LABEL[r["status"]], len(iss),
                  r["counts"]["pass"], r["counts"]["not_assessed"]))
            w("<p>%s</p>" % _h(r["rationale"]))
            w("<details%s><summary>Affected (%d)</summary><div class=\"scroll\"><table><thead><tr><th>Target</th>"
              "<th>Status</th><th>Detail</th></tr></thead><tbody>" % (" open" if len(iss) <= 10 else "", len(iss)))
            for res in iss:
                d = _h(res["detail"])
                if res.get("waiver"):
                    d += "<br><span class=\"muted\">Accepted: %s</span>" % _h(res["waiver"].get("reason"))
                if res.get("evidence"):
                    d += "<br><code>%s</code>" % _h(evidence_text(res["evidence"]))
                w("<tr><td>%s</td><td><span class=\"badge st-%s\">%s</span></td><td>%s</td></tr>" % (
                    _h(res["target"]), res["status"], STATUS_LABEL[res["status"]], d))
            w("</tbody></table></div></details>")
            w("<p><b>Recommendation.</b> %s</p>" % _h(r["remediation"]))
            if r.get("references"):
                w("<p class=\"refs\"><b>References.</b> ")
                w("; ".join("<a href=\"%s\">%s</a>" % (_h(x["url"]), _h(ref_text(x))) if x.get("url") else _h(ref_text(x))
                            for x in r["references"]))
                w("</p>")
            w("</article>")
    w("</section>")

    w("<section><h2>Passed checks</h2><ul class=\"cols\">")
    for r in report["rules"]:
        if r["status"] in ("pass", "info"):
            w("<li>%s %s</li>" % (_h(r["id"]), _h(r["title"])))
    w("</ul></section>")

    w("<section><h2>Not assessed</h2><p>These checks could not be evaluated from the collected data. "
      "Verify them manually.</p><div class=\"scroll\"><table><thead><tr><th>Rule</th><th>Target</th><th>Reason</th>"
      "<th>Manual check</th></tr></thead><tbody>")
    for c in report["coverage"]:
        w("<tr><td>%s %s</td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
            _h(c["rule"]), _h(c["title"]), _h(c["target"]), _h(c["reason"]), _h(c["manual_check"])))
    w("</tbody></table></div></section>")

    w("<section><h2>Method</h2><p>%s</p><ul>" % _h(METHOD_TEXT))
    for s in report["sources"]:
        w("<li><a href=\"%s\">%s</a></li>" % (_h(s["url"]), _h(s["name"])))
    w("</ul></section></main></body></html>\n")
    return "".join(out)


# --- DOCX ----------------------------------------------------------------------
_XML_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _x(s):
    return _xml_escape(_XML_BAD.sub("", "" if s is None else str(s)), {'"': "&quot;"})


W_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
DOCX_STYLES = {
    "Title": '<w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:basedOn w:val="Normal"/>'
             '<w:pPr><w:spacing w:after="200"/></w:pPr><w:rPr><w:b/><w:sz w:val="48"/></w:rPr></w:style>',
    "Heading1": '<w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/>'
                '<w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="360" w:after="120"/><w:outlineLvl w:val="0"/>'
                '</w:pPr><w:rPr><w:b/><w:sz w:val="32"/></w:rPr></w:style>',
    "Heading2": '<w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/>'
                '<w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="280" w:after="80"/><w:outlineLvl w:val="1"/>'
                '</w:pPr><w:rPr><w:b/><w:sz w:val="26"/></w:rPr></w:style>',
    "Heading3": '<w:style w:type="paragraph" w:styleId="Heading3"><w:name w:val="heading 3"/><w:basedOn w:val="Normal"/>'
                '<w:next w:val="Normal"/><w:pPr><w:keepNext/><w:spacing w:before="200" w:after="60"/><w:outlineLvl w:val="2"/>'
                '</w:pPr><w:rPr><w:b/><w:sz w:val="22"/></w:rPr></w:style>',
    "ListBullet": '<w:style w:type="paragraph" w:styleId="ListBullet"><w:name w:val="List Bullet"/><w:basedOn w:val="Normal"/>'
                  '<w:pPr><w:ind w:left="360" w:hanging="360"/></w:pPr></w:style>',
    "TableGrid": '<w:style w:type="table" w:styleId="TableGrid"><w:name w:val="Table Grid"/><w:tblPr><w:tblBorders>'
                 + "".join('<w:%s w:val="single" w:sz="4" w:space="0" w:color="A0A0A0"/>' % s
                           for s in ("top", "left", "bottom", "right", "insideH", "insideV"))
                 + '</w:tblBorders><w:tblCellMar><w:left w:w="80" w:type="dxa"/><w:right w:w="80" w:type="dxa"/>'
                 '</w:tblCellMar></w:tblPr></w:style>',
    "Hyperlink": '<w:style w:type="character" w:styleId="Hyperlink"><w:name w:val="Hyperlink"/>'
                 '<w:rPr><w:color w:val="0563C1"/><w:u w:val="single"/></w:rPr></w:style>',
}
DOCX_DEFAULT_STYLES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="%s">'
    '<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri" w:cs="Calibri"/>'
    '<w:sz w:val="20"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="100"/></w:pPr>'
    '</w:pPrDefault></w:docDefaults>'
    '<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>'
    '%s</w:styles>') % (W_NS, "".join(DOCX_STYLES.values()))


class Docx:
    def __init__(self):
        self.body = []
        self.links = []

    def _runs(self, parts):
        """parts: str, or list of str / ("b", text) / ("link", text, url) / ("code", text)."""
        if isinstance(parts, str):
            parts = [parts]
        xml = []
        for p in parts:
            if isinstance(p, str):
                xml.append('<w:r><w:t xml:space="preserve">%s</w:t></w:r>' % _x(p))
            elif p[0] == "b":
                xml.append('<w:r><w:rPr><w:b/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r>' % _x(p[1]))
            elif p[0] == "code":
                xml.append('<w:r><w:rPr><w:rFonts w:ascii="Consolas" w:hAnsi="Consolas"/><w:sz w:val="16"/></w:rPr>'
                           '<w:t xml:space="preserve">%s</w:t></w:r>' % _x(p[1]))
            elif p[0] == "link":
                rid = "rIdL%d" % (len(self.links) + 1)
                self.links.append((rid, p[2]))
                xml.append('<w:hyperlink r:id="%s"><w:r><w:rPr><w:rStyle w:val="Hyperlink"/></w:rPr>'
                           '<w:t xml:space="preserve">%s</w:t></w:r></w:hyperlink>' % (rid, _x(p[1])))
        return "".join(xml)

    def para(self, parts, style=None):
        ppr = '<w:pPr><w:pStyle w:val="%s"/></w:pPr>' % style if style else ""
        self.body.append("<w:p>%s%s</w:p>" % (ppr, self._runs(parts)))

    def heading(self, text, level):
        self.para(text, "Title" if level == 0 else "Heading%d" % level)

    def bullet(self, parts):
        self.para(["\u2022\t"] + (parts if isinstance(parts, list) else [parts]), "ListBullet")

    def table(self, header, rows, widths=None):
        def cell(parts, bold=False, w=None):
            tcpr = '<w:tcPr><w:tcW w:w="%d" w:type="pct"/></w:tcPr>' % (w * 50) if w else ""
            if bold:
                parts = [("b", parts)] if isinstance(parts, str) else parts
            return "<w:tc>%s<w:p>%s</w:p></w:tc>" % (tcpr, self._runs(parts))
        widths = widths or [100 // len(header)] * len(header)
        # tblGrid is required by the schema; 9638 twips is the A4 text width with our margins
        grid = "".join('<w:gridCol w:w="%d"/>' % (9638 * w // 100) for w in widths)
        xml = ['<w:tbl><w:tblPr><w:tblStyle w:val="TableGrid"/><w:tblW w:w="5000" w:type="pct"/></w:tblPr>'
               '<w:tblGrid>%s</w:tblGrid>' % grid]
        xml.append('<w:tr><w:trPr><w:tblHeader/></w:trPr>%s</w:tr>' % "".join(
            cell(h, True, w) for h, w in zip(header, widths)))
        for row in rows:
            xml.append("<w:tr>%s</w:tr>" % "".join(cell(c, False, w) for c, w in zip(row, widths)))
        xml.append("</w:tbl>")
        self.body.append("".join(xml))
        self.para("")

    def save(self, path, template=None):
        tpl = {}
        if template:
            with zipfile.ZipFile(template) as z:
                for n in z.namelist():
                    tpl[n] = z.read(n)
        sect = '<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1134" w:right="1134" w:bottom="1134" ' \
               'w:left="1134" w:header="567" w:footer="567" w:gutter="0"/></w:sectPr>'
        rels = ['<Relationship Id="rIdStyles" Type="%s/styles" Target="styles.xml"/>' % R_NS]
        rels += ['<Relationship Id="%s" Type="%s/hyperlink" Target="%s" TargetMode="External"/>' % (rid, R_NS, _x(url))
                 for rid, url in self.links]
        overrides = []
        extra = {}
        styles = DOCX_DEFAULT_STYLES.encode("utf-8")
        if tpl:
            styles = self._merge_styles(tpl.get("word/styles.xml"))
            # Carry over the template's page setup, header and footer
            doc = tpl.get("word/document.xml", b"").decode("utf-8", "replace")
            m = re.search(r"<w:sectPr\b.*?</w:sectPr>", doc, re.S)
            tpl_rels = tpl.get("word/_rels/document.xml.rels", b"").decode("utf-8", "replace")
            if m:
                sect = m.group(0)
                for rid in re.findall(r'r:id="([^"]+)"', sect):
                    rm = re.search(r'<Relationship [^>]*Id="%s"[^>]*/>' % re.escape(rid), tpl_rels)
                    if not rm:
                        continue
                    rels.append(rm.group(0))
                    target = re.search(r'Target="([^"]+)"', rm.group(0)).group(1)
                    part = "word/" + target
                    if part in tpl:
                        extra[part] = tpl[part]
                        kind = "header" if "header" in target else "footer"
                        overrides.append('<Override PartName="/%s" ContentType="application/vnd.openxmlformats-'
                                         'officedocument.wordprocessingml.%s+xml"/>' % (part, kind))
                        prel = "word/_rels/%s.rels" % target
                        if prel in tpl:
                            extra[prel] = tpl[prel]
            for n, data in tpl.items():
                if n.startswith("word/media/") or n.startswith("word/theme/"):
                    extra[n] = data
            if "word/theme/theme1.xml" in tpl:
                rels.append('<Relationship Id="rIdTheme" Type="%s/theme" Target="theme/theme1.xml"/>' % R_NS)
                overrides.append('<Override PartName="/word/theme/theme1.xml" '
                                 'ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>')
        document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<w:document xmlns:w="%s" xmlns:r="%s"><w:body>%s%s</w:body></w:document>'
                    % (W_NS, R_NS, "".join(self.body), sect))
        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Default Extension="png" ContentType="image/png"/><Default Extension="jpeg" ContentType="image/jpeg"/>'
            '<Default Extension="jpg" ContentType="image/jpeg"/><Default Extension="emf" ContentType="image/x-emf"/>'
            '<Override PartName="/word/document.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '<Override PartName="/word/styles.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>%s</Types>'
            % "".join(overrides))
        root_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                     '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                     '<Relationship Id="rId1" Type="%s/officeDocument" Target="word/document.xml"/></Relationships>' % R_NS)
        doc_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">%s'
                    '</Relationships>' % "".join(rels))
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", content_types)
            z.writestr("_rels/.rels", root_rels)
            z.writestr("word/document.xml", document)
            z.writestr("word/_rels/document.xml.rels", doc_rels)
            z.writestr("word/styles.xml", styles)
            for n, data in sorted(extra.items()):
                z.writestr(n, data)

    @staticmethod
    def _merge_styles(tpl_styles):
        """Template styles, plus our definitions for any style IDs the template lacks."""
        if not tpl_styles:
            return DOCX_DEFAULT_STYLES.encode("utf-8")
        s = tpl_styles.decode("utf-8", "replace")
        missing = [xml for sid, xml in DOCX_STYLES.items() if 'w:styleId="%s"' % sid not in s]
        if missing:
            s = s.replace("</w:styles>", "".join(missing) + "</w:styles>")
        return s.encode("utf-8")


def render_docx(report, path, template=None):
    sc, sm = report["scope"], report["summary"]
    d = Docx()
    d.heading("GitHub Enterprise security assessment: %s" % sc.get("enterprise"), 0)
    d.table(["Item", "Value"], [
        ["Host", sc.get("host") or ""], ["Collected", sc.get("collection_started") or ""],
        ["Collected as", sc.get("user") or ""], ["Token scopes", ", ".join(sc.get("token_scopes") or [])],
        ["Collector", "%s (sha256 %s)" % (sc.get("collector_version"), (sc.get("collector_sha256") or "")[:12])],
        ["Report generated", report["generated"]], ["Rule catalog", report["tool"]["catalog_version"] or ""],
    ], [25, 75])
    d.heading("Summary", 1)
    bs = sm["by_status"]
    d.para("%d rules evaluated: %d fail, %d need review, %d accepted, %d pass, %d not assessed." % (
        sm["rules"], bs["fail"], bs["review"], bs["accepted"], bs["pass"], bs["not_assessed"]))
    d.table(["Severity", "Failed rules"], [[s.capitalize(), str(n)] for s, n in sm["failed_by_severity"].items()], [50, 50])
    if sm["top"]:
        d.heading("Top risks", 2)
        for t in sm["top"]:
            d.bullet([("b", "%s %s" % (t["id"], t["title"])), " (%s, %s)" % (t["severity"], STATUS_LABEL[t["status"]].lower())])
    d.heading("Organizations", 1)
    rows = []
    for o in report["organizations"]:
        if not o["collected"]:
            rows.append([o["org"], "Not collected", o["reason"]])
            continue
        parts = ["%s: %d issues / %d ok" % (a["name"], o["areas"][a["id"]]["issues"], o["areas"][a["id"]]["pass"])
                 for a in report["areas"] if o["areas"][a["id"]]["issues"] or o["areas"][a["id"]]["pass"]]
        rows.append([o["org"], "%s of %s" % (o["repos_assessed"], o["repos_listed"]), "; ".join(parts)])
    d.table(["Organization", "Repositories assessed", "Results by area"], rows, [20, 15, 65])
    d.heading("Findings", 1)
    for area in report["areas"]:
        rules = [r for r in report["rules"] if r["area"] == area["id"] and r["status"] in ("fail", "review", "accepted")]
        if not rules:
            continue
        d.heading(area["name"], 2)
        for r in sorted(rules, key=lambda r: (SEVERITIES.index(r["severity"]), r["id"])):
            iss = issues(r)
            d.heading("%s %s" % (r["id"], r["title"]), 3)
            d.para([("b", "Severity: "), r["severity"].capitalize(), "   ", ("b", "Status: "), STATUS_LABEL[r["status"]],
                    "   ", ("b", "Affected: "), str(len(iss))])
            d.para(r["rationale"])
            limit = 40
            rows = [[x["target"] or "", STATUS_LABEL[x["status"]],
                     x["detail"] + (" (accepted: %s)" % x["waiver"].get("reason") if x.get("waiver") else "")]
                    for x in iss[:limit]]
            if len(iss) > limit:
                rows.append(["...", "", "%d more; see findings.csv" % (len(iss) - limit)])
            d.table(["Target", "Status", "Detail"], rows, [30, 12, 58])
            d.para([("b", "Recommendation. "), r["remediation"]])
            if r.get("references"):
                parts = [("b", "References. ")]
                for i, x in enumerate(r["references"]):
                    if i:
                        parts.append("; ")
                    parts.append(("link", ref_text(x), x["url"]) if x.get("url") else ref_text(x))
                d.para(parts)
    d.heading("Passed checks", 1)
    for r in report["rules"]:
        if r["status"] in ("pass", "info"):
            d.bullet("%s %s" % (r["id"], r["title"]))
    d.heading("Not assessed", 1)
    d.para("These checks could not be evaluated from the collected data. Verify them manually.")
    d.table(["Rule", "Target", "Reason", "Manual check"],
            [["%s %s" % (c["rule"], c["title"]), c["target"] or "", c["reason"], c["manual_check"]]
             for c in report["coverage"]], [25, 15, 30, 30])
    d.heading("Method", 1)
    d.para(METHOD_TEXT)
    for s in report["sources"]:
        d.bullet([("link", s["name"], s["url"])])
    d.save(path, template)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
FORMATS = ("html", "md", "docx", "json", "csv")


def parse_args(argv):
    p = argparse.ArgumentParser(
        prog="ghe-audit.py",
        description="Offline security assessment of ghe-collect output. Never contacts GitHub.")
    p.add_argument("outdir", help="Extracted ghe-collect output directory")
    p.add_argument("--out", help="Report directory (default: OUTDIR-report next to OUTDIR)")
    p.add_argument("--format", default=",".join(FORMATS),
                   help="Comma-separated formats: %s (default: all)" % ",".join(FORMATS))
    p.add_argument("--zizmor", help="zizmor JSON output to include (zizmor --offline --format json workflows/)")
    p.add_argument("--waivers", help="JSON file with accepted risks")
    p.add_argument("--docx-template", help="Word .docx/.dotx whose styles, header and footer are used")
    p.add_argument("--strict", action="store_true", help="Exit with status 2 if any check fails to run")
    p.add_argument("--catalog", default=CATALOG_PATH, help=argparse.SUPPRESS)
    p.add_argument("--version", action="version", version="ghe-audit %s" % TOOL_VERSION)
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    formats = [f.strip() for f in args.format.split(",") if f.strip()]
    bad = [f for f in formats if f not in FORMATS]
    if bad:
        die("Unknown format(s): %s" % ", ".join(bad))
    d = OutputDir(args.outdir)
    zizmor = None
    if args.zizmor:
        with open(args.zizmor, encoding="utf-8") as fh:
            zizmor = json.load(fh)
    catalog = load_catalog(args.catalog)
    today = dt.date.today().isoformat()
    waivers = load_waivers(args.waivers, today) if args.waivers else []

    audit = Audit(d, zizmor)
    errors = []
    rules = evaluate(audit, catalog, waivers, errors)
    report = build_report(audit, catalog, rules, waivers)

    out = args.out or (d.root.rstrip("/\\") + "-report")
    os.makedirs(out, exist_ok=True)
    written = []

    def write(name, text):
        path = os.path.join(out, name)
        with open(path, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        written.append(path)

    if "json" in formats:
        write("findings.json", render_json(report))
    if "csv" in formats:
        write("findings.csv", render_csv(report))
    if "md" in formats:
        write("report.md", render_markdown(report))
    if "html" in formats:
        with open(CSS_PATH, encoding="utf-8") as fh:
            write("report.html", render_html(report, fh.read()))
    if "docx" in formats:
        path = os.path.join(out, "report.docx")
        render_docx(report, path, args.docx_template)
        written.append(path)

    bs = report["summary"]["by_status"]
    sys.stderr.write("ghe-audit %s: %d rules: %d fail, %d review, %d accepted, %d pass, %d not assessed\n" % (
        TOOL_VERSION, len(rules), bs["fail"], bs["review"], bs["accepted"], bs["pass"], bs["not_assessed"]))
    for path in written:
        sys.stderr.write("  %s\n" % path)
    sys.stderr.write("The report contains customer data. Store it only in the engagement folder.\n")
    if errors:
        warn("%d check(s) failed to run: %s" % (len(errors), ", ".join(e[0] for e in errors)))
        return 2 if args.strict else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
