#!/usr/bin/env python3
"""
Tests for ghe-audit.py. Builds small ghe-collect output directories in a temp folder:
a "good" one where every rule should pass, a "bad" one where every rule should fail or
need review, and focused ones for edge cases (missing data, redaction, renderers).

Usage: python3 -m unittest discover -s tests -p 'test_audit.py'
"""
import csv
import importlib.util
import io
import json
import os
import re
import shutil
import tempfile
import unittest
import zipfile
from xml.dom import minidom

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location("ghe_audit", os.path.join(ROOT, "ghe-audit.py"))
ga = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ga)

SHA = "0123456789abcdef0123456789abcdef01234567"
GQL = lambda owner_info: {"data": {"enterprise": {"ownerInfo": owner_info}}}


def build(tmp, files, index=(), scopes=("repo", "read:org", "read:enterprise", "read:audit_log", "read:repo_hook")):
    """Write an output directory. files: {rel: obj or str}. index: [(status, endpoint, rel)]."""
    files = dict(files)
    files.setdefault("meta/run.json", {
        "script_version": "test", "host": "test.ghe.com", "enterprise": "ent", "user": "auditor",
        "token_scopes": list(scopes), "started": "2026-10-26T12:00:00Z", "params": {"audit_days": 90}})
    for rel, data in files.items():
        path = os.path.join(tmp, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(data if isinstance(data, str) else json.dumps(data))
    rows = ["time\tstatus\tcategory\tendpoint\tfile"]
    rows += ["2026-10-26T12:00:00Z\t%s\tx\t%s\t%s" % (st, ep, rel) for st, ep, rel in index]
    rows += ["2026-10-26T12:00:00Z\t200\tx\t/%s\t%s" % (rel, rel) for rel in files if rel.endswith(".json")]
    with open(os.path.join(tmp, "index.tsv"), "w") as fh:
        fh.write("\n".join(rows) + "\n")
    return tmp


def good_files():
    E, O, R = "enterprise/", "orgs/o/", "orgs/o/repos/r/"
    return {
        E + "graphql-policies.json": GQL({
            "defaultRepositoryPermissionSetting": "READ", "membersCanChangeRepositoryVisibilitySetting": "DISABLED",
            "membersCanDeleteRepositoriesSetting": "DISABLED", "allowPrivateRepositoryForkingSetting": "DISABLED",
            "membersCanInviteCollaboratorsSetting": "DISABLED"}),
        E + "graphql-identity-provider.json": GQL({"oidcProvider": {"providerType": "AAD"}, "samlIdentityProvider": None}),
        E + "graphql-ip-allow-list.json": [GQL({"ipAllowListEnabledSetting": "ENABLED",
                                                "ipAllowListEntries": {"nodes": [{"name": "office"}]}})],
        E + "graphql-admins.json": [GQL({"admins": {"edges": [
            {"role": "OWNER", "node": {"login": n}} for n in ("a", "b", "c")] + [
            {"role": "BILLING_MANAGER", "node": {"login": "z"}}]}})],
        E + "graphql-counts.json": GQL({"outsideCollaborators": {"totalCount": 0}}),
        E + "actions-permissions.json": {"enabled_organizations": "all", "allowed_actions": "selected",
                                         "sha_pinning_required": True},
        E + "actions-selected-actions.json": {"github_owned_allowed": True, "patterns_allowed": ["corp/*"]},
        E + "actions-workflow-permissions.json": {"default_workflow_permissions": "read",
                                                  "can_approve_pull_request_reviews": False},
        E + "actions-fork-pr-approval.json": {"approval_policy": "all_external_contributors"},
        E + "actions-runner-groups.json": [{"total_count": 1, "runner_groups": [
            {"name": "Default", "visibility": "selected", "allows_public_repositories": False}]}],
        E + "actions-runners.json": [{"total_count": 1, "runners": [{"name": "r1"}]}],
        E + "code-security-defaults.json": [{"default_for_new_repos": "all",
                                             "configuration": {"name": "Corp", "enforcement": "enforced"}}],
        E + "audit-log-streams.json": [{"enabled": True, "stream_type": "Splunk"}],
        E + "copilot-seats.json": [{"total_seats": 1, "seats": [
            {"assignee": {"login": "u"}, "last_activity_at": "2026-10-20T10:00:00Z"}]}],
        E + "audit-log-web.ndjson": json.dumps({"action": "repo.create", "actor": "u", "@timestamp": 1761480000000}) + "\n",
        O + "org.json": {"login": "o", "default_repository_permission": "read",
                         "members_can_fork_private_repositories": False},
        O + "owners.json": [{"login": n} for n in ("a", "b", "c")],
        O + "outside-collaborators.json": [],
        O + "rule-suites-bypass-30d.json": [],
        O + "rulesets/1.json": {"id": 1, "name": "main", "enforcement": "active",
                                "bypass_actors": [{"actor_type": "Team", "actor_id": 5, "bypass_mode": "pull_request"}]},
        O + "actions-permissions.json": {"enabled_repositories": "all", "allowed_actions": "local_only",
                                         "sha_pinning_required": True},
        O + "actions-workflow-permissions.json": {"default_workflow_permissions": "read",
                                                  "can_approve_pull_request_reviews": False},
        O + "actions-fork-pr-approval.json": {"approval_policy": "all_external_contributors"},
        O + "actions-runner-groups.json": [{"total_count": 0, "runner_groups": []}],
        O + "actions-runners.json": [{"total_count": 0, "runners": []}],
        O + "actions-secrets.json": [{"total_count": 1, "secrets": [{"name": "S", "visibility": "selected"}]}],
        O + "code-security-defaults.json": [{"default_for_new_repos": "private_and_internal",
                                             "configuration": {"name": "Corp", "enforcement": "enforced"}}],
        O + "alerts-secret-scanning-open.json": [],
        O + "alerts-dependabot-open.json": [],
        O + "alerts-code-scanning-open.json": [],
        O + "webhooks.json": [{"id": 1, "active": True,
                               "config": {"url": "https://hooks.example/x", "secret": "********", "insecure_ssl": "0"}}],
        O + "app-installations.json": [{"total_count": 1, "installations": [
            {"id": 1, "app_slug": "ci", "repository_selection": "selected", "permissions": {"contents": "write"}}]}],
        O + "repos.json": [{"name": "r", "archived": False, "default_branch": "main"},
                           {"name": "old", "archived": True, "default_branch": "main"}],
        R + "repo.json": {"name": "r", "security_and_analysis": {
            "secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "enabled"}}},
        R + "collaborators-direct.json": [{"login": "a", "permissions": {"admin": True}},
                                          {"login": "dev", "permissions": {"admin": False, "push": True}}],
        R + "effective-rules-default-branch.json": [
            {"type": "pull_request", "parameters": {"required_approving_review_count": 1, "dismiss_stale_reviews_on_push": True,
                                                    "require_code_owner_review": True}},
            {"type": "non_fast_forward"}, {"type": "deletion"}, {"type": "required_status_checks"}],
        R + "CODEOWNERS": "* @o/team\n",
        R + "codeowners-errors.json": {"errors": []},
        R + "deploy-keys.json": [{"title": "k", "read_only": True}],
        R + "environments.json": [{"total_count": 1, "environments": [
            {"name": "production", "protection_rules": [{"type": "required_reviewers"}],
             "deployment_branch_policy": {"protected_branches": True}}]}],
        R + "actions-workflow-permissions.json": {"default_workflow_permissions": "read",
                                                  "can_approve_pull_request_reviews": False},
        R + "dependabot-alerts-enabled.json": {"_http_status": 204},
        R + "dependabot-security-updates.json": {"enabled": True},
        R + "code-security-configuration.json": {"status": "attached", "configuration": {
            "name": "Corp", "code_scanning_default_setup": "enabled"}},
        "orgs/o/repos/old/repo.json": {"name": "old", "archived": True},
        "workflows/o/r/ci.yml": "permissions:\n  contents: read\non: push\njobs:\n  b:\n    runs-on: x\n    steps:\n"
                                "      - uses: actions/checkout@v4\n      - uses: corp/build@%s # v1\n" % SHA,
    }


def bad_files():
    E, O, R = "enterprise/", "orgs/o/", "orgs/o/repos/r/"
    f = good_files()
    f.update({
        E + "graphql-policies.json": GQL({
            "defaultRepositoryPermissionSetting": "WRITE", "membersCanChangeRepositoryVisibilitySetting": "ENABLED",
            "membersCanDeleteRepositoriesSetting": "ENABLED", "allowPrivateRepositoryForkingSetting": "ENABLED",
            "membersCanInviteCollaboratorsSetting": "ENABLED"}),
        E + "graphql-identity-provider.json": GQL({"oidcProvider": None, "samlIdentityProvider": None}),
        E + "graphql-ip-allow-list.json": [GQL({"ipAllowListEnabledSetting": "DISABLED", "ipAllowListEntries": {"nodes": []}})],
        E + "graphql-admins.json": [GQL({"admins": {"edges": [{"role": "OWNER", "node": {"login": "solo"}}]}})],
        E + "graphql-counts.json": GQL({"outsideCollaborators": {"totalCount": 2}}),
        E + "actions-permissions.json": {"enabled_organizations": "all", "allowed_actions": "all", "sha_pinning_required": False},
        E + "actions-workflow-permissions.json": {"default_workflow_permissions": "write",
                                                  "can_approve_pull_request_reviews": True},
        E + "actions-fork-pr-approval.json": {"approval_policy": "first_time_contributors"},
        E + "actions-runner-groups.json": [{"total_count": 1, "runner_groups": [
            {"name": "Default", "visibility": "all", "allows_public_repositories": True}]}],
        E + "code-security-defaults.json": [{"default_for_new_repos": "public", "configuration": {"name": "GitHub recommended"}}],
        E + "audit-log-streams.json": [],
        E + "copilot-seats.json": [{"total_seats": 1, "seats": [{"assignee": {"login": "idle"}, "last_activity_at": None}]}],
        E + "audit-log-web.ndjson": "\n".join(json.dumps(e) for e in (
            {"action": "secret_scanning_push_protection.bypass", "actor": "dev", "repo": "o/r", "@timestamp": 1761480000000},
            {"action": "protected_branch.destroy", "actor": "dev", "repo": "o/r", "@timestamp": 1761480000000},
            {"action": "org.secret_scanning_push_protection_disable", "actor": "adm", "org": "o", "@timestamp": 1761480000000},
            {"action": "repo.access", "actor": "dev", "repo": "o/r", "visibility": "internal",
             "previous_visibility": "private", "@timestamp": 1761480000000},
            {"action": "repo.register_self_hosted_runner", "actor": "ops", "repo": "o/r", "@timestamp": 1761480000000},
        )) + "\n",
        O + "org.json": {"login": "o", "default_repository_permission": "write", "members_can_fork_private_repositories": True},
        O + "owners.json": [{"login": "o%d" % i} for i in range(7)],
        O + "outside-collaborators.json": [{"login": "contractor"}],
        O + "rule-suites-bypass-30d.json": [{"repository_name": "r", "actor_name": "dev"}],
        O + "rulesets/1.json": {"id": 1, "name": "main", "enforcement": "active",
                                "bypass_actors": [{"actor_type": "OrganizationAdmin", "actor_id": None, "bypass_mode": "always"}]},
        O + "actions-permissions.json": {"enabled_repositories": "all", "allowed_actions": "all", "sha_pinning_required": False},
        O + "actions-workflow-permissions.json": {"default_workflow_permissions": "write",
                                                  "can_approve_pull_request_reviews": True},
        O + "actions-fork-pr-approval.json": {"approval_policy": "first_time_contributors_new_to_github"},
        O + "actions-runner-groups.json": [{"total_count": 1, "runner_groups": [
            {"name": "Default", "visibility": "all", "allows_public_repositories": False, "restricted_to_workflows": False}]}],
        O + "actions-runners.json": [{"total_count": 1, "runners": [{"name": "r1"}]}],
        O + "actions-secrets.json": [{"total_count": 1, "secrets": [{"name": "DEPLOY_KEY", "visibility": "all"}]}],
        O + "code-security-defaults.json": [],
        O + "alerts-secret-scanning-open.json": [{"secret_type_display_name": "AWS", "created_at": "2026-01-01T00:00:00Z",
                                                  "repository": {"full_name": "o/r"}, "push_protection_bypassed": True}],
        O + "alerts-dependabot-open.json": [{"security_advisory": {"severity": "critical"}, "repository": {"full_name": "o/r"}}],
        O + "alerts-code-scanning-open.json": [{"rule": {"security_severity_level": "high"}, "repository": {"full_name": "o/r"}}],
        O + "webhooks.json": [{"id": 1, "active": True, "config": {"url": "http://hooks.example/x", "insecure_ssl": "1"}}],
        O + "app-installations.json": [{"total_count": 1, "installations": [
            {"id": 1, "app_slug": "bot", "repository_selection": "all", "permissions": {"contents": "write", "metadata": "read"}}]}],
        R + "repo.json": {"name": "r", "security_and_analysis": {
            "secret_scanning": {"status": "disabled"}, "secret_scanning_push_protection": {"status": "disabled"}}},
        R + "collaborators-direct.json": [{"login": "eve", "permissions": {"admin": True}}],
        R + "effective-rules-default-branch.json": [],
        R + "codeowners-errors.json": {"errors": [{"line": 1, "kind": "Unknown owner"}]},
        R + "deploy-keys.json": [{"title": "ci", "read_only": False, "created_at": "2024-01-01T00:00:00Z"}],
        R + "environments.json": [{"total_count": 1, "environments": [
            {"name": "prod", "protection_rules": [], "deployment_branch_policy": None}]}],
        R + "actions-workflow-permissions.json": {"default_workflow_permissions": "write",
                                                  "can_approve_pull_request_reviews": True},
        R + "dependabot-alerts-enabled.json": {"_http_status": "404"},
        R + "dependabot-security-updates.json": {"enabled": False},
        R + "code-security-configuration.json": {"_http_status": 204},
        "workflows/o/r/ci.yml": "on:\n  pull_request_target:\njobs:\n  b:\n    steps:\n"
                                "      - uses: actions/checkout@v4\n        with:\n"
                                "          ref: ${{ github.event.pull_request.head.sha }}\n"
                                "      - uses: corp/build@v1\n",
    })
    return f


BAD_INDEX = [("404", "/repos/o/r/branches/main/protection", "orgs/o/repos/r/branch-protection-default-branch.json")]
ZIZMOR = [{"ident": "template-injection", "desc": "code injection via template expansion",
           "url": "https://docs.zizmor.sh/audits/#template-injection",
           "determinations": {"confidence": "High", "severity": "High", "persona": "Regular"},
           "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": "workflows/o/r/ci.yml"}}}}], "ignored": False}]

EXPECTED_BAD = {
    "review": {"IAM-06", "BRP-07", "BRP-08", "ACT-07", "SEC-05", "INT-03", "AUD-02", "AUD-03", "AUD-04", "AUD-05", "HYG-01"},
    "info": {"AUD-06"},
}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_audit(self, files, index=(), zizmor=None, waivers=(), **kw):
        d = ga.OutputDir(build(os.path.join(self.tmp, "out"), files, index, **kw))
        errors = []
        audit = ga.Audit(d, zizmor)
        rules = ga.evaluate(audit, ga.load_catalog(), list(waivers), errors)
        self.assertEqual(errors, [], "checks raised exceptions")
        return audit, {r["id"]: r for r in rules}


class CatalogTest(unittest.TestCase):
    def test_catalog_and_checks_match(self):
        cat = ga.load_catalog()
        ids = [r["id"] for r in cat["rules"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate rule IDs")
        self.assertEqual(set(ids), set(ga.CHECKS), "catalog entries and check functions differ")

    def test_catalog_fields(self):
        cat = ga.load_catalog()
        areas = {a["id"] for a in cat["areas"]}
        for r in cat["rules"]:
            self.assertIn(r["area"], areas, r["id"])
            self.assertIn(r["severity"], ga.SEVERITIES, r["id"])
            self.assertIn(r["scope"], ("enterprise", "org", "repo"), r["id"])
            for k in ("title", "rationale", "remediation"):
                self.assertTrue(r.get(k), "%s: %s missing" % (r["id"], k))
            self.assertTrue(r["references"], r["id"])
            for ref in r["references"]:
                self.assertTrue(ref["url"].startswith("https://"), r["id"])


class RulesTest(Base):
    def test_good_output_passes_every_rule(self):
        _, rules = self.run_audit(good_files(), zizmor=[])
        wrong = {i: (r["status"], [x["detail"] for x in r["results"] if x["status"] != "pass"])
                 for i, r in rules.items() if r["status"] != "pass"}
        self.assertEqual(wrong, {})

    def test_bad_output_fails_every_rule(self):
        _, rules = self.run_audit(bad_files(), BAD_INDEX, zizmor=ZIZMOR)
        for rid, r in rules.items():
            expected = next((s for s, ids in EXPECTED_BAD.items() if rid in ids), "fail")
            self.assertEqual(r["status"], expected, "%s: %s" % (rid, r["results"]))

    def test_admin_enterprise_files_are_not_assessed_with_reason(self):
        files = {k: v for k, v in good_files().items() if k not in ga.ADMIN_ENTERPRISE_FILES}
        _, rules = self.run_audit(files, zizmor=[])
        for rid in ("IAM-01", "IAM-02", "AUD-01"):
            self.assertEqual(rules[rid]["status"], "not_assessed", rid)
            self.assertIn("admin:enterprise", rules[rid]["results"][0]["detail"])
        ent = [x for x in rules["ACT-01"]["results"] if x["target"] == "ent"][0]
        self.assertEqual(ent["status"], "not_assessed")

    def test_uncollected_org_is_not_assessed(self):
        index = [("403", "/orgs/blocked", "orgs/blocked/org.json")]
        _, rules = self.run_audit(good_files(), index, zizmor=[])
        for rid in ("BRP-01", "SEC-07", "IAM-04"):
            na = [x for x in rules[rid]["results"] if x["target"] == "blocked"]
            self.assertEqual(len(na), 1, rid)
            self.assertEqual(na[0]["status"], "not_assessed")
            self.assertIn("403", na[0]["detail"])
        self.assertEqual(rules["BRP-01"]["status"], "pass")

    def test_unreadable_classic_protection_is_not_a_failure(self):
        f = bad_files()
        index = [("403", "/repos/o/r/branches/main/protection", "orgs/o/repos/r/branch-protection-default-branch.json")]
        _, rules = self.run_audit(f, index, zizmor=ZIZMOR)
        self.assertEqual(rules["BRP-02"]["results"][0]["status"], "not_assessed")

    def test_classic_branch_protection_counts(self):
        f = good_files()
        f["orgs/o/repos/r/effective-rules-default-branch.json"] = []
        f["orgs/o/repos/r/branch-protection-default-branch.json"] = {
            "required_pull_request_reviews": {"required_approving_review_count": 2, "dismiss_stale_reviews": True,
                                              "require_code_owner_reviews": True},
            "allow_force_pushes": {"enabled": False}, "allow_deletions": {"enabled": False},
            "required_status_checks": {"contexts": ["ci"]}, "enforce_admins": {"enabled": True}}
        _, rules = self.run_audit(f, zizmor=[])
        for rid in ("BRP-01", "BRP-02", "BRP-03", "BRP-04", "BRP-05", "BRP-06", "BRP-07"):
            self.assertEqual(rules[rid]["status"], "pass", rid)

    def test_archived_repos_are_skipped(self):
        _, rules = self.run_audit(good_files(), zizmor=[])
        self.assertNotIn("o/old", {x["target"] for x in rules["BRP-01"]["results"]})

    def test_webhook_url_secrets_are_not_reported(self):
        f = bad_files()
        f["orgs/o/webhooks.json"] = [{"id": 1, "config": {"url": "https://user:pw@hooks.example/p?token=SECRET"}}]
        _, rules = self.run_audit(f, BAD_INDEX)
        text = json.dumps(rules["INT-01"])
        self.assertNotIn("SECRET", text)
        self.assertNotIn("pw@", text)
        self.assertIn("https://hooks.example/p", text)

    def test_zizmor_old_path_key(self):
        old = [dict(ZIZMOR[0], locations=[{"symbolic": {"key": {"Local": {"given_path": "x/workflows/o/r/ci.yml"}}}}])]
        _, rules = self.run_audit(bad_files(), BAD_INDEX, zizmor=old)
        self.assertEqual(rules["WFL-04"]["results"][0]["target"], "o/r/ci.yml")

    def test_zizmor_missing_is_not_assessed(self):
        _, rules = self.run_audit(good_files())
        self.assertEqual(rules["WFL-04"]["status"], "not_assessed")

    def test_waivers(self):
        waivers = [{"rule": "IAM-04", "target": "o", "reason": "Break-glass accounts"}]
        _, rules = self.run_audit(bad_files(), BAD_INDEX, ZIZMOR, waivers)
        self.assertEqual(rules["IAM-04"]["status"], "accepted")
        self.assertEqual(rules["IAM-04"]["results"][0]["waiver"]["reason"], "Break-glass accounts")

    def test_expired_waiver_is_ignored(self):
        path = os.path.join(self.tmp, "w.json")
        with open(path, "w") as fh:
            json.dump({"waivers": [{"rule": "IAM-04", "expires": "2000-01-01"}]}, fh)
        self.assertEqual(ga.load_waivers(path, "2026-10-26"), [])

    def test_nested_output_folder_is_found(self):
        build(os.path.join(self.tmp, "outer", "ghe-collect-x"), good_files())
        d = ga.OutputDir(os.path.join(self.tmp, "outer"))
        self.assertTrue(d.root.endswith("ghe-collect-x"))


class RenderTest(Base):
    def report(self, files=None, index=BAD_INDEX):
        f = files or bad_files()
        audit, rules = self.run_audit(f, index, ZIZMOR)
        return ga.build_report(audit, ga.load_catalog(), list(rules.values()), [])

    def test_html_is_self_contained_and_escaped(self):
        f = bad_files()
        f["orgs/o/outside-collaborators.json"] = [{"login": "<script>alert(1)</script>"}]
        with open(ga.CSS_PATH) as fh:
            page = ga.render_html(self.report(f), fh.read())
        self.assertNotIn("<script", page)
        self.assertNotRegex(page, r"(?i)<(link|img|iframe|object|embed)\b")
        self.assertNotRegex(page, r"(?i)\bsrc=")
        self.assertNotIn("url(", page)
        self.assertIn("Content-Security-Policy", page)

    def test_csv_neutralizes_formulas(self):
        f = bad_files()
        f["orgs/o/repos/r/deploy-keys.json"] = [{"title": "=HYPERLINK(\"x\")", "read_only": False}]
        rows = list(csv.reader(io.StringIO(ga.render_csv(self.report(f)))))
        for row in rows:
            for cell in row:
                self.assertFalse(cell[:1] in ("=", "+", "@"), cell)

    def test_markdown_and_json(self):
        rep = self.report()
        md = ga.render_markdown(rep)
        self.assertIn("## Findings", md)
        self.assertIn("BRP-01", md)
        data = json.loads(ga.render_json(rep))
        self.assertEqual(data["summary"]["rules"], len(ga.load_catalog()["rules"]))
        for r in data["rules"]:
            self.assertIn(r["status"], ga.STATUSES)

    def _check_docx(self, path):
        with zipfile.ZipFile(path) as z:
            self.assertIsNone(z.testzip())
            for n in z.namelist():
                if n.endswith(".xml") or n.endswith(".rels"):
                    minidom.parseString(z.read(n))
            return {n: z.read(n) for n in z.namelist()}

    def test_docx(self):
        path = os.path.join(self.tmp, "r.docx")
        ga.render_docx(self.report(), path)
        parts = self._check_docx(path)
        doc = parts["word/document.xml"].decode()
        self.assertIn("BRP-01", doc)
        # Every table needs a grid, or Word reports the file as damaged
        self.assertEqual(doc.count("<w:tbl>"), doc.count("<w:tblGrid>"))
        self.assertGreater(doc.count("<w:tbl>"), 3)
        self.assertIn(b"hyperlink", parts["word/_rels/document.xml.rels"])

    def test_docx_template(self):
        tpl = os.path.join(self.tmp, "tpl.docx")
        W = 'xmlns:w="%s" xmlns:r="%s"' % (ga.W_NS, ga.R_NS)
        with zipfile.ZipFile(tpl, "w") as z:
            z.writestr("word/document.xml", '<w:document %s><w:body><w:p/><w:sectPr><w:headerReference w:type="default" '
                                            'r:id="rId9"/></w:sectPr></w:body></w:document>' % W)
            z.writestr("word/_rels/document.xml.rels",
                       '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                       '<Relationship Id="rId9" Type="%s/header" Target="header1.xml"/></Relationships>' % ga.R_NS)
            z.writestr("word/header1.xml", '<w:hdr %s><w:p><w:r><w:t>CONFIDENTIAL</w:t></w:r></w:p></w:hdr>' % W)
            z.writestr("word/styles.xml", '<w:styles %s><w:style w:type="paragraph" w:styleId="Heading1">'
                                          '<w:name w:val="HOUSE"/></w:style></w:styles>' % W)
        path = os.path.join(self.tmp, "r.docx")
        ga.render_docx(self.report(), path, tpl)
        parts = self._check_docx(path)
        self.assertIn(b"CONFIDENTIAL", parts["word/header1.xml"])
        self.assertIn(b"HOUSE", parts["word/styles.xml"])
        self.assertIn(b'w:styleId="Title"', parts["word/styles.xml"])
        self.assertEqual(parts["word/styles.xml"].count(b'w:styleId="Heading1"'), 1)
        self.assertIn(b"header1.xml", parts["[Content_Types].xml"])

    def test_cli_writes_all_formats(self):
        out = build(os.path.join(self.tmp, "out"), bad_files(), BAD_INDEX)
        zpath = os.path.join(self.tmp, "z.json")
        with open(zpath, "w") as fh:
            json.dump(ZIZMOR, fh)
        rc = ga.main([out, "--out", os.path.join(self.tmp, "rep"), "--zizmor", zpath, "--strict"])
        self.assertEqual(rc, 0)
        self.assertEqual(sorted(os.listdir(os.path.join(self.tmp, "rep"))),
                         ["findings.csv", "findings.json", "report.docx", "report.html", "report.md"])


if __name__ == "__main__":
    unittest.main()
