# Changelog

## Unreleased

- Detects organizations that block classic PATs, explains the fix and lists them under `ACTION NEEDED` in `summary.txt` (gh's `admin:org` hint is misleading here)
- Accepts OAuth tokens from `gh auth login` (`gho_...`) as an alternative when organizations block classic PATs: no format warning, `gist` scope allowed, revoke reminder at the end, `token_type` in `meta/run.json`
- Skips calls that need `admin:enterprise` when the token lacks it, and records them as `SKIP` instead of reporting them as failures

## 1.1.0 (2026-10-26)

- English output, comments and documentation
- Runs on bash 3.2 (macOS default); no Homebrew needed
- `scripts/install-tools-macos.sh`: installs `gh` and `jq` into `~/bin` with checksum verification
- `--version` flag
- Test suite against a fake `gh` (`tests/`), and CI on Ubuntu and macOS

## 1.0.0 (2026-10-26)

- First version: read-only collection of enterprise, organization and repository settings, audit log and workflow files from GHE.com
