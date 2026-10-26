# Changelog

## 1.1.0 (2026-10-26)

- English output, comments and documentation
- Runs on bash 3.2 (macOS default); no Homebrew needed
- `scripts/install-tools-macos.sh`: installs `gh` and `jq` into `~/bin` with checksum verification
- `--version` flag
- Test suite against a fake `gh` (`tests/`), and CI on Ubuntu and macOS

## 1.0.0 (2026-10-26)

- First version: read-only collection of enterprise, organization and repository settings, audit log and workflow files from GHE.com
