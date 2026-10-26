#!/usr/bin/env bash
#
# install-tools-macos.sh
#
# Installs gh and jq into ~/bin on macOS without Homebrew or admin rights.
# Downloads the latest releases from GitHub and verifies SHA-256 checksums before installing.
#
# Usage: bash scripts/install-tools-macos.sh [--force-jq]
#   --force-jq   Install jq even if a usable jq (>= 1.6) is already on PATH
#
# Afterwards, in the same terminal:  export PATH="$HOME/bin:$PATH"
# Clean up:                          rm -rf ~/ghe-tools ~/bin/gh ~/bin/jq
#
set -euo pipefail

FORCE_JQ=0
[[ "${1:-}" == "--force-jq" ]] && FORCE_JQ=1

[[ "$(uname -s)" == "Darwin" ]] || { echo "This script is for macOS" >&2; exit 1; }

ARCH="$(uname -m)"
[[ "$ARCH" == "x86_64" ]] && ARCH=amd64   # Apple Silicon reports arm64

BIN="$HOME/bin"
WORK="$HOME/ghe-tools"
mkdir -p "$BIN" "$WORK"
cd "$WORK"

# --- gh --------------------------------------------------------------------
V="$(curl -fsSI https://github.com/cli/cli/releases/latest | awk 'tolower($1)=="location:" {print $2}' | tr -d '\r' | sed 's#.*/v##')"
[[ "$V" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Could not determine latest gh version (got '$V')" >&2; exit 1; }
echo "Installing gh ${V} (${ARCH})"

ZIP="gh_${V}_macOS_${ARCH}.zip"
curl -fsSLO "https://github.com/cli/cli/releases/download/v${V}/${ZIP}"
curl -fsSLO "https://github.com/cli/cli/releases/download/v${V}/gh_${V}_checksums.txt"
grep " ${ZIP}\$" "gh_${V}_checksums.txt" | shasum -a 256 -c -
unzip -oq "$ZIP"
cp "gh_${V}_macOS_${ARCH}/bin/gh" "$BIN/gh"
chmod +x "$BIN/gh"

# --- jq --------------------------------------------------------------------
if (( ! FORCE_JQ )) && command -v jq >/dev/null 2>&1 && jq -n '[1] | walk(.)' >/dev/null 2>&1; then
  echo "Using existing $(command -v jq) ($(jq --version))"
else
  echo "Installing jq (${ARCH})"
  curl -fsSLo "jq-macos-${ARCH}" "https://github.com/jqlang/jq/releases/latest/download/jq-macos-${ARCH}"
  curl -fsSLO https://github.com/jqlang/jq/releases/latest/download/sha256sum.txt
  grep " jq-macos-${ARCH}\$" sha256sum.txt | shasum -a 256 -c -
  cp "jq-macos-${ARCH}" "$BIN/jq"
  chmod +x "$BIN/jq"
fi

echo
"$BIN/gh" --version | head -n1
{ [[ -x "$BIN/jq" ]] && "$BIN/jq" --version; } || jq --version
echo
echo "Now run in this terminal:  export PATH=\"\$HOME/bin:\$PATH\""
