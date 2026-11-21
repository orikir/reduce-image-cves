#!/usr/bin/env bash
# Check tools and known environment traps before starting. Save the output: the versions go in the report.
# Usage: bash preflight.sh | tee summaries/tools.txt
set -u
DOCKER=${DOCKER:-docker}
fail=0
say() { printf '%-9s %s\n' "$1" "$2"; }

need() {
  if command -v "$1" >/dev/null 2>&1; then say OK "$1: $(eval "$2" 2>&1 | head -1)"
  else say MISSING "$1 - $3"; [ "${4:-req}" = req ] && fail=1; fi
}
need "$DOCKER" "$DOCKER --version" "install docker or podman (set DOCKER=podman)"
need grype "grype version | grep -m1 ^Version" "curl -sSfL https://get.anchore.io/grype | sh -s -- -b ~/.local/bin"
need python3 "python3 --version" "needed for summarize_scan.py / compare_tests.py"
need syft "syft version" "optional (SBOM)" opt
need openssl "openssl version" "optional (test certificates for TLS checks)" opt

if command -v "$DOCKER" >/dev/null 2>&1; then
  if $DOCKER info >/dev/null 2>&1; then say OK "daemon reachable"
  else say FAIL "cannot talk to the $DOCKER daemon (running? user in docker group?)"; fail=1; fi
fi
if command -v grype >/dev/null 2>&1; then
  grype version 2>/dev/null | grep -E '^Version' | sed 's/^/          grype /'
  grype db status 2>&1 | grep -E 'Built|Status' | sed 's/^/          db /'
  echo "          -> record the DB 'Built' date; compare scans only if they used the same DB build"
fi

# --- environment traps seen in practice ---------------------------------------------------------
if command -v "$DOCKER" >/dev/null 2>&1 && { command -v "$DOCKER" | grep -q '^/snap/' || readlink -f "$(command -v "$DOCKER")" | grep -q '/snap'; }; then
  say WARN "docker is a snap: the daemon cannot see /tmp, so bind-mount test files from \$HOME, not mktemp -d"
  if [ -d "$HOME/snap" ] && [ ! -x "$HOME/snap" ]; then
    say WARN "~/snap is not traversable (mode $(stat -c %A "$HOME/snap")): the docker client fails after a snap refresh. Fix: chmod 755 ~/snap"
  fi
fi
if grep -qi microsoft /proc/version 2>/dev/null; then
  say NOTE "WSL: write commands into script files (no inline quoting through PowerShell/Git Bash),"
  say NOTE "     strip CRLF from files edited on Windows: sed -i 's/\\r\$//' <file>"
fi
[ $fail -eq 0 ] && echo "preflight: OK" || { echo "preflight: FIX THE ITEMS ABOVE FIRST"; exit 1; }
