#!/usr/bin/env bash
# Prints the directory of every Go module of the repository, the core module
# (".") first. CI loops over them: each adapter (v2/interop/<format>) and the
# command (v2/cmd/ctis) is its own module.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
echo "."
git ls-files '*/go.mod' | xargs -n1 dirname | sort
