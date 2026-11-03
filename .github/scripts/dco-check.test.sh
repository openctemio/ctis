#!/usr/bin/env bash
# Tests .github/scripts/dco-check.py with fixed commit lists.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
check="$here/dco-check.py"
fail=0

run() { # name, want exit code, json
  local name="$1" want="$2" json="$3" got=0
  printf '%s' "$json" | python3 "$check" >/dev/null || got=$?
  if [ "$got" != "$want" ]; then echo "FAIL $name: exit $got, want $want"; fail=1; else echo "ok   $name"; fi
}

c() { # sha, author email, message, [login], [parents]
  python3 -c 'import json,sys; print(json.dumps({"sha":sys.argv[1],"author":{"login":sys.argv[4]},"parents":[{}]*int(sys.argv[5]),"commit":{"author":{"email":sys.argv[2]},"message":sys.argv[3]}}))' "$1" "$2" "$3" "${4:-dev}" "${5:-1}"
}

run "signed" 0 "[$(c a1 dev@example.org $'fix: x\n\nSigned-off-by: Dev <dev@example.org>')]"
run "signed, email case" 0 "[$(c a2 Dev@Example.org $'fix: x\n\nSigned-off-by: Dev <dev@example.org>')]"
run "unsigned" 1 "[$(c a3 dev@example.org 'fix: x')]"
run "signed by someone else" 1 "[$(c a4 dev@example.org $'fix: x\n\nSigned-off-by: Other <other@example.org>')]"
run "sign-off not at line start" 1 "[$(c a5 dev@example.org 'fix: x Signed-off-by: Dev <dev@example.org>')]"
run "merge commit skipped" 0 "[$(c a6 dev@example.org 'Merge main' dev 2)]"
run "bot skipped" 0 "[$(c a7 bot@example.org 'build(deps): bump' 'dependabot[bot]')]"
run "one of two unsigned" 1 "[$(c a8 dev@example.org $'a\n\nSigned-off-by: Dev <dev@example.org>'),$(c a9 dev@example.org 'b')]"
run "not json" 2 "nope"
run "not a list" 2 '{"a":1}'

exit "$fail"
