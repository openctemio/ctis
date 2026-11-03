#!/usr/bin/env python3
"""Developer Certificate of Origin check.

Reads the commit list of a pull request (the JSON array returned by
GET /repos/{owner}/{repo}/pulls/{n}/commits) on stdin and fails when a
commit lacks a "Signed-off-by:" trailer naming its author's e-mail address.

Merge commits and commits authored by GitHub bot accounts are skipped. Commit
messages are untrusted input: they are only parsed here, never executed or
echoed into a shell. Output is one line per commit (short sha and reason).
"""
import json
import re
import sys

SIGNOFF = re.compile(r"^Signed-off-by:\s*(?P<name>[^<\n]+?)\s*<(?P<email>[^>\n]+)>\s*$", re.M)


def check(commits):
    problems = []
    for c in commits:
        sha = (c.get("sha") or "")[:12]
        if len(c.get("parents") or []) > 1:
            continue
        login = ((c.get("author") or {}).get("login") or "")
        if login.endswith("[bot]"):
            continue
        commit = c.get("commit") or {}
        email = ((commit.get("author") or {}).get("email") or "").strip().lower()
        message = commit.get("message") or ""
        signers = {m.group("email").strip().lower() for m in SIGNOFF.finditer(message)}
        if not signers:
            problems.append(f"{sha}: no Signed-off-by trailer")
        elif email not in signers:
            problems.append(f"{sha}: Signed-off-by does not name the commit author's e-mail")
    return problems


def main():
    try:
        commits = json.load(sys.stdin)
    except json.JSONDecodeError:
        print("cannot read the commit list")
        return 2
    if not isinstance(commits, list):
        print("cannot read the commit list")
        return 2
    problems = check(commits)
    for p in problems:
        print(p)
    if problems:
        print("Sign off each commit (git commit -s); see CONTRIBUTING.md.")
        return 1
    print(f"DCO: {len(commits)} commit(s) checked")
    return 0


if __name__ == "__main__":
    sys.exit(main())
