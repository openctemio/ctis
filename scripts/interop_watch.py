#!/usr/bin/env python3
"""Upstream watcher of the interoperability adapters.

  interop_watch.py plan                     list new upstream versions (JSON lines)
  interop_watch.py apply FORMAT VERSION TAG vendor that version and prepare its mapping

plan reads interop/upstreams.json, lists the tags of each format's official
repository and reports, per format, every version newer than the newest one
vendored (a new upstream version), and every vendored version whose latest
release tag differs from the pinned one (a corrected schema).

apply downloads the schema files of FORMAT at TAG, checks that each is JSON
(nothing upstream is executed), writes them to v2/interop/FORMAT/schemas/VERSION/,
records their sha256 in upstreams.json, writes schema-diff.md against the
previous vendored version, and for a new version copies the latest mapping
directory to v2/interop/FORMAT/VERSION/ as the starting point.

Network: only https to the hosts upstreams.json pins (api.github.com,
raw.githubusercontent.com); redirects elsewhere are refused. Stdlib only.
GITHUB_TOKEN, when set, is sent to api.github.com only.
"""
import hashlib
import json
import os
import re
import shutil
import sys
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAMS = os.path.join(ROOT, "interop", "upstreams.json")
MAX_FILE = 8 << 20
SAFE = re.compile(r"^[A-Za-z0-9._-]+$")


def load():
    with open(UPSTREAMS, encoding="utf-8") as f:
        return json.load(f)


class PinnedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_url(newurl, self.hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def check_url(url, hosts):
    u = urllib.parse.urlparse(url)
    if u.scheme != "https" or u.hostname not in hosts or u.port not in (None, 443) or u.username or u.password:
        raise SystemExit("refused URL outside the pinned hosts: %s" % url)


def fetch(url, hosts, api=False):
    check_url(url, hosts)
    req = urllib.request.Request(url, headers={"User-Agent": "ctis-interop-watch"})
    token = os.environ.get("GITHUB_TOKEN", "")
    if api and token and urllib.parse.urlparse(url).hostname == "api.github.com":
        req.add_header("Authorization", "Bearer " + token)
        req.add_header("Accept", "application/vnd.github+json")
    opener = urllib.request.build_opener(PinnedRedirect(hosts))
    with opener.open(req, timeout=30) as resp:
        data = resp.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise SystemExit("refused: %s is larger than %d bytes" % (url, MAX_FILE))
    return data


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def tags(fm, hosts):
    out = []
    for page in range(1, 6):
        url = "https://api.github.com/repos/%s/tags?per_page=100&page=%d" % (fm["repo"], page)
        batch = json.loads(fetch(url, hosts, api=True))
        if not batch:
            break
        out += [t["name"] for t in batch if isinstance(t, dict) and isinstance(t.get("name"), str)]
    return out


def plan(up):
    hosts = up["hosts"]
    for name, fm in sorted(up["formats"].items()):
        if os.environ.get("INTEROP_FORMAT") and os.environ["INTEROP_FORMAT"] != name:
            continue
        pat = re.compile(fm["tag_pattern"])
        latest = {}
        for t in tags(fm, hosts):
            m = pat.match(t)
            if not m:
                continue
            v = m.group("version")
            if v not in latest or vkey(t) > vkey(latest[v]):
                latest[v] = t
        vendored = {v["version"]: v["ref"] for v in fm["vendored"]}
        newest = max((vkey(v) for v in vendored), default=())
        # The newest new version only: one pull request per format, from
        # the latest vendored mapping.
        new = [v for v in latest if v not in vendored and vkey(v) > newest]
        if new:
            v = max(new, key=vkey)
            print(json.dumps({"format": name, "version": v, "tag": latest[v], "kind": "new"}))
        for v, t in sorted(latest.items(), key=lambda x: vkey(x[0])):
            if v in vendored and pat.match(vendored[v]) and vkey(t) > vkey(vendored[v]):
                print(json.dumps({"format": name, "version": v, "tag": t, "kind": "refresh"}))


def fill(tpl, version):
    parts = version.split(".") + ["0", "0"]
    return tpl.format(version=version, major=parts[0], minor=parts[1])


def walk(node, path, out):
    if isinstance(node, dict):
        for k in sorted(node):
            walk(node[k], path + "/" + k, out)
    else:
        out.add(path)


def schema_diff(old_path, new_path):
    def members(p):
        with open(p, encoding="utf-8") as f:
            s = json.load(f)
        out = set()
        walk(s, "", out)
        return {m for m in out if "/properties/" in m or "/enum" in m or "/required" in m}

    old, new = members(old_path), members(new_path)
    lines = ["Added (%d):" % len(new - old)] + ["+ " + m for m in sorted(new - old)[:500]]
    lines += ["", "Removed (%d):" % len(old - new)] + ["- " + m for m in sorted(old - new)[:500]]
    return "\n".join(lines)


def apply(up, name, version, tag):
    hosts = up["hosts"]
    fm = up["formats"].get(name)
    if fm is None or not SAFE.match(name) or not re.match(r"^\d+(\.\d+){1,2}$", version):
        raise SystemExit("unknown format or bad version")
    m = re.compile(fm["tag_pattern"]).match(tag)
    if not m or m.group("version") != version:
        raise SystemExit("tag %s does not name version %s" % (tag, version))
    dest = os.path.join(ROOT, "v2", "interop", name, "schemas", version)
    os.makedirs(dest, exist_ok=True)
    files = []
    for tpl in fm["files"]:
        path = fill(tpl, version)
        url = "https://raw.githubusercontent.com/%s/%s/%s" % (fm["repo"], urllib.parse.quote(tag), urllib.parse.quote(path))
        data = fetch(url, hosts)
        json.loads(data)  # JSON only: nothing upstream is executed
        fn = os.path.basename(path)
        if not SAFE.match(fn):
            raise SystemExit("unsafe file name %r" % fn)
        with open(os.path.join(dest, fn), "wb") as f:
            f.write(data)
        files.append({"path": path, "file": fn, "sha256": hashlib.sha256(data).hexdigest()})
    vendored = [v for v in fm["vendored"] if v["version"] != version]
    prev = max(vendored, key=lambda v: vkey(v["version"]), default=None)
    vendored.append({"version": version, "ref": tag, "files": files})
    fm["vendored"] = sorted(vendored, key=lambda v: vkey(v["version"]))
    if prev is not None:
        diff = ["# %s %s schema diff (from %s)" % (fm["title"], version, prev["version"]), ""]
        for i, fe in enumerate(files):
            # The same template of the previous version.
            if i >= len(prev["files"]):
                continue
            old = os.path.join(ROOT, "v2", "interop", name, "schemas", prev["version"], prev["files"][i]["file"])
            if os.path.isfile(old):
                diff += ["## " + fe["file"], "", "```", schema_diff(old, os.path.join(dest, fe["file"])), "```", ""]
        with open(os.path.join(dest, "schema-diff.md"), "w", encoding="utf-8") as f:
            f.write("\n".join(diff) + "\n")
        mdir = os.path.join(ROOT, "v2", "interop", name, version)
        src = os.path.join(ROOT, "v2", "interop", name, prev["version"])
        if not os.path.isdir(mdir) and os.path.isdir(src):
            shutil.copytree(src, mdir)
            for p in os.listdir(mdir):
                fp = os.path.join(mdir, p)
                with open(fp, encoding="utf-8") as f:
                    text = f.read()
                text = text.replace('"version": "%s"' % prev["version"], '"version": "%s"' % version, 1)
                with open(fp, "w", encoding="utf-8") as f:
                    f.write(text)
    with open(UPSTREAMS, "w", encoding="utf-8") as f:
        json.dump(up, f, indent=2)
        f.write("\n")
    print(json.dumps({"format": name, "version": version, "tag": tag, "files": [f["file"] for f in files]}))


def main(argv):
    up = load()
    if argv[:1] == ["plan"]:
        plan(up)
    elif len(argv) == 4 and argv[0] == "apply":
        apply(up, argv[1], argv[2], argv[3])
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
