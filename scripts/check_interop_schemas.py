#!/usr/bin/env python3
"""Check the vendored upstream schemas of the interoperability adapters.

  1. interop/upstreams.json is well formed: every format names its repository,
     a tag pattern, its files and the hosts are the pinned ones;
  2. every vendored file exists under v2/interop/<format>/schemas/<version>/ and
     its sha256 equals the one in upstreams.json; no other file is there;
  3. every vendored version of a format has a mapping directory
     v2/interop/<format>/<version>/ and every mapping directory a vendored schema;
  4. with --validate (needs jsonschema): every upstream sample document of
     conformance/interop/<format>/<version>/ validates against the vendored
     schema of that version. References resolve only to vendored files; a
     reference to anything else is an empty schema (nothing is fetched).

Stdlib only for checks 1-3. Exit status 0 when everything holds.
"""
import glob
import hashlib
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOSTS = ["api.github.com", "raw.githubusercontent.com"]
SAFE = re.compile(r"^[A-Za-z0-9._-]+$")

# The vendored schema each format's samples are validated against, by file
# name, and the sample suffix.
MAIN = {
    "sarif": ("sarif-schema-{version}.json", ".sarif.json"),
    "cyclonedx": ("bom-{version}.schema.json", ".cdx.json"),
    "spdx": ("spdx-schema.json", ".spdx.json"),
    "csaf": ("csaf_json_schema.json", ".csaf.json"),
    "openvex": ("openvex_json_schema.json", ".openvex.json"),
}


def fail(errors, msg):
    errors.append(msg)


def check_upstreams(errors):
    path = os.path.join(ROOT, "interop", "upstreams.json")
    with open(path, encoding="utf-8") as f:
        up = json.load(f)
    if up.get("hosts") != HOSTS:
        fail(errors, "upstreams.json: hosts must be exactly %s" % HOSTS)
    formats = up.get("formats") or {}
    for name, fm in formats.items():
        if not SAFE.match(name):
            fail(errors, "upstreams.json: format name %r" % name)
            continue
        for key in ("title", "repo", "tag_pattern", "files", "module", "vendored"):
            if key not in fm:
                fail(errors, "%s: missing %s" % (name, key))
        if not re.match(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", fm.get("repo", "")):
            fail(errors, "%s: repo %r" % (name, fm.get("repo")))
        try:
            if "version" not in re.compile(fm.get("tag_pattern", "")).groupindex:
                fail(errors, "%s: tag_pattern needs a (?P<version>...) group" % name)
        except re.error as e:
            fail(errors, "%s: tag_pattern: %s" % (name, e))
        if fm.get("module") != "v2/interop/" + name:
            fail(errors, "%s: module must be v2/interop/%s" % (name, name))
        seen = set()
        for v in fm.get("vendored", []):
            ver = v.get("version", "")
            if not re.match(r"^\d+(\.\d+){1,2}$", ver) or ver in seen:
                fail(errors, "%s: vendored version %r" % (name, ver))
                continue
            seen.add(ver)
            if not re.match(r"^[A-Za-z0-9._-]{1,64}$", v.get("ref", "")):
                fail(errors, "%s %s: ref %r" % (name, ver, v.get("ref")))
            d = os.path.join(ROOT, "v2", "interop", name, "schemas", ver)
            want = set()
            for fe in v.get("files", []):
                fn = fe.get("file", "")
                if not SAFE.match(fn) or fn != os.path.basename(fe.get("path", "")):
                    fail(errors, "%s %s: file %r" % (name, ver, fn))
                    continue
                want.add(fn)
                p = os.path.join(d, fn)
                if not os.path.isfile(p):
                    fail(errors, "%s %s: %s is missing" % (name, ver, fn))
                    continue
                with open(p, "rb") as f:
                    got = hashlib.sha256(f.read()).hexdigest()
                if got != fe.get("sha256"):
                    fail(errors, "%s %s: %s sha256 %s, upstreams.json says %s" % (name, ver, fn, got, fe.get("sha256")))
            have = set(os.listdir(d)) if os.path.isdir(d) else set()
            for extra in sorted(have - want):
                if extra != "schema-diff.md":
                    fail(errors, "%s %s: %s is not listed in upstreams.json" % (name, ver, extra))
            if not os.path.isdir(os.path.join(ROOT, "v2", "interop", name, ver)):
                fail(errors, "%s %s: no mapping directory v2/interop/%s/%s" % (name, ver, name, ver))
        for d in glob.glob(os.path.join(ROOT, "v2", "interop", name, "[0-9]*")):
            if os.path.basename(d) not in seen:
                fail(errors, "%s: mapping directory %s has no vendored schema" % (name, os.path.basename(d)))
        sdir = os.path.join(ROOT, "v2", "interop", name, "schemas")
        for d in glob.glob(os.path.join(sdir, "*")):
            if os.path.basename(d) not in seen:
                fail(errors, "%s: schemas/%s is not in upstreams.json" % (name, os.path.basename(d)))
    return formats


def validate_samples(errors, formats):
    from jsonschema import Draft202012Validator, FormatChecker
    from jsonschema.validators import validator_for
    from referencing import Registry, Resource
    from referencing.jsonschema import DRAFT202012

    count = 0
    for name, (main_tpl, suffix) in MAIN.items():
        fm = formats.get(name)
        if not fm:
            continue
        for v in fm["vendored"]:
            ver = v["version"]
            d = os.path.join(ROOT, "v2", "interop", name, "schemas", ver)
            resources = []
            for fe in v["files"]:
                with open(os.path.join(d, fe["file"]), encoding="utf-8") as f:
                    s = json.load(f)
                res = Resource.from_contents(s, default_specification=DRAFT202012)
                # Reachable by its $id and by its bare file name, as the
                # upstream schemas refer to each other.
                if s.get("$id"):
                    resources.append((s["$id"], res))
                resources.append((fe["file"], res))
            empty = Resource.from_contents({}, default_specification=DRAFT202012)

            def retrieve(uri):
                return empty  # never fetched: an unvendored reference is open

            registry = Registry(retrieve=retrieve).with_resources(resources)
            with open(os.path.join(d, main_tpl.format(version=ver)), encoding="utf-8") as f:
                schema = json.load(f)
            cls = validator_for(schema, default=Draft202012Validator)
            validator = cls(schema, registry=registry, format_checker=FormatChecker())
            for sample in sorted(glob.glob(os.path.join(ROOT, "conformance", "interop", name, ver, "*" + suffix))):
                with open(sample, encoding="utf-8") as f:
                    doc = json.load(f)
                errs = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
                for e in errs[:5]:
                    fail(errors, "%s: %s at /%s" % (os.path.relpath(sample, ROOT), e.message[:200], "/".join(str(p) for p in e.path)))
                count += 1
    if count == 0:
        fail(errors, "no upstream samples found under conformance/interop")
    return count


def main():
    errors = []
    formats = check_upstreams(errors)
    n = 0
    if "--validate" in sys.argv[1:]:
        n = validate_samples(errors, formats)
    for e in errors:
        print("ERROR:", e)
    if errors:
        return 1
    print("interop schemas: %d formats checked%s" % (len(formats), ", %d samples valid" % n if n else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
