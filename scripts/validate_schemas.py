#!/usr/bin/env python3
"""Validate the CTIS schemas and examples with the reference implementation.

  1. every schemas/v1/*.json is a valid draft-07 schema (meta-validation);
  2. every $ref resolves, through a registry built from the files' $ids;
  3. examples/*.json and the converter golden files validate against
     report.json;
  4. examples/invalid/*.json do not;
  5. conformance/v1/documents/manifest.json: every document it lists as valid
     validates, and every one it lists as invalid is rejected, except those
     marked "schema_level": false (only semantic validation refuses them; the
     Go conformance test covers those).

The Go tests use their own small validator (the module has no dependencies);
this script cross-checks it against python-jsonschema.

Usage: python3 scripts/validate_schemas.py   (needs: pip install jsonschema)
"""

import glob
import json
import os
import sys

from jsonschema import Draft7Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT7

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXPECTED = {
    "report.json", "asset.json", "finding.json", "dependency.json",
    "web3-asset.json", "web3-finding.json",
}


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    failures = 0
    schemas = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "schemas", "v1", "*.json"))):
        name = os.path.basename(path)
        schema = load(path)
        Draft7Validator.check_schema(schema)
        schemas[name] = schema
    # Namespace schemas of extensions (informative) must be valid too.
    for path in sorted(glob.glob(os.path.join(ROOT, "schemas", "extensions", "*", "*.json"))):
        Draft7Validator.check_schema(load(path))
        print(f"ok      {os.path.relpath(path, ROOT)} (extension schema)")
    missing = EXPECTED - set(schemas)
    if missing:
        print("MISSING schemas:", ", ".join(sorted(missing)))
        return 1

    registry = Registry().with_resources(
        (s["$id"], Resource.from_contents(s, default_specification=DRAFT7))
        for s in schemas.values()
    )
    validator = Draft7Validator(
        schemas["report.json"], registry=registry, format_checker=FormatChecker()
    )

    # Resolve every $ref once, so a dangling one fails even if no example
    # reaches it.
    def refs(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "$ref":
                    yield v
                else:
                    yield from refs(v)
        elif isinstance(node, list):
            for v in node:
                yield from refs(v)

    for name, schema in schemas.items():
        resolver = registry.resolver(base_uri=schema["$id"])
        for ref in refs(schema):
            try:
                resolver.lookup(ref)
            except Exception as exc:  # noqa: BLE001 - report and continue
                print(f"UNRESOLVABLE $ref {ref!r} in {name}: {exc}")
                failures += 1

    valid = sorted(glob.glob(os.path.join(ROOT, "examples", "*.json")))
    valid += sorted(glob.glob(os.path.join(ROOT, "testdata", "**", "*.golden.json"), recursive=True))
    # Reports made by the sample mappings of importer/mapping.
    valid += sorted(glob.glob(os.path.join(ROOT, "importer", "mapping", "testdata", "*", "expect.ctis.json")))
    for path in valid:
        errors = sorted(validator.iter_errors(load(path)), key=lambda e: list(e.path))
        rel = os.path.relpath(path, ROOT)
        if errors:
            failures += 1
            print(f"INVALID {rel}")
            for e in errors[:20]:
                print(f"  /{'/'.join(map(str, e.path))}: {e.message}")
        else:
            print(f"ok      {rel}")

    for path in sorted(glob.glob(os.path.join(ROOT, "examples", "invalid", "*.json"))):
        rel = os.path.relpath(path, ROOT)
        doc = load(path)
        if validator.is_valid(doc):
            # Some mistakes are only caught by Report.Validate (Go); those
            # are listed here and checked by the Go tests.
            if os.path.basename(path) not in GO_ONLY_INVALID:
                failures += 1
                print(f"ACCEPTED {rel} (must be rejected)")
        else:
            print(f"rejected {rel}")

    failures += check_manifest(validator)

    if not valid:
        print("no examples found")
        failures += 1
    print(f"{len(schemas)} schemas, {len(valid)} valid documents, {failures} failure(s)")
    return 1 if failures else 0


def check_manifest(validator):
    base = os.path.join(ROOT, "conformance", "v1", "documents")
    manifest = load(os.path.join(base, "manifest.json"))
    failures = 0
    for entry in manifest["documents"]:
        path = os.path.normpath(os.path.join(base, entry["file"]))
        rel = os.path.relpath(path, ROOT)
        valid = entry["result"] == "valid"
        if not valid and entry["result"] != "invalid":
            print(f"MANIFEST {rel}: result must be valid or invalid")
            failures += 1
            continue
        if not valid and entry.get("schema_level") is False:
            print(f"skipped  {rel} (semantic-only invalid)")
            continue
        try:
            ok = validator.is_valid(load(path))
        except ValueError:
            # Not JSON at all: invalid for every schema.
            ok = False
        if ok != valid:
            failures += 1
            print(f"MANIFEST {rel}: schema says {'valid' if ok else 'invalid'}, manifest says {entry['result']}")
        else:
            print(f"manifest {rel} ({entry['result']})")
    return failures


# Invalid examples the schema itself cannot reject (none today).
GO_ONLY_INVALID = set()

if __name__ == "__main__":
    sys.exit(main())
