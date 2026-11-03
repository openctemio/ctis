#!/usr/bin/env python3
"""Run the CTIS conformance vectors against any implementation.

The implementation is a command that speaks the line protocol of
conformance/PROTOCOL.md on its standard input and output: one JSON request
per line in, one JSON answer per line out. The harness walks
conformance/v2, turns every vector into a request, and compares the answers.

    python3 scripts/conformance_harness.py [options] -- <command> [args...]

    # the Go reference implementation
    python3 scripts/conformance_harness.py -- ctis conformance --serve

Options:
    --vectors DIR        the vectors (default: conformance/v2 next to this script)
    --only OP[,OP...]    run only these operations
    --strict-messages    also require the message substrings of expected errors
                         (the Go reference words its messages as the vectors say;
                         other implementations match on the category only)
    --timeout SECONDS    longest wait for one answer (default 30)
    --list               print the cases per suite without running anything
    -v, --verbose        print every failing case in full

Exit status: 0 every case passed (optional operations the implementation
does not provide are skipped), 1 a case failed, 2 usage or protocol error.
Python standard library only.
"""

import argparse
import glob
import json
import os
import queue
import subprocess
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The core operations every implementation provides; the others belong to
# the declarative mapping language and the interoperability engine.
REQUIRED_OPS = [
    "canonical", "asset_key", "vulnerability_id", "preferred_id", "location_key",
    "fingerprint", "secret_digest", "correlation_key", "web_url", "decode", "validate",
]
OPTIONAL_OPS = ["mapping_apply", "interop_path_match", "interop_select", "interop_collect"]


class Case:
    def __init__(self, suite, name, op, inp, want=None, want_err=None):
        self.suite, self.name, self.op, self.input = suite, name, op, inp
        self.want, self.want_err = want, want_err


class Loader:
    """Builds the cases of every vector family (same rules as the Go runner,
    internal/conformance/cases.go)."""

    def __init__(self, vdir):
        self.dir = vdir
        self.cases = []
        self.errors = []  # (suite, message): a vector file that cannot be read

    def load(self, suite):
        try:
            with open(os.path.join(self.dir, suite), encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError) as e:
            self.errors.append((suite, "load: %s" % e))
            return None

    def add(self, suite, name, op, inp, want=None, want_err=None):
        self.cases.append(Case(suite, name, op, inp, want, want_err))

    def ref(self, sub, inline, file, text):
        if not file:
            return inline
        with open(os.path.join(self.dir, sub, file), encoding="utf-8", newline="") as f:
            raw = f.read()
        return raw if text else json.loads(raw)

    def all(self):
        files = sorted(glob.glob(os.path.join(self.dir, "canonical", "*.json")))
        if not files:
            self.errors.append(("canonical", "no canonical/*.json"))
        for path in files:
            self.canonical(os.path.relpath(path, self.dir).replace(os.sep, "/"))
        self.simple("vulnerability-id.json", "vulnerability_id", lambda c: {"id": c["id"]}, lambda c: c.get("expected"))
        self.simple("location-key.json", "location_key", lambda c: {"finding": c["finding"]}, lambda c: c["expected"])
        self.simple("preferred-id.json", "preferred_id", lambda c: {"vulnerability": c["vulnerability"]}, lambda c: c.get("expected"))
        self.fingerprint()
        self.secret_digest()
        self.simple(
            "correlation/correlation.json", "correlation_key",
            lambda c: {"asset_key": c["asset_key"], "tool": c["tool"], "finding": c["finding"]},
            lambda c: {"vulnerability_id": c.get("vulnerability_id", ""), "location_key": c.get("location_key", ""), "key": c["expected"]},
        )
        self.web_url()
        self.decode()
        self.documents()
        self.mapping()
        self.interop()
        return self

    def canonical(self, suite):
        f = self.load(suite)
        if f is None:
            return
        if not f.get("vectors"):
            self.errors.append((suite, "no vectors"))
        for i, v in enumerate(f.get("vectors", [])):
            fn = v.get("function") or f.get("function")
            name = "%d %s %s" % (i, fn, json.dumps(v["input"], ensure_ascii=False))
            err = {"category": "canonical"} if v.get("error") else None
            if fn == "AssetKey":
                self.add(suite, name, "asset_key", v["input"], v.get("output"), err)
            else:
                self.add(suite, name, "canonical", {"function": fn, "value": v["input"]}, v.get("output"), err)

    def simple(self, suite, op, inp, want):
        f = self.load(suite)
        if f is None:
            return
        for c in f["cases"]:
            self.add(suite, c["name"], op, inp(c), want(c))

    def fingerprint(self):
        suite = "fingerprint/fingerprint.json"
        f = self.load(suite)
        if f is None:
            return
        for c in f["cases"]:
            inp = {"input": c["input"]}
            if c.get("detect"):
                inp["detect"] = True
            want = {"recipe": c.get("type", ""), "parts": c.get("parts") or [], "value": c.get("expected", "")}
            self.add(suite, c["name"], "fingerprint", inp, want, {"category": "fingerprint"} if c.get("error") else None)

    def secret_digest(self):
        suite = "fingerprint/secret-digest.json"
        f = self.load(suite)
        if f is None:
            return
        for i, c in enumerate(f["cases"]):
            self.add(suite, str(i), "secret_digest", {"key_hex": f["key_hex"], "secret": c["secret"]}, c["expected"])

    def web_url(self):
        suite = "weburl/urls.json"
        f = self.load(suite)
        if f is None:
            return
        for i, c in enumerate(f["cases"]):
            name = "%d %s" % (i, json.dumps(c["in"], ensure_ascii=False))
            if c.get("error"):
                self.add(suite, name, "web_url", {"url": c["in"]}, None, {"category": "web_url"})
            else:
                want = {"origin": c["origin"], "path": c["path"], "template": c["template"], "params": c.get("params") or []}
                self.add(suite, name, "web_url", {"url": c["in"]}, want)

    def decode(self):
        suite = "decode/decode.json"
        f = self.load(suite)
        if f is None:
            return
        for c in f["cases"]:
            inp = {"text": c["text"]} if "text" in c else {"document": c["document"]}
            self.add(suite, c["name"], "decode", inp, c.get("expected"), c.get("error"))

    def documents(self):
        suite = "documents"
        base = os.path.join(self.dir, "documents")
        m = self.load("documents/manifest.json")
        if m is None:
            return
        for e in m["documents"]:
            try:
                with open(os.path.join(base, e["file"]), encoding="utf-8", newline="") as f:
                    text = f.read()
            except OSError as err:
                self.errors.append((suite, "%s: %s" % (e["file"], err)))
                continue
            if e["result"] == "valid":
                self.add(suite, e["file"], "validate", {"text": text}, {"valid": True})
            elif e["result"] == "invalid":
                self.add(suite, e["file"], "validate", {"text": text}, None,
                         {"category": e.get("category", ""), "message": e.get("error", "")})
            else:
                self.errors.append((suite, "%s: result %r" % (e["file"], e["result"])))

    def mapping(self):
        suite = "mapping/vectors.json"
        f = self.load(suite)
        if f is None:
            return
        for c in f["cases"]:
            try:
                req = {
                    "mapping": self.ref("mapping", c.get("mapping"), c.get("mapping_file"), False),
                    "input": self.ref("mapping", c.get("input"), c.get("input_file"), True),
                }
                if "options" in c:
                    req["options"] = c["options"]
                if "error" in c:
                    self.add(suite, c["name"], "mapping_apply", req, None, c["error"])
                    continue
                report = self.ref("mapping", c.get("expected_report"), c.get("expected_report_file"), False)
            except (OSError, ValueError) as e:
                self.errors.append((suite, "%s: %s" % (c["name"], e)))
                continue
            self.add(suite, c["name"], "mapping_apply", req, {"report": report, "stats": c.get("expected_stats")})

    def interop(self):
        f = self.load("interop-engine/path.json")
        if f is not None:
            for c in f["cases"]:
                self.add("interop-engine/path.json", c["pattern"] + " ~ " + c["path"], "interop_path_match",
                         {"pattern": c["pattern"], "path": c["path"]}, c["match"])
        f = self.load("interop-engine/select.json")
        if f is not None:
            for c in f["cases"]:
                self.add("interop-engine/select.json", c["name"], "interop_select",
                         {"mappings": f["mappings"], "document": c["document"]}, c.get("expected"), c.get("error"))
        f = self.load("interop-engine/collect.json")
        if f is not None:
            for c in f["cases"]:
                self.add("interop-engine/collect.json", c["name"], "interop_collect",
                         {"mapping": c["mapping"], "document": c["document"], "records": c.get("records") or []},
                         c.get("expected"), c.get("error"))


def normal(v):
    """A value in a canonical form for comparison: integral floats as ints."""
    if isinstance(v, float) and v.is_integer() and abs(v) < 2**53:
        return int(v)
    if isinstance(v, list):
        return [normal(x) for x in v]
    if isinstance(v, dict):
        return {k: normal(x) for k, x in v.items()}
    return v


def canon(v):
    return json.dumps(normal(v), sort_keys=True, ensure_ascii=False, separators=(",", ":"))


class Implementation:
    def __init__(self, argv, timeout):
        self.timeout = timeout
        try:
            self.proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr)
        except OSError as e:
            raise ProtocolError("cannot start %s: %s" % (argv[0], e))
        self.lines = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()
        self.next_id = 0

    def _read(self):
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def call(self, op, inp):
        self.next_id += 1
        req = {"id": self.next_id, "op": op}
        if inp is not None:
            req["input"] = inp
        data = (json.dumps(req, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise ProtocolError("cannot write to the implementation: %s" % e)
        try:
            line = self.lines.get(timeout=self.timeout)
        except queue.Empty:
            raise ProtocolError("no answer within %ss to request %d (%s)" % (self.timeout, self.next_id, op))
        if line is None:
            raise ProtocolError("the implementation exited (request %d, %s)" % (self.next_id, op))
        try:
            ans = json.loads(line)
        except ValueError:
            raise ProtocolError("answer is not JSON: %r" % line[:200])
        if not isinstance(ans, dict) or ans.get("id") != self.next_id:
            raise ProtocolError("answer %r does not carry id %d" % (line[:200], self.next_id))
        if ("output" in ans) == ("error" in ans):
            raise ProtocolError("answer %d has neither or both of output and error" % self.next_id)
        return ans

    def close(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class ProtocolError(Exception):
    pass


def check(case, ans, strict_messages):
    """None when the answer meets the case, else why not."""
    if case.want_err is not None:
        if "error" not in ans:
            return "expected an error, got %s" % canon(ans["output"])
        err = ans["error"]
        cat = case.want_err.get("category", "")
        if cat and err.get("category") != cat:
            return "category %s, want %s (%s)" % (err.get("category"), cat, err.get("message", ""))
        msg = case.want_err.get("message", "")
        if strict_messages and msg and msg not in err.get("message", ""):
            return "message %r does not contain %r" % (err.get("message", ""), msg)
        return None
    if "error" in ans:
        return "error %s: %s" % (ans["error"].get("category"), ans["error"].get("message"))
    got, want = canon(ans["output"]), canon(case.want)
    if got != want:
        return "got %s, want %s" % (got, want)
    return None


def main():
    ap = argparse.ArgumentParser(description="Run the CTIS conformance vectors against an implementation.")
    ap.add_argument("--vectors", default=os.path.join(ROOT, "conformance", "v2"))
    ap.add_argument("--only", default="")
    ap.add_argument("--strict-messages", action="store_true")
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("command", nargs=argparse.REMAINDER)
    args = ap.parse_args()
    cmd = args.command[1:] if args.command[:1] == ["--"] else args.command

    loader = Loader(args.vectors).all()
    cases = loader.cases
    only = {o for o in args.only.split(",") if o}
    if only:
        cases = [c for c in cases if c.op in only]

    if args.list:
        per = {}
        for c in cases:
            per[c.suite] = per.get(c.suite, 0) + 1
        for s in sorted(per):
            print("%6d  %s" % (per[s], s))
        print("cases: %d" % len(cases))
        return 0 if not loader.errors else 1
    if not cmd:
        ap.error("give the implementation command after --")

    stats = {}  # op -> [passed, failed, skipped]
    failures = []
    impl = None
    try:
        impl = Implementation(cmd, args.timeout)
        info = impl.call("info", None)
        if "error" in info or not isinstance(info.get("output"), dict):
            raise ProtocolError("the info operation failed: %s" % info)
        provided = set(info["output"].get("ops", []))
        print("implementation: %s %s (CTIS %s)" % (info["output"].get("implementation"), info["output"].get("version"), info["output"].get("ctis")))
        for c in cases:
            s = stats.setdefault(c.op, [0, 0, 0])
            if c.op not in provided:
                if c.op in REQUIRED_OPS:
                    s[1] += 1
                    failures.append((c, "required operation %s is not provided" % c.op))
                else:
                    s[2] += 1
                continue
            ans = impl.call(c.op, c.input)
            if "error" in ans and ans["error"].get("category") in ("protocol", "unsupported") and (c.want_err is None or c.want_err.get("category") not in ("protocol", "unsupported")):
                s[1] += 1
                failures.append((c, "%s error: %s" % (ans["error"].get("category"), ans["error"].get("message"))))
                continue
            why = check(c, ans, args.strict_messages)
            if why is None:
                s[0] += 1
            else:
                s[1] += 1
                failures.append((c, why))
    except ProtocolError as e:
        print("protocol error: %s" % e, file=sys.stderr)
        if impl is not None:
            impl.close()
        return 2
    impl.close()

    for suite, msg in loader.errors:
        failures.append((Case(suite, "load", "-", None), msg))
    for c, why in failures:
        line = "FAIL %s: %s: %s" % (c.suite, c.name, why)
        print(line if args.verbose or len(line) < 400 else line[:400] + "...")
    print("%-20s %7s %7s %7s" % ("operation", "passed", "failed", "skipped"))
    for op in REQUIRED_OPS + OPTIONAL_OPS:
        if op in stats:
            p, f, s = stats[op]
            print("%-20s %7d %7d %7d%s" % (op, p, f, s, "" if op in REQUIRED_OPS else "  (optional)"))
    total = sum(sum(v) for v in stats.values())
    print("cases: %d, failed: %d" % (total, len(failures)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
