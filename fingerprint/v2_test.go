package fingerprint

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestV2Format(t *testing.T) {
	got := V2SAST("a.go", "r", 1, 2)
	if !strings.HasPrefix(got, Prefix) || len(got) != len(Prefix)+64 {
		t.Fatalf("bad shape %q", got)
	}
	if got != strings.ToLower(got) {
		t.Fatalf("not lowercase %q", got)
	}
	if got != V2SAST("a.go", "r", 1, 2) {
		t.Fatal("not deterministic")
	}
	// The canonical input is written out here so another language can copy it.
	if enc := EncodeParts("sca", "a:b", "c"); enc != "3:sca\x1f3:a:b\x1f1:c" {
		t.Fatalf("canonical input %q", enc)
	}
	if want := Prefix + Hash("3:sca\x1f3:a:b\x1f1:c"); V2SCA("a:b", "c") != want {
		t.Fatal("sca does not hash the canonical input")
	}
}

// Inputs that recipe v1 mapped to one value must be distinct in v2.
func TestV2CollisionsThatV1Had(t *testing.T) {
	if GenerateSCA("a:b", "c", "d") != GenerateSCA("a", "b:c", "d") { // v1 premise
		t.Fatal("v1 premise changed")
	}
	pairs := [][2]string{
		{V2SCA("a:b", "c"), V2SCA("a", "b:c")},
		{V2SCA("a\x1fb", "c"), V2SCA("a", "b\x1fc")},
		{V2SCA("1:a", "b"), V2SCA("1", "a:b")},
		{V2Misconfiguration("a:b", "c", "r", "f"), V2Misconfiguration("a", "b:c", "r", "f")},
		{V2Compliance("a:b", "c", "d"), V2Compliance("a", "b:c", "d")},
		{V2VA("h", 1, "tcp", "2:3"), V2VA("h", 12, "tcp", ":3")},
		{V2Generic("", "ab", 1, 2), V2Generic("a", "b", 1, 2)},
	}
	for i, p := range pairs {
		if p[0] == "" || p[1] == "" || p[0] == p[1] {
			t.Errorf("pair %d collides or is empty: %q %q", i, p[0], p[1])
		}
	}
}

func TestV2PathsKeepCase(t *testing.T) {
	if V2SAST("src/app.py", "r", 1, 1) == V2SAST("src/App.py", "r", 1, 1) {
		t.Error("paths that differ in case must differ")
	}
	same := []string{"src/App.py", `src\App.py`, "./src/App.py", "src//App.py", "src/./App.py", " src/App.py "}
	want := V2SAST("src/App.py", "r", 1, 1)
	for _, p := range same {
		if got := V2SAST(p, "r", 1, 1); got != want {
			t.Errorf("%q should equal the canonical path", p)
		}
	}
	if V2SAST("/a/b", "r", 1, 1) == V2SAST("a/b", "r", 1, 1) {
		t.Error("absolute and relative paths must differ")
	}
	if V2SAST("Rule", "R", 1, 1) == V2SAST("Rule", "r", 1, 1) {
		t.Error("rule ids keep their case")
	}
}

func TestV2NoMessageNoLinesOutsideLineRecipes(t *testing.T) {
	// SAST content and secret recipes carry no line numbers; none of the
	// recipes read a message (V2Input has no such member).
	a := V2SASTContent("f", "r", "fn", "x  =  1")
	b := V2SASTContent("f", "r", "fn", "x = 1")
	if a == "" || a != b {
		t.Error("sast-content must ignore whitespace")
	}
	if V2SASTContent("f", "r", "fn", " ") != "" {
		t.Error("empty snippet must give no fingerprint")
	}
	var d SecretDigest
	d[0] = 1
	in := V2Input{Type: TypeSecret, FilePath: "f", RuleID: "r", SecretDigest: d}
	x, _ := V2Generate(in)
	in.StartLine, in.EndLine = 5, 6
	y, _ := V2Generate(in)
	if x != y {
		t.Error("secret recipe must not read lines")
	}
}

func TestV2SecretHMACOnly(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	d1, err := NewSecretDigest(key, []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := NewSecretDigest(key, []byte("s3cret2"))
	d3, _ := NewSecretDigest(bytes.Repeat([]byte{8}, 32), []byte("s3cret"))
	if d1 == d2 || d1 == d3 {
		t.Fatal("digest must depend on secret and key")
	}
	if V2Secret("f", "r", d1) == V2Secret("f", "r", d3) {
		t.Fatal("another key must give another fingerprint")
	}
	if _, err := NewSecretDigest([]byte("short"), []byte("x")); err != ErrSecretKey {
		t.Errorf("short key: %v", err)
	}
	if _, err := NewSecretDigest(key, nil); err != ErrEmptySecret {
		t.Errorf("empty secret: %v", err)
	}
	if V2Secret("f", "r", SecretDigest{}) != "" {
		t.Error("zero digest must give no fingerprint")
	}
	if _, err := V2Generate(V2Input{Type: TypeSecret, FilePath: "f", RuleID: "r"}); err == nil {
		t.Error("no digest must be an error")
	}
	// The raw secret and its plain hash appear nowhere in the canonical input.
	_, parts, _ := V2Parts(V2Input{Type: TypeSecret, FilePath: "f", RuleID: "r", SecretDigest: d1})
	for _, p := range parts {
		if strings.Contains(p, "s3cret") || p == Hash("s3cret") {
			t.Errorf("part leaks the secret: %q", p)
		}
	}
	// JSON form is hex and round-trips.
	b, _ := json.Marshal(d1)
	var back SecretDigest
	if err := json.Unmarshal(b, &back); err != nil || back != d1 {
		t.Errorf("json round trip: %v", err)
	}
	if err := json.Unmarshal([]byte(`"ab"`), &back); err == nil {
		t.Error("short digest must be refused")
	}
}

func TestV2Normalisers(t *testing.T) {
	for in, want := range map[string]string{
		"pkg:npm/lodash@4.1?a=b#c":           "pkg:npm/lodash",
		"PKG:Maven/org.x/Lib@1":              "pkg:maven/org.x/Lib",
		"pkg:npm/%40scope/name@1.0.0":        "pkg:npm/%40scope/name",
		"pkg://golang/github.com/a/b@v1.0.0": "pkg:golang/github.com/a/b",
		"\tnpm/lodash":                       "npm/lodash",
		"org.apache:log4j-core":              "org.apache:log4j-core",
	} {
		if got := VersionlessPURL(in); got != want {
			t.Errorf("VersionlessPURL(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"nginx":                              "docker.io/library/nginx",
		"nginx:latest":                       "docker.io/library/nginx",
		"library/nginx":                      "docker.io/library/nginx",
		"user/app:1":                         "docker.io/user/app",
		"index.docker.io/user/app":           "docker.io/user/app",
		"Ghcr.IO/Org/App:tag":                "ghcr.io/Org/App",
		"localhost:5000/app:1":               "localhost:5000/app",
		"reg.example.com:5000/a/b:1":         "reg.example.com:5000/a/b",
		"reg.example.com/a/b@SHA256:" + "AB": "reg.example.com/a/b@sha256:ab",
	} {
		if got := ImageIdentity(in); got != want {
			t.Errorf("ImageIdentity(%q) = %q, want %q", in, got, want)
		}
	}
	if v2Host(" Example.COM. ") != "example.com" {
		t.Error("host")
	}
}

func TestV2DetectAndAuto(t *testing.T) {
	var d SecretDigest
	d[1] = 9
	for _, c := range []struct {
		name string
		in   V2Input
		want Type
	}{
		{"web3", V2Input{ContractAddress: "0x1", RuleID: "SWC-1"}, TypeWeb3},
		{"container", V2Input{ImageRef: "nginx", PackagePURL: "pkg:deb/x"}, TypeContainer},
		{"compliance", V2Input{Framework: "cis", ControlID: "1"}, TypeCompliance},
		{"secret", V2Input{SecretDigest: d, FilePath: "f"}, TypeSecret},
		{"dast", V2Input{URL: "https://a/b"}, TypeDAST},
		{"va", V2Input{AssetValue: "h", Port: 22}, TypeVA},
		{"sca", V2Input{PackagePURL: "pkg:npm/x", VulnerabilityID: "CVE-1-1"}, TypeSCA},
		{"misconfig", V2Input{ResourceType: "t"}, TypeMisconfiguration},
		{"sast-content", V2Input{FilePath: "f", RuleID: "r", Snippet: "x", StartLine: 3}, TypeSASTContent},
		{"sast", V2Input{FilePath: "f", RuleID: "r", StartLine: 3}, TypeSAST},
		{"generic", V2Input{RuleID: "r"}, TypeGeneric},
		{"empty", V2Input{}, TypeGeneric},
	} {
		if got := V2Detect(c.in); got != c.want {
			t.Errorf("%s: detected %q, want %q", c.name, got, c.want)
		}
	}
	in := V2Input{FilePath: "f", RuleID: "r", StartLine: 3, EndLine: 4}
	auto, err := V2Auto(in)
	if err != nil || auto != V2SAST("f", "r", 3, 4) {
		t.Errorf("auto: %q %v", auto, err)
	}
	in.Type = TypeGeneric // an explicit type wins
	if g, _ := V2Auto(in); g != V2Generic("r", "f", 3, 4) {
		t.Error("explicit type must win")
	}
	if _, err := V2Generate(V2Input{Type: "nope"}); err == nil {
		t.Error("unknown type must be an error")
	}
	if V2Web("r", "ftp://x/y", "") != "" {
		t.Error("non-http url must give no fingerprint")
	}
}

func TestV2ContainerAndWebIdentity(t *testing.T) {
	if V2Container("nginx:1", "pkg:deb/d/openssl@1", "CVE-1-1") != V2Container("docker.io/library/nginx:2", "pkg:deb/d/openssl@2", "CVE-1-1") {
		t.Error("tag and package version must not change the key")
	}
	if V2Container("nginx@sha256:"+strings.Repeat("a", 64), "p", "v") == V2Container("nginx@sha256:"+strings.Repeat("b", 64), "p", "v") {
		t.Error("digest must change the key")
	}
	if V2Web("r", "https://EXAMPLE.com:443/a?x=1", "p") != V2Web("r", "https://example.com/a?x=2#f", "p") {
		t.Error("origin and path are normalised, query and fragment dropped")
	}
	if V2Web("r", "https://example.com/A", "p") == V2Web("r", "https://example.com/a", "p") {
		t.Error("url path keeps its case")
	}
	if V2VA("HOST.example.", 22, "TCP", "1") != V2VA("host.example", 22, "tcp", "1") {
		t.Error("va asset value and transport are normalised")
	}
}

// ---- conformance vectors ----

type v2Vector struct {
	Name     string          `json:"name"`
	Type     string          `json:"type"`
	Input    json.RawMessage `json:"input"`
	Parts    []string        `json:"parts"`
	Expected string          `json:"expected"`
	Error    bool            `json:"error"`
}

func TestV2ConformanceVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "conformance", "v2", "fingerprint", "fingerprint.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Recipe string     `json:"recipe"`
		Cases  []v2Vector `json:"cases"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.Recipe != "ctis-fp/2" || len(f.Cases) < 40 {
		t.Fatalf("unexpected vector file: %q, %d cases", f.Recipe, len(f.Cases))
	}
	seen := map[string]string{}
	for _, c := range f.Cases {
		dec := json.NewDecoder(bytes.NewReader(c.Input))
		dec.DisallowUnknownFields()
		var in V2Input
		if err := dec.Decode(&in); err != nil {
			t.Errorf("%s: input: %v", c.Name, err)
			continue
		}
		recipe, parts, err := V2Parts(in)
		got, gerr := V2Generate(in)
		if c.Error {
			if err == nil || gerr == nil || got != "" {
				t.Errorf("%s: must be refused", c.Name)
			}
			continue
		}
		if err != nil || gerr != nil {
			t.Errorf("%s: %v %v", c.Name, err, gerr)
			continue
		}
		if recipe != c.Type || strings.Join(parts, "\x00") != strings.Join(c.Parts, "\x00") || len(parts) != len(c.Parts) {
			t.Errorf("%s: parts %q, want %q", c.Name, parts, c.Parts)
		}
		if got != c.Expected {
			t.Errorf("%s: got %s, want %s", c.Name, got, c.Expected)
		}
		// Equal values must come from equal inputs only: vectors that
		// share a value share their parts.
		if prev, ok := seen[got]; ok && prev != recipe+"\x00"+strings.Join(c.Parts, "\x1e") {
			t.Errorf("%s: collides with a vector of different parts", c.Name)
		}
		seen[got] = recipe + "\x00" + strings.Join(c.Parts, "\x1e")
	}
}

func TestV2SecretDigestVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "conformance", "v2", "fingerprint", "secret-digest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		KeyHex string `json:"key_hex"`
		Cases  []struct{ Secret, Expected string }
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(f.KeyHex)
	if err != nil || len(f.Cases) == 0 {
		t.Fatalf("bad vector file: %v", err)
	}
	for _, c := range f.Cases {
		d, err := NewSecretDigest(key, []byte(c.Secret))
		if err != nil || d.String() != c.Expected {
			t.Errorf("secret %q: %v %s, want %s", c.Secret, err, d, c.Expected)
		}
	}
}
