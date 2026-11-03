package fingerprint

import "testing"

type pinCase struct {
	name string
	in   Input
	want string
}

func pinCases() []pinCase {
	return []pinCase{
		{"sast", Input{Type: TypeSAST, FilePath: `Src\App.py`, RuleID: "Rule.1", StartLine: 10, EndLine: 12}, "1a8b16c66fa71a4294fe54e42d10b840bb95a2d4b9c742ba93ea905b22e68306"},
		{"sast-content", Input{Type: TypeSASTContent, FilePath: "src/App.py", RuleID: "Rule.1", LogicalLocation: "app.main", Snippet: "eval( x )"}, "2aa20cff1449b517d2112f71c8244368e600c2d565fc3b6c583dcfe914b940b9"},
		{"sca", Input{Type: TypeSCA, PackageName: "lodash", PackageVersion: "4.17.20", VulnerabilityID: "CVE-2021-23337"}, "9f1db051a46c4baac14700fead4409a55b87a5daeaecc735132329518c73a91b"},
		{"sca maven name with colon", Input{Type: TypeSCA, PackageName: "org.apache.logging.log4j:log4j-core", PackageVersion: "2.14.1", VulnerabilityID: "CVE-2021-44228"}, "72f165439991783aeaa1949d68d5dfe3ed904ca841507ef18dc8d31cbb1954ab"},
		{"secret", Input{Type: TypeSecret, FilePath: "deploy/env.sh", RuleID: "aws-access-token", StartLine: 3, SecretValue: "AKIAIOSFODNN7EXAMPLE"}, "286eb0ac58d2fe3f1ef175f11069bab31fb91ab4431e66e4f5422ec0518fd231"},
		{"misconfig", Input{Type: TypeMisconfiguration, ResourceType: "aws_s3_bucket", ResourceName: "logs", RuleID: "AVD-AWS-0086", FilePath: "main.tf"}, "817fddf90b66c1372bcd16d5cc4d0ece4e60daed331cf35aa224f40037190013"},
		{"dast", Input{Type: TypeDAST, RuleID: "xss-reflected", TargetHost: "Example.com:443", TargetPath: "/Search?q=1", Parameter: "q"}, "d93f2aede04bc12f9622684d53ddbcc372b87559dd29def6db30097eaca88af7"},
		{"container", Input{Type: TypeContainer, ImageTarget: "nginx:latest", PackageName: "openssl", PackageVersion: "3.0.1", VulnerabilityID: "CVE-2022-0778"}, "0b64188ae34990c6e875773d676aa0807926d145dadafb9e6626144a0023f7d2"},
		{"web3", Input{Type: TypeWeb3, ContractAddress: "0xAbC0000000000000000000000000000000000001", ChainID: 1, SWCID: "SWC-101", FunctionSignature: "transfer(address,uint256)"}, "b7f98c7f14d02f24d9fb6ee893e0998e48afd7879f3acca3eb53c94746f0de5d"},
		{"generic", Input{Type: TypeGeneric, RuleID: "r", FilePath: "a.txt", StartLine: 1, EndLine: 2, Message: "m"}, "6c4218cba8b7b0c49621ddbdc5b970e989d6af3d545c7b9ad57196cc9a574bba"},
		// The joiner is ":" in the recipes above, so these two different
		// inputs share a value. Recipe v2 fixes it; v1 stays as is.
		{"ambiguity a", Input{Type: TypeSCA, PackageName: "a:b", PackageVersion: "c", VulnerabilityID: "d"}, "cd0222f355620b2e62d398e0196b5bd5c3faf30275b3ae33df593a401b64a0d0"},
		{"ambiguity b", Input{Type: TypeSCA, PackageName: "a", PackageVersion: "b:c", VulnerabilityID: "d"}, "cd0222f355620b2e62d398e0196b5bd5c3faf30275b3ae33df593a401b64a0d0"},
	}
}

// TestRecipeV1Pinned pins the v1 recipe outputs. Receivers store these
// values and compare them across producers and releases, so a change here is
// a breaking change of the standard, not a refactor. The ":" joiner of the
// recipes is ambiguous (a package name that contains ":" can shift into the
// next field, as maven names do); escaping it would change stored
// fingerprints, so the ambiguity is fixed only by recipe v2 at CTIS 2.0.
func TestRecipeV1Pinned(t *testing.T) {
	for _, c := range pinCases() {
		if got := Generate(c.in); got != c.want {
			t.Errorf("%s: v1 output changed: %s, want %s", c.name, got, c.want)
		}
	}
}
