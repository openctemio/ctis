// Command ctis checks CTIS documents and runs the conformance vectors. It
// uses only the standard library, reads only the files it is given (or
// standard input) and never fetches a URL.
//
//	ctis validate [--json] [--max-size BYTES] <file|->...
//	ctis canon <asset-type> <value>
//	ctis conformance [dir]
//	ctis version
//
// Exit status: 0 everything valid, 1 a document is invalid or a vector
// failed, 2 usage or I/O error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/openctemio/ctis"
	"github.com/openctemio/ctis/internal/conformance"
	"github.com/openctemio/ctis/internal/validatedoc"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3".
var version = "dev"

// defaultMaxSize bounds one input document.
const defaultMaxSize = 64 << 20

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "validate":
		return cmdValidate(args[1:], stdin, stdout, stderr)
	case "canon":
		return cmdCanon(args[1:], stdout, stderr)
	case "conformance":
		return cmdConformance(args[1:], stdout, stderr)
	case "version", "--version":
		fmt.Fprintf(stdout, "ctis %s (CTIS %s)\n", version, ctis.SchemaVersion)
		return 0
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	}
	fmt.Fprintf(stderr, "ctis: unknown command %q\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage:
  ctis validate [--json] [--max-size BYTES] <file|->...
  ctis canon <asset-type> <value>
  ctis conformance [dir]
  ctis version
`)
}

// fileResult is one line of "validate --json" output.
type fileResult struct {
	File     string `json:"file"`
	Valid    bool   `json:"valid"`
	Category string `json:"category,omitempty"`
	Problem  string `json:"problem,omitempty"`
}

func cmdValidate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print one JSON object per file")
	maxSize := fs.Int64("max-size", defaultMaxSize, "largest document to read, in bytes")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 || *maxSize <= 0 {
		usage(stderr)
		return 2
	}
	enc := json.NewEncoder(stdout)
	exit := 0
	for _, name := range fs.Args() {
		raw, err := readInput(name, stdin, *maxSize)
		if err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", name, err)
			exit = 2
			continue
		}
		p := validatedoc.Check(raw)
		res := fileResult{File: name, Valid: p == nil}
		if p != nil {
			res.Category, res.Problem = p.Category, p.Message
			if exit == 0 {
				exit = 1
			}
		}
		switch {
		case *asJSON:
			_ = enc.Encode(res)
		case p != nil:
			fmt.Fprintf(stdout, "%s: %s: %s\n", name, p.Category, p.Message)
		default:
			fmt.Fprintf(stdout, "%s: ok\n", name)
		}
	}
	return exit
}

// readInput reads a file, or stdin for "-", and refuses more than limit bytes.
func readInput(name string, stdin io.Reader, limit int64) ([]byte, error) {
	var r io.Reader = stdin
	if name != "-" {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("larger than %d bytes (see --max-size)", limit)
	}
	return raw, nil
}

func cmdCanon(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 {
		usage(stderr)
		return 2
	}
	fmt.Fprintln(stdout, ctis.NormalizeAssetName(ctis.AssetType(args[0]), args[1]))
	return 0
}

func cmdConformance(args []string, stdout, stderr io.Writer) int {
	dir := "conformance"
	switch len(args) {
	case 0:
	case 1:
		dir = args[0]
	default:
		usage(stderr)
		return 2
	}
	results, err := conformance.Run(dir)
	if err != nil {
		fmt.Fprintf(stderr, "ctis: %v\n", err)
		return 2
	}
	bad := conformance.Failures(results)
	for _, r := range bad {
		fmt.Fprintf(stdout, "FAIL %s: %s: %s\n", r.Suite, r.Name, r.Err)
	}
	fmt.Fprintf(stdout, "%d vectors, %d failed\n", len(results), len(bad))
	if len(bad) > 0 {
		return 1
	}
	return 0
}
