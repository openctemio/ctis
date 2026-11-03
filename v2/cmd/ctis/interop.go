package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/openctemio/ctis/v2"
	"github.com/openctemio/ctis/v2/importer"
	"github.com/openctemio/ctis/v2/interop/cyclonedx"
	"github.com/openctemio/ctis/v2/interop/ocsf"
	"github.com/openctemio/ctis/v2/interop/sarif"

	// The adapters register their formats with package importer.
	_ "github.com/openctemio/ctis/v2/interop/csaf"
	_ "github.com/openctemio/ctis/v2/interop/openvex"
	_ "github.com/openctemio/ctis/v2/interop/spdx"
)

// exporters are the formats "ctis export" writes.
var exporters = map[string]func(*ctis.Report, bool) ([]byte, error){
	"sarif": func(r *ctis.Report, noPass bool) ([]byte, error) {
		return sarif.Export(r, &sarif.ExportOptions{NoPassthrough: noPass})
	},
	"cyclonedx": func(r *ctis.Report, noPass bool) ([]byte, error) {
		return cyclonedx.Export(r, &cyclonedx.ExportOptions{NoPassthrough: noPass})
	},
	"ocsf": func(r *ctis.Report, _ bool) ([]byte, error) { return ocsf.Export(r, nil) },
}

func exportFormats() string {
	names := make([]string, 0, len(exporters))
	for n := range exporters {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// cmdImport converts a file of another format to a CTIS report.
func cmdImport(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "", "input format (default: detected); one of "+formatNames())
	maxSize := fs.Int64("max-size", defaultMaxSize, "largest input to read, in bytes")
	noPass := fs.Bool("no-passthrough", false, "leave out the members the mapping does not list")
	result := fs.Bool("result", false, "print the whole import result (report, VEX statements, counts, issues)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 || *maxSize <= 0 {
		usage(stderr)
		return 2
	}
	raw, err := readInput(fs.Arg(0), stdin, *maxSize)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", fs.Arg(0), err)
		return 2
	}
	res, err := importer.Parse(context.Background(), bytes.NewReader(raw), importer.Options{
		Format:        importer.Format(*format),
		NoPassthrough: *noPass,
		Limits:        importer.Limits{MaxInputBytes: *maxSize},
	})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ctis: %v\n", err)
		var pe *importer.ParseError
		if errors.As(err, &pe) && errors.Is(err, importer.ErrUnknownFormat) {
			return 2
		}
		return 1
	}
	for _, is := range res.Issues {
		_, _ = fmt.Fprintf(stderr, "%s\n", is.String())
	}
	var v any = res.Report
	if *result {
		v = res
	}
	return writeJSON(stdout, stderr, v)
}

// cmdExport writes a CTIS report in another format.
func cmdExport(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "", "output format: "+exportFormats())
	maxSize := fs.Int64("max-size", defaultMaxSize, "largest document to read, in bytes")
	noPass := fs.Bool("no-passthrough", false, "do not write back the members an import kept")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	exp, ok := exporters[*format]
	if fs.NArg() != 1 || *maxSize <= 0 || !ok {
		if !ok {
			_, _ = fmt.Fprintf(stderr, "ctis: --format must be one of %s\n", exportFormats())
		}
		usage(stderr)
		return 2
	}
	raw, err := readInput(fs.Arg(0), stdin, *maxSize)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "%s: %v\n", fs.Arg(0), err)
		return 2
	}
	r, _, err := ctis.Decode(bytes.NewReader(raw))
	if err == nil {
		err = r.Validate()
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ctis: %s is not a valid CTIS document: %v\n", fs.Arg(0), err)
		return 1
	}
	out, err := exp(&r, *noPass)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "ctis: %v\n", err)
		return 1
	}
	_, _ = stdout.Write(append(out, '\n'))
	return 0
}

func formatNames() string {
	var s []string
	for _, f := range importer.AllFormats() {
		s = append(s, string(f))
	}
	return strings.Join(s, ", ")
}

func writeJSON(stdout, stderr io.Writer, v any) int {
	enc := json.NewEncoder(stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_, _ = fmt.Fprintf(stderr, "ctis: %v\n", err)
		return 1
	}
	return 0
}
