package mapping

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/openctemio/ctis/importer"
)

// Bounds of an XML input. The reader is importer.SafeXMLTokenReader: no
// document type declaration of any kind, so no entity can be declared or
// expanded and no external resource is named or read.
const (
	// DefaultMaxXMLElements is the most elements in one document.
	DefaultMaxXMLElements = 4_000_000
	maxXMLAttributes      = 64
	maxXMLNameLen         = 128
)

// xmlElem and xmlList are the decoded forms of an XML element with
// attributes or children, and of a repeated child element. Paths walk them
// leniently (path.get): a member step on a repeated element reads its first
// occurrence, and index 0 of a single element is the element, because one
// XML document may hold one <item> where the next holds several.
type (
	xmlElem map[string]any
	xmlList []any
)

var xmlNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

// xmlSelector is the "each" of an XML mapping: an absolute element path
// from the root ("/testsuites/testsuite/testcase") or every element of one
// name at any depth ("//testcase").
type xmlSelector struct {
	steps    []string
	anyDepth bool
}

func parseXMLSelector(s string) (xmlSelector, error) {
	var sel xmlSelector
	if s == "" {
		return sel, errors.New(`source xml needs each: "/root/item" or "//item"`)
	}
	if len(s) > 512 {
		return sel, errors.New("each is longer than 512 bytes")
	}
	var rest string
	switch {
	case strings.HasPrefix(s, "//"):
		sel.anyDepth = true
		rest = s[2:]
		if strings.Contains(rest, "/") {
			return sel, fmt.Errorf("%q: //name takes one element name", s)
		}
	case strings.HasPrefix(s, "/"):
		rest = s[1:]
	default:
		return sel, fmt.Errorf("%q: each starts with / or //", s)
	}
	for _, st := range strings.Split(rest, "/") {
		if len(st) > maxXMLNameLen || !xmlNameRE.MatchString(st) {
			return sel, fmt.Errorf("%q: element name %q", s, truncate(st, 64))
		}
		sel.steps = append(sel.steps, st)
	}
	if len(sel.steps) > maxPathSteps {
		return sel, fmt.Errorf("%q: more than %d steps", s, maxPathSteps)
	}
	return sel, nil
}

func (s xmlSelector) match(stack []string) bool {
	if s.anyDepth {
		return len(stack) > 0 && stack[len(stack)-1] == s.steps[0]
	}
	if len(stack) != len(s.steps) {
		return false
	}
	for i := range stack {
		if stack[i] != s.steps[i] {
			return false
		}
	}
	return true
}

// xmlNode is an element being built.
type xmlNode struct {
	name     string
	elem     xmlElem
	text     strings.Builder
	children bool
}

// xmlBuilder builds the value of one record element, within a byte budget.
type xmlBuilder struct {
	stack    []*xmlNode
	left     int
	tooLarge bool
	result   any
}

func (b *xmlBuilder) charge(n int) {
	b.left -= n
	if b.left < 0 {
		b.tooLarge = true
	}
}

func (b *xmlBuilder) start(t xml.StartElement) {
	if len(b.stack) > 0 {
		b.stack[len(b.stack)-1].children = true
	}
	n := &xmlNode{name: t.Name.Local}
	b.charge(len(t.Name.Local) + 2)
	for _, a := range t.Attr {
		if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" {
			continue
		}
		b.charge(len(a.Name.Local) + len(a.Value) + 2)
		if b.tooLarge {
			break
		}
		if n.elem == nil {
			n.elem = xmlElem{}
		}
		n.elem["@"+a.Name.Local] = a.Value
	}
	b.stack = append(b.stack, n)
}

func (b *xmlBuilder) text(t xml.CharData) {
	b.charge(len(t))
	if b.tooLarge || len(b.stack) == 0 {
		return
	}
	b.stack[len(b.stack)-1].text.Write(t)
}

// end closes the innermost element; done is true when it was the record.
func (b *xmlBuilder) end() (done bool) {
	n := b.stack[len(b.stack)-1]
	b.stack = b.stack[:len(b.stack)-1]
	var v any
	if !b.tooLarge {
		text := strings.TrimSpace(n.text.String())
		if n.elem == nil && !n.children {
			v = text
		} else {
			if n.elem == nil {
				n.elem = xmlElem{}
			}
			if text != "" {
				n.elem["#text"] = text
			}
			v = n.elem
		}
	}
	if len(b.stack) == 0 {
		b.result = v
		return true
	}
	if b.tooLarge {
		return false
	}
	p := b.stack[len(b.stack)-1]
	if p.elem == nil {
		p.elem = xmlElem{}
	}
	switch prev := p.elem[n.name].(type) {
	case nil:
		p.elem[n.name] = v
	case xmlList:
		p.elem[n.name] = append(prev, v)
	default:
		p.elem[n.name] = xmlList{prev, v}
	}
	return false
}

// xmlInput maps an XML input: every element the each selector names is one
// record, numbered from 1 in document order. An element nested in a
// record is part of that record, never a record of its own.
func (a *applier) xmlInput(ctx context.Context, r io.Reader) error {
	lim := importer.Limits{
		// One byte over the mapping's cap, so Apply reports
		// ErrInputTooLarge for an input over it.
		MaxInputBytes: a.opts.MaxInputBytes + 2,
		MaxDepth:      MaxInputDepth,
		MaxElements:   a.opts.MaxXMLElements,
		MaxAttributes: maxXMLAttributes,
		MaxTextBytes:  a.opts.MaxRecordBytes,
	}
	tr := importer.SafeXMLTokenReader(r, lim)
	var stack []string
	var b *xmlBuilder
	n, roots := 0, 0
	for {
		tok, err := tr.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("mapping: input: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if len(stack) == 0 {
				if roots++; roots > 1 {
					return fmt.Errorf("mapping: input: %w: more than one root element", importer.ErrMalformed)
				}
			}
			stack = append(stack, t.Name.Local)
			if b == nil && a.m.xmlSel.match(stack) {
				b = &xmlBuilder{left: a.opts.MaxRecordBytes}
				n++
			}
			if b != nil {
				b.start(t)
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			if b == nil || !b.end() {
				continue
			}
			rec, tooLarge := b.result, b.tooLarge
			b = nil
			if tooLarge {
				a.issue(n, -1, fmt.Sprintf("element longer than %d bytes", a.opts.MaxRecordBytes))
				a.stats.Skipped++
				if stop, cerr := a.countRecord(); cerr != nil || stop {
					return cerr
				}
				continue
			}
			if stop, err := a.decoded(ctx, n, rec); err != nil || stop {
				return err
			}
		case xml.CharData:
			if b != nil {
				b.text(t)
			}
		}
	}
	if n == 0 {
		a.issue(0, -1, "the each path matched no element")
	}
	return nil
}
