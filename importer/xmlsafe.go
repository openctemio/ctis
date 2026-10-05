package importer

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

// capReader reads at most limit bytes from r and fails with ErrTooLarge,
// instead of stopping quietly, when the input is longer.
type capReader struct {
	r     io.Reader
	left  int64
	limit int64
}

func newCapReader(r io.Reader, limit int64) *capReader {
	return &capReader{r: r, left: limit, limit: limit}
}

func (c *capReader) Read(p []byte) (int, error) {
	if c.left <= 0 {
		// Probe one byte: input of exactly limit bytes is fine.
		var one [1]byte
		n, err := c.r.Read(one[:])
		if n > 0 {
			return 0, fmt.Errorf("%w: input is larger than %d bytes", ErrTooLarge, c.limit)
		}
		return 0, err
	}
	if int64(len(p)) > c.left {
		p = p[:c.left]
	}
	n, err := c.r.Read(p)
	c.left -= int64(n)
	return n, err
}

// observer records the distinct source field paths of a document, for the
// coverage check and Result.Unmapped.
type observer struct {
	max      int
	seen     map[string]struct{}
	overflow bool
	// rewrite, when set, folds a path before it is recorded (CycloneDX
	// components nest to any depth; their paths fold to one level).
	rewrite func(string) string
}

func newObserver(max int) *observer {
	return &observer{max: max, seen: map[string]struct{}{}}
}

func (o *observer) add(p string) {
	if o == nil {
		return
	}
	if o.rewrite != nil {
		p = o.rewrite(p)
	}
	if _, ok := o.seen[p]; ok {
		return
	}
	if len(o.seen) >= o.max {
		o.overflow = true
		return
	}
	o.seen[p] = struct{}{}
}

func (o *observer) paths() []string {
	out := make([]string, 0, len(o.seen))
	for p := range o.seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// xmlReader is the only way this package reads XML. It is an xml.TokenReader
// over a strict encoding/xml decoder that:
//
//   - refuses a document type declaration with an internal subset, and so
//     every entity declaration; an external identifier is allowed (Qualys
//     names its DTD) and never read;
//   - knows only the five predefined entities (encoding/xml's default);
//   - reads UTF-8, US-ASCII and ISO-8859-1 only, and refuses invalid UTF-8;
//   - bounds the nesting depth, the element count, the attributes per
//     element and the size of a text node;
//   - records the path of every element and attribute it hands out.
//
// Paths are "/"-separated local names from the root, attributes as "@name".
// An element listed in keyAttrs is named by the value of that attribute:
// Nessus' <tag name="host-ip"> is "tag[host-ip]".
type xmlReader struct {
	d        *xml.Decoder
	format   Format
	lim      Limits
	keyAttrs map[string]string
	obs      *observer
	stack    []string
	elements int
}

func newXMLReader(r io.Reader, format Format, lim Limits, keyAttrs map[string]string, obs *observer) *xmlReader {
	d := xml.NewDecoder(bufio.NewReaderSize(newCapReader(r, lim.MaxInputBytes), 64<<10))
	d.Strict = true
	d.CharsetReader = charsetReader
	return &xmlReader{d: d, format: format, lim: lim, keyAttrs: keyAttrs, obs: obs}
}

// path returns the current element path.
func (x *xmlReader) path() string {
	return "/" + strings.Join(x.stack, "/")
}

// fail returns a ParseError at the current input position.
func (x *xmlReader) fail(kind error, msg string) error {
	line, col := x.d.InputPos()
	return &ParseError{Format: x.format, Line: line, Column: col, Msg: msg, Err: kind}
}

// Token returns the next token, enforcing the rules above. Comments,
// processing instructions and the allowed document type declaration are
// dropped.
func (x *xmlReader) Token() (xml.Token, error) {
	for {
		tok, err := x.d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.EOF
			}
			if errors.Is(err, ErrTooLarge) {
				return nil, x.fail(ErrTooLarge, err.Error())
			}
			var pe *ParseError
			if errors.As(err, &pe) {
				return nil, err
			}
			var se *xml.SyntaxError
			if errors.As(err, &se) {
				return nil, &ParseError{Format: x.format, Line: se.Line, Msg: se.Msg, Err: ErrMalformed}
			}
			if errors.Is(err, errCharset) {
				return nil, x.fail(ErrUnsafe, err.Error())
			}
			return nil, x.fail(ErrMalformed, err.Error())
		}
		switch t := tok.(type) {
		case xml.Directive:
			if err := checkDirective(t); err != nil {
				return nil, x.fail(ErrUnsafe, err.Error())
			}
			continue
		case xml.Comment, xml.ProcInst:
			continue
		case xml.StartElement:
			x.elements++
			if x.elements > x.lim.MaxElements {
				return nil, x.fail(ErrTooLarge, fmt.Sprintf("more than %d elements", x.lim.MaxElements))
			}
			if len(x.stack)+1 > x.lim.MaxDepth {
				return nil, x.fail(ErrTooLarge, fmt.Sprintf("elements nested deeper than %d", x.lim.MaxDepth))
			}
			if len(t.Attr) > x.lim.MaxAttributes {
				return nil, x.fail(ErrTooLarge, fmt.Sprintf("<%s> has more than %d attributes", t.Name.Local, x.lim.MaxAttributes))
			}
			seg := t.Name.Local
			if attr, ok := x.keyAttrs[seg]; ok {
				if v := attrValue(t, attr); v != "" {
					seg += "[" + pathKey(v) + "]"
				}
			}
			x.stack = append(x.stack, seg)
			p := x.path()
			x.obs.add(p)
			for _, a := range t.Attr {
				if a.Name.Space == "xmlns" || a.Name.Local == "xmlns" || a.Name.Space == "http://www.w3.org/2000/xmlns/" {
					continue
				}
				if len(a.Value) > x.lim.MaxTextBytes {
					return nil, x.fail(ErrTooLarge, fmt.Sprintf("attribute %s is larger than %d bytes", a.Name.Local, x.lim.MaxTextBytes))
				}
				x.obs.add(p + "/@" + a.Name.Local)
			}
			return t, nil
		case xml.EndElement:
			if len(x.stack) > 0 {
				x.stack = x.stack[:len(x.stack)-1]
			}
			return t, nil
		case xml.CharData:
			if len(t) > x.lim.MaxTextBytes {
				return nil, x.fail(ErrTooLarge, fmt.Sprintf("text of %s is larger than %d bytes", x.path(), x.lim.MaxTextBytes))
			}
			return t, nil
		default:
			return tok, nil
		}
	}
}

// pathKey bounds a key value used in a path and keeps it printable.
func pathKey(v string) string {
	v = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '/' || r == '[' || r == ']' {
			return '_'
		}
		return r
	}, v)
	if len(v) > 128 {
		v = v[:128]
		for !utf8.ValidString(v) {
			v = v[:len(v)-1]
		}
	}
	return v
}

func attrValue(t xml.StartElement, name string) string {
	for _, a := range t.Attr {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

// checkDirective allows only <!DOCTYPE name>, optionally with an external
// identifier (SYSTEM "uri" or PUBLIC "id" "uri"). An internal subset ("[")
// is where entity declarations live, so it is refused whole: no entity
// expansion, no billion laughs, no external entity. encoding/xml never reads
// the external identifier.
func checkDirective(d xml.Directive) error {
	s := strings.TrimSpace(string(d))
	upper := strings.ToUpper(s)
	if !strings.HasPrefix(upper, "DOCTYPE") {
		return fmt.Errorf("markup declaration <!%s> is not allowed", firstWord(s))
	}
	if strings.ContainsAny(s, "[]<>%&") || strings.Contains(upper, "ENTITY") {
		return errors.New("a document type declaration with an internal subset or entities is not allowed")
	}
	return nil
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " \t\r\n"); i > 0 {
		s = s[:i]
	}
	if len(s) > 16 {
		s = s[:16]
	}
	return s
}

var errCharset = errors.New("unsupported character encoding")

// charsetReader accepts the declared encodings this package reads besides
// UTF-8 (which encoding/xml reads itself).
func charsetReader(label string, input io.Reader) (io.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "us-ascii", "ascii":
		return input, nil
	case "iso-8859-1", "iso8859-1", "latin1", "latin-1", "l1":
		return &latin1Reader{r: bufio.NewReader(input)}, nil
	}
	return nil, fmt.Errorf("%w %q (UTF-8, US-ASCII and ISO-8859-1 are read)", errCharset, label)
}

// latin1Reader decodes ISO-8859-1 to UTF-8.
type latin1Reader struct {
	r       *bufio.Reader
	pending []byte
}

func (l *latin1Reader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(l.pending) > 0 {
			c := copy(p[n:], l.pending)
			l.pending = l.pending[c:]
			n += c
			continue
		}
		b, err := l.r.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		if b < 0x80 {
			p[n] = b
			n++
			continue
		}
		var buf [2]byte
		w := utf8.EncodeRune(buf[:], rune(b))
		l.pending = append(l.pending[:0], buf[:w]...)
	}
	return n, nil
}
