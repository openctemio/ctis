package importer

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"unicode"
)

// ArchiveLimits bound what OpenZip accepts. Zero fields take the defaults of
// DefaultArchiveLimits.
type ArchiveLimits struct {
	// Most files in the archive (directories are not counted).
	MaxEntries int
	// Largest uncompressed file.
	MaxEntryBytes int64
	// Largest sum of the uncompressed files.
	MaxTotalBytes int64
	// Largest ratio of uncompressed to compressed size of one file, checked
	// as the file is read, once it is past 1 MiB.
	MaxRatio int64
}

// DefaultArchiveLimits returns the limits a zero ArchiveLimits stands for.
func DefaultArchiveLimits() ArchiveLimits {
	return ArchiveLimits{MaxEntries: 100, MaxEntryBytes: 256 << 20, MaxTotalBytes: 1 << 30, MaxRatio: 200}
}

func (l ArchiveLimits) withDefaults() ArchiveLimits {
	d := DefaultArchiveLimits()
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxEntryBytes <= 0 {
		l.MaxEntryBytes = d.MaxEntryBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
	if l.MaxRatio <= 0 {
		l.MaxRatio = d.MaxRatio
	}
	return l
}

// ArchiveFile is one file of an archive.
type ArchiveFile struct {
	// The file's path inside the archive, cleaned. It is only a label: it is
	// never used to create a file.
	Name string
	// Uncompressed size as the archive declares it (the reader enforces the
	// limits on the real size).
	DeclaredSize int64

	f     *zip.File
	lim   ArchiveLimits
	total *int64
}

// Open returns the file's content. The reader fails with ErrTooLarge as soon
// as the file passes MaxEntryBytes, the archive passes MaxTotalBytes, or the
// file decompresses at more than MaxRatio.
func (a ArchiveFile) Open() (io.ReadCloser, error) {
	rc, err := a.f.Open()
	if err != nil {
		return nil, &ParseError{Msg: fmt.Sprintf("archive file %s: %v", a.Name, err), Err: ErrMalformed}
	}
	return &bombGuard{rc: rc, name: a.Name, lim: a.lim, compressed: int64(a.f.CompressedSize64), total: a.total}, nil
}

// IsZip reports whether head starts like a ZIP archive.
func IsZip(head []byte) bool {
	return bytes.HasPrefix(head, []byte("PK\x03\x04")) || bytes.HasPrefix(head, []byte("PK\x05\x06"))
}

// OpenZip lists the regular files of a ZIP archive. It refuses the whole
// archive when an entry has an absolute path, a ".." element, a backslash,
// a drive letter or a control character in its name, is a link or another
// non-regular file, is encrypted, or is itself an archive, and when there
// are more than MaxEntries files. Nothing is ever written to disk.
func OpenZip(r io.ReaderAt, size int64, lim ArchiveLimits) ([]ArchiveFile, error) {
	lim = lim.withDefaults()
	zr, err := zip.NewReader(r, size)
	if errors.Is(err, zip.ErrInsecurePath) {
		return nil, &ParseError{Msg: "archive has an entry with an unsafe path", Err: ErrUnsafe}
	}
	if err != nil {
		return nil, &ParseError{Msg: "not a readable ZIP archive: " + err.Error(), Err: ErrMalformed}
	}
	var total int64
	var out []ArchiveFile
	for _, f := range zr.File {
		name := f.Name
		if err := checkEntryName(name); err != nil {
			return nil, &ParseError{Msg: fmt.Sprintf("archive entry %q: %v", safeLabel(name), err), Err: ErrUnsafe}
		}
		mode := f.Mode()
		if mode.IsDir() || strings.HasSuffix(name, "/") {
			continue
		}
		if !mode.IsRegular() {
			return nil, &ParseError{Msg: fmt.Sprintf("archive entry %q is a link or special file", safeLabel(name)), Err: ErrUnsafe}
		}
		if f.Flags&0x1 != 0 {
			return nil, &ParseError{Msg: fmt.Sprintf("archive entry %q is encrypted", safeLabel(name)), Err: ErrUnsafe}
		}
		switch strings.ToLower(path.Ext(name)) {
		case ".zip", ".gz", ".tgz", ".tar", ".7z", ".rar", ".bz2", ".xz", ".zst":
			return nil, &ParseError{Msg: fmt.Sprintf("archive entry %q is an archive; nested archives are not read", safeLabel(name)), Err: ErrUnsafe}
		}
		if f.UncompressedSize64 > uint64(lim.MaxEntryBytes) {
			return nil, &ParseError{Msg: fmt.Sprintf("archive entry %q is larger than %d bytes", safeLabel(name), lim.MaxEntryBytes), Err: ErrTooLarge}
		}
		if len(out) >= lim.MaxEntries {
			return nil, &ParseError{Msg: fmt.Sprintf("archive has more than %d files", lim.MaxEntries), Err: ErrTooLarge}
		}
		out = append(out, ArchiveFile{Name: path.Clean(name), DeclaredSize: int64(f.UncompressedSize64), f: f, lim: lim, total: &total})
	}
	return out, nil
}

func checkEntryName(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("empty name")
	case strings.HasPrefix(name, "/"):
		return fmt.Errorf("absolute path")
	case strings.Contains(name, "\\"):
		return fmt.Errorf("backslash in path")
	case len(name) >= 2 && name[1] == ':':
		return fmt.Errorf("drive letter in path")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("control character in path")
		}
	}
	for _, el := range strings.Split(name, "/") {
		if el == ".." {
			return fmt.Errorf("path traversal")
		}
	}
	return nil
}

// safeLabel makes an entry name safe to put in an error message.
func safeLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return '?'
		}
		return r
	}, s)
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}

// bombGuard enforces the archive limits while a file is read.
type bombGuard struct {
	rc         io.ReadCloser
	name       string
	lim        ArchiveLimits
	compressed int64
	read       int64
	total      *int64
}

func (g *bombGuard) Read(p []byte) (int, error) {
	n, err := g.rc.Read(p)
	g.read += int64(n)
	*g.total += int64(n)
	switch {
	case g.read > g.lim.MaxEntryBytes:
		return n, &ParseError{Msg: fmt.Sprintf("archive entry %q is larger than %d bytes", safeLabel(g.name), g.lim.MaxEntryBytes), Err: ErrTooLarge}
	case *g.total > g.lim.MaxTotalBytes:
		return n, &ParseError{Msg: fmt.Sprintf("archive content is larger than %d bytes", g.lim.MaxTotalBytes), Err: ErrTooLarge}
	case g.read > 1<<20 && g.read > g.compressed*g.lim.MaxRatio:
		return n, &ParseError{Msg: fmt.Sprintf("archive entry %q decompresses more than %d times its size", safeLabel(g.name), g.lim.MaxRatio), Err: ErrTooLarge}
	}
	return n, err
}

func (g *bombGuard) Close() error { return g.rc.Close() }
