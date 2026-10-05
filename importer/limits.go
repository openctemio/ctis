package importer

// Limits bound what a parser accepts. A zero field takes its default
// (DefaultLimits). The defaults are sized for a real export of a large
// estate; a receiver that accepts uploads from people should pass smaller
// values.
type Limits struct {
	// Largest input, in bytes.
	MaxInputBytes int64

	// Deepest nesting of XML elements or JSON objects and arrays.
	MaxDepth int

	// Most XML elements in one document.
	MaxElements int

	// Most attributes on one XML element.
	MaxAttributes int

	// Largest text of one XML element or one JSON string, in bytes. Longer
	// values are refused, not truncated, so a file that needs them is seen
	// as what it is.
	MaxTextBytes int

	// Most findings, assets, dependencies and VEX statements in one result.
	MaxFindings   int
	MaxAssets     int
	MaxComponents int
	MaxStatements int

	// Most distinct source field paths recorded for the coverage check.
	MaxObservedPaths int

	// Most problems reported in Result.Issues.
	MaxIssues int
}

// DefaultLimits returns the limits a zero Limits stands for.
func DefaultLimits() Limits {
	return Limits{
		MaxInputBytes:    256 << 20,
		MaxDepth:         64,
		MaxElements:      20_000_000,
		MaxAttributes:    64,
		MaxTextBytes:     8 << 20,
		MaxFindings:      1_000_000,
		MaxAssets:        200_000,
		MaxComponents:    500_000,
		MaxStatements:    200_000,
		MaxObservedPaths: 4096,
		MaxIssues:        200,
	}
}

// withDefaults fills the zero fields of l from DefaultLimits.
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxInputBytes <= 0 {
		l.MaxInputBytes = d.MaxInputBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxElements <= 0 {
		l.MaxElements = d.MaxElements
	}
	if l.MaxAttributes <= 0 {
		l.MaxAttributes = d.MaxAttributes
	}
	if l.MaxTextBytes <= 0 {
		l.MaxTextBytes = d.MaxTextBytes
	}
	if l.MaxFindings <= 0 {
		l.MaxFindings = d.MaxFindings
	}
	if l.MaxAssets <= 0 {
		l.MaxAssets = d.MaxAssets
	}
	if l.MaxComponents <= 0 {
		l.MaxComponents = d.MaxComponents
	}
	if l.MaxStatements <= 0 {
		l.MaxStatements = d.MaxStatements
	}
	if l.MaxObservedPaths <= 0 {
		l.MaxObservedPaths = d.MaxObservedPaths
	}
	if l.MaxIssues <= 0 {
		l.MaxIssues = d.MaxIssues
	}
	return l
}
