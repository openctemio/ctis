package ctis

// DataFlow represents taint analysis data flow trace.
// This structure captures the complete path from source to sink,
// including all intermediate steps and transformations.
type DataFlow struct {
	// Taint source locations (where untrusted data enters)
	Sources []DataFlowLocation `json:"sources,omitempty"`

	// Intermediate variable locations (propagation path)
	Intermediates []DataFlowLocation `json:"intermediates,omitempty"`

	// Taint sink location (where data reaches dangerous function)
	Sinks []DataFlowLocation `json:"sinks,omitempty"`

	// Sanitizers applied (functions that clean/escape data)
	Sanitizers []DataFlowLocation `json:"sanitizers,omitempty"`

	// Whether the data is still tainted at the sink
	// (false if properly sanitized before reaching sink)
	IsTainted bool `json:"is_tainted"`

	// Type of taint: user_input, file_read, env_var, network, database
	TaintType string `json:"taint_type,omitempty"`

	// Flow confidence score (0-100)
	Confidence int `json:"confidence,omitempty"`

	// Is interprocedural (crosses function boundaries)
	IsInterprocedural bool `json:"is_interprocedural,omitempty"`

	// Is cross-file (data flows across multiple files)
	IsCrossFile bool `json:"is_cross_file,omitempty"`

	// Call graph path (function names in order)
	CallPath []string `json:"call_path,omitempty"`

	// Summary of the flow for human readability
	Summary string `json:"summary,omitempty"`
}

// DataFlowLocation represents a location in a data flow trace.
type DataFlowLocation struct {
	// File path
	Path string `json:"path,omitempty"`

	// Line number (1-indexed)
	Line int `json:"line,omitempty"`

	// End line (for multi-line spans)
	EndLine int `json:"end_line,omitempty"`

	// Column number (1-indexed)
	Column int `json:"column,omitempty"`

	// End column
	EndColumn int `json:"end_column,omitempty"`

	// Code content at this location
	Content string `json:"content,omitempty"`

	// Variable or expression name
	Label string `json:"label,omitempty"`

	// Step index in the flow (for ordering, 0-indexed)
	Index int `json:"index,omitempty"`

	// Location type: source, sink, propagator, sanitizer, transform
	Type DataFlowLocationType `json:"type,omitempty"`

	// Function/method name containing this location
	Function string `json:"function,omitempty"`

	// Class/struct name (if applicable)
	ClassName string `json:"class_name,omitempty"`

	// Module/namespace
	Module string `json:"module,omitempty"`

	// The operation performed: assignment, call, return, parameter, concat, etc.
	Operation string `json:"operation,omitempty"`

	// For function calls: the function being called
	CalledFunction string `json:"called_function,omitempty"`

	// For parameters: the parameter index (0-indexed)
	ParameterIndex int `json:"parameter_index,omitempty"`

	// Taint state at this location: tainted, sanitized, unknown
	TaintState string `json:"taint_state,omitempty"`

	// Transformation applied: encode, decode, escape, hash, encrypt, etc.
	Transformation string `json:"transformation,omitempty"`

	// Notes for human understanding
	Notes string `json:"notes,omitempty"`
}

// DataFlowLocationType represents the type of a location in dataflow.
type DataFlowLocationType string

const (
	// DataFlowLocationSource is where untrusted data enters the system
	DataFlowLocationSource DataFlowLocationType = "source"

	// DataFlowLocationSink is where data reaches a dangerous function
	DataFlowLocationSink DataFlowLocationType = "sink"

	// DataFlowLocationPropagator is where data is passed/assigned
	DataFlowLocationPropagator DataFlowLocationType = "propagator"

	// DataFlowLocationSanitizer is where data is cleaned/escaped
	DataFlowLocationSanitizer DataFlowLocationType = "sanitizer"

	// DataFlowLocationTransform is where data is transformed (not sanitized)
	DataFlowLocationTransform DataFlowLocationType = "transform"
)

// AllDataFlowLocationTypes returns every valid data flow location type.
func AllDataFlowLocationTypes() []DataFlowLocationType {
	return []DataFlowLocationType{
		DataFlowLocationSource,
		DataFlowLocationSink,
		DataFlowLocationPropagator,
		DataFlowLocationSanitizer,
		DataFlowLocationTransform,
	}
}

// =============================================================================
// DataFlow Helper Functions
// =============================================================================

// NewDataFlow creates a new DataFlow with the given source and sink.
func NewDataFlow(source, sink DataFlowLocation) *DataFlow {
	source.Type = DataFlowLocationSource
	source.Index = 0
	sink.Type = DataFlowLocationSink
	sink.Index = 1

	return &DataFlow{
		Sources:   []DataFlowLocation{source},
		Sinks:     []DataFlowLocation{sink},
		IsTainted: true,
	}
}

// AddIntermediate adds an intermediate step to the dataflow path.
func (df *DataFlow) AddIntermediate(loc DataFlowLocation) {
	loc.Type = DataFlowLocationPropagator
	loc.Index = len(df.Sources) + len(df.Intermediates)
	df.Intermediates = append(df.Intermediates, loc)

	// Update sink indices
	for i := range df.Sinks {
		df.Sinks[i].Index = loc.Index + 1 + i
	}

	// Check if flow crosses files
	if len(df.Intermediates) > 0 && len(df.Sources) > 0 {
		if loc.Path != df.Sources[0].Path {
			df.IsCrossFile = true
		}
	}
}

// AddSanitizer adds a sanitizer location that cleans the tainted data.
func (df *DataFlow) AddSanitizer(loc DataFlowLocation) {
	loc.Type = DataFlowLocationSanitizer
	loc.TaintState = "sanitized"
	df.Sanitizers = append(df.Sanitizers, loc)
}

// MarkAsSanitized marks the dataflow as no longer tainted.
func (df *DataFlow) MarkAsSanitized() {
	df.IsTainted = false
}

// GetFullPath returns all locations in order from source to sink.
func (df *DataFlow) GetFullPath() []DataFlowLocation {
	path := make([]DataFlowLocation, 0, len(df.Sources)+len(df.Intermediates)+len(df.Sinks))
	path = append(path, df.Sources...)
	path = append(path, df.Intermediates...)
	path = append(path, df.Sinks...)
	return path
}

// GetPathLength returns the number of steps in the dataflow.
func (df *DataFlow) GetPathLength() int {
	return len(df.Sources) + len(df.Intermediates) + len(df.Sinks)
}

// IsCrossFunction checks if the dataflow crosses function boundaries.
func (df *DataFlow) IsCrossFunction() bool {
	if df.IsInterprocedural {
		return true
	}

	functions := make(map[string]bool)
	for _, loc := range df.GetFullPath() {
		if loc.Function != "" {
			functions[loc.Function] = true
		}
	}
	return len(functions) > 1
}

// BuildSummary generates a human-readable summary of the dataflow.
func (df *DataFlow) BuildSummary() string {
	if len(df.Sources) == 0 || len(df.Sinks) == 0 {
		return ""
	}

	source := df.Sources[0]
	sink := df.Sinks[len(df.Sinks)-1]

	summary := ""
	if source.Label != "" {
		summary = source.Label
	} else {
		summary = "tainted data"
	}

	if df.TaintType != "" {
		summary += " (" + df.TaintType + ")"
	}

	summary += " flows from "
	if source.Path != "" {
		summary += source.Path
		if source.Line > 0 {
			summary += ":" + itoa(source.Line)
		}
	}

	if len(df.Intermediates) > 0 {
		summary += " through " + itoa(len(df.Intermediates)) + " step(s)"
	}

	summary += " to "
	switch {
	case sink.CalledFunction != "":
		summary += sink.CalledFunction + "()"
	case sink.Label != "":
		summary += sink.Label
	default:
		summary += "sink"
	}

	if sink.Path != "" && sink.Path != source.Path {
		summary += " in " + sink.Path
		if sink.Line > 0 {
			summary += ":" + itoa(sink.Line)
		}
	} else if sink.Line > 0 {
		summary += " at line " + itoa(sink.Line)
	}

	if !df.IsTainted {
		summary += " (sanitized)"
	}

	df.Summary = summary
	return summary
}

// itoa converts int to string without importing strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	// Work in unsigned to avoid overflow when negating math.MinInt
	// (-MinInt is not representable as int; unsigned negation is well-defined).
	u := uint(i)
	if neg {
		u = -u
	}
	digits := ""
	for u > 0 {
		digits = string(rune('0'+u%10)) + digits
		u /= 10
	}
	if neg {
		return "-" + digits
	}
	return digits
}

// NewDataFlowLocation creates a new DataFlowLocation.
func NewDataFlowLocation(path string, line, column int, content string) DataFlowLocation {
	return DataFlowLocation{
		Path:    path,
		Line:    line,
		Column:  column,
		Content: content,
	}
}

// WithLabel sets the label for the location.
func (loc DataFlowLocation) WithLabel(label string) DataFlowLocation {
	loc.Label = label
	return loc
}

// WithFunction sets the function context for the location.
func (loc DataFlowLocation) WithFunction(fn string) DataFlowLocation {
	loc.Function = fn
	return loc
}

// WithOperation sets the operation type for the location.
func (loc DataFlowLocation) WithOperation(op string) DataFlowLocation {
	loc.Operation = op
	return loc
}

// AsSource marks this location as a taint source.
func (loc DataFlowLocation) AsSource() DataFlowLocation {
	loc.Type = DataFlowLocationSource
	loc.TaintState = "tainted"
	return loc
}

// AsSink marks this location as a taint sink.
func (loc DataFlowLocation) AsSink() DataFlowLocation {
	loc.Type = DataFlowLocationSink
	return loc
}

// AsSanitizer marks this location as a sanitizer.
func (loc DataFlowLocation) AsSanitizer() DataFlowLocation {
	loc.Type = DataFlowLocationSanitizer
	loc.TaintState = "sanitized"
	return loc
}
