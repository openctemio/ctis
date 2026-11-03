package ctis

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version-gated decoding (spec section 2.2).
//
// A receiver decodes a document that declares its own minor or an older one
// strictly: an unknown member is an error, so a typo never passes. A
// document that declares a newer minor of the same major may carry members
// and enum values the receiver does not know; the receiver ignores those
// members and maps those enum values to the member's documented fallback,
// and lists what it ignored. Another major is refused.

// MaxUnknownEntries bounds the entries Decode lists in Unknown; the rest are
// counted in Unknown.Omitted.
const MaxUnknownEntries = 1000

// UnknownKind says what Decode did with something it did not know.
type UnknownKind string

// Unknown kinds.
const (
	// UnknownMember: a member the receiver does not know, ignored.
	UnknownMember UnknownKind = "member"
	// UnknownEnumValue: an enum value the receiver does not know. Fallback
	// is the value it was mapped to; empty when the enum has none, and then
	// a UnknownRemoved or UnknownDropped entry follows.
	UnknownEnumValue UnknownKind = "enum_value"
	// UnknownRemoved: an optional member removed because its value could
	// not be kept.
	UnknownRemoved UnknownKind = "removed"
	// UnknownDropped: an array item removed because a required value of it
	// could not be kept (a finding of a type the receiver does not know).
	UnknownDropped UnknownKind = "dropped"
)

// UnknownEntry is one thing Decode ignored, mapped or removed. Path is a
// JSON Pointer (RFC 6901) into the document as received; Value is the
// offending enum value, cut to 64 characters.
type UnknownEntry struct {
	Path     string      `json:"path"`
	Kind     UnknownKind `json:"kind"`
	Value    string      `json:"value,omitempty"`
	Fallback string      `json:"fallback,omitempty"`
}

// Unknown lists what Decode did not know in a newer-minor document. It is
// empty for a document of this module's minor or an older one.
type Unknown struct {
	Entries []UnknownEntry `json:"entries,omitempty"`
	// Omitted counts entries beyond MaxUnknownEntries.
	Omitted int `json:"omitted,omitempty"`
}

// Empty reports whether nothing was ignored, mapped or removed.
func (u Unknown) Empty() bool { return len(u.Entries) == 0 && u.Omitted == 0 }

func (u *Unknown) add(path string, kind UnknownKind, value, fallback string) {
	if len(u.Entries) >= MaxUnknownEntries {
		u.Omitted++
		return
	}
	u.Entries = append(u.Entries, UnknownEntry{Path: path, Kind: kind, Value: truncateForError(value), Fallback: fallback})
}

// Decode reads one CTIS document from r under the compatibility rule of
// spec section 2.2:
//
//   - version missing or malformed: an error;
//   - another major: an error. There is no conversion between majors;
//   - this module's major, the same or an older minor than SchemaVersion:
//     strict decoding, an unknown member is an error, and Unknown is empty;
//   - this module's major, a newer minor: unknown members are ignored, and
//     an enum value this module does not know is mapped to the enum's
//     fallback (EnumFallback). An enum with no fallback loses the value:
//     the member is removed when it is optional, else the nearest enclosing
//     optional member or array item is removed (a finding of an unknown
//     type is dropped). Each of these is listed in Unknown.
//
// Decode checks shape only; run Report.Validate on the result. It reads the
// whole of r: bound the input first (io.LimitReader). Trailing data after
// the document is an error.
func Decode(r io.Reader) (Report, Unknown, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return Report{}, Unknown{}, fmt.Errorf("ctis: read: %w", err)
	}
	_, current, _ := ParseVersion(SchemaVersion)
	return decodeAt(raw, SchemaMajor, current)
}

// decodeAt decodes raw as a receiver of version recvMajor.recvMinor would.
func decodeAt(raw []byte, recvMajor, recvMinor int) (Report, Unknown, error) {
	var unknown Unknown
	var head struct {
		Version *string `json:"version"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return Report{}, unknown, fmt.Errorf("ctis: decode: %w", err)
	}
	if head.Version == nil {
		return Report{}, unknown, errors.New("ctis: decode: version is required")
	}
	major, minor, ok := ParseVersion(*head.Version)
	if !ok {
		return Report{}, unknown, fmt.Errorf("ctis: decode: malformed version %q", truncateForError(*head.Version))
	}
	switch {
	case major != recvMajor:
		return Report{}, unknown, fmt.Errorf("ctis: decode: version %s is major %d, this receiver reads only major %d: upgrade the producer to CTIS %d (there is no conversion between majors)", truncateForError(*head.Version), major, recvMajor, recvMajor)
	case minor <= recvMinor:
		rep, err := decodeStrictBytes(raw)
		return rep, unknown, err
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var tree any
	if err := dec.Decode(&tree); err != nil {
		return Report{}, unknown, fmt.Errorf("ctis: decode: %w", err)
	}
	if err := noTrailingData(dec); err != nil {
		return Report{}, unknown, err
	}
	w := lenientWalker{u: &unknown}
	tree, act := w.walk(tree, reflect.TypeOf(Report{}), "")
	if act != actKeep {
		return Report{}, unknown, errors.New("ctis: decode: a required report member has a value this receiver does not know")
	}
	w.goneWithoutReason(tree)
	pruned, err := json.Marshal(tree)
	if err != nil {
		return Report{}, unknown, fmt.Errorf("ctis: decode: %w", err)
	}
	rep, err := decodeStrictBytes(pruned)
	return rep, unknown, err
}

func decodeStrictBytes(raw []byte) (Report, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var rep Report
	if err := dec.Decode(&rep); err != nil {
		return Report{}, fmt.Errorf("ctis: decode: %w", err)
	}
	if err := noTrailingData(dec); err != nil {
		return Report{}, err
	}
	return rep, nil
}

func noTrailingData(dec *json.Decoder) error {
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("ctis: decode: trailing data after the document")
	}
	return nil
}

// enumPolicy is what the lenient decoder does with a value of one enum type.
type enumPolicy struct {
	values   func() []string
	fallback string // mapped to when the value is unknown
	dropItem bool   // unknown value drops the nearest array item
	open     bool   // any open token is valid
}

func enumOf[T ~string](all func() []T) func() []string {
	return func() []string {
		in := all()
		out := make([]string, len(in))
		for i, v := range in {
			out[i] = string(v)
		}
		return out
	}
}

// enumPolicies registers every Go enum type of the format. A test keeps it
// equal to the enums the schema declares.
var enumPolicies = map[reflect.Type]enumPolicy{
	reflect.TypeOf(Severity("")):               {values: enumOf(AllSeverities), fallback: string(SeverityUnknown)},
	reflect.TypeOf(FindingType("")):            {values: enumOf(AllFindingTypes)},
	reflect.TypeOf(FindingStatus("")):          {values: enumOf(AllFindingStatuses)},
	reflect.TypeOf(AssetType("")):              {values: enumOf(AllAssetTypes), fallback: string(AssetTypeUnclassified)},
	reflect.TypeOf(Criticality("")):            {values: enumOf(AllCriticalities)},
	reflect.TypeOf(DataFlowLocationType("")):   {values: enumOf(AllDataFlowLocationTypes)},
	reflect.TypeOf(NativeScheme("")):           {values: enumOf(AllNativeSchemes), open: true},
	reflect.TypeOf(DetectionType("")):          {values: enumOf(AllDetectionTypes)},
	reflect.TypeOf(ScoreSystem("")):            {values: enumOf(AllScoreSystems)},
	reflect.TypeOf(VEXStatus("")):              {values: enumOf(AllVEXStatuses)},
	reflect.TypeOf(VEXJustification("")):       {values: enumOf(AllVEXJustifications)},
	reflect.TypeOf(SourceState("")):            {values: enumOf(AllSourceStates)},
	reflect.TypeOf(VulnerabilityIDType("")):    {values: enumOf(AllVulnerabilityIDTypes)},
	reflect.TypeOf(SolutionType("")):           {values: enumOf(AllSolutionTypes)},
	reflect.TypeOf(EndpointKind("")):           {values: enumOf(AllEndpointKinds), fallback: string(EndpointKindOther)},
	reflect.TypeOf(EndpointSource("")):         {values: enumOf(AllEndpointSources)},
	reflect.TypeOf(EndpointAuth("")):           {values: enumOf(AllEndpointAuths), fallback: string(EndpointAuthUnknown)},
	reflect.TypeOf(ParamLocation("")):          {values: enumOf(AllParamLocations)},
	reflect.TypeOf(RelationshipType("")):       {values: enumOf(AllRelationshipTypes)},
	reflect.TypeOf(Environment("")):            {values: enumOf(AllEnvironments), fallback: string(EnvironmentUnknown)},
	reflect.TypeOf(OwnerKind("")):              {values: enumOf(AllOwnerKinds)},
	reflect.TypeOf(OwnerRole("")):              {values: enumOf(AllOwnerRoles)},
	reflect.TypeOf(AssetState("")):             {values: enumOf(AllAssetStates)},
	reflect.TypeOf(AssetStateReason("")):       {values: enumOf(AllAssetStateReasons)},
	reflect.TypeOf(ValidationStatus("")):       {values: enumOf(AllValidationStatuses)},
	reflect.TypeOf(ValidationMethod("")):       {values: enumOf(AllValidationMethods)},
	reflect.TypeOf(ThreatSignalType("")):       {values: enumOf(AllThreatSignalTypes)},
	reflect.TypeOf(TargetState("")):            {values: enumOf(AllTargetStates)},
	reflect.TypeOf(Channel("")):                {values: enumOf(AllChannels)},
	reflect.TypeOf(CoverageType("")):           {values: enumOf(AllCoverageTypes)},
	reflect.TypeOf(Profile("")):                {values: enumOf(AllProfiles)},
	reflect.TypeOf(Technique("")):              {values: enumOf(AllTechniques)},
	reflect.TypeOf(DataClassification("")):     {values: enumOf(AllDataClassifications)},
	reflect.TypeOf(ComplianceFramework("")):    {values: enumOf(AllComplianceFrameworks), open: true},
	reflect.TypeOf(TLSVersion("")):             {values: enumOf(AllTLSVersions)},
	reflect.TypeOf(IdentityKind("")):           {values: enumOf(AllIdentityKinds)},
	reflect.TypeOf(NetworkDeviceKind("")):      {values: enumOf(AllNetworkDeviceKinds), fallback: string(NetworkDeviceOther)},
	reflect.TypeOf(PortState("")):              {values: enumOf(AllPortStates)},
	reflect.TypeOf(Transport("")):              {values: enumOf(AllTransports)},
	reflect.TypeOf(DependencyRelationship("")): {values: enumOf(AllDependencyRelationships)},
	reflect.TypeOf(DependencyType("")):         {values: enumOf(AllDependencyTypes)},
	reflect.TypeOf(ExposureVector("")):         {values: enumOf(AllExposureVectors)},
	reflect.TypeOf(Effort("")):                 {values: enumOf(AllEfforts)},
	// A target with a class this receiver does not know is never read as
	// done: the entry is dropped, so the target counts as not covered.
	reflect.TypeOf(TargetClass("")): {values: enumOf(AllTargetClasses), dropItem: true},
	reflect.TypeOf(TargetCause("")): {values: enumOf(AllTargetCauses)},
}

// EnumFallback returns the documented fallback of an enum type for a value
// a receiver does not know ("unknown", "unclassified", "other"), and false
// when the enum has none. v is any value of the enum type.
func EnumFallback(v any) (string, bool) {
	p, ok := enumPolicies[reflect.TypeOf(v)]
	if !ok || p.fallback == "" {
		return "", false
	}
	return p.fallback, true
}

type walkAction int

const (
	actKeep     walkAction = iota
	actRemove              // the value cannot be kept; its member goes
	actDropItem            // the nearest enclosing array item goes
)

type lenientWalker struct{ u *Unknown }

var (
	unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	timeTypeOf      = reflect.TypeOf(time.Time{})
)

func (w lenientWalker) walk(v any, t reflect.Type, path string) (any, walkAction) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if v == nil || t == timeTypeOf || reflect.PointerTo(t).Implements(unmarshalerType) {
		return v, actKeep
	}
	if p, ok := enumPolicies[t]; ok {
		s, isString := v.(string)
		if !isString {
			return v, actKeep // a type error, reported by the strict decode
		}
		return w.enum(p, s, path)
	}
	switch t.Kind() {
	case reflect.Struct:
		m, ok := v.(map[string]any)
		if !ok {
			return v, actKeep
		}
		return w.object(m, t, path)
	case reflect.Slice:
		arr, ok := v.([]any)
		if !ok {
			return v, actKeep
		}
		out := arr[:0]
		for i, item := range arr {
			p := path + "/" + strconv.Itoa(i)
			nv, act := w.walk(item, t.Elem(), p)
			if act != actKeep {
				w.u.add(p, UnknownDropped, "", "")
				continue
			}
			out = append(out, nv)
		}
		return out, actKeep
	case reflect.Map:
		m, ok := v.(map[string]any)
		if !ok || t.Elem().Kind() == reflect.Interface {
			return v, actKeep
		}
		for _, k := range sortedKeysOf(m) {
			p := path + "/" + pointerEscape(k)
			nv, act := w.walk(m[k], t.Elem(), p)
			if act != actKeep {
				delete(m, k)
				w.u.add(p, UnknownRemoved, "", "")
				continue
			}
			m[k] = nv
		}
		return m, actKeep
	}
	return v, actKeep
}

func (w lenientWalker) enum(p enumPolicy, s, path string) (any, walkAction) {
	if p.open && IsOpenToken(s) {
		return s, actKeep
	}
	for _, known := range p.values() {
		if s == known {
			return s, actKeep
		}
	}
	if p.fallback != "" {
		w.u.add(path, UnknownEnumValue, s, p.fallback)
		return p.fallback, actKeep
	}
	w.u.add(path, UnknownEnumValue, s, "")
	if p.dropItem {
		return s, actDropItem
	}
	return s, actRemove
}

func (w lenientWalker) object(m map[string]any, t reflect.Type, path string) (any, walkAction) {
	fields := jsonFields(t)
	for _, k := range sortedKeysOf(m) {
		p := path + "/" + pointerEscape(k)
		f, known := fields[k]
		if !known {
			delete(m, k)
			w.u.add(p, UnknownMember, "", "")
			continue
		}
		nv, act := w.walk(m[k], f.typ, p)
		switch {
		case act == actKeep:
			m[k] = nv
		case act == actRemove && f.omitempty:
			delete(m, k)
			w.u.add(p, UnknownRemoved, "", "")
		default:
			// A required member was lost, or an item drop was asked for:
			// hand it to the enclosing member or array.
			return m, act
		}
	}
	return m, actKeep
}

// goneWithoutReason removes state gone from an asset whose state_reason was
// removed: gone needs an authoritative signal this module understands.
func (w lenientWalker) goneWithoutReason(tree any) {
	root, _ := tree.(map[string]any)
	assets, _ := root["assets"].([]any)
	for i, a := range assets {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		if _, hasReason := m["state_reason"]; m["state"] == string(AssetStateGone) && !hasReason {
			delete(m, "state")
			w.u.add("/assets/"+strconv.Itoa(i)+"/state", UnknownRemoved, "", "")
		}
	}
}

type jsonField struct {
	typ       reflect.Type
	omitempty bool
}

var jsonFieldCache sync.Map // reflect.Type -> map[string]jsonField

// jsonFields returns the members encoding/json reads for struct type t,
// embedded structs flattened.
func jsonFields(t reflect.Type) map[string]jsonField {
	if c, ok := jsonFieldCache.Load(t); ok {
		return c.(map[string]jsonField)
	}
	out := map[string]jsonField{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, opts, _ := strings.Cut(tag, ",")
		if name == "-" && opts == "" {
			continue
		}
		if f.Anonymous && name == "" {
			et := f.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				for k, v := range jsonFields(et) {
					if _, dup := out[k]; !dup {
						out[k] = v
					}
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = jsonField{typ: f.Type, omitempty: strings.Contains(","+opts+",", ",omitempty,")}
	}
	jsonFieldCache.Store(t, out)
	return out
}

func pointerEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}
