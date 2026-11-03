package engine

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/openctemio/ctis/v2"
)

// Transforms of a set rule, applied in order. A transform that rejects the
// value makes it missing, and a missing value leaves the member unset.
//
//	trim            remove leading and trailing white space
//	lower, upper    change case
//	token           trim, lower case, remove '_', '-' and ' '
//	line            remove control characters, white space runs become one space
//	table:<name>    look the value up in a table of the mapping
//	max_bytes:<n>   cut to n bytes (1 to 1 MiB) on a character boundary
//	http_url        keep only an absolute http or https URL (ctis.IsWebURL)
//
// Every value a set rule writes is also cut to MaxSetBytes.

// MaxSetBytes bounds a value a set rule writes.
const MaxSetBytes = 64 << 10

func (m *Mapping) checkTransform(t string) error {
	name, arg, _ := strings.Cut(t, ":")
	switch name {
	case "trim", "lower", "upper", "token", "line", "http_url":
		if arg != "" {
			return fmt.Errorf("transform %s takes no argument", name)
		}
	case "table":
		if _, ok := m.Tables[arg]; !ok {
			return fmt.Errorf("transform table:%s names no table", short(arg))
		}
	case "max_bytes":
		n, err := strconv.Atoi(arg)
		if err != nil || n < 1 || n > 1<<20 {
			return fmt.Errorf("transform max_bytes:%s: 1 to 1048576", short(arg))
		}
	default:
		return fmt.Errorf("transform %q is not in the registry", short(t))
	}
	return nil
}

// apply runs the transforms of a field on a scalar source value.
func (m *Mapping) apply(f Field, v string) (string, bool) {
	for _, t := range f.Transform {
		name, arg, _ := strings.Cut(t, ":")
		switch name {
		case "trim":
			v = strings.TrimSpace(v)
		case "lower":
			v = strings.ToLower(v)
		case "upper":
			v = strings.ToUpper(v)
		case "token":
			v = normalize("token", v)
		case "line":
			v = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
				if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
					return -1
				}
				return r
			}, v)), " ")
		case "table":
			var ok bool
			if v, ok = m.Lookup(arg, v); !ok {
				return "", false
			}
		case "max_bytes":
			n, _ := strconv.Atoi(arg)
			v = cutBytes(v, n)
		case "http_url":
			if !ctis.IsWebURL(v) {
				return "", false
			}
		}
	}
	return cutBytes(v, MaxSetBytes), true
}

func cutBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// kindTypes are the Go types of the record kinds a set rule writes into.
var kindTypes = map[string]reflect.Type{
	"finding":    reflect.TypeOf(ctis.Finding{}),
	"asset":      reflect.TypeOf(ctis.Asset{}),
	"dependency": reflect.TypeOf(ctis.Dependency{}),
	"vex":        reflect.TypeOf(ctis.VEX{}),
}

// Members a set rule may never write: identity and the links between
// records are the adapter's, and a source document must not choose them.
var reservedMembers = map[string]bool{
	"id": true, "asset_ref": true, "dependency_ref": true, "rule_ref": true,
	"fingerprint": true, "depends_on": true, "extensions": true, "properties": true,
}

// checkTarget checks that member names a settable scalar of the kind.
func checkTarget(kind, member string) error {
	t, ok := kindTypes[kind]
	if !ok {
		return fmt.Errorf("kind %q takes no set rules", kind)
	}
	parts := strings.Split(member, ".")
	if reservedMembers[parts[0]] {
		return fmt.Errorf("set %q: the member is reserved to the adapter", member)
	}
	for i, p := range parts {
		sf, ok := fieldByJSON(t, p)
		if !ok {
			return fmt.Errorf("set %q: %s has no member %q", member, t.Name(), p)
		}
		ft := sf.Type
		if ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		if i < len(parts)-1 {
			if ft.Kind() != reflect.Struct {
				return fmt.Errorf("set %q: %q is not an object", member, p)
			}
			t = ft
			continue
		}
		switch ft.Kind() {
		case reflect.String, reflect.Int, reflect.Bool, reflect.Float64:
			return nil
		}
		return fmt.Errorf("set %q: only text, integer, number and boolean members can be set", member)
	}
	return nil
}

func fieldByJSON(t reflect.Type, name string) (reflect.StructField, bool) {
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		tag, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
		if tag == name {
			return sf, true
		}
	}
	return reflect.StructField{}, false
}

// ErrSetTarget is returned by Set for a target that is not a pointer to the
// record kind's type.
var ErrSetTarget = errors.New("engine: set target is not a pointer to the record type")

// setMember writes s into the member of the struct v points to, creating
// the objects on the way. It returns false when s does not convert.
func setMember(v reflect.Value, member, s string) bool {
	parts := strings.Split(member, ".")
	for i, p := range parts {
		sf, _ := fieldByJSON(v.Type(), p)
		fv := v.FieldByIndex(sf.Index)
		if fv.Kind() == reflect.Pointer {
			if fv.IsNil() {
				nv := reflect.New(fv.Type().Elem())
				if i == len(parts)-1 {
					if !assign(nv.Elem(), s) {
						return false
					}
					fv.Set(nv)
					return true
				}
				fv.Set(nv)
			}
			fv = fv.Elem()
		}
		if i < len(parts)-1 {
			v = fv
			continue
		}
		return assign(fv, s)
	}
	return false
}

func assign(fv reflect.Value, s string) bool {
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(s)
	case reflect.Int:
		n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
		if err != nil || n > 1<<53 || n < -(1<<53) {
			return false
		}
		fv.SetInt(n)
	case reflect.Float64:
		f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil || f != f {
			return false
		}
		fv.SetFloat(f)
	case reflect.Bool:
		b, err := strconv.ParseBool(strings.TrimSpace(s))
		if err != nil {
			return false
		}
		fv.SetBool(b)
	default:
		return false
	}
	return true
}

// scalarText is the text of a scalar JSON value; ok is false for an object,
// an array or null.
func scalarText(raw json.RawMessage) (string, bool) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	}
	return "", false
}
