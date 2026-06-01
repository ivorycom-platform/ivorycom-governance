package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
)

// Diff produces a JSON document of the form {"old":{...},"new":{...}}
// containing only the fields whose JSON representation differs between before
// and after. Each side is marshaled to a map via a JSON round-trip; the union
// of keys is compared and only differing keys are included.
//
// When before is nil the "old" side is emitted as the literal null (a create);
// when after is nil the "new" side is emitted as the literal null (a delete).
// A typed-nil pointer (e.g. (*Lead)(nil)) counts as nil. An error is returned
// if either operand fails to marshal or does not encode to a JSON object.
func Diff(before, after any) (json.RawMessage, error) {
	beforeNil := isNil(before)
	afterNil := isNil(after)

	beforeMap, err := toMap(before)
	if err != nil {
		return nil, err
	}
	afterMap, err := toMap(after)
	if err != nil {
		return nil, err
	}

	result := make(map[string]json.RawMessage, 2)

	oldChanged := map[string]json.RawMessage{}
	newChanged := map[string]json.RawMessage{}

	keys := map[string]struct{}{}
	for k := range beforeMap {
		keys[k] = struct{}{}
	}
	for k := range afterMap {
		keys[k] = struct{}{}
	}

	for k := range keys {
		ov, oOK := beforeMap[k]
		nv, nOK := afterMap[k]
		if oOK && nOK && bytes.Equal(ov, nv) {
			continue
		}
		if oOK {
			oldChanged[k] = ov
		}
		if nOK {
			newChanged[k] = nv
		}
	}

	if beforeNil {
		result["old"] = json.RawMessage("null")
	} else {
		result["old"] = mustMarshal(oldChanged)
	}
	if afterNil {
		result["new"] = json.RawMessage("null")
	} else {
		result["new"] = mustMarshal(newChanged)
	}

	return mustMarshal(result), nil
}

// isNil reports whether v is a nil interface or a typed-nil reference value
// (pointer, map, slice, interface, channel or func). This lets a typed-nil
// pointer such as (*Lead)(nil) be treated the same as an untyped nil.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Ptr, reflect.Map, reflect.Slice, reflect.Interface, reflect.Chan, reflect.Func:
		return rv.IsNil()
	}
	return false
}

// toMap marshals v to JSON then unmarshals into a map of raw JSON values so
// each field can be compared by its canonical JSON encoding. Using
// json.RawMessage preserves int64 magnitude and numeric precision. A nil input
// yields an empty map. A marshal/unmarshal failure is wrapped and returned; a
// non-nil value that does not encode to a JSON object is an error.
func toMap(v any) (map[string]json.RawMessage, error) {
	if isNil(v) {
		return map[string]json.RawMessage{}, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("audit: diff marshal: %w", err)
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("audit: diff operand is not a JSON object")
	}
	return m, nil
}

// mustMarshal marshals v, which is only ever a map[string]json.RawMessage built
// from already-valid JSON values; that cannot fail, so a failure is a
// programming error.
func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
