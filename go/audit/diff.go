package audit

import (
	"bytes"
	"encoding/json"
)

// Diff produces a JSON document of the form {"old":{...},"new":{...}}
// containing only the fields whose JSON representation differs between old and
// new. Each side is marshaled to a map via a JSON round-trip; the union of keys
// is compared and only differing keys are included.
//
// When old is nil the "old" side is emitted as null (a create); when new is
// nil the "new" side is emitted as null (a delete).
func Diff(old, new any) json.RawMessage {
	oldMap := toMap(old)
	newMap := toMap(new)

	result := make(map[string]json.RawMessage, 2)

	oldChanged := map[string]json.RawMessage{}
	newChanged := map[string]json.RawMessage{}

	keys := map[string]struct{}{}
	for k := range oldMap {
		keys[k] = struct{}{}
	}
	for k := range newMap {
		keys[k] = struct{}{}
	}

	for k := range keys {
		ov, oOK := oldMap[k]
		nv, nOK := newMap[k]
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

	if old == nil {
		result["old"] = json.RawMessage("null")
	} else {
		result["old"] = mustMarshal(oldChanged)
	}
	if new == nil {
		result["new"] = json.RawMessage("null")
	} else {
		result["new"] = mustMarshal(newChanged)
	}

	return mustMarshal(result)
}

// toMap marshals v to JSON then unmarshals into a map of raw JSON values so
// each field can be compared by its canonical JSON encoding. A nil input or a
// value that does not encode to a JSON object yields an empty map.
func toMap(v any) map[string]json.RawMessage {
	if v == nil {
		return map[string]json.RawMessage{}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]json.RawMessage{}
	}
	m := map[string]json.RawMessage{}
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]json.RawMessage{}
	}
	return m
}

func mustMarshal(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		// v is always a JSON-safe map of RawMessage; marshal cannot fail.
		panic(err)
	}
	return b
}
