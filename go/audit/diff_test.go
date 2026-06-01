package audit

import (
	"encoding/json"
	"testing"
)

func TestDiff_ChangedFieldsOnly(t *testing.T) {
	before := map[string]any{"name": "Acme", "status": "new", "owner": "u1"}
	after := map[string]any{"name": "Acme", "status": "qualified", "owner": "u1"}
	raw, err := Diff(before, after)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Old map[string]any `json:"old"`
		New map[string]any `json:"new"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Old["name"]; ok {
		t.Fatal("unchanged field 'name' must be excluded")
	}
	if d.Old["status"] != "new" || d.New["status"] != "qualified" {
		t.Fatalf("status diff wrong: old=%v new=%v", d.Old["status"], d.New["status"])
	}
}

func TestDiff_StructBased(t *testing.T) {
	type Lead struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Owner  string `json:"owner"`
	}
	before := Lead{Name: "Acme", Status: "new", Owner: "u1"}
	after := Lead{Name: "Acme", Status: "qualified", Owner: "u1"}
	raw, err := Diff(before, after)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Old map[string]any `json:"old"`
		New map[string]any `json:"new"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Old["name"]; ok {
		t.Fatal("unchanged field 'name' must be excluded")
	}
	if _, ok := d.Old["owner"]; ok {
		t.Fatal("unchanged field 'owner' must be excluded")
	}
	if d.Old["status"] != "new" || d.New["status"] != "qualified" {
		t.Fatalf("status diff wrong: old=%v new=%v", d.Old["status"], d.New["status"])
	}
}

func TestDiff_CreateHasNilOld(t *testing.T) {
	raw, err := Diff(nil, map[string]any{"name": "Acme"})
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if string(d["old"]) != "null" {
		t.Fatalf("expected null old, got %s", d["old"])
	}
	var after map[string]any
	if err := json.Unmarshal(d["new"], &after); err != nil {
		t.Fatal(err)
	}
	if after["name"] != "Acme" {
		t.Fatalf("expected new.name=Acme, got %v", after["name"])
	}
}

func TestDiff_DeleteHasNilNew(t *testing.T) {
	raw, err := Diff(map[string]any{"name": "Acme"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if string(d["new"]) != "null" {
		t.Fatalf("expected null new, got %s", d["new"])
	}
	var before map[string]any
	if err := json.Unmarshal(d["old"], &before); err != nil {
		t.Fatal(err)
	}
	if before["name"] != "Acme" {
		t.Fatalf("expected old.name=Acme, got %v", before["name"])
	}
}

// TestDiff_TypedNilPointerIsCreate ensures a typed-nil pointer (e.g.
// (*Lead)(nil)) is treated as nil so the "old" side is the literal null,
// not an empty object.
func TestDiff_TypedNilPointerIsCreate(t *testing.T) {
	type Lead struct {
		Name string `json:"name"`
	}
	raw, err := Diff((*Lead)(nil), &Lead{Name: "Acme"})
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if string(d["old"]) != "null" {
		t.Fatalf("expected typed-nil old to be null, got %s", d["old"])
	}
	var after map[string]any
	if err := json.Unmarshal(d["new"], &after); err != nil {
		t.Fatal(err)
	}
	if after["name"] != "Acme" {
		t.Fatalf("expected new.name=Acme, got %v", after["name"])
	}
}

// TestDiff_NestedObjectChanged documents that diff granularity is the
// whole top-level field: when a value inside a nested struct changes, the
// entire top-level key appears on both sides, and unchanged top-level keys
// are excluded.
func TestDiff_NestedObjectChanged(t *testing.T) {
	type Addr struct {
		City string `json:"city"`
		Zip  string `json:"zip"`
	}
	type Lead struct {
		Name    string `json:"name"`
		Address Addr   `json:"address"`
	}
	before := Lead{Name: "Acme", Address: Addr{City: "NY", Zip: "10001"}}
	after := Lead{Name: "Acme", Address: Addr{City: "NY", Zip: "10002"}}
	raw, err := Diff(before, after)
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Old map[string]json.RawMessage `json:"old"`
		New map[string]json.RawMessage `json:"new"`
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.Old["name"]; ok {
		t.Fatal("unchanged top-level field 'name' must be excluded")
	}
	if _, ok := d.Old["address"]; !ok {
		t.Fatal("changed top-level field 'address' must appear in old")
	}
	if _, ok := d.New["address"]; !ok {
		t.Fatal("changed top-level field 'address' must appear in new")
	}
}

func TestDiff_ErrorOnNonObject(t *testing.T) {
	if _, err := Diff("a string", "b string"); err == nil {
		t.Fatal("expected error when operands are not JSON objects")
	}
}

func TestDiff_ErrorOnUnmarshalable(t *testing.T) {
	type Bad struct {
		Ch chan int `json:"ch"`
	}
	if _, err := Diff(Bad{Ch: make(chan int)}, Bad{}); err == nil {
		t.Fatal("expected error when a value cannot be marshaled")
	}
}
