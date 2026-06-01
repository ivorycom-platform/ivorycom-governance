package audit

import (
	"encoding/json"
	"testing"
)

func TestDiff_ChangedFieldsOnly(t *testing.T) {
	old := map[string]any{"name": "Acme", "status": "new", "owner": "u1"}
	nw := map[string]any{"name": "Acme", "status": "qualified", "owner": "u1"}
	raw := Diff(old, nw)
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
	old := Lead{Name: "Acme", Status: "new", Owner: "u1"}
	nw := Lead{Name: "Acme", Status: "qualified", Owner: "u1"}
	raw := Diff(old, nw)
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
	raw := Diff(nil, map[string]any{"name": "Acme"})
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if string(d["old"]) != "null" {
		t.Fatalf("expected null old, got %s", d["old"])
	}
	var nw map[string]any
	if err := json.Unmarshal(d["new"], &nw); err != nil {
		t.Fatal(err)
	}
	if nw["name"] != "Acme" {
		t.Fatalf("expected new.name=Acme, got %v", nw["name"])
	}
}

func TestDiff_DeleteHasNilNew(t *testing.T) {
	raw := Diff(map[string]any{"name": "Acme"}, nil)
	var d map[string]json.RawMessage
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	if string(d["new"]) != "null" {
		t.Fatalf("expected null new, got %s", d["new"])
	}
	var old map[string]any
	if err := json.Unmarshal(d["old"], &old); err != nil {
		t.Fatal(err)
	}
	if old["name"] != "Acme" {
		t.Fatalf("expected old.name=Acme, got %v", old["name"])
	}
}
