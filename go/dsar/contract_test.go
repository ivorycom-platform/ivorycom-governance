package dsar

import (
	"encoding/json"
	"testing"
	"time"
)

func TestExportResponseRoundTrip(t *testing.T) {
	orig := ExportResponse{
		Service:   "crm-sales",
		ContactID: "c-123",
		Slices: []Slice{
			{Kind: "leads", Rows: []map[string]any{{"id": "l-1", "status": "open"}}},
			{Kind: "opportunities", Rows: []map[string]any{}},
		},
		GeneratedAt: time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC),
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got ExportResponse
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Service != orig.Service || got.ContactID != orig.ContactID {
		t.Fatalf("scalar mismatch: %+v", got)
	}
	if len(got.Slices) != 2 || got.Slices[0].Kind != "leads" {
		t.Fatalf("slices mismatch: %+v", got.Slices)
	}
	if got.Slices[0].Rows[0]["status"] != "open" {
		t.Fatalf("row payload lost: %+v", got.Slices[0].Rows)
	}
	if !got.GeneratedAt.Equal(orig.GeneratedAt) {
		t.Fatalf("generated_at mismatch: %v", got.GeneratedAt)
	}
}

func TestExportResponseJSONKeys(t *testing.T) {
	b, _ := json.Marshal(ExportResponse{Service: "s", ContactID: "c"})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"service", "contact_id", "slices", "generated_at"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing wire key %q in %v", k, m)
		}
	}
}

func TestDeleteResponseRoundTrip(t *testing.T) {
	orig := DeleteResponse{
		Service:    "billing",
		ContactID:  "c-9",
		Deleted:    0,
		Anonymized: 4,
		Blocked:    false,
	}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got DeleteResponse
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got != orig {
		t.Fatalf("round-trip mismatch: %+v vs %+v", got, orig)
	}
}

func TestDeleteRequestKeys(t *testing.T) {
	b, _ := json.Marshal(DeleteRequest{ContactID: "c", TenantID: "t", Mode: ModeAnonymize, Held: true})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"contact_id", "tenant_id", "mode", "held"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing wire key %q in %v", k, m)
		}
	}
	if m["mode"] != "anonymize" {
		t.Fatalf("mode constant mismatch: %v", m["mode"])
	}
}
