package audit

import (
	"context"
	"encoding/json"
	"testing"
)

func TestEmit_WritesEnvelopeToOutbox(t *testing.T) {
	var got OutboxEnvelope
	writer := func(_ context.Context, env OutboxEnvelope) error { got = env; return nil }
	ev := NewEvent(Params{TenantID: "t1", Action: ActionCreate, ObjectType: "lead", ObjectID: "l1", Service: "crm-sales"})
	if err := Emit(context.Background(), writer, ev); err != nil {
		t.Fatal(err)
	}
	if got.EventType != "audit.lead.create" {
		t.Fatalf("event_type = %q", got.EventType)
	}
	if got.Topic != "audit" {
		t.Fatalf("topic = %q", got.Topic)
	}
	if got.TenantID != "t1" {
		t.Fatalf("tenant_id = %q", got.TenantID)
	}
	var decoded AuditEvent
	if err := json.Unmarshal(got.Payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ObjectID != "l1" {
		t.Fatalf("payload object_id = %q", decoded.ObjectID)
	}
}
