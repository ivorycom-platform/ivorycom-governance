package audit

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEmit_WritesEnvelopeToOutbox(t *testing.T) {
	var got OutboxEnvelope
	writer := func(_ context.Context, env OutboxEnvelope) error { got = env; return nil }
	ev := MustNewEvent(Params{TenantID: "t1", Action: ActionCreate, ObjectType: "lead", ObjectID: "l1", Service: "crm-sales"})
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

func TestEmit_PropagatesWriteError(t *testing.T) {
	boom := errors.New("boom")
	writer := func(_ context.Context, _ OutboxEnvelope) error { return boom }
	ev := MustNewEvent(Params{TenantID: "t1", Action: ActionCreate, ObjectType: "lead", Service: "crm-sales"})
	err := Emit(context.Background(), writer, ev)
	if err == nil {
		t.Fatal("expected error from write to propagate")
	}
	if !errors.Is(err, boom) && !strings.Contains(err.Error(), "boom") {
		t.Fatalf("expected wrapped boom, got %v", err)
	}
}

func TestEmit_EventTypeForUpdate(t *testing.T) {
	var got OutboxEnvelope
	writer := func(_ context.Context, env OutboxEnvelope) error { got = env; return nil }
	ev := MustNewEvent(Params{TenantID: "t1", Action: ActionUpdate, ObjectType: "opportunity", ObjectID: "o1", Service: "crm-sales"})
	if err := Emit(context.Background(), writer, ev); err != nil {
		t.Fatal(err)
	}
	if got.EventType != "audit.opportunity.update" {
		t.Fatalf("event_type = %q", got.EventType)
	}
}
