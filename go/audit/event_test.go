package audit

import "testing"

func TestNewEvent_RequiredFields(t *testing.T) {
	e := NewEvent(Params{
		TenantID: "11111111-1111-1111-1111-111111111111",
		UserID:   "22222222-2222-2222-2222-222222222222",
		Action:   ActionUpdate, ObjectType: "lead", ObjectID: "lead-1",
		Service: "crm-sales", TraceID: "trace-abc", JTI: "jti-xyz",
	})
	if e.ID == "" {
		t.Fatal("expected generated event ID")
	}
	if e.EventTime.IsZero() {
		t.Fatal("expected EventTime set")
	}
	if e.Action != ActionUpdate {
		t.Fatalf("action = %q", e.Action)
	}
}

func TestNewEvent_RejectsMissingTenant(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on empty tenant")
		}
	}()
	_ = NewEvent(Params{Action: ActionCreate, ObjectType: "lead", Service: "crm-sales"})
}
