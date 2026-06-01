package audit

import (
	"strings"
	"testing"
)

func TestNewEvent_RequiredFields(t *testing.T) {
	e, err := NewEvent(Params{
		TenantID: "11111111-1111-1111-1111-111111111111",
		UserID:   "22222222-2222-2222-2222-222222222222",
		Action:   ActionUpdate, ObjectType: "lead", ObjectID: "lead-1",
		Service: "crm-sales", TraceID: "trace-abc", JTI: "jti-xyz",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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

func TestNewEvent_ErrorOnMissingTenant(t *testing.T) {
	base := func() Params {
		return Params{
			TenantID:   "t1",
			UserID:     "u1",
			Action:     ActionCreate,
			ObjectType: "lead",
			Service:    "crm-sales",
		}
	}

	cases := []struct {
		name    string
		mutate  func(*Params)
		wantErr bool
		field   string
	}{
		{"missing tenant", func(p *Params) { p.TenantID = "" }, true, "TenantID"},
		{"missing action", func(p *Params) { p.Action = "" }, true, "Action"},
		{"missing object type", func(p *Params) { p.ObjectType = "" }, true, "ObjectType"},
		{"missing service", func(p *Params) { p.Service = "" }, true, "Service"},
		{"missing user", func(p *Params) { p.UserID = "" }, false, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base()
			tc.mutate(&p)
			_, err := NewEvent(p)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tc.field) {
					t.Fatalf("error %q should name field %q", err.Error(), tc.field)
				}
			} else if err != nil {
				t.Fatalf("expected no error, got %v", err)
			}
		})
	}
}

func TestMustNewEvent_PanicsOnMissing(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on missing required field")
		}
	}()
	_ = MustNewEvent(Params{Action: ActionCreate, ObjectType: "lead", Service: "crm-sales"})
}

func TestMustNewEvent_OK(t *testing.T) {
	e := MustNewEvent(Params{
		TenantID: "t1", Action: ActionCreate, ObjectType: "lead", Service: "crm-sales",
	})
	if e.ID == "" {
		t.Fatal("expected generated event ID")
	}
}
