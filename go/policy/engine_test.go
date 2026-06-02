package policy

import "testing"

func staticEngine(b CompiledBundle) *Engine {
	return NewEngine(func() CompiledBundle { return b })
}

func TestCan_DeniesUpdateWhenOnlyRead(t *testing.T) {
	const role, obj = "viewer", "contact"
	e := staticEngine(CompiledBundle{
		Version: 1,
		System: map[RoleObj]PolicyRule{
			{Role: role, ObjectType: obj}: {Read: true},
		},
	})
	id := Identity{TenantID: "t1", UserID: "u1", UserRole: role}

	if got := e.Can(id, "read", obj, ""); !got.Allow {
		t.Errorf("read: want Allow=true, got %+v", got)
	}
	if got := e.Can(id, "update", obj, ""); got.Allow {
		t.Errorf("update: want Allow=false, got %+v", got)
	}
}

func TestCan_NoPolicyStrictDeny(t *testing.T) {
	e := staticEngine(CompiledBundle{Version: 1})
	id := Identity{TenantID: "t1", UserID: "u1", UserRole: "ghost"}
	got := e.Can(id, "read", "secret", "")
	if got.Allow {
		t.Errorf("want deny for unknown role/object, got %+v", got)
	}
	if got.Reason != "no policy" {
		t.Errorf("want Reason=%q, got %q", "no policy", got.Reason)
	}
}

func TestCan_AllActions(t *testing.T) {
	const role, obj = "admin", "deal"
	e := staticEngine(CompiledBundle{
		Version: 1,
		System: map[RoleObj]PolicyRule{
			{Role: role, ObjectType: obj}: {
				Create: true, Read: true, Update: true, Delete: true,
				ViewAll: true, ModifyAll: true,
			},
		},
	})
	id := Identity{TenantID: "t1", UserID: "u1", UserRole: role}
	for _, a := range []string{"create", "read", "update", "delete", "view_all", "modify_all"} {
		if got := e.Can(id, a, obj, ""); !got.Allow {
			t.Errorf("action %q: want Allow=true, got %+v", a, got)
		}
	}
	if got := e.Can(id, "bogus", obj, ""); got.Allow {
		t.Errorf("unknown action: want deny, got %+v", got)
	}
}

func TestCan_HotReloadViaGetter(t *testing.T) {
	const role, obj = "viewer", "contact"
	cur := CompiledBundle{
		Version: 1,
		System: map[RoleObj]PolicyRule{
			{Role: role, ObjectType: obj}: {Read: true},
		},
	}
	e := NewEngine(func() CompiledBundle { return cur })
	id := Identity{TenantID: "t1", UserID: "u1", UserRole: role}

	if e.Can(id, "update", obj, "").Allow {
		t.Fatal("update should be denied before reload")
	}
	cur = CompiledBundle{
		Version: 2,
		System: map[RoleObj]PolicyRule{
			{Role: role, ObjectType: obj}: {Read: true, Update: true},
		},
	}
	if !e.Can(id, "update", obj, "").Allow {
		t.Fatal("update should be allowed after the getter returns a new bundle")
	}
}

func TestCan_FieldLevel(t *testing.T) {
	const role, obj = "rep", "opportunity"
	e := staticEngine(CompiledBundle{
		Version: 1,
		System: map[RoleObj]PolicyRule{
			{Role: role, ObjectType: obj}: {
				Read: true,
				Fields: map[string]FieldRule{
					"close_date": {Read: false},
					"ssn":        {Read: true, MaskStrategy: "redact"},
				},
			},
		},
	})
	id := Identity{TenantID: "t1", UserID: "u1", UserRole: role}

	if got := e.Can(id, "read", obj, "close_date"); got.Allow {
		t.Errorf("read close_date: want deny (Read=false), got %+v", got)
	}
	if got := e.Can(id, "read", obj, "ssn"); !got.Allow {
		t.Errorf("read ssn: want allow, got %+v", got)
	}

	whole := e.Can(id, "read", obj, "")
	if !whole.Allow {
		t.Fatalf("whole-object read: want allow, got %+v", whole)
	}
	if whole.MaskedFields["ssn"] != "redact" {
		t.Errorf("MaskedFields[ssn]: want %q, got %q", "redact", whole.MaskedFields["ssn"])
	}
	if _, ok := whole.MaskedFields["close_date"]; ok {
		t.Errorf("close_date should not appear in MaskedFields (not readable), got %+v", whole.MaskedFields)
	}
	if contains(whole.VisibleFields, "close_date") {
		t.Errorf("close_date should not be visible, got %+v", whole.VisibleFields)
	}
	if !contains(whole.VisibleFields, "ssn") {
		t.Errorf("ssn should be visible, got %+v", whole.VisibleFields)
	}
}

func TestCan_FieldGlobDefault(t *testing.T) {
	const role, obj = "rep", "lead"
	e := staticEngine(CompiledBundle{
		Version: 1,
		System: map[RoleObj]PolicyRule{
			{Role: role, ObjectType: obj}: {
				Read:   true,
				Update: true,
				Fields: map[string]FieldRule{
					"*":      {Read: true, Write: true},
					"score":  {Read: true, Write: false},
					"secret": {Read: false, Write: false},
				},
			},
		},
	})
	id := Identity{TenantID: "t1", UserID: "u1", UserRole: role}

	// Unlisted field falls through to "*": readable + writable.
	if got := e.Can(id, "read", obj, "name"); !got.Allow {
		t.Errorf("read name via *: want allow, got %+v", got)
	}
	if got := e.Can(id, "update", obj, "name"); !got.Allow {
		t.Errorf("update name via *: want allow, got %+v", got)
	}
	// Explicit rule wins over "*": score not writable.
	if got := e.Can(id, "update", obj, "score"); got.Allow {
		t.Errorf("update score: explicit Write=false should win over *, got %+v", got)
	}
	if got := e.Can(id, "read", obj, "score"); !got.Allow {
		t.Errorf("read score: want allow, got %+v", got)
	}
	// secret: not readable.
	if got := e.Can(id, "read", obj, "secret"); got.Allow {
		t.Errorf("read secret: want deny, got %+v", got)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
