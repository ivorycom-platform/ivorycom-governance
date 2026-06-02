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
