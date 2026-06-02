package policy

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestBundle_TenantOverridesSystemDefault(t *testing.T) {
	const (
		tenant = "tenant-a"
		role   = "sales_rep"
		obj    = "opportunity"
	)

	bundle := CompiledBundle{
		Version: 1,
		System: map[RoleObj]PolicyRule{
			{Role: role, ObjectType: obj}: {
				Read: true,
				Fields: map[string]FieldRule{
					"amount": {Read: true},
				},
			},
		},
		Tenant: map[string]map[RoleObj]PolicyRule{
			tenant: {
				{Role: role, ObjectType: obj}: {
					Update: true,
					Fields: map[string]FieldRule{
						"amount": {Read: true, Write: true},
						"stage":  {Read: true},
					},
				},
			},
		},
	}

	got := bundle.RuleFor(tenant, role, obj)

	if !got.Read {
		t.Errorf("Read: want true (from system default), got false")
	}
	if !got.Update {
		t.Errorf("Update: want true (granted by tenant override), got false")
	}
	if !got.Fields["amount"].Write {
		t.Errorf("amount.Write: want true (tenant override), got false")
	}
	if !got.Fields["stage"].Read {
		t.Errorf("stage.Read: want true (tenant-added field), got false")
	}
}

func TestBundle_RuleFor_SystemOnly(t *testing.T) {
	const role, obj = "viewer", "contact"
	bundle := CompiledBundle{
		Version: 1,
		System: map[RoleObj]PolicyRule{
			{Role: role, ObjectType: obj}: {Read: true},
		},
	}
	got := bundle.RuleFor("tenant-x", role, obj)
	if !got.Read || got.Update {
		t.Errorf("system-only rule: want Read=true Update=false, got %+v", got)
	}
}

func TestBundle_RuleFor_Unknown(t *testing.T) {
	bundle := CompiledBundle{Version: 1}
	got := bundle.RuleFor("t", "nobody", "nothing")
	if got.Read || got.Create || got.Update || got.Delete {
		t.Errorf("unknown role/object: want zero rule, got %+v", got)
	}
}

func TestMergeRule_RecordConditionsTenantReplaces(t *testing.T) {
	base := PolicyRule{
		Read:             true,
		RecordConditions: []Condition{{Field: "owner_id", Op: "==", Value: "$user_id"}},
	}
	override := PolicyRule{
		Update:           true,
		RecordConditions: []Condition{{Field: "team_id", Op: "in", Value: "1,2"}},
	}
	got := mergeRule(base, override)
	want := []Condition{{Field: "team_id", Op: "in", Value: "1,2"}}
	if !reflect.DeepEqual(got.RecordConditions, want) {
		t.Errorf("RecordConditions: tenant should replace base, got %+v", got.RecordConditions)
	}
}

func TestMergeRule_RecordConditionsEmptyOverrideKeepsBase(t *testing.T) {
	base := PolicyRule{
		Read:             true,
		RecordConditions: []Condition{{Field: "owner_id", Op: "==", Value: "$user_id"}},
	}
	override := PolicyRule{Update: true}
	got := mergeRule(base, override)
	if len(got.RecordConditions) != 1 || got.RecordConditions[0].Field != "owner_id" {
		t.Errorf("empty override should keep base conditions, got %+v", got.RecordConditions)
	}
}

func TestCompiledBundle_JSONRoundTrip(t *testing.T) {
	in := CompiledBundle{
		Version: 7,
		System: map[RoleObj]PolicyRule{
			{Role: "viewer", ObjectType: "contact"}: {
				Read:   true,
				Fields: map[string]FieldRule{"ssn": {Read: true, MaskStrategy: "redact"}},
			},
		},
		Tenant: map[string]map[RoleObj]PolicyRule{
			"tenant-a": {
				{Role: "viewer", ObjectType: "contact"}: {
					Update:           true,
					RecordConditions: []Condition{{Field: "owner_id", Op: "==", Value: "$user_id"}},
				},
			},
		},
	}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out CompiledBundle
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Errorf("round-trip mismatch:\n in=%+v\nout=%+v", in, out)
	}
	// Marshal must be deterministic (signed-body stability).
	raw2, _ := json.Marshal(in)
	if string(raw) != string(raw2) {
		t.Errorf("marshal not deterministic:\n%s\n%s", raw, raw2)
	}
}
