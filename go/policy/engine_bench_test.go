package policy

import (
	"fmt"
	"testing"
	"time"
)

// buildRealisticBundle constructs a bundle approximating production scale:
// ~50 roles x 30 object types (= ~1500 rules), each rule carrying 20 field rules
// plus a couple of ABAC record conditions. This is the worst-case map size the
// hot-path lookup must traverse.
func buildRealisticBundle() CompiledBundle {
	const (
		nRoles   = 50
		nObjects = 30
		nFields  = 20
	)
	system := make(map[RoleObj]PolicyRule, nRoles*nObjects)
	for r := 0; r < nRoles; r++ {
		for o := 0; o < nObjects; o++ {
			fields := make(map[string]FieldRule, nFields+1)
			fields["*"] = FieldRule{Read: true, Write: false}
			for f := 0; f < nFields; f++ {
				mask := ""
				if f%5 == 0 {
					mask = "redact"
				}
				fields[fmt.Sprintf("field_%d", f)] = FieldRule{
					Read:         true,
					Write:        f%2 == 0,
					MaskStrategy: mask,
				}
			}
			system[RoleObj{
				Role:       fmt.Sprintf("role_%d", r),
				ObjectType: fmt.Sprintf("object_%d", o),
			}] = PolicyRule{
				Create: true, Read: true, Update: r%2 == 0, Delete: false,
				ViewAll: r%3 == 0, ModifyAll: false,
				Fields: fields,
				RecordConditions: []Condition{
					{Field: "tenant_id", Op: "==", Value: "$tenant_id"},
					{Field: "owner_id", Op: "==", Value: "$user_id"},
				},
			}
		}
	}

	// A handful of tenant overrides layered on top.
	tenant := map[string]map[RoleObj]PolicyRule{
		"tenant-bench": {
			{Role: "role_0", ObjectType: "object_0"}: {
				Update: true,
				Fields: map[string]FieldRule{"field_1": {Read: true, Write: true}},
			},
		},
	}

	return CompiledBundle{Version: 1, System: system, Tenant: tenant}
}

func benchEngine() (*Engine, Identity) {
	b := buildRealisticBundle()
	e := NewEngine(func() CompiledBundle { return b })
	id := Identity{TenantID: "tenant-bench", UserID: "u-1", UserRole: "role_0"}
	return e, id
}

func BenchmarkCan_WholeObjectRead(b *testing.B) {
	e, id := benchEngine()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Can(id, "read", "object_0", "")
	}
}

func BenchmarkCan_FieldScoped(b *testing.B) {
	e, id := benchEngine()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.Can(id, "update", "object_0", "field_2")
	}
}

func BenchmarkCanRecord(b *testing.B) {
	e, id := benchEngine()
	rec := map[string]any{"tenant_id": "tenant-bench", "owner_id": "u-1"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.CanRecord(id, "read", "object_0", rec)
	}
}

// TestCan_Under5ms guards the hot path against accidental network/lock latency.
// A single evaluation over the realistic bundle must complete well under 5ms
// (in practice sub-microsecond).
func TestCan_Under5ms(t *testing.T) {
	e, id := benchEngine()

	// Warm any lazy allocation, then time a single representative call.
	_ = e.Can(id, "read", "object_0", "")

	const budget = 5 * time.Millisecond
	start := time.Now()
	dec := e.Can(id, "read", "object_0", "")
	elapsed := time.Since(start)

	if !dec.Allow {
		t.Fatalf("expected allow for read object_0, got %+v", dec)
	}
	if elapsed > budget {
		t.Fatalf("Can took %v, exceeds %v budget", elapsed, budget)
	}
	t.Logf("Can whole-object read latency: %v", elapsed)

	// Field-scoped and record-scoped calls must also be within budget.
	start = time.Now()
	_ = e.Can(id, "update", "object_0", "field_2")
	if d := time.Since(start); d > budget {
		t.Fatalf("field-scoped Can took %v, exceeds %v", d, budget)
	}

	rec := map[string]any{"tenant_id": "tenant-bench", "owner_id": "u-1"}
	start = time.Now()
	_ = e.CanRecord(id, "read", "object_0", rec)
	if d := time.Since(start); d > budget {
		t.Fatalf("CanRecord took %v, exceeds %v", d, budget)
	}
}
