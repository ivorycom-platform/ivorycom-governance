package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

// MarshalJSON must reject any role or object-type name containing the \x1f
// separator, rather than silently producing a key that round-trips wrong.
func TestMarshal_RejectsSeparatorInNames(t *testing.T) {
	cases := []struct {
		name   string
		bundle CompiledBundle
	}{
		{
			name: "separator in system role",
			bundle: CompiledBundle{
				Version: 1,
				System: map[RoleObj]PolicyRule{
					{Role: "sales\x1frep", ObjectType: "opportunity"}: {Read: true},
				},
			},
		},
		{
			name: "separator in system object type",
			bundle: CompiledBundle{
				Version: 1,
				System: map[RoleObj]PolicyRule{
					{Role: "viewer", ObjectType: "con\x1ftact"}: {Read: true},
				},
			},
		},
		{
			name: "separator in tenant role",
			bundle: CompiledBundle{
				Version: 1,
				Tenant: map[string]map[RoleObj]PolicyRule{
					"tenant-a": {
						{Role: "ad\x1fmin", ObjectType: "contact"}: {Read: true},
					},
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := json.Marshal(tc.bundle)
			if err == nil {
				t.Fatalf("expected marshal error for %s, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), "separator") {
				t.Errorf("error should mention the separator invariant, got %q", err.Error())
			}
		})
	}
}

// A bundle with clean names must still marshal without error.
func TestMarshal_CleanNamesOK(t *testing.T) {
	b := CompiledBundle{
		Version: 1,
		System: map[RoleObj]PolicyRule{
			{Role: "viewer", ObjectType: "contact"}: {Read: true},
		},
	}
	if _, err := json.Marshal(b); err != nil {
		t.Fatalf("clean bundle should marshal, got %v", err)
	}
}
