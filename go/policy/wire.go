package policy

import (
	"encoding/json"
	"fmt"
	"strings"
)

// roleObjSep separates Role from ObjectType when a RoleObj is used as a JSON
// object key. The ASCII unit separator (0x1f) is never valid in a role or
// object-type name, so it cannot collide with real values.
const roleObjSep = "\x1f"

// roleObjKey renders a RoleObj as its JSON map-key string.
func roleObjKey(k RoleObj) string {
	return k.Role + roleObjSep + k.ObjectType
}

// parseRoleObjKey reverses roleObjKey.
func parseRoleObjKey(s string) (RoleObj, error) {
	parts := strings.SplitN(s, roleObjSep, 2)
	if len(parts) != 2 {
		return RoleObj{}, fmt.Errorf("policy: invalid role/object key %q", s)
	}
	return RoleObj{Role: parts[0], ObjectType: parts[1]}, nil
}

// bundleWire is the JSON representation of a CompiledBundle. Go cannot marshal a
// map keyed by a struct, so the RoleObj-keyed maps are flattened to string keys.
type bundleWire struct {
	Version int                              `json:"version"`
	System  map[string]PolicyRule            `json:"system,omitempty"`
	Tenant  map[string]map[string]PolicyRule `json:"tenant,omitempty"`
}

// MarshalJSON encodes the bundle with string map keys (see bundleWire). Marshal
// is deterministic for a given bundle because encoding/json sorts string map
// keys, which keeps the signed body stable across encodes of equal bundles.
func (b CompiledBundle) MarshalJSON() ([]byte, error) {
	w := bundleWire{Version: b.Version}

	if len(b.System) > 0 {
		w.System = make(map[string]PolicyRule, len(b.System))
		for k, v := range b.System {
			w.System[roleObjKey(k)] = v
		}
	}
	if len(b.Tenant) > 0 {
		w.Tenant = make(map[string]map[string]PolicyRule, len(b.Tenant))
		for tenant, rules := range b.Tenant {
			m := make(map[string]PolicyRule, len(rules))
			for k, v := range rules {
				m[roleObjKey(k)] = v
			}
			w.Tenant[tenant] = m
		}
	}
	return json.Marshal(w)
}

// UnmarshalJSON decodes the string-keyed wire form back into RoleObj-keyed maps.
func (b *CompiledBundle) UnmarshalJSON(data []byte) error {
	var w bundleWire
	if err := json.Unmarshal(data, &w); err != nil {
		return err
	}

	out := CompiledBundle{Version: w.Version}
	if len(w.System) > 0 {
		out.System = make(map[RoleObj]PolicyRule, len(w.System))
		for ks, v := range w.System {
			k, err := parseRoleObjKey(ks)
			if err != nil {
				return err
			}
			out.System[k] = v
		}
	}
	if len(w.Tenant) > 0 {
		out.Tenant = make(map[string]map[RoleObj]PolicyRule, len(w.Tenant))
		for tenant, rules := range w.Tenant {
			m := make(map[RoleObj]PolicyRule, len(rules))
			for ks, v := range rules {
				k, err := parseRoleObjKey(ks)
				if err != nil {
					return err
				}
				m[k] = v
			}
			out.Tenant[tenant] = m
		}
	}
	*b = out
	return nil
}
