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

// roleObjKey renders a RoleObj as its JSON map-key string. It rejects a Role or
// ObjectType containing the roleObjSep byte: such a name would produce a key
// that parseRoleObjKey splits in the wrong place, silently corrupting the
// round-trip. The separator invariant is enforced here, marshal-side, so signed
// bundles are always parseable.
func roleObjKey(k RoleObj) (string, error) {
	if strings.Contains(k.Role, roleObjSep) {
		return "", fmt.Errorf("policy: role %q contains reserved key separator (\\x1f)", k.Role)
	}
	if strings.Contains(k.ObjectType, roleObjSep) {
		return "", fmt.Errorf("policy: object_type %q contains reserved key separator (\\x1f)", k.ObjectType)
	}
	return k.Role + roleObjSep + k.ObjectType, nil
}

// parseRoleObjKey reverses roleObjKey.
func parseRoleObjKey(s string) (RoleObj, error) {
	parts := strings.SplitN(s, roleObjSep, 2)
	if len(parts) != 2 {
		return RoleObj{}, fmt.Errorf("policy: invalid role/object key %q", s)
	}
	return RoleObj{Role: parts[0], ObjectType: parts[1]}, nil
}

// capKey renders a CapKey as its JSON map-key string, enforcing the same
// separator invariant as roleObjKey: a name containing the separator would be
// split in the wrong place on the way back, silently rebinding a capability to
// a different action.
func capKey(k CapKey) (string, error) {
	if strings.Contains(k.AgentRole, roleObjSep) {
		return "", fmt.Errorf("policy: agent_role %q contains reserved key separator (\\x1f)", k.AgentRole)
	}
	if strings.Contains(k.ToolAction, roleObjSep) {
		return "", fmt.Errorf("policy: tool_action %q contains reserved key separator (\\x1f)", k.ToolAction)
	}
	return k.AgentRole + roleObjSep + k.ToolAction, nil
}

// parseCapKey reverses capKey.
func parseCapKey(s string) (CapKey, error) {
	parts := strings.SplitN(s, roleObjSep, 2)
	if len(parts) != 2 {
		return CapKey{}, fmt.Errorf("policy: invalid capability key %q", s)
	}
	return CapKey{AgentRole: parts[0], ToolAction: parts[1]}, nil
}

// bundleWire is the JSON representation of a CompiledBundle. Go cannot marshal a
// map keyed by a struct, so the RoleObj-keyed maps are flattened to string keys.
type bundleWire struct {
	Version int                              `json:"version"`
	System  map[string]PolicyRule            `json:"system,omitempty"`
	Tenant  map[string]map[string]PolicyRule `json:"tenant,omitempty"`
	// Capabilities and Autonomy are additive: an older bundle simply omits
	// them, which grants no agent anything (fail-closed).
	Capabilities map[string]map[string]CapabilityRule `json:"capabilities,omitempty"`
	Autonomy     map[string]AutonomyProfile           `json:"autonomy,omitempty"`
}

// MarshalJSON encodes the bundle with string map keys (see bundleWire). Marshal
// is deterministic for a given bundle because encoding/json sorts string map
// keys, which keeps the signed body stable across encodes of equal bundles.
func (b CompiledBundle) MarshalJSON() ([]byte, error) {
	w := bundleWire{Version: b.Version}

	if len(b.System) > 0 {
		w.System = make(map[string]PolicyRule, len(b.System))
		for k, v := range b.System {
			ks, err := roleObjKey(k)
			if err != nil {
				return nil, err
			}
			w.System[ks] = v
		}
	}
	if len(b.Tenant) > 0 {
		w.Tenant = make(map[string]map[string]PolicyRule, len(b.Tenant))
		for tenant, rules := range b.Tenant {
			m := make(map[string]PolicyRule, len(rules))
			for k, v := range rules {
				ks, err := roleObjKey(k)
				if err != nil {
					return nil, err
				}
				m[ks] = v
			}
			w.Tenant[tenant] = m
		}
	}
	if len(b.Capabilities) > 0 {
		w.Capabilities = make(map[string]map[string]CapabilityRule, len(b.Capabilities))
		for tenant, caps := range b.Capabilities {
			m := make(map[string]CapabilityRule, len(caps))
			for k, v := range caps {
				ks, err := capKey(k)
				if err != nil {
					return nil, err
				}
				m[ks] = v
			}
			w.Capabilities[tenant] = m
		}
	}
	if len(b.Autonomy) > 0 {
		w.Autonomy = make(map[string]AutonomyProfile, len(b.Autonomy))
		for tenant, prof := range b.Autonomy {
			w.Autonomy[tenant] = prof
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
	if len(w.Capabilities) > 0 {
		out.Capabilities = make(map[string]map[CapKey]CapabilityRule, len(w.Capabilities))
		for tenant, caps := range w.Capabilities {
			m := make(map[CapKey]CapabilityRule, len(caps))
			for ks, v := range caps {
				k, err := parseCapKey(ks)
				if err != nil {
					return err
				}
				m[k] = v
			}
			out.Capabilities[tenant] = m
		}
	}
	if len(w.Autonomy) > 0 {
		out.Autonomy = make(map[string]AutonomyProfile, len(w.Autonomy))
		for tenant, prof := range w.Autonomy {
			out.Autonomy[tenant] = prof
		}
	}
	*b = out
	return nil
}
