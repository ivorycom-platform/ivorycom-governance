package policy

import (
	"fmt"
	"strings"
)

// CanRecord evaluates a record-scoped (ABAC) authorization decision. It first
// applies the same RBAC/object-level check as Can (whole-object, field == ""),
// then additionally evaluates every RecordConditions predicate on the rule
// against the supplied record. All conditions must pass (logical AND) for the
// decision to allow. The substitution tokens $user_id and $tenant_id in a
// condition's Value are replaced with the caller's identity before comparison.
func (e *Engine) CanRecord(id Identity, action, objectType string, record map[string]any) Decision {
	dec := e.Can(id, action, objectType, "")
	if !dec.Allow {
		return dec
	}

	rule := e.get().RuleFor(id.TenantID, id.UserRole, objectType)
	for _, c := range rule.RecordConditions {
		if !evalCondition(c, id, record) {
			return Decision{Allow: false, Reason: "record condition failed: " + c.Field}
		}
	}
	return dec
}

// evalCondition evaluates a single ABAC predicate against a record. The
// condition's Value has identity tokens substituted first; the record field's
// value is coerced to its string form for comparison.
func evalCondition(c Condition, id Identity, record map[string]any) bool {
	want := substitute(c.Value, id)
	got := stringify(record[c.Field])

	switch c.Op {
	case "==":
		return got == want
	case "!=":
		return got != want
	case "in":
		for _, cand := range strings.Split(want, ",") {
			if got == strings.TrimSpace(cand) {
				return true
			}
		}
		return false
	default:
		// Unknown operator denies (strict mode).
		return false
	}
}

// substitute replaces the supported identity tokens in a condition value.
func substitute(value string, id Identity) string {
	value = strings.ReplaceAll(value, "$user_id", id.UserID)
	value = strings.ReplaceAll(value, "$tenant_id", id.TenantID)
	return value
}

// stringify renders an arbitrary record value as a string for comparison. A
// missing field (nil) becomes the empty string.
func stringify(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}
