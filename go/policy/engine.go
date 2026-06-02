package policy

// Engine evaluates authorization decisions against the current compiled bundle.
// It holds no bundle of its own; instead it calls a getter supplied at
// construction time, which returns the latest bundle snapshot. This indirection
// lets a Loader atomically swap the bundle underneath a long-lived Engine
// (hot-reload) without the Engine taking any lock on the hot path.
type Engine struct {
	get func() CompiledBundle
}

// NewEngine returns an Engine that resolves the current bundle via get. get must
// be cheap and lock-free (e.g. an atomic.Pointer load); it is called on every
// evaluation.
func NewEngine(get func() CompiledBundle) *Engine {
	return &Engine{get: get}
}

// actionGrant maps a canonical action name to the corresponding PolicyRule
// boolean. The second return value is false for an unknown action.
func actionGrant(rule PolicyRule, action string) (bool, bool) {
	switch action {
	case "create":
		return rule.Create, true
	case "read":
		return rule.Read, true
	case "update":
		return rule.Update, true
	case "delete":
		return rule.Delete, true
	case "view_all":
		return rule.ViewAll, true
	case "modify_all":
		return rule.ModifyAll, true
	default:
		return false, false
	}
}

// hasRule reports whether any grant or field/condition is set on the rule, i.e.
// whether a policy actually exists for the (role, object) pair as opposed to the
// all-deny zero value.
func hasRule(r PolicyRule) bool {
	return r.Create || r.Read || r.Update || r.Delete || r.ViewAll || r.ModifyAll ||
		len(r.Fields) > 0 || len(r.RecordConditions) > 0
}

// Can evaluates a single authorization decision for the given identity, action,
// object type and (optional) field.
//
// When field == "" the decision is whole-object: Allow is the action grant, and
// for a read the Decision is populated with VisibleFields / MaskedFields derived
// from the rule's field-level security.
//
// When field != "" the decision is field-scoped: Allow is the action grant AND
// the field being readable (for "read") or writable (for any write action) per
// its FieldRule.
//
// An unknown role/object with no policy denies with Reason "no policy" (strict
// mode); an unknown action denies with Reason "unknown action".
func (e *Engine) Can(id Identity, action, objectType, field string) Decision {
	bundle := e.get()
	rule := bundle.RuleFor(id.TenantID, id.UserRole, objectType)

	if !hasRule(rule) {
		return Decision{Allow: false, Reason: "no policy"}
	}

	grant, known := actionGrant(rule, action)
	if !known {
		return Decision{Allow: false, Reason: "unknown action"}
	}

	if field == "" {
		dec := Decision{Allow: grant}
		if !grant {
			dec.Reason = "action denied"
		}
		if action == "read" {
			dec.VisibleFields, dec.MaskedFields = visibleAndMasked(rule)
		}
		return dec
	}

	return decideField(rule, action, field, grant)
}

// --- minimal field handling (extended in Task 4 / fls.go) ---

func visibleAndMasked(rule PolicyRule) ([]string, map[string]string) {
	return nil, nil
}

func decideField(rule PolicyRule, action, field string, grant bool) Decision {
	return Decision{Allow: grant}
}
