package policy

import "sort"

// fieldRuleFor resolves the effective FieldRule for a field, applying field-level
// security precedence: an exact field entry wins over the "*" default. The second
// return value is false when the field has neither an explicit entry nor a "*"
// default, in which case the field is governed solely by the object-level grant.
func fieldRuleFor(rule PolicyRule, field string) (FieldRule, bool) {
	if rule.Fields == nil {
		return FieldRule{}, false
	}
	if fr, ok := rule.Fields[field]; ok {
		return fr, true
	}
	if fr, ok := rule.Fields["*"]; ok {
		return fr, true
	}
	return FieldRule{}, false
}

// decideField evaluates a field-scoped decision: the object-level action grant
// must hold AND the field must permit the access (Read for "read", Write for any
// write action) per its resolved FieldRule. A field with no explicit or "*" rule
// inherits the object-level grant.
func decideField(rule PolicyRule, action, field string, grant bool) Decision {
	if !grant {
		return Decision{Allow: false, Reason: "action denied"}
	}

	fr, ok := fieldRuleFor(rule, field)
	if !ok {
		// No field-level rule governs this field; the object-level grant stands.
		return Decision{Allow: true}
	}

	if action == "read" {
		if !fr.Read {
			return Decision{Allow: false, Reason: "field not readable"}
		}
		return Decision{Allow: true}
	}

	// Any non-read action (create/update/delete/modify_all/view_all on a field)
	// is treated as a write requirement.
	if !fr.Write {
		return Decision{Allow: false, Reason: "field not writable"}
	}
	return Decision{Allow: true}
}

// visibleAndMasked computes, for a whole-object read, the set of fields the
// caller may read (VisibleFields, sorted) and the subset that must be masked on
// output mapped to their mask strategy (MaskedFields). Only fields with an
// explicit FieldRule are considered; the "*" default is not enumerated because
// the concrete field universe is not known here (callers apply "*" to any field
// absent from the rule). A readable field with a non-empty MaskStrategy is added
// to MaskedFields.
func visibleAndMasked(rule PolicyRule) ([]string, map[string]string) {
	if len(rule.Fields) == 0 {
		return nil, nil
	}

	var visible []string
	masked := map[string]string{}
	for name, fr := range rule.Fields {
		if name == "*" {
			continue
		}
		if !fr.Read {
			continue
		}
		visible = append(visible, name)
		if fr.MaskStrategy != "" {
			masked[name] = fr.MaskStrategy
		}
	}
	sort.Strings(visible)
	if len(masked) == 0 {
		masked = nil
	}
	return visible, masked
}
