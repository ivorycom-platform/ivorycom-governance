// Package policy provides the Ivorycom local PolicyEngine: a signed, in-memory
// compiled-bundle representation of every tenant's RBAC / field-level-security
// (FLS) / attribute-based (ABAC) authorization rules, plus a sub-5ms Engine that
// evaluates access decisions without any network round-trip, and a Loader that
// fetches, verifies (ed25519), caches, and hot-reloads the signed bundle.
//
// Each service embeds this package and answers authorization questions locally:
//
//	dec := engine.Can(id, "update", "opportunity", "")
//	if !dec.Allow { ... }
//
// The bundle is produced centrally by the governance service and distributed as
// a signed blob (see bundle.go); services never trust an unsigned bundle.
package policy

// RoleObj is the composite key identifying a single (role, object-type) policy
// rule within a compiled bundle.
type RoleObj struct {
	Role       string
	ObjectType string
}

// FieldRule is the field-level-security descriptor for a single field. Read and
// Write gate access; MaskStrategy (one of "", "redact", "partial", "hash")
// describes how a readable-but-sensitive field is masked on output.
type FieldRule struct {
	Read         bool
	Write        bool
	MaskStrategy string
}

// Condition is a single ABAC predicate evaluated against a record. Op is one of
// "==", "!=", "in"; for "in", Value is a comma-separated list of candidates.
// Value may contain the substitution tokens $user_id and $tenant_id, which the
// engine replaces with the caller's identity before comparison.
type Condition struct {
	Field string
	Op    string
	Value string
}

// PolicyRule is the full authorization rule for one (role, object-type). The
// boolean action grants map to the canonical actions; Fields holds per-field
// FLS (the key "*" is the default applied to any field without an explicit
// entry); RecordConditions are ABAC predicates ANDed together for record-scoped
// access.
type PolicyRule struct {
	Create           bool
	Read             bool
	Update           bool
	Delete           bool
	ViewAll          bool
	ModifyAll        bool
	Fields           map[string]FieldRule
	RecordConditions []Condition
}

// Decision is the result of an authorization evaluation. For whole-object reads,
// VisibleFields lists the fields the caller may read and MaskedFields maps a
// readable field to its mask strategy. Reason explains a denial.
type Decision struct {
	Allow         bool
	VisibleFields []string
	MaskedFields  map[string]string
	Reason        string
}

// CompiledBundle is the in-memory, ready-to-evaluate policy set. System holds
// the platform defaults; Tenant holds per-tenant overrides layered on top of the
// system defaults (tenant wins). Version is monotonically increasing and is used
// by the Loader to decide whether a freshly fetched bundle is newer.
type CompiledBundle struct {
	Version int
	System  map[RoleObj]PolicyRule
	Tenant  map[string]map[RoleObj]PolicyRule
}

// Identity is the authenticated caller for whom a decision is made.
type Identity struct {
	TenantID string
	UserID   string
	UserRole string
}

// RuleFor returns the effective PolicyRule for (tenant, role, objectType): the
// system default merged with the tenant override, tenant winning. If neither
// exists the zero PolicyRule (all-deny) is returned.
func (b CompiledBundle) RuleFor(tenant, role, objectType string) PolicyRule {
	key := RoleObj{Role: role, ObjectType: objectType}
	base, hasBase := b.System[key]

	override, hasOverride := PolicyRule{}, false
	if tm, ok := b.Tenant[tenant]; ok {
		override, hasOverride = tm[key]
	}

	switch {
	case hasBase && hasOverride:
		return mergeRule(base, override)
	case hasBase:
		return base
	case hasOverride:
		return override
	default:
		return PolicyRule{}
	}
}

// mergeRule layers a tenant override on top of a system-default base. Action
// booleans are ORed so the tenant can only grant additional access (tenant
// precedence). Fields entries from the override replace or add to the base.
// RecordConditions from the override replace the base entirely when non-empty,
// otherwise the base conditions are kept.
func mergeRule(base, override PolicyRule) PolicyRule {
	out := PolicyRule{
		Create:    base.Create || override.Create,
		Read:      base.Read || override.Read,
		Update:    base.Update || override.Update,
		Delete:    base.Delete || override.Delete,
		ViewAll:   base.ViewAll || override.ViewAll,
		ModifyAll: base.ModifyAll || override.ModifyAll,
	}

	if len(base.Fields) > 0 || len(override.Fields) > 0 {
		out.Fields = make(map[string]FieldRule, len(base.Fields)+len(override.Fields))
		for k, v := range base.Fields {
			out.Fields[k] = v
		}
		for k, v := range override.Fields {
			out.Fields[k] = v
		}
	}

	if len(override.RecordConditions) > 0 {
		out.RecordConditions = override.RecordConditions
	} else {
		out.RecordConditions = base.RecordConditions
	}

	return out
}
