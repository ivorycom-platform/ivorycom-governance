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
//
// BUNDLE-AUTHOR WARNING (field inheritance): a field with neither an explicit
// Fields entry nor a "*" default INHERITS the object-level action grant — i.e.
// if the role can Read the object, it can read that field. Therefore sensitive
// fields (SSN, salary, payment data, etc.) MUST be gated explicitly: give them
// a FieldRule with Read:false (or a MaskStrategy), or set a restrictive "*"
// default. Omitting BOTH leaves the field visible to anyone holding the
// object-level read grant.
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
	// Capabilities holds per-tenant agent tool-action grants. Additive: a
	// bundle without it simply grants no agent any capability, which denies.
	Capabilities map[string]map[CapKey]CapabilityRule
	// Autonomy holds each tenant's agent-execution profile. Additive: absent
	// means the tenant has delegated no autonomy, which denies.
	Autonomy map[string]AutonomyProfile
}

// Identity is the authenticated caller for whom a decision is made.
type Identity struct {
	ActorType ActorType
	AgentID   string
	TenantID  string
	UserID    string
	UserRole  string
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
// precedence). Fields entries from the override replace or add to the base
// (field-level restriction is the tenant's prerogative, override wins).
//
// RecordConditions are CONCATENATED (base ++ override), not replaced. Because
// CanRecord requires ALL conditions to pass, concatenation is a logical AND: a
// tenant customizing a SYSTEM role can only TIGHTEN record scope (add
// conditions), never drop a system-level row scope such as
// owner_id == $user_id. A tenant that wants broader visibility instead defines
// a NEW custom role — that role has no system default, so RuleFor performs no
// merge and the custom role's conditions stand alone. Exact duplicate
// conditions (same Field+Op+Value) are deduped to avoid redundant checks.
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

	// Append-AND base then override conditions, deduping exact duplicates.
	if len(base.RecordConditions) > 0 || len(override.RecordConditions) > 0 {
		seen := make(map[Condition]struct{}, len(base.RecordConditions)+len(override.RecordConditions))
		merged := make([]Condition, 0, len(base.RecordConditions)+len(override.RecordConditions))
		for _, c := range base.RecordConditions {
			if _, dup := seen[c]; dup {
				continue
			}
			seen[c] = struct{}{}
			merged = append(merged, c)
		}
		for _, c := range override.RecordConditions {
			if _, dup := seen[c]; dup {
				continue
			}
			seen[c] = struct{}{}
			merged = append(merged, c)
		}
		out.RecordConditions = merged
	}

	return out
}

// CapKey identifies an agent capability rule: which agent role may invoke which
// registry tool action.
type CapKey struct {
	AgentRole  string
	ToolAction string
}

// CapabilityRule authorizes one tool action for one agent role. Absence of a
// rule denies: an agent has only the capabilities a tenant has explicitly
// granted it (least privilege first).
type CapabilityRule struct {
	Allow bool
	// MaxRisk is the highest risk this agent may execute autonomously. Above
	// it the action requires human approval. Empty is invalid, not unlimited.
	MaxRisk RiskLevel
	// RequiresApproval forces approval regardless of risk.
	RequiresApproval bool
}

// AutonomyMode is a tenant's global agent-execution switch. It is deliberately
// independent of AI infrastructure so it keeps working when that is degraded.
type AutonomyMode string

const (
	AutonomyEnabled    AutonomyMode = "ENABLED"
	AutonomyRestricted AutonomyMode = "RESTRICTED"
	AutonomyPaused     AutonomyMode = "PAUSED"
	AutonomyDisabled   AutonomyMode = "DISABLED"
)

// Limits are a tenant's hard ceilings. They are returned to the caller as a
// requirement to reserve; the engine itself is stateless and never counts.
type Limits struct {
	MaxActionsPerRun      int
	MaxActionsPerHour     int
	MaxMoneyMovementMinor int64
}

// AutonomyProfile is a tenant's agent-execution configuration. An absent
// profile denies — a tenant that has never configured autonomy has not
// delegated any.
type AutonomyProfile struct {
	Mode        AutonomyMode
	MaxAutoRisk RiskLevel
	Limits      Limits
}

// CapabilityFor returns the capability rule for (tenant, agentRole, action) and
// whether one exists. Tenant rules are the only source: capabilities are never
// granted platform-wide, because a system-default agent capability would apply
// to every tenant that never asked for it.
func (b CompiledBundle) CapabilityFor(tenant, agentRole, action string) (CapabilityRule, bool) {
	tm, ok := b.Capabilities[tenant]
	if !ok {
		return CapabilityRule{}, false
	}
	r, ok := tm[CapKey{AgentRole: agentRole, ToolAction: action}]
	return r, ok
}

// AutonomyFor returns the tenant's autonomy profile and whether one exists.
func (b CompiledBundle) AutonomyFor(tenant string) (AutonomyProfile, bool) {
	p, ok := b.Autonomy[tenant]
	return p, ok
}
