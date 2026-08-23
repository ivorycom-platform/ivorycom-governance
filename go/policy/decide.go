package policy

// ActorType classifies the principal on whose behalf a decision is made. It is
// the platform's seven-value actor taxonomy. An empty ActorType is never valid
// on a live request: Decide denies it rather than defaulting to a human, so a
// caller that omits the field can never be mistaken for a user.
type ActorType string

const (
	ActorUser                ActorType = "USER"
	ActorAdmin               ActorType = "ADMIN"
	ActorService             ActorType = "SERVICE"
	ActorAgent               ActorType = "AGENT"
	ActorAutomation          ActorType = "AUTOMATION"
	ActorExternalIntegration ActorType = "EXTERNAL_INTEGRATION"
	ActorSystem              ActorType = "SYSTEM"
	// ActorLegacyUnknown labels audit rows backfilled from before actor typing
	// existed. It is accepted ONLY as stored audit data and is never a valid
	// actor on a live request.
	ActorLegacyUnknown ActorType = "LEGACY_UNKNOWN"
)

// RiskLevel is the registry-assigned risk class of an action. Comparison is by
// the canonical ordinal from riskOrdinal, never by string ordering.
type RiskLevel string

const (
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// Effect is the four-value decision vocabulary.
type Effect string

const (
	EffectAllow               Effect = "ALLOW"
	EffectDeny                Effect = "DENY"
	EffectAllowWithConditions Effect = "ALLOW_WITH_CONDITIONS"
	EffectRequireApproval     Effect = "REQUIRE_APPROVAL"
)

// Stable, programmatic reason codes. Callers branch on these; the human-readable
// Reason string is for operators and must never be parsed.
const (
	ReasonCriticalAgentProhibited = "critical_agent_prohibited"
	ReasonExternalRiskCap         = "external_risk_cap"
	ReasonActorTypeMissing        = "actor_type_missing"
	ReasonInvalidRequest          = "invalid_request"
	ReasonPolicyAbsent            = "policy_absent"
	ReasonResourceDenied          = "resource_denied"
	ReasonNoCapability            = "no_capability"
	ReasonAutonomyUnconfigured    = "autonomy_unconfigured"
	ReasonAutonomyHalted          = "autonomy_halted"
	ReasonInvalidPolicyConfig     = "invalid_policy_config"
)

// riskOrdinal maps a RiskLevel to its canonical ordinal. The bool reports
// whether the value is recognised at all; an unrecognised risk denies rather
// than comparing as a string (where "CRITICAL" < "LOW" lexically, which would
// invert the entire ordering).
func riskOrdinal(r RiskLevel) (int, bool) {
	switch r {
	case RiskLow:
		return 10, true
	case RiskMedium:
		return 20, true
	case RiskHigh:
		return 30, true
	case RiskCritical:
		return 40, true
	default:
		return 0, false
	}
}

// isLiveActor reports whether an actor type may appear on a live request.
// LEGACY_UNKNOWN is audit-backfill data only, and the empty string is a caller
// that omitted the field; neither may authorize anything.
func isLiveActor(a ActorType) bool {
	switch a {
	case ActorUser, ActorAdmin, ActorService, ActorAgent,
		ActorAutomation, ActorExternalIntegration, ActorSystem:
		return true
	default:
		return false
	}
}

// DecisionRequest is the input to Decide.
type DecisionRequest struct {
	Identity   Identity
	Action     string
	ObjectType string
	ActionVerb string
	Field      string
	Risk       RiskLevel

	// ApprovalVerified is set by the caller ONLY after cryptographically
	// verified approval evidence bound to this exact action has been checked
	// and claimed. It is never accepted from an untrusted request body.
	ApprovalVerified bool

	// AmountMinor is the money movement implied by the action, in minor units,
	// derived by the registry from validated parameters — never caller-asserted.
	AmountMinor int64

	// ServiceAllowed and MutatesTenantData are registry-declared properties of
	// the action, supplied by the trusted registry attestation.
	ServiceAllowed    bool
	MutatesTenantData bool
}

// DecisionResult is the outcome of Decide.
type DecisionResult struct {
	Effect        Effect
	ReasonCode    string
	Reason        string
	VisibleFields []string
	MaskedFields  map[string]string
	PolicyVersion int

	// LimitsRequired is the tenant's hard ceilings for an agent-class decision.
	// Decide is stateless and never counts; the caller MUST atomically reserve
	// against these before executing, and a reservation failure is a denial.
	LimitsRequired Limits
}

// isAgentClass reports whether an actor is subject to the agent guardrails.
// AUTOMATION and EXTERNAL_INTEGRATION are agent-class because they are
// delegated autonomy: exempting them would leave the guardrail unenforced for
// exactly the callers a tenant is least able to supervise.
func isAgentClass(a ActorType) bool {
	switch a {
	case ActorAgent, ActorAutomation, ActorExternalIntegration:
		return true
	default:
		return false
	}
}

// deny is a small constructor keeping every refusal shaped identically.
//
// version is required rather than optional: a denial IS an audit record, and
// one that cannot say which policy produced it defeats the attributability the
// guardrail exists to provide. Taking it as a parameter means a new refusal
// path cannot silently omit it.
func deny(version int, code, msg string) DecisionResult {
	return DecisionResult{
		Effect: EffectDeny, ReasonCode: code, Reason: msg, PolicyVersion: version,
	}
}

// Decide evaluates an authorization decision under the agent guardrails.
//
// The ordering is load-bearing and must not be rearranged: every absolute
// denial is evaluated BEFORE any approval branch. If approval were selected
// first, an action that is over-limit, unauthorized on the resource, or outside
// the agent's capability could become a pending approval and later execute —
// approval would launder a denial. Stages therefore run A (universal denials),
// B (agent-class denials), then E (outcome selection).
//
// Limits are deliberately NOT evaluated here. Counting requires mutable state
// and Decide is stateless, so it returns the tenant's Limits in
// LimitsRequired for the caller to reserve atomically before execution.
func (e *Engine) Decide(req DecisionRequest) DecisionResult {
	bundle := e.get()

	// ---- Preconditions -----------------------------------------------------
	if bundle.Version <= 0 {
		return deny(0, ReasonPolicyAbsent, "no policy bundle loaded")
	}
	if !isLiveActor(req.Identity.ActorType) {
		return deny(bundle.Version, ReasonActorTypeMissing, "actor type is missing or not valid on a live request")
	}
	riskOrd, riskKnown := riskOrdinal(req.Risk)
	if !riskKnown {
		return deny(bundle.Version, ReasonInvalidRequest, "unrecognised risk level")
	}

	agentClass := isAgentClass(req.Identity.ActorType)

	// ---- Stage A: universal denials ----------------------------------------
	if agentClass && req.Risk == RiskCritical {
		return deny(bundle.Version, ReasonCriticalAgentProhibited,
			"CRITICAL actions are never executable by an agent-class actor")
	}
	// The EXTERNAL_INTEGRATION ceiling is a hard cap, not an approval prompt:
	// returning REQUIRE_APPROVAL here would let an approval lift the cap.
	if req.Identity.ActorType == ActorExternalIntegration {
		if mediumOrd, _ := riskOrdinal(RiskMedium); riskOrd > mediumOrd {
			return deny(bundle.Version, ReasonExternalRiskCap,
				"external integrations may not exceed MEDIUM risk")
		}
	}
	if req.Identity.ActorType == ActorService && !req.ServiceAllowed {
		return deny(bundle.Version, ReasonResourceDenied,
			"service actors may only invoke registry service_allowed actions")
	}
	if req.Identity.ActorType == ActorSystem && req.MutatesTenantData {
		return deny(bundle.Version, ReasonResourceDenied, "system actor may not mutate tenant data")
	}

	// Object/field authorization. Record-level (ABAC) authorization is NOT
	// evaluated here: it needs trusted record attributes that only the owning
	// service holds, so it happens there, inside the mutation transaction.
	rbac := e.Can(req.Identity, req.ActionVerb, req.ObjectType, req.Field)
	if !rbac.Allow {
		return deny(bundle.Version, ReasonResourceDenied, rbac.Reason)
	}

	// ---- Stage B: agent-class denials --------------------------------------
	var cap CapabilityRule
	if agentClass {
		profile, ok := bundle.AutonomyFor(req.Identity.TenantID)
		if !ok {
			return deny(bundle.Version, ReasonAutonomyUnconfigured,
				"tenant has not configured agent autonomy")
		}
		switch profile.Mode {
		case AutonomyEnabled, AutonomyRestricted:
			// permitted to continue
		case AutonomyPaused, AutonomyDisabled:
			return deny(bundle.Version, ReasonAutonomyHalted, "tenant autonomy is "+string(profile.Mode))
		default:
			return deny(bundle.Version, ReasonInvalidPolicyConfig, "unrecognised autonomy mode")
		}
		if _, ok := riskOrdinal(profile.MaxAutoRisk); !ok {
			return deny(bundle.Version, ReasonInvalidPolicyConfig, "tenant MaxAutoRisk is missing or invalid")
		}
		if profile.Limits.MaxActionsPerRun < 0 || profile.Limits.MaxActionsPerHour < 0 ||
			profile.Limits.MaxMoneyMovementMinor < 0 {
			return deny(bundle.Version, ReasonInvalidPolicyConfig, "tenant limits must be non-negative")
		}

		cap, ok = bundle.CapabilityFor(req.Identity.TenantID, req.Identity.UserRole, req.Action)
		if !ok || !cap.Allow {
			return deny(bundle.Version, ReasonNoCapability,
				"no capability grants this agent role the action")
		}
		if _, ok := riskOrdinal(cap.MaxRisk); !ok {
			return deny(bundle.Version, ReasonInvalidPolicyConfig, "capability MaxRisk is missing or invalid")
		}

		// Money movement the tenant has not funded at all is a denial, not an
		// approval prompt.
		if req.AmountMinor > 0 && profile.Limits.MaxMoneyMovementMinor == 0 {
			return deny(bundle.Version, ReasonInvalidPolicyConfig,
				"tenant prohibits money movement by agents")
		}

		out := e.outcome(req, riskOrd, profile, cap, rbac)
		out.LimitsRequired = profile.Limits
		out.PolicyVersion = bundle.Version
		return out
	}

	out := e.outcome(req, riskOrd, AutonomyProfile{}, CapabilityRule{}, rbac)
	out.PolicyVersion = bundle.Version
	return out
}

// outcome selects the allow-shape. It is reached ONLY after every denial above
// has passed, so nothing unauthorized can become a pending approval.
func (e *Engine) outcome(
	req DecisionRequest, riskOrd int,
	profile AutonomyProfile, cap CapabilityRule, rbac Decision,
) DecisionResult {
	res := DecisionResult{
		VisibleFields: rbac.VisibleFields,
		MaskedFields:  rbac.MaskedFields,
	}

	// Verified approval evidence is the successful transition: it converts an
	// otherwise approval-requiring action into an allow. Without this branch a
	// HIGH action would loop back to REQUIRE_APPROVAL forever.
	if req.ApprovalVerified {
		res.Effect = EffectAllow
		if len(rbac.MaskedFields) > 0 {
			res.Effect = EffectAllowWithConditions
		}
		return res
	}

	// The HIGH floor applies to every actor type and cannot be lowered by any
	// tenant configuration.
	highOrd, _ := riskOrdinal(RiskHigh)
	if riskOrd >= highOrd {
		res.Effect = EffectRequireApproval
		res.ReasonCode = "approval_required_high_risk"
		return res
	}

	if isAgentClass(req.Identity.ActorType) {
		capOrd, _ := riskOrdinal(cap.MaxRisk)
		autoOrd, _ := riskOrdinal(profile.MaxAutoRisk)
		lowOrd, _ := riskOrdinal(RiskLow)
		switch {
		case cap.RequiresApproval:
			res.Effect = EffectRequireApproval
			res.ReasonCode = "approval_required_capability"
			return res
		case riskOrd > capOrd:
			res.Effect = EffectRequireApproval
			res.ReasonCode = "approval_required_capability_max_risk"
			return res
		case riskOrd > autoOrd:
			res.Effect = EffectRequireApproval
			res.ReasonCode = "approval_required_tenant_max_auto_risk"
			return res
		case profile.Mode == AutonomyRestricted && riskOrd > lowOrd:
			res.Effect = EffectRequireApproval
			res.ReasonCode = "approval_required_autonomy_restricted"
			return res
		}
	}

	if len(rbac.MaskedFields) > 0 {
		res.Effect = EffectAllowWithConditions
		return res
	}
	res.Effect = EffectAllow
	return res
}
