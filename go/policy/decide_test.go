package policy

import (
	"encoding/json"
	"testing"
)

// bundleWithRule returns a single-rule bundle granting the given role full CRUD
// on objectType, so that Decide tests exercise the agent-guardrail logic rather
// than tripping over a missing RBAC rule.
func bundleWithRule(tenant, role, objectType string) CompiledBundle {
	return CompiledBundle{
		Version: 1,
		System: map[RoleObj]PolicyRule{
			{Role: role, ObjectType: objectType}: {
				Create: true, Read: true, Update: true, Delete: true,
			},
		},
	}
}

// TestDecide_AgentCriticalIsAlwaysDenied asserts the terminal Stage A rule: an
// agent-class actor may never execute a CRITICAL action, regardless of tenant
// configuration, capability grants, or approval. This is the guardrail's
// hardest stop — CRITICAL is not approvable for an agent, it is denied.
func TestDecide_AgentCriticalIsAlwaysDenied(t *testing.T) {
	b := bundleWithRule("t1", "sales_agent", "payment")
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(DecisionRequest{
		Identity: Identity{
			TenantID:  "t1",
			UserRole:  "sales_agent",
			ActorType: ActorAgent,
			AgentID:   "sales-agent",
		},
		Action:     "billing.refund",
		ObjectType: "payment",
		ActionVerb: "delete",
		Risk:       RiskCritical,
	})

	if got.Effect != EffectDeny {
		t.Fatalf("agent CRITICAL must be DENY, got %q (reason %q)", got.Effect, got.ReasonCode)
	}
	if got.ReasonCode != ReasonCriticalAgentProhibited {
		t.Fatalf("expected reason %q, got %q", ReasonCriticalAgentProhibited, got.ReasonCode)
	}
}

// TestDecide_MissingActorTypeIsDenied asserts there is no human default. A
// request that omits actor_type must be denied, never silently treated as a
// USER — that default was how an agent could shed its guardrails.
func TestDecide_MissingActorTypeIsDenied(t *testing.T) {
	b := bundleWithRule("t1", "member", "lead")
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(DecisionRequest{
		Identity:   Identity{TenantID: "t1", UserRole: "member"},
		Action:     "crm.read_lead",
		ObjectType: "lead",
		ActionVerb: "read",
		Risk:       RiskLow,
	})

	if got.Effect != EffectDeny {
		t.Fatalf("missing actor type must be DENY, got %q", got.Effect)
	}
	if got.ReasonCode != ReasonActorTypeMissing {
		t.Fatalf("expected %q, got %q", ReasonActorTypeMissing, got.ReasonCode)
	}
}

// TestDecide_LegacyUnknownActorRejectedOnLiveRequest asserts the audit-only
// backfill value cannot be used to authorize anything.
func TestDecide_LegacyUnknownActorRejectedOnLiveRequest(t *testing.T) {
	b := bundleWithRule("t1", "member", "lead")
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(DecisionRequest{
		Identity:   Identity{TenantID: "t1", UserRole: "member", ActorType: ActorLegacyUnknown},
		Action:     "crm.read_lead",
		ObjectType: "lead",
		ActionVerb: "read",
		Risk:       RiskLow,
	})

	if got.Effect != EffectDeny {
		t.Fatalf("LEGACY_UNKNOWN must be DENY on a live request, got %q", got.Effect)
	}
}

// TestDecide_UnknownRiskIsDenied asserts an unrecognised risk value denies
// rather than falling through to an allow branch.
func TestDecide_UnknownRiskIsDenied(t *testing.T) {
	b := bundleWithRule("t1", "member", "lead")
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(DecisionRequest{
		Identity:   Identity{TenantID: "t1", UserRole: "member", ActorType: ActorUser},
		Action:     "crm.read_lead",
		ObjectType: "lead",
		ActionVerb: "read",
		Risk:       RiskLevel("SPICY"),
	})

	if got.Effect != EffectDeny || got.ReasonCode != ReasonInvalidRequest {
		t.Fatalf("unknown risk must DENY invalid_request, got %q/%q", got.Effect, got.ReasonCode)
	}
}

// TestDecide_EmptyBundleIsDenied asserts a cold start is not an open door.
func TestDecide_EmptyBundleIsDenied(t *testing.T) {
	e := NewEngine(func() CompiledBundle { return CompiledBundle{} })

	got := e.Decide(DecisionRequest{
		Identity:   Identity{TenantID: "t1", UserRole: "member", ActorType: ActorUser},
		Action:     "crm.read_lead",
		ObjectType: "lead",
		ActionVerb: "read",
		Risk:       RiskLow,
	})

	if got.Effect != EffectDeny || got.ReasonCode != ReasonPolicyAbsent {
		t.Fatalf("empty bundle must DENY policy_absent, got %q/%q", got.Effect, got.ReasonCode)
	}
}

// TestDecide_HighRiskRequiresApprovalForHumans asserts the HIGH floor applies to
// every actor type, not just agents, and is reached only after denials.
func TestDecide_HighRiskRequiresApprovalForHumans(t *testing.T) {
	b := bundleWithRule("t1", "admin", "payment")
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(DecisionRequest{
		Identity:   Identity{TenantID: "t1", UserRole: "admin", ActorType: ActorAdmin},
		Action:     "billing.refund",
		ObjectType: "payment",
		ActionVerb: "update",
		Risk:       RiskHigh,
	})

	if got.Effect != EffectRequireApproval {
		t.Fatalf("HIGH must REQUIRE_APPROVAL for humans too, got %q", got.Effect)
	}
}

// TestDecide_ExternalIntegrationAboveMediumIsHardDenied asserts the cap is a
// ceiling, not an approval prompt: an EXTERNAL_INTEGRATION cannot reach HIGH
// even with an approval available.
func TestDecide_ExternalIntegrationAboveMediumIsHardDenied(t *testing.T) {
	b := bundleWithRule("t1", "integration", "payment")
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(DecisionRequest{
		Identity: Identity{
			TenantID: "t1", UserRole: "integration",
			ActorType: ActorExternalIntegration, AgentID: "zapier",
		},
		Action:           "billing.refund",
		ObjectType:       "payment",
		ActionVerb:       "update",
		Risk:             RiskHigh,
		ApprovalVerified: true,
	})

	if got.Effect != EffectDeny || got.ReasonCode != ReasonExternalRiskCap {
		t.Fatalf("EXTERNAL_INTEGRATION above MEDIUM must DENY external_risk_cap, got %q/%q",
			got.Effect, got.ReasonCode)
	}
}

// agentBundle builds a bundle with RBAC, one capability and an autonomy profile,
// so agent-path tests can vary one dimension at a time.
func agentBundle(mode AutonomyMode, capMaxRisk, autoMaxRisk RiskLevel, reqApproval bool) CompiledBundle {
	return CompiledBundle{
		Version: 7,
		System: map[RoleObj]PolicyRule{
			{Role: "sales_agent", ObjectType: "lead"}: {
				Create: true, Read: true, Update: true,
			},
		},
		Capabilities: map[string]map[CapKey]CapabilityRule{
			"t1": {{AgentRole: "sales-agent", ToolAction: "crm.update_lead"}: {
				Allow: true, MaxRisk: capMaxRisk, RequiresApproval: reqApproval,
			}},
		},
		Autonomy: map[string]AutonomyProfile{
			"t1": {Mode: mode, MaxAutoRisk: autoMaxRisk,
				Limits: Limits{MaxActionsPerRun: 25, MaxActionsPerHour: 100, MaxMoneyMovementMinor: 5000}},
		},
	}
}

func agentReq(risk RiskLevel) DecisionRequest {
	return DecisionRequest{
		Identity: Identity{
			TenantID: "t1", UserRole: "sales_agent",
			ActorType: ActorAgent, AgentID: "sales-agent",
		},
		Action:     "crm.update_lead",
		ObjectType: "lead",
		ActionVerb: "update",
		Risk:       risk,
	}
}

// TestDecide_AgentWithinCapabilityIsAllowed is the positive path: a granted
// action at or below both ceilings executes autonomously.
func TestDecide_AgentWithinCapabilityIsAllowed(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskMedium, RiskMedium, false)
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(agentReq(RiskMedium))

	if got.Effect != EffectAllow {
		t.Fatalf("expected ALLOW, got %q (%s)", got.Effect, got.ReasonCode)
	}
	if got.PolicyVersion != 7 {
		t.Fatalf("decision must carry the bundle version, got %d", got.PolicyVersion)
	}
	if got.LimitsRequired.MaxActionsPerHour != 100 {
		t.Fatalf("agent decision must return limits to reserve, got %+v", got.LimitsRequired)
	}
}

// TestDecide_AgentWithoutCapabilityIsDenied asserts absence denies: an agent has
// only what a tenant explicitly granted.
func TestDecide_AgentWithoutCapabilityIsDenied(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskMedium, RiskMedium, false)
	e := NewEngine(func() CompiledBundle { return b })

	req := agentReq(RiskLow)
	req.Action = "billing.issue_refund" // never granted

	got := e.Decide(req)

	if got.Effect != EffectDeny || got.ReasonCode != ReasonNoCapability {
		t.Fatalf("ungranted action must DENY no_capability, got %q/%q", got.Effect, got.ReasonCode)
	}
}

// TestDecide_AutonomyPausedDeniesAgent asserts the tenant kill switch stops
// agent execution outright.
func TestDecide_AutonomyPausedDeniesAgent(t *testing.T) {
	b := agentBundle(AutonomyPaused, RiskMedium, RiskMedium, false)
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(agentReq(RiskLow))

	if got.Effect != EffectDeny || got.ReasonCode != ReasonAutonomyHalted {
		t.Fatalf("PAUSED autonomy must DENY autonomy_halted, got %q/%q", got.Effect, got.ReasonCode)
	}
}

// TestDecide_AutonomyUnconfiguredDeniesAgent asserts a tenant that never
// configured autonomy has delegated none.
func TestDecide_AutonomyUnconfiguredDeniesAgent(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskMedium, RiskMedium, false)
	delete(b.Autonomy, "t1")
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(agentReq(RiskLow))

	if got.Effect != EffectDeny || got.ReasonCode != ReasonAutonomyUnconfigured {
		t.Fatalf("expected autonomy_unconfigured, got %q/%q", got.Effect, got.ReasonCode)
	}
}

// TestDecide_AboveCapabilityMaxRiskRequiresApproval asserts exceeding the
// agent's own ceiling escalates to a human rather than denying outright.
func TestDecide_AboveCapabilityMaxRiskRequiresApproval(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskLow, RiskMedium, false)
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(agentReq(RiskMedium))

	if got.Effect != EffectRequireApproval {
		t.Fatalf("above capability MaxRisk must REQUIRE_APPROVAL, got %q", got.Effect)
	}
}

// TestDecide_RestrictedModeEscalatesAboveLow asserts RESTRICTED forces approval
// for anything above LOW even when capability would allow it.
func TestDecide_RestrictedModeEscalatesAboveLow(t *testing.T) {
	b := agentBundle(AutonomyRestricted, RiskMedium, RiskMedium, false)
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(agentReq(RiskMedium))

	if got.Effect != EffectRequireApproval {
		t.Fatalf("RESTRICTED above LOW must REQUIRE_APPROVAL, got %q", got.Effect)
	}
}

// TestDecide_VerifiedApprovalConvertsToAllow asserts the successful transition:
// without it an approval-requiring action could never execute.
func TestDecide_VerifiedApprovalConvertsToAllow(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskLow, RiskLow, false)
	e := NewEngine(func() CompiledBundle { return b })

	req := agentReq(RiskMedium)
	req.ApprovalVerified = true

	got := e.Decide(req)

	if got.Effect != EffectAllow {
		t.Fatalf("verified approval must ALLOW, got %q (%s)", got.Effect, got.ReasonCode)
	}
}

// TestDecide_ApprovalCannotLiftAgentCriticalProhibition asserts approval never
// launders the hardest stop.
func TestDecide_ApprovalCannotLiftAgentCriticalProhibition(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskCritical, RiskCritical, false)
	e := NewEngine(func() CompiledBundle { return b })

	req := agentReq(RiskCritical)
	req.ApprovalVerified = true

	got := e.Decide(req)

	if got.Effect != EffectDeny || got.ReasonCode != ReasonCriticalAgentProhibited {
		t.Fatalf("approval must not lift agent CRITICAL, got %q/%q", got.Effect, got.ReasonCode)
	}
}

// TestDecide_MoneyMovementDeniedWhenTenantProhibits asserts a zero money ceiling
// is a prohibition, not an approval prompt.
func TestDecide_MoneyMovementDeniedWhenTenantProhibits(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskMedium, RiskMedium, false)
	p := b.Autonomy["t1"]
	p.Limits.MaxMoneyMovementMinor = 0
	b.Autonomy["t1"] = p
	e := NewEngine(func() CompiledBundle { return b })

	req := agentReq(RiskMedium)
	req.AmountMinor = 100

	got := e.Decide(req)

	if got.Effect != EffectDeny {
		t.Fatalf("money movement with a zero ceiling must DENY, got %q", got.Effect)
	}
}

// TestDecide_UnauthorizedResourceDeniedBeforeApproval is the ordering guard: a
// HIGH action the role cannot perform must DENY, never become a pending
// approval that could later execute.
func TestDecide_UnauthorizedResourceDeniedBeforeApproval(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskHigh, RiskHigh, false)
	e := NewEngine(func() CompiledBundle { return b })

	req := agentReq(RiskHigh)
	req.ActionVerb = "delete" // rule grants only create/read/update

	got := e.Decide(req)

	if got.Effect != EffectDeny || got.ReasonCode != ReasonResourceDenied {
		t.Fatalf("unauthorized resource must DENY before approval, got %q/%q",
			got.Effect, got.ReasonCode)
	}
}

// TestDecide_HumanRbacBehaviourUnchanged is the regression guard for existing
// callers: a USER decision must still follow Can exactly.
func TestDecide_HumanRbacBehaviourUnchanged(t *testing.T) {
	b := bundleWithRule("t1", "member", "lead")
	e := NewEngine(func() CompiledBundle { return b })

	id := Identity{TenantID: "t1", UserRole: "member", ActorType: ActorUser}

	allowed := e.Decide(DecisionRequest{
		Identity: id, Action: "crm.read_lead",
		ObjectType: "lead", ActionVerb: "read", Risk: RiskLow,
	})
	if allowed.Effect != EffectAllow {
		t.Fatalf("granted human read must ALLOW, got %q", allowed.Effect)
	}

	denied := e.Decide(DecisionRequest{
		Identity: id, Action: "crm.read_invoice",
		ObjectType: "invoice", ActionVerb: "read", Risk: RiskLow,
	})
	if denied.Effect != EffectDeny {
		t.Fatalf("human read of an ungoverned object must DENY, got %q", denied.Effect)
	}
	if !e.Can(id, "read", "lead", "").Allow {
		t.Fatal("Can must remain unchanged for existing callers")
	}
}

// TestBundleWire_RoundTripsCapabilitiesAndAutonomy guards a silent-failure mode:
// CompiledBundle has custom JSON marshalling, and the bundle is distributed to
// every service as signed JSON. If the new capability/autonomy maps are not on
// the wire they would be silently empty at every consumer — which denies every
// agent action while looking like a correctly-signed bundle.
func TestBundleWire_RoundTripsCapabilitiesAndAutonomy(t *testing.T) {
	orig := agentBundle(AutonomyRestricted, RiskMedium, RiskHigh, true)

	raw, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var back CompiledBundle
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	cap, ok := back.CapabilityFor("t1", "sales-agent", "crm.update_lead")
	if !ok {
		t.Fatal("capability did not survive the wire round-trip")
	}
	if !cap.Allow || cap.MaxRisk != RiskMedium || !cap.RequiresApproval {
		t.Fatalf("capability corrupted on the wire: %+v", cap)
	}

	prof, ok := back.AutonomyFor("t1")
	if !ok {
		t.Fatal("autonomy profile did not survive the wire round-trip")
	}
	if prof.Mode != AutonomyRestricted || prof.MaxAutoRisk != RiskHigh ||
		prof.Limits.MaxActionsPerHour != 100 || prof.Limits.MaxMoneyMovementMinor != 5000 {
		t.Fatalf("autonomy profile corrupted on the wire: %+v", prof)
	}
}

// TestDecide_DenialCarriesPolicyVersion asserts a refusal reports which policy
// produced it. Found by probing the live PDP: a production DENY came back with
// policy_version 0 even though a bundle was loaded.
//
// This matters because a denial is an audit record. "We refused this action,
// but cannot say under which policy" defeats the attributability the guardrail
// exists to provide, and makes an observe-mode would-be denial impossible to
// correlate with the bundle that caused it.
func TestDecide_DenialCarriesPolicyVersion(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskMedium, RiskMedium, false) // Version 7
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(agentReq(RiskCritical)) // agent CRITICAL -> terminal deny

	if got.Effect != EffectDeny {
		t.Fatalf("expected DENY, got %q", got.Effect)
	}
	if got.PolicyVersion != 7 {
		t.Fatalf("a denial must report the policy version that produced it, got %d", got.PolicyVersion)
	}
}

// TestDecide_EveryDenialPathCarriesPolicyVersion covers the other refusal
// paths, so the fix cannot regress on one branch while holding on another.
func TestDecide_EveryDenialPathCarriesPolicyVersion(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskMedium, RiskMedium, false) // Version 7
	e := NewEngine(func() CompiledBundle { return b })

	noCapability := agentReq(RiskLow)
	noCapability.Action = "billing.issue_refund"

	unauthorized := agentReq(RiskLow)
	unauthorized.ActionVerb = "delete"

	badRisk := agentReq(RiskLevel("SPICY"))

	for name, req := range map[string]DecisionRequest{
		"no_capability":   noCapability,
		"resource_denied": unauthorized,
		"invalid_request": badRisk,
	} {
		got := e.Decide(req)
		if got.Effect != EffectDeny {
			t.Fatalf("%s: expected DENY, got %q", name, got.Effect)
		}
		if got.PolicyVersion != 7 {
			t.Fatalf("%s: denial must carry the policy version, got %d", name, got.PolicyVersion)
		}
	}
}

// TestDecide_AbsentBundleReportsVersionZero asserts the one case where zero is
// the honest answer: there is no policy loaded, so there is no version.
func TestDecide_AbsentBundleReportsVersionZero(t *testing.T) {
	e := NewEngine(func() CompiledBundle { return CompiledBundle{} })

	got := e.Decide(agentReq(RiskLow))

	if got.ReasonCode != ReasonPolicyAbsent {
		t.Fatalf("expected policy_absent, got %q", got.ReasonCode)
	}
	if got.PolicyVersion != 0 {
		t.Fatalf("with no bundle loaded there is no version to report, got %d", got.PolicyVersion)
	}
}

// TestDecide_CapabilityIsKeyedByAgentIdentityNotUserRole asserts an agent's
// capabilities belong to the AGENT, not to whoever it is acting for.
//
// Keying them by UserRole would mean any agent acting on behalf of an admin
// inherits admin capabilities — the opposite of the least-privilege,
// specialized-agent model. The RBAC role still governs which OBJECTS may be
// touched; the agent identity governs which TOOLS it may invoke.
func TestDecide_CapabilityIsKeyedByAgentIdentityNotUserRole(t *testing.T) {
	b := CompiledBundle{
		Version: 5,
		// The human role the agent acts for can read+update leads.
		System: map[RoleObj]PolicyRule{
			{Role: "admin", ObjectType: "lead"}: {Read: true, Update: true},
		},
		// The capability is granted to the AGENT "sales-agent".
		Capabilities: map[string]map[CapKey]CapabilityRule{
			"t1": {{AgentRole: "sales-agent", ToolAction: "crm.update_lead"}: {
				Allow: true, MaxRisk: RiskMedium,
			}},
		},
		Autonomy: map[string]AutonomyProfile{
			"t1": {Mode: AutonomyEnabled, MaxAutoRisk: RiskMedium},
		},
	}
	e := NewEngine(func() CompiledBundle { return b })

	req := DecisionRequest{
		Identity: Identity{
			TenantID: "t1", UserRole: "admin",
			ActorType: ActorAgent, AgentID: "sales-agent",
		},
		Action: "crm.update_lead", ObjectType: "lead", ActionVerb: "update", Risk: RiskMedium,
	}

	if got := e.Decide(req); got.Effect != EffectAllow {
		t.Fatalf("the agent holding the capability must be allowed, got %q/%q",
			got.Effect, got.ReasonCode)
	}

	// A DIFFERENT agent, acting for the SAME admin role, holds no capability.
	other := req
	other.Identity.AgentID = "marketing-agent"
	if got := e.Decide(other); got.Effect != EffectDeny || got.ReasonCode != ReasonNoCapability {
		t.Fatalf("a different agent must not inherit capabilities from the user's role, got %q/%q",
			got.Effect, got.ReasonCode)
	}
}

// TestDecide_AgentWithoutAnIdentityIsDenied asserts an agent-class request with
// no agent id cannot be authorized: there is no identity to attach capabilities
// to, so allowing it would mean an anonymous agent.
//
// The bundle deliberately contains a capability under the EMPTY key. Without an
// explicit guard the map lookup would FIND it and allow the call, so this test
// isolates the guard rather than passing incidentally because a lookup missed.
func TestDecide_AgentWithoutAnIdentityIsDenied(t *testing.T) {
	b := CompiledBundle{
		Version: 5,
		System: map[RoleObj]PolicyRule{
			{Role: "admin", ObjectType: "lead"}: {Read: true, Update: true},
		},
		Capabilities: map[string]map[CapKey]CapabilityRule{
			"t1": {{AgentRole: "", ToolAction: "crm.update_lead"}: {
				Allow: true, MaxRisk: RiskHigh,
			}},
		},
		Autonomy: map[string]AutonomyProfile{
			"t1": {Mode: AutonomyEnabled, MaxAutoRisk: RiskHigh},
		},
	}
	e := NewEngine(func() CompiledBundle { return b })

	got := e.Decide(DecisionRequest{
		Identity: Identity{
			TenantID: "t1", UserRole: "admin",
			ActorType: ActorAgent, AgentID: "", // anonymous
		},
		Action: "crm.update_lead", ObjectType: "lead", ActionVerb: "update", Risk: RiskMedium,
	})

	if got.Effect != EffectDeny || got.ReasonCode != ReasonNoCapability {
		t.Fatalf("an anonymous agent must be denied even if a capability exists under the empty key, got %q/%q",
			got.Effect, got.ReasonCode)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// A verified approval authorises the ACTION, and only relaxes WHO executes it.
// ─────────────────────────────────────────────────────────────────────────────

// TestDecide_ApprovedActionMayBeExecutedByAServiceWithoutItsOwnRBACRight.
//
// A tenant purge is carried out by a background worker. Requiring that worker to
// independently hold delete-on-tenant would mean no approved destructive action
// could ever be executed by the platform that approved it — the approval machine
// would be unusable for the one workflow it was built for.
//
// The right was checked on the APPROVER, by the identity authority, at the
// moment they approved. The worker is the executor, not the authority.
func TestDecide_ApprovedActionMayBeExecutedByAServiceWithoutItsOwnRBACRight(t *testing.T) {
	// A bundle that grants the service NOTHING on tenant.
	b := bundleWithRule("t1", "owner", "tenant")
	e := NewEngine(func() CompiledBundle { return b })

	req := DecisionRequest{
		Identity:          Identity{TenantID: "t1", ActorType: ActorService},
		Action:            "tenant.wipe",
		ObjectType:        "tenant",
		ActionVerb:        "delete",
		Risk:              RiskCritical,
		ServiceAllowed:    true,
		MutatesTenantData: true,
	}

	// Without an approval: refused on the resource, as before.
	if got := e.Decide(req); got.Effect != EffectDeny || got.ReasonCode != ReasonResourceDenied {
		t.Fatalf("an unapproved service purge must be denied on the resource, got %s/%s", got.Effect, got.ReasonCode)
	}

	// With a verified approval: permitted.
	req.ApprovalVerified = true
	if got := e.Decide(req); got.Effect != EffectAllow {
		t.Fatalf("an APPROVED purge must be executable by the service carrying it out, got %s/%s (%s)",
			got.Effect, got.ReasonCode, got.Reason)
	}
}

// TestDecide_ApprovalDoesNotLiftTheAbsoluteDenials is the other half, and the
// more important one: an approval relaxes WHO may carry an action out. It must
// never relax WHAT may be carried out.
func TestDecide_ApprovalDoesNotLiftTheAbsoluteDenials(t *testing.T) {
	b := bundleWithRule("t1", "owner", "tenant")
	e := NewEngine(func() CompiledBundle { return b })

	base := DecisionRequest{
		Identity:          Identity{TenantID: "t1", UserRole: "owner", ActorType: ActorAgent, AgentID: "a1"},
		Action:            "tenant.wipe",
		ObjectType:        "tenant",
		ActionVerb:        "delete",
		Risk:              RiskCritical,
		ServiceAllowed:    true,
		MutatesTenantData: true,
		ApprovalVerified:  true,
	}

	// An agent may never execute CRITICAL, approval or not.
	if got := e.Decide(base); got.Effect != EffectDeny || got.ReasonCode != ReasonCriticalAgentProhibited {
		t.Fatalf("an approval must not let an agent execute CRITICAL, got %s/%s", got.Effect, got.ReasonCode)
	}

	// A service that is not a permitted executor for the action is still refused:
	// the approval says the ACTION is authorised, not that anything may run it.
	svc := base
	svc.Identity = Identity{TenantID: "t1", ActorType: ActorService}
	svc.ServiceAllowed = false
	if got := e.Decide(svc); got.Effect != EffectDeny || got.ReasonCode != ReasonResourceDenied {
		t.Fatalf("an approval must not make an unpermitted service executor allowed, got %s/%s", got.Effect, got.ReasonCode)
	}

	// SYSTEM still may not mutate tenant data.
	sys := base
	sys.Identity = Identity{TenantID: "t1", ActorType: ActorSystem}
	if got := e.Decide(sys); got.Effect != EffectDeny {
		t.Fatalf("an approval must not let SYSTEM mutate tenant data, got %s", got.Effect)
	}

	// An external integration is still capped at MEDIUM.
	ext := base
	ext.Identity = Identity{TenantID: "t1", UserRole: "owner", ActorType: ActorExternalIntegration}
	ext.Risk = RiskHigh
	if got := e.Decide(ext); got.Effect != EffectDeny || got.ReasonCode != ReasonExternalRiskCap {
		t.Fatalf("an approval must not lift the external-integration risk cap, got %s/%s", got.Effect, got.ReasonCode)
	}
}

// ---- delegated HIGH autonomy (2026-08-26) ---------------------------------
//
// The owner's product decision: a tenant may configure an agent to carry a
// whole workflow (build, approve, publish and send a campaign; issue a quote)
// without a human clicking through each step. The engine's HIGH floor now
// yields to an EXPLICIT delegation — autonomy ENABLED at HIGH plus a HIGH
// capability without a per-tool approval flag — and to nothing less. The
// guardrail set (money movement, destructive deletes, billing/security
// configuration) never yields.

func TestDecide_AgentHighAutoExecutesOnlyUnderExplicitHighDelegation(t *testing.T) {
	cases := []struct {
		name string
		mode AutonomyMode
		cap  RiskLevel
		auto RiskLevel
		req  bool
		want Effect
	}{
		{"enabled+high cap+high ceiling → allow", AutonomyEnabled, RiskHigh, RiskHigh, false, EffectAllow},
		{"capability demands approval → approval", AutonomyEnabled, RiskHigh, RiskHigh, true, EffectRequireApproval},
		{"tenant ceiling MEDIUM → approval", AutonomyEnabled, RiskHigh, RiskMedium, false, EffectRequireApproval},
		{"capability ceiling MEDIUM → approval", AutonomyEnabled, RiskMedium, RiskHigh, false, EffectRequireApproval},
		{"RESTRICTED mode → approval", AutonomyRestricted, RiskHigh, RiskHigh, false, EffectRequireApproval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := agentBundle(tc.mode, tc.cap, tc.auto, tc.req)
			e := NewEngine(func() CompiledBundle { return b })
			got := e.Decide(agentReq(RiskHigh))
			if got.Effect != tc.want {
				t.Fatalf("want %q, got %q (%s)", tc.want, got.Effect, got.ReasonCode)
			}
		})
	}
}

func TestDecide_HighDelegationNeverLiftsTheGuardrailSet(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskHigh, RiskHigh, false)
	// The principal may delete leads (RBAC is a precondition, not the subject here).
	b.System[RoleObj{Role: "sales_agent", ObjectType: "lead"}] = PolicyRule{Create: true, Read: true, Update: true, Delete: true}
	e := NewEngine(func() CompiledBundle { return b })

	money := agentReq(RiskMedium)
	money.AmountMinor = 1250 // within the tenant's funded limit — still confirmed
	if got := e.Decide(money); got.Effect != EffectRequireApproval || got.ReasonCode != "approval_required_money_movement" {
		t.Fatalf("money movement must always require approval for an agent, got %q %q", got.Effect, got.ReasonCode)
	}

	del := agentReq(RiskHigh)
	del.ActionVerb = "delete"
	if got := e.Decide(del); got.Effect != EffectRequireApproval || got.ReasonCode != "approval_required_destructive" {
		t.Fatalf("a HIGH delete must always require approval for an agent, got %q %q", got.Effect, got.ReasonCode)
	}

	// A MEDIUM delete (a single record) is not in the guardrail set — the
	// tenant's delegation governs it.
	smallDel := agentReq(RiskMedium)
	smallDel.ActionVerb = "delete"
	if got := e.Decide(smallDel); got.Effect != EffectAllow {
		t.Fatalf("a MEDIUM delete under full delegation should be allowed, got %q %q", got.Effect, got.ReasonCode)
	}
}

func TestDecide_ProtectedConfigAlwaysRequiresApprovalForAgents(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskHigh, RiskHigh, false)
	b.System[RoleObj{Role: "sales_agent", ObjectType: "billing_config"}] = PolicyRule{Create: true, Read: true, Update: true, Delete: true}
	e := NewEngine(func() CompiledBundle { return b })
	r := agentReq(RiskMedium)
	r.ObjectType = "billing_config"
	if got := e.Decide(r); got.Effect != EffectRequireApproval || got.ReasonCode != "approval_required_protected_config" {
		t.Fatalf("billing configuration must always require approval for an agent, got %q %q", got.Effect, got.ReasonCode)
	}
}

func TestDecide_HumanHighFloorUnchangedByAgentDelegation(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskHigh, RiskHigh, false)
	e := NewEngine(func() CompiledBundle { return b })
	r := agentReq(RiskHigh)
	r.Identity.ActorType = ActorUser
	r.Identity.AgentID = ""
	if got := e.Decide(r); got.Effect != EffectRequireApproval || got.ReasonCode != "approval_required_high_risk" {
		t.Fatalf("a human's HIGH action still requires approval, got %q %q", got.Effect, got.ReasonCode)
	}
}
