package policy

import "testing"

func TestRequestedActionApprovalCannotReplaceAgentRbac(t *testing.T) {
	b := agentBundle(AutonomyEnabled, RiskHigh, RiskHigh, false)
	e := NewEngine(func() CompiledBundle { return b })
	req := agentReq(RiskHigh)
	req.ActionVerb = "delete" // not granted by this principal's role
	req.ApprovalVerified = true
	if got := e.Decide(req); got.Effect != EffectDeny || got.ReasonCode != ReasonResourceDenied {
		t.Fatalf("approval cannot grant the requesting agent broader access: %+v", got)
	}
}

func TestRequestedActionConfirmationCategoriesAcrossRiskLevels(t *testing.T) {
	for _, risk := range []RiskLevel{RiskLow, RiskMedium, RiskHigh} {
		for _, operation := range []string{"update", "delete", "money"} {
			t.Run(string(risk)+"/"+operation, func(t *testing.T) {
				b := agentBundle(AutonomyRestricted, RiskLow, RiskLow, true)
				b.System[RoleObj{Role: "sales_agent", ObjectType: "lead"}] = PolicyRule{Update: true, Delete: true}
				e := NewEngine(func() CompiledBundle { return b })
				req := agentReq(risk)
				want := EffectAllow
				if operation == "delete" {
					req.ActionVerb = "delete"
					want = EffectRequireApproval
				}
				if operation == "money" {
					req.AmountMinor = 1
					want = EffectRequireApproval
				}
				got := e.Decide(req)
				if got.Effect != want {
					t.Fatalf("want %s, got %+v", want, got)
				}
				if got.LimitsRequired.MaxActionsPerHour != 100 {
					t.Fatalf("lost limits: %+v", got)
				}
			})
		}
	}
}
