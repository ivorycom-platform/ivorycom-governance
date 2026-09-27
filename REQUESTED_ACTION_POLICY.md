# Requested agent actions — migration in progress

User requirement (2026-09-27): a user request or tenant-authorized automation
must not require another approval for ordinary work. Only money movement and
deletion require explicit OWNER or ADMIN approval. Execution retains the requesting
principal's normal permissions. The latest instruction includes single-record
deletion, not only bulk deletion.

## This branch

- Go policy outcome selection no longer prompts agent-class actors solely for
  HIGH risk, legacy capability approval flags, capability/tenant risk preferences,
  RESTRICTED mode, or an authorized billing/security configuration update.
- Deletion requires confirmation at LOW, MEDIUM and HIGH, as does a positive
  trusted money-movement amount.
- Agent approval evidence cannot replace the requester's current RBAC grant.
- Identity, capability grants, missing/invalid policy, paused/disabled automation,
  tenant limits, external-integration ceilings and service/system restrictions
  remain enforced before outcome selection. Limits are still returned for atomic
  reservation by the consumer. Direct-human approval behavior is unchanged.

Ruling: legacy approval flags and risk ceilings no longer create additional
confirmation for otherwise granted agent work, following the owner's explicit
instruction. They remain schema-compatible and validated but are not approval
selectors. This changes the semantics of existing tenant configurations and must
be released as a coordinated policy migration, not silently backported.

## Not finished / release dependencies

This is NOT the full platform fix and is NOT deployed. The companion/agent
implementation map is in ivorycom-agent at
`docs/live-companion/requested-action-policy-map.md`.

The existing CRITICAL-agent prohibition remains unchanged: OWNER/ADMIN-approved
CRITICAL operations still cannot execute. Resolving it requires the trusted
operation-effect contract and exact approver-decision binding, not a blanket removal
of the prohibition. OWNER-or-ADMIN approval must be enforced by the consuming
decision endpoints; the pure policy engine receives verified evidence and cannot
independently prove the approver's role.

Consumers must obtain operation verb and movement amount from authoritative
action definitions; a model/browser assertion is not sufficient. Recording a
payment already received is not necessarily money movement. Dynamic integration
actions require their actual service capability classification.

Policy PR #84 pins governance commit `34ce89a889f5` with vendored code and API
tests. Agent PR #269 migrates registered built-in gates in Chat/Builder, graph
and voice; commit `15a6a65` permits OWNER or ADMIN decisions. These draft changes
are not production proof. Dynamic integration classification, gateway action
descriptors and remaining independent decision consumers still need coordinated
review. No production config, deployment or tenant data was changed here.

## Execution ledger

- Isolated clone based on GitHub main `62af962f0abfb07a24c61452e2b8a1526806ff59`.
- Baseline `go test ./...`: all four Go packages passed.
- Changed ordinary-action/single-deletion tests failed against the old engine;
  implementation then passed. New approval/RBAC regression failed with ALLOW
  before the agent-specific permission check was corrected.
- Final `go test -count=1 ./...` and `go vet ./...` passed.
- Inline implementation and self-review only, per the user's no-subagent rule.
  Full deployed authorization, OWNER/ADMIN confirmation and audit evidence remain open.
