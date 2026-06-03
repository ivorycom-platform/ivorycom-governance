// Package dsar defines the platform-wide Data Subject Access Request (DSAR)
// contract — the standard request/response shapes and the Fiber Mount scaffold
// that every bounded context (the 7 Go satellites + the Java CRM) implements so
// the ivorycom-compliance orchestrator can fan a single GDPR export or erasure
// out across all of them.
//
// A4.3 (Privacy & Compliance Center), decision D4: a real compliance service
// runs a saga over a standard `/dsar/export` + `/dsar/delete` contract. Each
// context owns its own slice of a contact's data; the orchestrator aggregates
// the exported slices (plus the A4.1 audit trail) into one bundle and, for
// erasure, cascades a delete/anonymize across every context after the central
// legal-hold gate clears.
//
// The wire types here are the SINGLE source of truth for that contract. A
// mismatch between a context's handler and the orchestrator is the classic
// "only visible in live E2E" contract gap (cf. the A4.1 audit `data` envelope
// lesson), so contexts MUST mount via Mount rather than hand-rolling routes.
package dsar

import "time"

// ExportRequest is the body the orchestrator POSTs to each context's
// /dsar/export. TenantID is informational only — the authoritative tenant is
// the verified JWT the orchestrator mints (which drives Postgres RLS in the
// context); a context MUST scope its queries by the request tenant from its
// own tenant-tx context, never trust this field for isolation.
type ExportRequest struct {
	ContactID string `json:"contact_id"`
	TenantID  string `json:"tenant_id"`
	// Email is the contact's email when known. Contexts whose rows carry no
	// contact UUID but do carry the person's email (billing payer emails,
	// marketing recipient emails) match on it; empty means "UUID-keyed rows
	// only". Supplied by the DSAR requester (Trust Center / admin) and threaded
	// through the saga.
	Email string `json:"email,omitempty"`
}

// Slice is one named collection of a context's rows referencing the contact.
// Kind is the owned object kind (e.g. "leads", "opportunities", "files"); Rows
// are the de-identified-on-export records. Rows is always non-nil in a well
// behaved handler (an empty slice, not null) so the aggregated bundle is stable.
type Slice struct {
	Kind string           `json:"kind"`
	Rows []map[string]any `json:"rows"`
}

// ExportResponse is what a context returns from /dsar/export: every slice of
// the contact's data it owns. Service identifies the emitting context so the
// orchestrator can label the bundle and detect a missing context.
type ExportResponse struct {
	Service     string    `json:"service"`
	ContactID   string    `json:"contact_id"`
	Slices      []Slice   `json:"slices"`
	GeneratedAt time.Time `json:"generated_at"`
}

// DeleteRequest is the body the orchestrator POSTs to each context's
// /dsar/delete. Mode selects hard deletion vs. anonymization — billing, for
// example, has a statutory retention obligation on financial records and MUST
// anonymize (PII-strip) rather than hard-delete. Held, when true, tells the
// context the central legal-hold gate has already flagged this contact; the
// context must refuse and report Blocked. (Contexts may also call the gate
// themselves for defence in depth.)
type DeleteRequest struct {
	ContactID string `json:"contact_id"`
	TenantID  string `json:"tenant_id"`
	// Email — see ExportRequest.Email; email-keyed contexts erase by it.
	Email string `json:"email,omitempty"`
	Mode  string `json:"mode"` // "delete" | "anonymize"
	Held  bool   `json:"held"`
}

// DeleteResponse reports the outcome of a context's erasure: how many rows were
// hard-deleted vs. anonymized, and whether a legal hold blocked the operation.
// When Blocked is true the context performed no deletion.
type DeleteResponse struct {
	Service    string `json:"service"`
	ContactID  string `json:"contact_id"`
	Deleted    int    `json:"deleted"`
	Anonymized int    `json:"anonymized"`
	Blocked    bool   `json:"blocked"`
}

// Delete modes.
const (
	ModeDelete    = "delete"
	ModeAnonymize = "anonymize"
)
