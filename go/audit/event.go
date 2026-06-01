// Package audit provides the canonical Ivorycom audit-ledger envelope, a
// before/after diff helper, and a uniform Emit helper that writes audit
// events into each service's transactional outbox.
package audit

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Action is the verb describing what happened to an object.
type Action string

// Canonical audit actions emitted across the Ivorycom platform.
const (
	ActionCreate           Action = "create"
	ActionUpdate           Action = "update"
	ActionDelete           Action = "delete"
	ActionToolCall         Action = "tool_call"
	ActionSync             Action = "sync"
	ActionWorkflowRun      Action = "workflow_run"
	ActionImpersonate      Action = "impersonate"
	ActionPermissionChange Action = "permission_change"
	ActionBilling          Action = "billing"
	ActionExport           Action = "export"
)

// AuditEvent is the canonical immutable audit-ledger envelope.
type AuditEvent struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id"`
	UserID     string          `json:"user_id,omitempty"`
	AgentID    string          `json:"agent_id,omitempty"`
	Action     Action          `json:"action"`
	ObjectType string          `json:"object_type"`
	ObjectID   string          `json:"object_id,omitempty"`
	DiffJSON   json.RawMessage `json:"diff_json,omitempty"`
	SourceIP   string          `json:"source_ip,omitempty"`
	TraceID    string          `json:"trace_id,omitempty"`
	Service    string          `json:"service"`
	JTI        string          `json:"jti,omitempty"`
	EventTime  time.Time       `json:"event_time"`
}

// Params is the input to NewEvent.
type Params struct {
	TenantID   string
	UserID     string
	AgentID    string
	Action     Action
	ObjectType string
	ObjectID   string
	DiffJSON   json.RawMessage
	SourceIP   string
	TraceID    string
	Service    string
	JTI        string
}

// NewEvent builds an AuditEvent from p, generating a UUID id and a UTC
// EventTime. It panics if TenantID, Action, ObjectType, or Service are empty,
// since an audit event missing any of these cannot be attributed.
func NewEvent(p Params) AuditEvent {
	if p.TenantID == "" {
		panic("audit: TenantID is required")
	}
	if p.Action == "" {
		panic("audit: Action is required")
	}
	if p.ObjectType == "" {
		panic("audit: ObjectType is required")
	}
	if p.Service == "" {
		panic("audit: Service is required")
	}
	return AuditEvent{
		ID:         uuid.NewString(),
		TenantID:   p.TenantID,
		UserID:     p.UserID,
		AgentID:    p.AgentID,
		Action:     p.Action,
		ObjectType: p.ObjectType,
		ObjectID:   p.ObjectID,
		DiffJSON:   p.DiffJSON,
		SourceIP:   p.SourceIP,
		TraceID:    p.TraceID,
		Service:    p.Service,
		JTI:        p.JTI,
		EventTime:  time.Now().UTC(),
	}
}
