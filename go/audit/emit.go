package audit

import (
	"context"
	"encoding/json"
	"fmt"
)

// OutboxEnvelope is the service-agnostic shape Emit hands to a service's
// transactional outbox. Each service adapts its own outbox row type to this.
type OutboxEnvelope struct {
	Topic     string          `json:"topic"`
	EventType string          `json:"event_type"`
	TenantID  string          `json:"tenant_id"`
	Payload   json.RawMessage `json:"payload"`
}

// WriteFunc persists an OutboxEnvelope, typically into the caller's
// transactional outbox within the same DB transaction as the domain write.
type WriteFunc func(ctx context.Context, env OutboxEnvelope) error

// Emit marshals ev into an OutboxEnvelope on the "audit" topic with an
// event_type of "audit.<object_type>.<action>" and writes it via write.
func Emit(ctx context.Context, write WriteFunc, ev AuditEvent) error {
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("audit: marshal event: %w", err)
	}
	env := OutboxEnvelope{
		Topic:     "audit",
		EventType: fmt.Sprintf("audit.%s.%s", ev.ObjectType, ev.Action),
		TenantID:  ev.TenantID,
		Payload:   payload,
	}
	return write(ctx, env)
}
