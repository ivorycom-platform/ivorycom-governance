# ivorycom-governance

Shared governance library for the Ivorycom platform: a Go-first package every service imports to emit audit events into the platform-wide immutable audit ledger. It provides the canonical `AuditEvent` envelope, a before/after `Diff` helper, and a uniform `Emit` helper that writes to each service's transactional outbox via a small `WriteFunc`/`OutboxEnvelope` interface — without depending on any specific service's outbox type. The Go package lives under `go/`.
