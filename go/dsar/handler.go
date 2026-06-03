package dsar

import (
	"time"

	"github.com/gofiber/fiber/v2"
)

// ExportFunc is a context's implementation of /dsar/export. It receives the
// live Fiber request context (so the closure can reach the request-scoped,
// tenant-bound DB transaction the satellite's TenantTx middleware installed —
// Postgres RLS therefore scopes every query) and the parsed request, and
// returns the slices of the contact's data it owns. Returning an error makes
// Mount respond 500; the orchestrator treats that as a failed task and retries.
type ExportFunc func(c *fiber.Ctx, req ExportRequest) ([]Slice, error)

// DeleteFunc is a context's implementation of /dsar/delete. It returns a fully
// populated DeleteResponse (Deleted/Anonymized counts, or Blocked when a legal
// hold prevented erasure); Mount stamps Service and ContactID. An error makes
// Mount respond 500 so the orchestrator retries.
type DeleteFunc func(c *fiber.Ctx, req DeleteRequest) (DeleteResponse, error)

// Mount registers POST /dsar/export and POST /dsar/delete on router, dispatching
// to the supplied context implementations and wrapping their results in the
// standard contract envelopes.
//
// IDENTITY: Mount performs no authentication of its own. Callers MUST mount it
// under the satellite's authenticated, tenant-bound router group (the same
// JWTAuthMiddleware + TenantTx chain that guards every tenant endpoint) so that
// (a) only a verified internal service identity — the short-lived Bearer JWT
// the compliance orchestrator mints per call — reaches these routes, and
// (b) the export/delete closures run inside the request's RLS-scoped tx. This
// keeps the shared lib free of any identity/DB dependency while still enforcing
// "verified internal service identity" at the seam where it belongs.
func Mount(router fiber.Router, svc string, exportFn ExportFunc, deleteFn DeleteFunc) {
	router.Post("/dsar/export", func(c *fiber.Ctx) error {
		var req ExportRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		if req.ContactID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "contact_id required"})
		}
		slices, err := exportFn(c, req)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		if slices == nil {
			slices = []Slice{}
		}
		return c.JSON(ExportResponse{
			Service:     svc,
			ContactID:   req.ContactID,
			Slices:      slices,
			GeneratedAt: time.Now().UTC(),
		})
	})

	router.Post("/dsar/delete", func(c *fiber.Ctx) error {
		var req DeleteRequest
		if err := c.BodyParser(&req); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request body"})
		}
		if req.ContactID == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "contact_id required"})
		}
		if req.Mode == "" {
			req.Mode = ModeDelete
		}
		resp, err := deleteFn(c, req)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		resp.Service = svc
		resp.ContactID = req.ContactID
		return c.JSON(resp)
	})
}
