package dsar

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

func newApp(exportFn ExportFunc, deleteFn DeleteFunc) *fiber.App {
	app := fiber.New()
	g := app.Group("/internal")
	Mount(g, "crm-test", exportFn, deleteFn)
	return app
}

func post(t *testing.T, app *fiber.App, path string, body any) (int, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestMountExportDispatches(t *testing.T) {
	var gotReq ExportRequest
	app := newApp(
		func(c *fiber.Ctx, req ExportRequest) ([]Slice, error) {
			gotReq = req
			return []Slice{{Kind: "leads", Rows: []map[string]any{{"id": "l1"}}}}, nil
		},
		nil,
	)
	code, out := post(t, app, "/internal/dsar/export", ExportRequest{ContactID: "c1", TenantID: "t1"})
	if code != 200 {
		t.Fatalf("status=%d body=%s", code, out)
	}
	if gotReq.ContactID != "c1" || gotReq.TenantID != "t1" {
		t.Fatalf("fn did not receive parsed request: %+v", gotReq)
	}
	var resp ExportResponse
	if err := json.Unmarshal(out, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.Service != "crm-test" || resp.ContactID != "c1" || len(resp.Slices) != 1 {
		t.Fatalf("bad envelope: %+v", resp)
	}
	if resp.GeneratedAt.IsZero() {
		t.Fatalf("generated_at not stamped")
	}
}

func TestMountExportNilSlicesBecomesEmpty(t *testing.T) {
	app := newApp(func(c *fiber.Ctx, req ExportRequest) ([]Slice, error) { return nil, nil }, nil)
	_, out := post(t, app, "/internal/dsar/export", ExportRequest{ContactID: "c1"})
	var resp ExportResponse
	_ = json.Unmarshal(out, &resp)
	if resp.Slices == nil {
		t.Fatalf("nil slices should marshal as empty array, got null")
	}
}

func TestMountExportMissingContactID(t *testing.T) {
	app := newApp(func(c *fiber.Ctx, req ExportRequest) ([]Slice, error) { return nil, nil }, nil)
	code, _ := post(t, app, "/internal/dsar/export", ExportRequest{})
	if code != 400 {
		t.Fatalf("expected 400 for missing contact_id, got %d", code)
	}
}

func TestMountExportError(t *testing.T) {
	app := newApp(func(c *fiber.Ctx, req ExportRequest) ([]Slice, error) { return nil, errors.New("db down") }, nil)
	code, _ := post(t, app, "/internal/dsar/export", ExportRequest{ContactID: "c1"})
	if code != 500 {
		t.Fatalf("expected 500 on fn error, got %d", code)
	}
}

func TestMountDeleteStampsServiceAndContact(t *testing.T) {
	app := newApp(nil, func(c *fiber.Ctx, req DeleteRequest) (DeleteResponse, error) {
		if req.Mode != ModeDelete {
			t.Fatalf("default mode should be delete, got %q", req.Mode)
		}
		return DeleteResponse{Deleted: 3}, nil
	})
	code, out := post(t, app, "/internal/dsar/delete", DeleteRequest{ContactID: "c2"})
	if code != 200 {
		t.Fatalf("status=%d body=%s", code, out)
	}
	var resp DeleteResponse
	_ = json.Unmarshal(out, &resp)
	if resp.Service != "crm-test" || resp.ContactID != "c2" || resp.Deleted != 3 {
		t.Fatalf("bad delete envelope: %+v", resp)
	}
}

func TestMountDeleteBlocked(t *testing.T) {
	app := newApp(nil, func(c *fiber.Ctx, req DeleteRequest) (DeleteResponse, error) {
		if req.Held {
			return DeleteResponse{Blocked: true}, nil
		}
		return DeleteResponse{Deleted: 1}, nil
	})
	_, out := post(t, app, "/internal/dsar/delete", DeleteRequest{ContactID: "c2", Held: true})
	var resp DeleteResponse
	_ = json.Unmarshal(out, &resp)
	if !resp.Blocked || resp.Deleted != 0 {
		t.Fatalf("held delete should be blocked with no deletions: %+v", resp)
	}
}
