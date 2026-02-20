package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"identitymirror/server/internal/identity"
)

type healthyChecker struct{}

func (healthyChecker) HealthCheck(context.Context) error { return nil }

func TestHealthEndpoint(t *testing.T) {
	h := NewHandler(healthyChecker{}, identity.NewInMemoryService())
	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestCreateSnapshotEndpoint(t *testing.T) {
	h := NewHandler(healthyChecker{}, identity.NewInMemoryService())
	mux := http.NewServeMux()
	h.Register(mux)

	body := `{"user_id":"user-1","snapshot_version":1,"payload":{"a":1}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/identity/snapshot", strings.NewReader(body))
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d body=%s", rr.Code, rr.Body.String())
	}

	var response map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("response not json: %v", err)
	}
	if response["user_id"] != "user-1" {
		t.Fatalf("unexpected user_id: %v", response["user_id"])
	}
	if _, err := time.Parse(time.RFC3339Nano, response["received_at"].(string)); err != nil {
		t.Fatalf("invalid received_at: %v", err)
	}
}

func TestCreateSnapshotConflict(t *testing.T) {
	h := NewHandler(healthyChecker{}, identity.NewInMemoryService())
	mux := http.NewServeMux()
	h.Register(mux)

	first := httptest.NewRequest(http.MethodPost, "/v1/identity/snapshot", strings.NewReader(`{"user_id":"user-1","snapshot_version":1,"payload":{"a":1}}`))
	firstRR := httptest.NewRecorder()
	mux.ServeHTTP(firstRR, first)

	second := httptest.NewRequest(http.MethodPost, "/v1/identity/snapshot", strings.NewReader(`{"user_id":"user-1","snapshot_version":1,"payload":{"a":1}}`))
	secondRR := httptest.NewRecorder()
	mux.ServeHTTP(secondRR, second)

	if secondRR.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", secondRR.Code)
	}
}
