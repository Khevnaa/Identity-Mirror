package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"identitymirror/server/internal/identity"
)

type HealthChecker interface {
	HealthCheck(ctx context.Context) error
}

type Handler struct {
	healthChecker   HealthChecker
	identityService identity.Service
}

func NewHandler(healthChecker HealthChecker, identityService identity.Service) *Handler {
	return &Handler{healthChecker: healthChecker, identityService: identityService}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /health", h.handleHealth)
	mux.HandleFunc("POST /v1/identity/snapshot", h.handleCreateSnapshot)
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := h.healthChecker.HealthCheck(ctx); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unhealthy"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type createSnapshotRequest struct {
	UserID          string          `json:"user_id"`
	SnapshotVersion int64           `json:"snapshot_version"`
	Payload         json.RawMessage `json:"payload"`
}

type createSnapshotResponse struct {
	SnapshotID      string `json:"snapshot_id"`
	UserID          string `json:"user_id"`
	SnapshotVersion int64  `json:"snapshot_version"`
	ReceivedAt      string `json:"received_at"`
}

func (h *Handler) handleCreateSnapshot(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	var request createSnapshotRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	snapshot, err := h.identityService.CreateSnapshot(r.Context(), identity.SnapshotInput{
		UserID:          request.UserID,
		SnapshotVersion: request.SnapshotVersion,
		Payload:         request.Payload,
	})
	if err != nil {
		writeDomainError(w, err)
		return
	}

	writeJSON(w, http.StatusCreated, createSnapshotResponse{
		SnapshotID:      snapshot.SnapshotID,
		UserID:          snapshot.UserID,
		SnapshotVersion: snapshot.SnapshotVersion,
		ReceivedAt:      snapshot.ReceivedAt.Format(time.RFC3339Nano),
	})
}

func writeDomainError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.ErrInvalidUserID),
		errors.Is(err, identity.ErrInvalidVersion),
		errors.Is(err, identity.ErrInvalidPayload):
		writeError(w, http.StatusBadRequest, "validation_error", err.Error())
	case errors.Is(err, identity.ErrSnapshotConflict):
		writeError(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, identity.ErrServiceUnavailable):
		writeError(w, http.StatusServiceUnavailable, "service_unavailable", err.Error())
	default:
		writeError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

type errorResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, errorResponse{Code: code, Message: message})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
