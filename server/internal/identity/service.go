package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrInvalidUserID      = errors.New("identity: invalid user_id")
	ErrInvalidVersion     = errors.New("identity: invalid snapshot_version")
	ErrInvalidPayload     = errors.New("identity: invalid payload")
	ErrSnapshotConflict   = errors.New("identity: snapshot_version conflict")
	ErrServiceUnavailable = errors.New("identity: service unavailable")
)

type SnapshotInput struct {
	UserID          string
	SnapshotVersion int64
	Payload         json.RawMessage
}

type Snapshot struct {
	SnapshotID      string
	UserID          string
	SnapshotVersion int64
	ReceivedAt      time.Time
}

type Service interface {
	CreateSnapshot(ctx context.Context, input SnapshotInput) (Snapshot, error)
}

type InMemoryService struct {
	mu            sync.Mutex
	latestVersion map[string]int64
}

func NewInMemoryService() *InMemoryService {
	return &InMemoryService{latestVersion: make(map[string]int64)}
}

func (s *InMemoryService) CreateSnapshot(_ context.Context, input SnapshotInput) (Snapshot, error) {
	if input.UserID == "" {
		return Snapshot{}, ErrInvalidUserID
	}
	if input.SnapshotVersion <= 0 {
		return Snapshot{}, ErrInvalidVersion
	}
	if len(input.Payload) == 0 || !json.Valid(input.Payload) {
		return Snapshot{}, ErrInvalidPayload
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	latest := s.latestVersion[input.UserID]
	if input.SnapshotVersion <= latest {
		return Snapshot{}, ErrSnapshotConflict
	}
	s.latestVersion[input.UserID] = input.SnapshotVersion

	now := time.Now().UTC()
	return Snapshot{
		SnapshotID:      fmt.Sprintf("%s-%d", input.UserID, input.SnapshotVersion),
		UserID:          input.UserID,
		SnapshotVersion: input.SnapshotVersion,
		ReceivedAt:      now,
	}, nil
}
