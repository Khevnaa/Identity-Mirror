package repository

import (
	"context"
	"database/sql"
)

type Tx interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type UserRepository interface{}
type DeviceRegistrationRepository interface{}
type SchemaVersionRepository interface{}
type UserSyncStateRepository interface{}
type IdentityDeclarationRepository interface{}
type BehaviorVectorRepository interface{}
type WeeklySummaryRepository interface{}
type SubscriptionStateRepository interface{}
type RefreshTokenSessionRepository interface{}
type IdempotencyKeyRepository interface{}
type DeletionRequestRepository interface{}
type DeletionAuditRepository interface{}
type ExportJobRepository interface{}
