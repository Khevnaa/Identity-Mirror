# Identity Mirror Phase 1 Backend Implementation Plan (Go + Postgres)

## 1) High-Level Backend Design

### Module boundaries and isolation

- `cmd/api`: process bootstrap only (config load, logger, DB pool, router, graceful shutdown).

- `internal/api`: HTTP transport boundary only (DTO decode, validation, response mapping).
- `internal/middleware`: auth, request size, version header, idempotency header extraction, rate limiting, request ID.
- `internal/auth`: JWT issuance/verification, refresh rotation, replay invalidation.
- `internal/sync`: identity declaration + encrypted vector persistence with strict invariants.
- `internal/export`: export job orchestration and signed URL issuance.
- `internal/deletion`: irreversible account deletion orchestration.
- `internal/subscription`: inactive entitlement scaffold (`free`, `trial_reserved`, `pro_reserved`).
- `internal/db`: sqlc query layer + explicit transaction wrapper.
- `internal/crypto`: envelope metadata and canonical AAD hash validation.
- `internal/audit`: append-only, non-content audit events.


### Package structure

```text
server/
  cmd/api/main.go
  internal/
    api/
      handlers/
<<<<<<< HEAD
        auth_handler.go
        identity_handler.go
        vector_handler.go
        export_handler.go
        deletion_handler.go
        subscription_handler.go
      dto/
        auth_dto.go
        sync_dto.go
        export_dto.go
      errors/
        problem.go
=======
      dto/
      errors/
>>>>>>> backend-plan-2
    middleware/
      authn.go
      version_header.go
      content_type.go
      body_limit.go
      rate_limit.go
      idempotency.go
      request_id.go
    auth/
      service.go
<<<<<<< HEAD
      token_signer.go
=======
      signer.go
>>>>>>> backend-plan-2
      refresh_store.go
    sync/
      declaration_service.go
      vector_service.go
<<<<<<< HEAD
=======
      summary_service.go
>>>>>>> backend-plan-2
      invariants.go
    export/
      service.go
      worker.go
      signer.go
    deletion/
      service.go
      worker.go
    subscription/
      service.go
    db/
      migrations/
      query/
      tx.go
    crypto/
      envelope_validation.go
    audit/
      logger.go
```

<<<<<<< HEAD
### Interface definitions (contract-first)

```go
// internal/sync/declaration_service.go
=======
### Interface definitions (contract-driven)

```go
>>>>>>> backend-plan-2
type DeclarationService interface {
    PutIdentityDeclaration(ctx context.Context, in PutDeclarationInput) (PutDeclarationResult, error)
    GetLatestIdentityDeclaration(ctx context.Context, userID uuid.UUID) (DeclarationRecord, error)
}

<<<<<<< HEAD
// internal/sync/vector_service.go
=======
>>>>>>> backend-plan-2
type VectorService interface {
    PutDailyVector(ctx context.Context, in PutVectorInput) (PutVectorResult, error)
    ListDailyVectors(ctx context.Context, userID uuid.UUID, from, to civil.Date) ([]VectorRecord, error)
}

<<<<<<< HEAD
// internal/auth/service.go
=======
>>>>>>> backend-plan-2
type AuthService interface {
    Login(ctx context.Context, in LoginInput) (TokenPair, error)
    Refresh(ctx context.Context, in RefreshInput) (TokenPair, error)
    Logout(ctx context.Context, in LogoutInput) error
}

<<<<<<< HEAD
// internal/deletion/service.go
=======
>>>>>>> backend-plan-2
type DeletionService interface {
    RequestDeletion(ctx context.Context, userID uuid.UUID, reason string) (DeletionRequestResult, error)
}

<<<<<<< HEAD
// internal/export/service.go
=======
>>>>>>> backend-plan-2
type ExportService interface {
    RequestExport(ctx context.Context, userID uuid.UUID) (ExportJobAccepted, error)
    GetExportJob(ctx context.Context, userID uuid.UUID, jobID uuid.UUID) (ExportJobView, error)
}
```

<<<<<<< HEAD
Design rule: handlers depend only on interfaces; concrete services depend on sqlc query interfaces and explicit transactions.
=======
Handlers depend on interfaces only. Services depend on sqlc query interfaces and explicit transactions only.
>>>>>>> backend-plan-2

---

## 2) Database Schema Design (Postgres)

<<<<<<< HEAD
### DDL

```sql
-- extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- users
=======
### Canonical DDL

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

>>>>>>> backend-plan-2
CREATE TABLE users (
  user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
<<<<<<< HEAD
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

-- device registrations
=======
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

>>>>>>> backend-plan-2
CREATE TABLE device_registrations (
  device_id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  device_fingerprint_hash BYTEA NOT NULL,
<<<<<<< HEAD
  platform TEXT NOT NULL CHECK (platform IN ('ios','android')),
=======
  platform TEXT NOT NULL CHECK (platform IN ('ios', 'android')),
>>>>>>> backend-plan-2
  app_version TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, device_fingerprint_hash)
);

<<<<<<< HEAD
-- schema versions allowlist
=======
>>>>>>> backend-plan-2
CREATE TABLE schema_versions_allowlist (
  domain TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  PRIMARY KEY (domain, version)
);

<<<<<<< HEAD
-- identity declarations (immutable history)
=======
CREATE TABLE user_sync_state (
  user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
  latest_declaration_version BIGINT NOT NULL DEFAULT 0 CHECK (latest_declaration_version >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

>>>>>>> backend-plan-2
CREATE TABLE identity_declarations (
  declaration_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  declaration_version BIGINT NOT NULL CHECK (declaration_version > 0),
<<<<<<< HEAD
=======
  domain TEXT NOT NULL DEFAULT 'identity_declaration' CHECK (domain = 'identity_declaration'),
  schema_version INTEGER NOT NULL,
>>>>>>> backend-plan-2
  payload_ciphertext BYTEA NOT NULL,
  payload_sha256 BYTEA NOT NULL CHECK (octet_length(payload_sha256) = 32),
  envelope_alg TEXT NOT NULL,
  envelope_kid TEXT NOT NULL,
  envelope_nonce BYTEA NOT NULL,
  envelope_aad_hash BYTEA NOT NULL CHECK (octet_length(envelope_aad_hash) = 32),
<<<<<<< HEAD
  schema_version INTEGER NOT NULL,
  client_created_at TIMESTAMPTZ NOT NULL,
  server_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, declaration_version),
  FOREIGN KEY (domain, schema_version)
    REFERENCES (
      SELECT 'identity_declaration'::TEXT AS domain, version FROM schema_versions_allowlist
    )
);
```

> Implementation note: Postgres cannot reference a SELECT in FK directly. Use a normalized table and explicit `domain` column in declarations/vectors; DDL below provides correct FK pattern.

```sql
ALTER TABLE identity_declarations
  ADD COLUMN domain TEXT NOT NULL DEFAULT 'identity_declaration',
  ADD CONSTRAINT fk_identity_schema_version
  FOREIGN KEY (domain, schema_version)
  REFERENCES schema_versions_allowlist(domain, version);

-- immutable enforcement trigger function
CREATE OR REPLACE FUNCTION forbid_update_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'immutable table: %', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_identity_immutable_ud
BEFORE UPDATE OR DELETE ON identity_declarations
FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();

-- declaration monotonicity guard
CREATE OR REPLACE FUNCTION enforce_monotonic_declaration_version() RETURNS trigger AS $$
DECLARE
  max_version BIGINT;
BEGIN
  SELECT COALESCE(MAX(declaration_version),0) INTO max_version
  FROM identity_declarations
  WHERE user_id = NEW.user_id;

  IF NEW.declaration_version <= max_version THEN
    RAISE EXCEPTION 'declaration_version must be strictly monotonic';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_declaration_monotonic
BEFORE INSERT ON identity_declarations
FOR EACH ROW EXECUTE FUNCTION enforce_monotonic_declaration_version();

-- encrypted daily vectors (immutable per date bucket)
=======
  aad_user_id UUID NOT NULL,
  aad_domain TEXT NOT NULL,
  aad_bucket TEXT NOT NULL,
  aad_schema_version INTEGER NOT NULL,
  aad_declaration_version BIGINT,
  client_created_at TIMESTAMPTZ NOT NULL,
  server_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, declaration_version),
  FOREIGN KEY (domain, schema_version) REFERENCES schema_versions_allowlist(domain, version),
  CHECK (aad_domain = domain),
  CHECK (aad_schema_version = schema_version),
  CHECK (aad_user_id = user_id),
  CHECK (aad_declaration_version = declaration_version)
);

>>>>>>> backend-plan-2
CREATE TABLE encrypted_behavior_vectors (
  vector_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  vector_date DATE NOT NULL,
<<<<<<< HEAD
=======
  domain TEXT NOT NULL DEFAULT 'daily_vector' CHECK (domain = 'daily_vector'),
  schema_version INTEGER NOT NULL,
>>>>>>> backend-plan-2
  payload_ciphertext BYTEA NOT NULL,
  payload_sha256 BYTEA NOT NULL CHECK (octet_length(payload_sha256) = 32),
  envelope_alg TEXT NOT NULL,
  envelope_kid TEXT NOT NULL,
  envelope_nonce BYTEA NOT NULL,
  envelope_aad_hash BYTEA NOT NULL CHECK (octet_length(envelope_aad_hash) = 32),
<<<<<<< HEAD
  schema_version INTEGER NOT NULL,
  domain TEXT NOT NULL DEFAULT 'daily_vector',
=======
  aad_user_id UUID NOT NULL,
  aad_domain TEXT NOT NULL,
  aad_bucket TEXT NOT NULL,
  aad_schema_version INTEGER NOT NULL,
>>>>>>> backend-plan-2
  client_created_at TIMESTAMPTZ NOT NULL,
  server_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (vector_date >= DATE '2020-01-01' AND vector_date <= DATE '2100-12-31'),
  UNIQUE (user_id, vector_date),
<<<<<<< HEAD
  FOREIGN KEY (domain, schema_version) REFERENCES schema_versions_allowlist(domain, version)
);

CREATE TRIGGER trg_vectors_immutable_ud
BEFORE UPDATE OR DELETE ON encrypted_behavior_vectors
FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();

-- weekly summaries (optional sync, immutable by week bucket)
=======
  FOREIGN KEY (domain, schema_version) REFERENCES schema_versions_allowlist(domain, version),
  CHECK (aad_domain = domain),
  CHECK (aad_schema_version = schema_version),
  CHECK (aad_user_id = user_id),
  CHECK (aad_bucket = to_char(vector_date, 'YYYY-MM-DD'))
) PARTITION BY RANGE (vector_date);

>>>>>>> backend-plan-2
CREATE TABLE weekly_drift_summaries (
  summary_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  week_start_date DATE NOT NULL,
<<<<<<< HEAD
  payload_ciphertext BYTEA NOT NULL,
  schema_version INTEGER NOT NULL,
  domain TEXT NOT NULL DEFAULT 'weekly_summary',
  server_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (EXTRACT(ISODOW FROM week_start_date) = 1),
  UNIQUE (user_id, week_start_date),
  FOREIGN KEY (domain, schema_version) REFERENCES schema_versions_allowlist(domain, version)
);

CREATE TRIGGER trg_weekly_immutable_ud
BEFORE UPDATE OR DELETE ON weekly_drift_summaries
FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();

-- subscription scaffold
CREATE TABLE subscription_state (
  user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK (state IN ('free','trial_reserved','pro_reserved')),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- refresh token families + rotation
=======
  domain TEXT NOT NULL DEFAULT 'weekly_summary' CHECK (domain = 'weekly_summary'),
  schema_version INTEGER NOT NULL,
  payload_ciphertext BYTEA NOT NULL,
  payload_sha256 BYTEA NOT NULL CHECK (octet_length(payload_sha256) = 32),
  envelope_alg TEXT NOT NULL,
  envelope_kid TEXT NOT NULL,
  envelope_nonce BYTEA NOT NULL,
  envelope_aad_hash BYTEA NOT NULL CHECK (octet_length(envelope_aad_hash) = 32),
  aad_user_id UUID NOT NULL,
  aad_domain TEXT NOT NULL,
  aad_bucket TEXT NOT NULL,
  aad_schema_version INTEGER NOT NULL,
  client_created_at TIMESTAMPTZ NOT NULL,
  server_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (EXTRACT(ISODOW FROM week_start_date) = 1),
  UNIQUE (user_id, week_start_date),
  FOREIGN KEY (domain, schema_version) REFERENCES schema_versions_allowlist(domain, version),
  CHECK (aad_domain = domain),
  CHECK (aad_schema_version = schema_version),
  CHECK (aad_user_id = user_id),
  CHECK (aad_bucket = to_char(week_start_date, 'YYYY-MM-DD'))
);

CREATE TABLE subscription_state (
  user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
  state TEXT NOT NULL CHECK (state IN ('free', 'trial_reserved', 'pro_reserved')),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

>>>>>>> backend-plan-2
CREATE TABLE refresh_token_sessions (
  session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  device_id UUID REFERENCES device_registrations(device_id) ON DELETE SET NULL,
  current_token_hash BYTEA NOT NULL UNIQUE,
  previous_token_hash BYTEA,
  issued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  rotated_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  replay_detected_at TIMESTAMPTZ,
  CHECK (expires_at > issued_at)
);

CREATE INDEX idx_refresh_token_sessions_user_active
ON refresh_token_sessions(user_id)
<<<<<<< HEAD
WHERE revoked_at IS NULL AND expires_at > now();

-- idempotency registry
=======
WHERE revoked_at IS NULL;

CREATE INDEX idx_refresh_token_sessions_user_expiry
ON refresh_token_sessions(user_id, expires_at);

>>>>>>> backend-plan-2
CREATE TABLE idempotency_keys (
  idempotency_key TEXT NOT NULL,
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  route_fingerprint TEXT NOT NULL,
  request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
<<<<<<< HEAD
  response_code INTEGER NOT NULL,
  response_body JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (user_id, idempotency_key, route_fingerprint)
=======
  status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed')),
  response_code INTEGER,
  response_body JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (user_id, idempotency_key, route_fingerprint),
  CHECK ((status = 'in_progress' AND response_code IS NULL AND response_body IS NULL)
      OR (status = 'completed' AND response_code IS NOT NULL AND response_body IS NOT NULL))
>>>>>>> backend-plan-2
);

CREATE INDEX idx_idempotency_gc ON idempotency_keys(expires_at);

<<<<<<< HEAD
-- deletion requests and immutable audit
CREATE TABLE deletion_requests (
  deletion_request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES users(user_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('requested','in_progress','completed','failed')),
=======
CREATE TABLE deletion_requests (
  deletion_request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('requested', 'in_progress', 'completed', 'failed')),
>>>>>>> backend-plan-2
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  failure_code TEXT
);

CREATE TABLE deletion_audit_log (
  audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
<<<<<<< HEAD
  deletion_request_id UUID NOT NULL,
=======
  deletion_request_id UUID NOT NULL REFERENCES deletion_requests(deletion_request_id) ON DELETE RESTRICT,
>>>>>>> backend-plan-2
  action TEXT NOT NULL,
  action_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL,
  CHECK (jsonb_typeof(metadata) = 'object')
);

<<<<<<< HEAD
CREATE TRIGGER trg_deletion_audit_immutable_ud
BEFORE UPDATE OR DELETE ON deletion_audit_log
FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();

-- export jobs
CREATE TABLE export_jobs (
  export_job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('queued','running','ready','expired','failed')),
=======
CREATE TABLE export_jobs (
  export_job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'ready', 'expired', 'failed')),
>>>>>>> backend-plan-2
  object_key TEXT,
  content_sha256 BYTEA,
  byte_size BIGINT CHECK (byte_size >= 0),
  failure_code TEXT,
<<<<<<< HEAD
=======
  download_issued_at TIMESTAMPTZ,
  download_nonce UUID,
>>>>>>> backend-plan-2
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  UNIQUE (user_id, export_job_id)
);

CREATE INDEX idx_export_jobs_user_created ON export_jobs(user_id, created_at DESC);
CREATE INDEX idx_export_jobs_ready_expiry ON export_jobs(expires_at) WHERE status = 'ready';
<<<<<<< HEAD
=======

CREATE OR REPLACE FUNCTION forbid_update_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'immutable table: %', TG_TABLE_NAME USING ERRCODE = '55000';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_identity_immutable_ud
BEFORE UPDATE OR DELETE ON identity_declarations
FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();

CREATE TRIGGER trg_vectors_immutable_ud
BEFORE UPDATE OR DELETE ON encrypted_behavior_vectors
FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();

CREATE TRIGGER trg_weekly_immutable_ud
BEFORE UPDATE OR DELETE ON weekly_drift_summaries
FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();

CREATE TRIGGER trg_deletion_audit_immutable_ud
BEFORE UPDATE OR DELETE ON deletion_audit_log
FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();
>>>>>>> backend-plan-2
```

### Ownership enforcement

<<<<<<< HEAD
- Every user-scoped table contains `user_id` with FK.
- Handler-layer enforces `jwt.sub == path user_id` where user_id path parameter is present.
- Query layer always filters by `user_id` from JWT claims, never from client body.
- Optional RLS hardening for defense in depth:

```sql
ALTER TABLE identity_declarations ENABLE ROW LEVEL SECURITY;
CREATE POLICY p_identity_owner ON identity_declarations
USING (user_id = current_setting('app.user_id', true)::uuid);
```

### Immutability enforcement strategy

- No UPDATE endpoints for immutable entities.
- DB trigger `forbid_update_delete` on immutable tables.
- Unique keys prevent overwrite (`(user_id, vector_date)`, `(user_id, declaration_version)`, `(user_id, week_start_date)`).

### Monotonic declaration version enforcement

- API requires explicit `declarationVersion` and rejects missing.
- DB trigger checks `NEW.declaration_version > max(existing)` for same user.
- Race-safe via transaction + `SELECT ... FOR UPDATE` lock on per-user advisory lock:
  - `SELECT pg_advisory_xact_lock(hashtextextended(user_id::text, 0));`

### Date bucket validation

- Vectors must use `YYYY-MM-DD` (UTC date bucket).
- DB `DATE` type + hard range check.
- API verifies no timezone suffix for bucket field.
- Weekly summaries enforce Monday week-start check.
=======
- Every user-scoped table has `user_id`.
- Handlers use `jwt.sub` only; client body `userId` is ignored for ownership.
- Every query includes user predicate from verified JWT claims.

### Immutability enforcement

- Immutable entities: `identity_declarations`, `encrypted_behavior_vectors`, `weekly_drift_summaries`, `deletion_audit_log`.
- No update/delete APIs for immutable entities.
- DB trigger blocks update/delete for immutable entities.
- Uniqueness constraints enforce write-once buckets and versions.

### Monotonic declaration version enforcement

- API requires explicit `declarationVersion > 0`.
- Transaction takes per-user advisory lock and `SELECT ... FOR UPDATE` on `user_sync_state`.
- Insert is allowed only when `incoming_version = latest_declaration_version + 1`.
- Transaction updates `user_sync_state.latest_declaration_version` in the same commit as declaration insert.

### Date bucket validation

- Daily vectors use `DATE` bucket and route path `YYYY-MM-DD`.
- Weekly summaries use Monday `week_start_date` only.
- Bucket strings in AAD fields must match canonical DB bucket format.
>>>>>>> backend-plan-2

---

## 3) API Contract Definitions

<<<<<<< HEAD
Common requirements for all JSON endpoints:

- Header `Content-Type: application/json`.
- Header `Accept: application/json`.
- Header `X-API-Version: 1` required.
- Unknown fields rejected (`json.Decoder.DisallowUnknownFields`).
- Max body size (e.g., 256KB for sync metadata, 1MB for encrypted payload endpoint as needed).

### Auth

#### `POST /v1/auth/login`
- Auth: none.
- Request:
  - `email` string
  - `password` string
  - `deviceId` UUID
- Response `200`:
  - `accessToken`, `accessTokenExpiresAt`
  - `refreshToken`, `refreshTokenExpiresAt`
- Errors: `400`, `401`, `429`.

#### `POST /v1/auth/refresh`
- Auth: none (refresh token in secure cookie or request body token field).
- Request:
  - `refreshToken` string
  - `deviceId` UUID
- Response `200`: new rotated token pair.
- Errors:
  - `401 invalid_refresh_token`
  - `401 refresh_replay_detected` (session revoked)
  - `409 device_mismatch`

#### `POST /v1/auth/logout`
- Auth: access JWT required.
- Request: optional `refreshToken` (if current session scope).
- Response `204`.
- Behavior: revokes session(s) deterministically.

### Identity declaration

#### `PUT /v1/identity/declaration`
- Auth: JWT claims required: `sub`, `sid`, `did`, `scope=sync:write`.
- Headers: `Idempotency-Key` required.
- Request:
  - `declarationVersion` int64 (>0)
  - `schemaVersion` int (allowlisted)
  - `ciphertext` base64
  - `sha256` base64(32 bytes)
  - `envelope`: `{alg,kid,nonce,aadHash}`
  - `clientCreatedAt` RFC3339
- Response `201` with commit metadata.
- Idempotency:
  - same key + same request hash => replay prior response.
  - same key + different request hash => `409 idempotency_conflict`.
- Conflict rules:
  - out-of-order version => `409 declaration_version_conflict`.
  - duplicate version, same hash => return stored success response.
  - duplicate version, different hash => `409 declaration_immutable_conflict`.

### Daily vectors

#### `PUT /v1/vectors/daily/{date}`
- Auth: JWT claims `sub`, `sid`, `did`, `scope=sync:write`.
- Headers: `Idempotency-Key` required.
- Path: `{date}` must be `YYYY-MM-DD`.
=======
### Global contract rules

- Required headers: `Content-Type: application/json`, `Accept: application/json`, `X-API-Version: 1`.
- Protected routes require `Authorization: Bearer <JWT>`.
- Unknown JSON fields are rejected.
- Duplicate JSON keys are rejected.
- Unknown `schemaVersion` is rejected with `422 unsupported_schema_version`.
- Max request body: 256KB default, 1MB for encrypted payload routes.
- Error response format is stable JSON problem object with deterministic `errorCode`.

### Auth routes

#### `POST /v1/auth/login`
- Auth: none.
- Request: `email`, `password`, `deviceId`.
- Response `200`: token pair.
- Errors: `400 invalid_request`, `401 invalid_credentials`, `429 rate_limited`.

#### `POST /v1/auth/refresh`
- Auth: none.
- Request: `refreshToken`, `deviceId`.
- Response `200`: rotated token pair.
- Errors: `401 invalid_refresh_token`, `401 refresh_replay_detected`, `409 device_mismatch`.

#### `POST /v1/auth/logout`
- Auth: access JWT.
- Request: optional `sessionScope` (`current`|`all`).
- Response `204`.

### Identity declaration route

#### `PUT /v1/identity/declaration`
- Auth claims required: `sub`, `sid`, `did`, `scope=sync:write`.
- Header required: `Idempotency-Key`.
- Request:
  - `declarationVersion` int64
  - `schemaVersion` int
  - `ciphertext` base64
  - `sha256` base64(32 bytes)
  - `envelope` `{alg,kid,nonce,aadHash}`
  - `aad` `{userId,domain,bucket,schemaVersion,declarationVersion}`
  - `clientCreatedAt` RFC3339
- Response `201` commit metadata.
- Conflict rules:
  - out-of-order version => `409 declaration_version_conflict`
  - duplicate version same hash => replay stored `201`
  - duplicate version different hash => `409 declaration_immutable_conflict`

### Daily vectors route

#### `PUT /v1/vectors/daily/{date}`
- Auth claims required: `sub`, `sid`, `did`, `scope=sync:write`.
- Header required: `Idempotency-Key`.
- `{date}` must be canonical `YYYY-MM-DD`.
>>>>>>> backend-plan-2
- Request:
  - `schemaVersion`
  - `ciphertext`
  - `sha256`
  - `envelope`
<<<<<<< HEAD
  - `clientCreatedAt`
- Response `201`.
- Conflict rules:
  - existing `(user_id, date)` with same hash => idempotent success replay.
  - existing with different hash => `409 vector_immutable_conflict`.

### Weekly summaries (optional)

#### `PUT /v1/summaries/weekly/{weekStartDate}`
- Same auth/idempotency patterns.
- `{weekStartDate}` must be Monday.
- Conflict: immutable per week bucket.

### Export

#### `POST /v1/export/jobs`
- Auth: JWT `scope=export:write`.
- Response `202` with `exportJobId`, `status=queued`.

#### `GET /v1/export/jobs/{jobId}`
- Auth: JWT `scope=export:read`.
- Response:
  - queued/running => status only.
  - ready => one-time signed URL + `expiresAt`.
  - failed => `failureCode`.

### Deletion

#### `POST /v1/deletion/requests`
- Auth: JWT `scope=account:delete`.
- Headers: `Idempotency-Key` required.
- Response `202` with request status.
- Conflict: if already completed => `409 already_deleted`; if in progress => returns in-progress state.

### Subscription scaffold

#### `GET /v1/subscription/state`
- Auth: JWT `scope=subscriptions:read`.
- Response: `state` only.
=======
  - `aad` `{userId,domain,bucket,schemaVersion}`
  - `clientCreatedAt`
- Response `201`.
- Conflict rules:
  - existing bucket same hash => replay stored `201`
  - existing bucket different hash => `409 vector_immutable_conflict`

### Weekly summaries route

#### `PUT /v1/summaries/weekly/{weekStartDate}`
- Auth claims required: `sub`, `sid`, `did`, `scope=sync:write`.
- Header required: `Idempotency-Key`.
- `{weekStartDate}` must be Monday `YYYY-MM-DD`.
- Request schema matches encrypted routes with summary domain AAD.
- Response `201`.
- Conflict rules identical to daily vectors.

### Export routes

#### `POST /v1/export/jobs`
- Auth claim required: `scope=export:write`.
- Response `202` with queued job.

#### `GET /v1/export/jobs/{jobId}`
- Auth claim required: `scope=export:read`.
- States:
  - `queued|running`: status only
  - `ready`: returns one deterministic URL payload tied to `download_nonce`
  - `failed`: `failureCode`
  - `expired`: `410 export_expired`

### Deletion route

#### `POST /v1/deletion/requests`
- Auth claim required: `scope=account:delete`.
- Header required: `Idempotency-Key`.
- Response `202` with request status.
- Conflict rules:
  - existing `in_progress` => `202` same request
  - existing `completed` => `409 already_deleted`

### Subscription scaffold route

#### `GET /v1/subscription/state`
- Auth claim required: `scope=subscriptions:read`.
- Response `200` with `state`.
>>>>>>> backend-plan-2

---

## 4) Auth & Token Rotation Strategy

- Access token TTL: 15 minutes.
- Refresh token TTL: 30 days absolute.
<<<<<<< HEAD
- Refresh rotation:
  1. Validate presented refresh token hash against `current_token_hash`.
  2. If matches previous hash (already rotated) => replay attempt, set `replay_detected_at`, revoke session, return `401 refresh_replay_detected`.
  3. On success, issue new refresh token, atomically move current->previous and set new current.
- Hash storage:
  - Store `HMAC-SHA256(server_pepper, refresh_token)` as `BYTEA`.
  - Never store raw refresh token.
- Logout invalidation:
  - Session logout: set `revoked_at=now()` for matching `session_id`.
  - Global logout: revoke all user sessions in one transaction.

---

## 5) Idempotency Design

- Required on all `PUT` and deletion request POST.
- Key scope: `(user_id, route_fingerprint, idempotency_key)`.
- Request hash: canonical JSON hash of validated request payload + path params.
- Expiration policy: 24h default (configurable up to 7d).
- Behavior:
  - new key: execute handler in transaction, persist response snapshot before commit.
  - duplicate key same hash: return stored status/body.
  - duplicate key different hash: `409 idempotency_conflict`.
- Concurrent race handling:
  - `INSERT ... ON CONFLICT DO NOTHING` + `SELECT ... FOR UPDATE` existing row.
  - Single winner executes write path; others wait/read stored response.
=======
- Refresh token carries opaque `session_id` prefix.
- Stored secret is `HMAC-SHA256(server_pepper, refresh_secret)` only.
- Refresh flow is one transaction:
  1. Parse token `session_id`.
  2. `SELECT ... FOR UPDATE` session row by `session_id`.
  3. Reject revoked/expired with `401 invalid_refresh_token`.
  4. Reject device mismatch with `409 device_mismatch`.
  5. If hash equals `previous_token_hash`, set `replay_detected_at`, set `revoked_at`, return `401 refresh_replay_detected`.
  6. If hash differs from `current_token_hash`, return `401 invalid_refresh_token`.
  7. Rotate `previous_token_hash <- current_token_hash`, `current_token_hash <- new_hash`, `rotated_at <- now()`.
  8. Issue new access + refresh tokens and commit.
- Logout revokes session(s) in a single transaction.
- Key rollout is deterministic: verify with active+previous keys, sign with active only, then retire previous after TTL window.
- JWT verification accepts ±90 seconds clock skew only.

---

## 5) Idempotency Design (Authoritative)

- Idempotency is mandatory for all `PUT` routes and `POST /v1/deletion/requests`.
- Scope key is `(user_id, route_fingerprint, idempotency_key)`.
- Request hash is SHA-256 of canonicalized validated request + canonical path params.
- TTL is 24h.
- State machine in `idempotency_keys`:
  - `in_progress`: reservation lock exists, no response payload.
  - `completed`: response code/body frozen.
- Deterministic algorithm:
  1. Begin transaction.
  2. Read existing idempotency row `FOR UPDATE`.
  3. If existing hash differs, return `409 idempotency_conflict`.
  4. If existing status `completed`, return stored response.
  5. If no row, insert `in_progress` reservation.
  6. Execute business write logic.
  7. Persist final response and set `status='completed'`.
  8. Commit.
- Any rollback removes in-flight business effects and reservation update atomically.
>>>>>>> backend-plan-2

---

## 6) Sync & Conflict Enforcement

### Declaration version monotonicity

<<<<<<< HEAD
- Enforcement layers:
  1. API precheck: fetch latest version for user; reject if incoming <= latest.
  2. DB trigger final guard for TOCTOU safety.
  3. Per-user advisory transaction lock to serialize declaration writes.

### Daily vector overwrite rejection

- `UNIQUE(user_id, vector_date)` prevents multiple records.
- Insert failure path compares hash:
  - equal hash => idempotent success.
  - different hash => immutable conflict.

### Server vs device timestamp

- `clientCreatedAt` stored for audit.
- `server_received_at` authoritative for ordering and retention.
- No ordering based on device clock for invariants.

### Multi-device races

- Declaration writes serialized via advisory lock.
- Daily vector writes naturally serialized by unique constraint.
- Deterministic winner: first committed transaction.
- Deterministic loser response: `409` with explicit conflict code.

---

## 7) Deletion Orchestrator

### Transaction order

1. Acquire per-user advisory lock.
2. Upsert `deletion_requests` as `in_progress` with `started_at`.
3. Insert `deletion_audit_log` action `deletion_started`.
4. Delete user-scoped tables in strict order:
=======
- Enforcement is strict increment-by-one (`incoming = latest + 1`).
- `user_sync_state` row is locked `FOR UPDATE` per request.
- Declaration insert and state advance occur in one transaction.

### Daily vector overwrite rejection

- `(user_id, vector_date)` unique constraint enforces write-once day bucket.
- Duplicate hash is treated as idempotent replay.
- Different hash on existing bucket returns `409 vector_immutable_conflict`.

### Server timestamp and device timestamp

- `clientCreatedAt` is stored as client metadata only.
- `server_received_at` controls ordering, retention, and operational decisions.

### Multi-device races

- Declaration writes serialize by lock on `user_sync_state` + advisory lock.
- Vector and weekly writes serialize by unique constraint and idempotency row lock.
- Conflict outcomes are deterministic and code-stable.

---

## 7) Deletion Orchestrator (Authoritative Lifecycle)

### Transaction order

Single transaction:

1. Acquire per-user advisory lock.
2. Lock `deletion_requests` row `FOR UPDATE`; set `status='in_progress'`, `started_at=now()`.
3. Insert `deletion_audit_log(action='deletion_started')`.
4. Delete user-scoped mutable tables:
>>>>>>> backend-plan-2
   - `idempotency_keys`
   - `refresh_token_sessions`
   - `export_jobs`
   - `weekly_drift_summaries`
   - `encrypted_behavior_vectors`
   - `identity_declarations`
   - `subscription_state`
   - `device_registrations`
<<<<<<< HEAD
5. Delete `users` row (cascades remaining if any).
6. Insert final audit log `deletion_completed` (metadata only).
7. Mark request `completed` with timestamp.
8. Commit.

### Lock semantics

- Advisory lock prevents concurrent sync/export/auth writes during deletion.
- Service methods check deletion status early and fail fast with `423 account_deletion_in_progress`.

### Worker strategy

- API marks request queued/in-progress; background worker executes deletion.
- Worker reads `requested` rows with `FOR UPDATE SKIP LOCKED`.

### Failure rollback behavior

- Entire deletion in single transaction to prevent partial delete.
- On failure, transaction rollback leaves all data intact; request set `failed` in separate compensating transaction with failure code.

### Audit guarantees

- Audit rows contain no behavioral payloads or ciphertext.
- Immutable trigger on audit table.
=======
   - `user_sync_state`
5. Set `deletion_requests.status='completed'`, `completed_at=now()`.
6. Insert `deletion_audit_log(action='deletion_completed')`.
7. Delete `users` row.
8. Commit.

### Failure behavior

- Any failure before commit rolls back all deletes and status changes.
- Worker writes `status='failed'` with `failure_code` in separate transaction only after rollback.
- API rejects write routes with `423 account_deletion_in_progress` while request status is `in_progress`.

### Irreversibility guarantees

- No restore path exists in Phase 1.
- Completion state is durable in `deletion_requests` and immutable events remain in `deletion_audit_log`.
>>>>>>> backend-plan-2

---

## 8) Export Job Orchestration

<<<<<<< HEAD
### Job schema/lifecycle

- States: `queued -> running -> ready -> expired` or `failed`.
- Transition rules are strict; invalid transition returns internal error and alerts.

### Signed URL issuance

- On `ready`, generate short-lived signed GET URL (e.g., 10 minutes).
- URL only issued from authenticated `GET /export/jobs/{id}` for owner.

### Access expiration

- Export object retained 24h max.
- `expires_at` in DB and object store lifecycle policy align.

### Export content structure

`export.json`:

```json
{
  "exportVersion": 1,
  "generatedAt": "RFC3339",
  "userId": "uuid",
  "identityDeclarations": [
    {"declarationVersion": 3, "schemaVersion": 1, "ciphertext": "...", "sha256": "...", "envelope": {"alg":"...","kid":"...","nonce":"...","aadHash":"..."}}
  ],
  "dailyVectors": [
    {"date":"YYYY-MM-DD", "schemaVersion":1, "ciphertext":"...", "sha256":"...", "envelope": {...}}
  ],
  "weeklySummaries": []
}
```

No decrypted content included.

### Rehydration safety

- Import path (future phase) must revalidate schema versions and immutable bucket rules.
- Export includes checksums to detect corruption/tampering.
=======
### Job lifecycle

- Valid transitions only:
  - `queued -> running`
  - `running -> ready|failed`
  - `ready -> expired`
- Invalid transition is rejected and logged as invariant violation.

### Signed URL issuance and consistency

- URL issuance occurs only for `ready` jobs.
- First URL issuance atomically sets `download_issued_at` and `download_nonce` if null.
- Later reads return URL metadata tied to existing `download_nonce` while unexpired.
- Expired jobs return `410 export_expired`.

### Access expiration

- Export object TTL is 24h maximum.
- DB `expires_at` equals object-store expiration policy.

### Export content structure

`export.json` contains encrypted records only:

- identity declarations: ciphertext + integrity metadata
- daily vectors: ciphertext + integrity metadata
- weekly summaries: ciphertext + integrity metadata

No decrypted behavioral content is emitted.
>>>>>>> backend-plan-2

---

## 9) Security Hardening

<<<<<<< HEAD
- TLS: require TLS 1.3 at edge; backend trust boundary assumes mTLS or private network from edge to service.
- Required headers:
  - `Content-Type`, `Accept`, `X-API-Version`, `Authorization` for protected routes.
- Strict JSON decode:
  - `DisallowUnknownFields`
  - explicit DTO validation
  - reject duplicate keys via canonical decode path
- Payload limits:
  - default 256KB
  - vector/declaration ciphertext endpoints configurable max 1MB
- Rate limiting:
  - per-user + per-device hash token bucket.
  - stricter on `/auth/*` and `/auth/refresh`.
- Structured logging (PII-safe):
  - log request ID, route, status, latency, invariant error code.
  - never log ciphertext, raw token, declarations, vectors.
- Envelope metadata validation:
  - required fields present and bounded length
  - algorithm allowlist (e.g., `XCHACHA20POLY1305`, `AES256GCM`)
  - nonce length check by algorithm
  - `aadHash` length fixed 32 bytes
- AAD binding expectation:
  - client AAD must bind user_id + table domain + schema_version + bucket (date/week/version).
  - server validates hash format and deterministic AAD field composition rules.
=======
- TLS 1.3 is mandatory at ingress.
- Strict header enforcement for content type, accept, API version, and auth.
- Strict JSON decoder:
  - unknown fields rejected
  - duplicate keys rejected
  - size limits enforced before decode
- Rate limiting:
  - per-user and per-device fingerprint
  - tighter budgets for auth and refresh endpoints
- Logging is structured and content-safe:
  - request ID, route, status, latency, invariant error code
  - never log tokens, ciphertext, or user behavioral fields
- Envelope metadata validation is mandatory:
  - algorithm allowlist
  - nonce length exact by algorithm
  - SHA-256 length checks
- Canonical AAD verification is mandatory:
  - server recomputes canonical AAD from explicit request AAD components
  - server verifies `envelope.aadHash == SHA256(canonicalAAD)` before persistence
>>>>>>> backend-plan-2

---

## 10) Failure Mode Handling

<<<<<<< HEAD
- DB outage:
  - Return `503 service_unavailable` with retry-after.
  - No in-memory write buffering.
- Partial transaction failure:
  - rollback and explicit error mapping; no best-effort partial commits.
- Worker crash recovery:
  - resume using `queued/requested` + `SKIP LOCKED` scanning.
- Token replay detection store failure:
  - fail closed (`503 auth_temporarily_unavailable`), do not issue tokens.
- Idempotency key collision:
  - route-scoped + user-scoped keys minimize collisions.
  - mismatched hash => deterministic `409`.
=======
- DB outage: return `503 service_unavailable` with `Retry-After`; no buffering.
- Transaction failure: rollback and deterministic error mapping.
- Worker crash: resume via `requested/queued` scanning with `FOR UPDATE SKIP LOCKED`.
- Token replay store failure: fail closed with `503 auth_temporarily_unavailable`.
- Idempotency key hash mismatch: `409 idempotency_conflict`.
- Background lock starvation: bounded lock wait timeout; return retryable `503 lock_timeout`.
>>>>>>> backend-plan-2

---

## 11) Scalability Boundaries

### 10K users

<<<<<<< HEAD
- Likely pressure: auth refresh write amplification and index cache churn.
- Mitigation: tuned indexes for refresh/idempotency hot paths.

### 100K users

- Likely pressure: `encrypted_behavior_vectors` growth and backup windows.
- Mitigation: monthly range partition by `vector_date`; vacuum tuning.

### 1M users

- Likely pressure: partition count/index bloat and export/deletion worker throughput.
- Mitigation:
  - partition pruning by date and potentially hash-subpartition by user.
  - archive/TTL old idempotency and expired exports.
  - separate worker pools for export vs deletion with bounded concurrency.

### Partitioning strategy

- `encrypted_behavior_vectors` range partition monthly.
- `weekly_drift_summaries` yearly partition optional.
- Keep `identity_declarations` unpartitioned initially (lower write rate).

### Index growth management

- Use partial indexes for active sessions and ready exports.
- Scheduled GC:
  - purge expired idempotency rows.
  - purge expired export jobs and objects.
- Reindex plan during maintenance windows.
=======
- First stressor: auth refresh + idempotency churn.
- Controls:
  - table autovacuum tuned for `refresh_token_sessions` and `idempotency_keys`
  - minute-level GC for expired idempotency rows

### 100K users

- First stressor: `encrypted_behavior_vectors` index growth.
- Controls:
  - monthly range partitions pre-created
  - partition-local indexes only
  - partition pruning in all date-bounded queries

### 1M users

- First stressor: deletion/export worker saturation and lock contention.
- Controls:
  - separate worker pools for export and deletion
  - fixed concurrency caps per worker type
  - deletion queue priority to satisfy irreversible-delete SLA

### Index and storage management

- Partial indexes only use immutable predicates.
- Expired exports and idempotency rows are purged continuously.
- Reindex schedule is defined in operations runbook.
>>>>>>> backend-plan-2

---

## 12) Observability (Minimal, Privacy-Safe)

### Allowed metrics

<<<<<<< HEAD
- Request count, latency histogram, status codes by route.
- DB transaction duration and rollback count.
- Worker queue depth and job state counts.
- Token refresh success/failure/replay counters.
- Conflict counters (`declaration_version_conflict`, `vector_immutable_conflict`, `idempotency_conflict`).

### Forbidden metrics

- Any metric carrying app identifiers, behavioral vectors, declaration text, ciphertext lengths per user, or content-derived dimensions.

### Health checks

- `GET /health/live`: process alive only.
- `GET /health/ready`: DB ping + migration version check.
=======
- Request rate, latency, and status by route.
- DB transaction duration and rollback count.
- Idempotency conflict count.
- Declaration/vector immutable conflict count.
- Refresh replay detection count.
- Advisory lock wait histogram: `db_advisory_lock_wait_seconds`.
- Deletion in-progress age histogram: `deletion_request_in_progress_age_seconds`.
- Export running age histogram: `export_job_running_age_seconds`.
- Queue depth for deletion and export workers.

### Forbidden metrics

- Metrics containing declaration content, behavioral content, ciphertext samples, raw app identifiers, or user-generated text.

### Health checks

- `GET /health/live`: process liveness.
- `GET /health/ready`: DB connectivity + migration version parity + worker lease sanity.
>>>>>>> backend-plan-2

### Structured error schema

```json
{
  "timestamp": "RFC3339",
  "requestId": "uuid",
  "route": "/v1/vectors/daily/{date}",
  "status": 409,
  "errorCode": "vector_immutable_conflict",
  "invariant": "daily_vector_immutable",
  "retryable": false
}
```

<<<<<<< HEAD
No PII fields, no payload fragments.
=======
---

## 13) Migration and Rollback Guarantees

### Migration ordering

1. Create base tables and allowlist tables.
2. Backfill/correction migrations.
3. Guard migration verifies no pending corrective rows.
4. Enable immutable triggers.
5. Enable workers dependent on final schema.

### Deploy safety

- Application deploy requires migration version at target before serving write traffic.
- Roll-forward is default. Rollback path uses backward-compatible app binaries and does not disable immutable triggers.
- Failed migration stops deployment immediately.

### Data integrity guarantees

- No migration alters encrypted payload bytes.
- Schema version allowlist is explicit and immutable per release.
- Constraint violations abort migration transaction.
>>>>>>> backend-plan-2

---

## Critical Flow Pseudocode

### A) `PUT /v1/identity/declaration`

```go
func PutIdentityDeclaration(ctx context.Context, req PutDeclarationRequest) Response {
  mustVersionHeader("1")
  claims := mustJWTClaims(ctx, "sync:write")
  mustIdempotencyKey(req.Headers)
<<<<<<< HEAD
  validateDTO(req) // strict fields, schema version allowlist, envelope metadata

  routeFP := "PUT:/v1/identity/declaration"
  reqHash := CanonicalHash(req.Body)

  return WithTx(ctx, db, func(tx Tx) Response {
    if row := tx.IdempotencyGetForUpdate(claims.UserID, routeFP, req.IdempotencyKey); row != nil {
      if row.RequestHash != reqHash { return Conflict("idempotency_conflict") }
      return Replay(row.ResponseCode, row.ResponseBody)
    }

    tx.IdempotencyReserve(claims.UserID, routeFP, req.IdempotencyKey, reqHash)
    tx.AdvisoryUserLock(claims.UserID)

    latest := tx.GetLatestDeclarationVersion(claims.UserID)
    if req.DeclarationVersion <= latest { return Conflict("declaration_version_conflict") }

    err := tx.InsertIdentityDeclaration(claims.UserID, req)
    if err == UniqueViolationOnUserVersion {
      existing := tx.GetIdentityByVersion(claims.UserID, req.DeclarationVersion)
      if existing.PayloadSHA256 == req.SHA256 { return Created(existing.CommitMeta) }
=======
  validateStrict(req)
  validateAAD(req.AAD, claims.UserID, "identity_declaration", req.DeclarationVersion, req.SchemaVersion)

  routeFP := "PUT:/v1/identity/declaration"
  reqHash := CanonicalHash(req.Body, req.Path)

  return WithTx(ctx, db, func(tx Tx) Response {
    row := tx.GetIdempotencyForUpdate(claims.UserID, routeFP, req.IdempotencyKey)
    if row != nil {
      if !bytes.Equal(row.RequestHash, reqHash) { return Conflict("idempotency_conflict") }
      if row.Status == "completed" { return Replay(row.ResponseCode, row.ResponseBody) }
    } else {
      tx.InsertIdempotencyInProgress(claims.UserID, routeFP, req.IdempotencyKey, reqHash, now().Add(24*time.Hour))
    }

    tx.AdvisoryUserLock(claims.UserID)
    state := tx.GetUserSyncStateForUpdate(claims.UserID)
    if req.DeclarationVersion != state.LatestDeclarationVersion+1 {
      return Conflict("declaration_version_conflict")
    }

    err := tx.InsertDeclaration(claims.UserID, req)
    if err == UniqueViolationOnUserVersion {
      existing := tx.GetDeclarationByVersion(claims.UserID, req.DeclarationVersion)
      if bytes.Equal(existing.PayloadSHA256, req.SHA256) {
        resp := Created(existing.CommitMeta)
        tx.CompleteIdempotency(claims.UserID, routeFP, req.IdempotencyKey, resp)
        return resp
      }
>>>>>>> backend-plan-2
      return Conflict("declaration_immutable_conflict")
    }
    mustNoErr(err)

<<<<<<< HEAD
    resp := Created(commitMeta)
    tx.IdempotencyFinalize(claims.UserID, routeFP, req.IdempotencyKey, resp)
=======
    tx.UpdateLatestDeclarationVersion(claims.UserID, req.DeclarationVersion)
    resp := Created(CommitMetaFrom(req))
    tx.CompleteIdempotency(claims.UserID, routeFP, req.IdempotencyKey, resp)
>>>>>>> backend-plan-2
    return resp
  })
}
```

### B) Refresh token rotation

```go
<<<<<<< HEAD
func Refresh(ctx context.Context, token string, deviceID uuid.UUID) (TokenPair, error) {
  tokenHash := HMACSHA256(serverPepper, token)

  return WithTx(ctx, db, func(tx Tx) (TokenPair, error) {
    sess := tx.GetSessionByCurrentOrPreviousHashForUpdate(tokenHash)
    if sess == nil || sess.Revoked || sess.Expired { return err401("invalid_refresh_token") }
    if sess.DeviceID != deviceID { return err409("device_mismatch") }

    if bytes.Equal(tokenHash, sess.PreviousTokenHash) {
      tx.MarkReplayAndRevokeSession(sess.SessionID)
      return err401("refresh_replay_detected")
    }

    if !bytes.Equal(tokenHash, sess.CurrentTokenHash) {
      return err401("invalid_refresh_token")
    }

    newRefresh := RandomToken(32)
    newHash := HMACSHA256(serverPepper, newRefresh)
    tx.RotateRefreshHash(sess.SessionID, prev=sess.CurrentTokenHash, curr=newHash)

    access := SignAccessJWT(sess.UserID, sess.SessionID, deviceID)
    return TokenPair{Access: access, Refresh: newRefresh}, nil
=======
func Refresh(ctx context.Context, rawToken string, deviceID uuid.UUID) (TokenPair, error) {
  sessionID, secret := ParseRefreshToken(rawToken)
  hash := HMACSHA256(serverPepper, secret)

  return WithTx(ctx, db, func(tx Tx) (TokenPair, error) {
    sess := tx.GetRefreshSessionForUpdate(sessionID)
    if sess == nil || sess.RevokedAt != nil || sess.ExpiresAt.Before(nowUTC()) {
      return TokenPair{}, err401("invalid_refresh_token")
    }
    if sess.DeviceID != deviceID {
      return TokenPair{}, err409("device_mismatch")
    }

    if bytes.Equal(hash, sess.PreviousTokenHash) {
      tx.MarkReplayAndRevokeSession(sessionID)
      return TokenPair{}, err401("refresh_replay_detected")
    }
    if !bytes.Equal(hash, sess.CurrentTokenHash) {
      return TokenPair{}, err401("invalid_refresh_token")
    }

    newSecret := RandomToken(32)
    newHash := HMACSHA256(serverPepper, newSecret)
    tx.RotateRefreshHash(sessionID, sess.CurrentTokenHash, newHash, nowUTC())

    return IssueTokenPair(sess.UserID, sessionID, deviceID, newSecret), nil
>>>>>>> backend-plan-2
  })
}
```

### C) Deletion worker

```go
func RunDeletionJob(ctx context.Context, userID uuid.UUID) error {
<<<<<<< HEAD
  return WithTx(ctx, db, func(tx Tx) error {
    tx.AdvisoryUserLock(userID)
    tx.MarkDeletionInProgress(userID)
    tx.Audit(userID, "deletion_started", Meta{"phase": "phase1"})
=======
  if err := WithTx(ctx, db, func(tx Tx) error {
    tx.AdvisoryUserLock(userID)

    req := tx.GetDeletionRequestForUpdate(userID)
    tx.MarkDeletionInProgress(req.ID)
    tx.InsertDeletionAudit(userID, req.ID, "deletion_started", Meta{"phase": "phase1"})
>>>>>>> backend-plan-2

    tx.DeleteIdempotency(userID)
    tx.DeleteRefreshSessions(userID)
    tx.DeleteExports(userID)
    tx.DeleteWeeklySummaries(userID)
    tx.DeleteDailyVectors(userID)
    tx.DeleteDeclarations(userID)
    tx.DeleteSubscription(userID)
    tx.DeleteDevices(userID)
<<<<<<< HEAD
    tx.DeleteUser(userID)

    tx.Audit(userID, "deletion_completed", Meta{"irreversible": true})
    tx.MarkDeletionCompleted(userID)
    return nil
  })
}
```
=======
    tx.DeleteUserSyncState(userID)

    tx.MarkDeletionCompleted(req.ID)
    tx.InsertDeletionAudit(userID, req.ID, "deletion_completed", Meta{"irreversible": true})

    tx.DeleteUser(userID)
    return nil
  }); err != nil {
    _ = MarkDeletionFailed(ctx, db, userID, classifyFailure(err))
    return err
  }
  return nil
}
```

---

## Production Survivability Audit (Historical Record)

This section records the risks identified during review. Canonical behavior is defined by sections 1–13 and pseudocode above.

Risk: Monotonic declaration race (DB-level invariant bypass under concurrent writes)

Failure Scenario:
Two concurrent transactions for the same user insert `declaration_version=5` and `6` using snapshot-visible `MAX()` checks.

Production Impact:
Out-of-order commits violate deterministic sync ordering.

Minimal Fix:
Use per-user `user_sync_state` row lock and strict increment-by-one update in one transaction.

Risk: Invalid migration DDL for schema allowlist FK

Failure Scenario:
FK definition references non-table expression.

Production Impact:
Migration failure during deploy.

Minimal Fix:
Use direct FK to `schema_versions_allowlist(domain, version)` in canonical table DDL.

Risk: Invalid partial index predicate (`now()`) in refresh sessions index

Failure Scenario:
Partial index predicate uses volatile function.

Production Impact:
Migration failure and degraded auth query performance.

Minimal Fix:
Use immutable predicate index and query-time expiry predicate.

Risk: Idempotency reserve/finalize transaction gap

Failure Scenario:
Reservation precedes response persistence but schema requires response columns non-null.

Production Impact:
Duplicate write races or failed reservations.

Minimal Fix:
Persist idempotency state machine with `in_progress` and `completed` states.

Risk: Refresh token replay false-negative / cross-session ambiguity

Failure Scenario:
Lookup by token hash without session binding selects wrong row under corruption scenarios.

Production Impact:
Incorrect revocation and replay handling.

Minimal Fix:
Refresh token carries `session_id`; row is locked by `session_id` then hash is validated.

Risk: Deletion request lifecycle broken by FK cascade ordering

Failure Scenario:
Deleting `users` cascades request state before completion marker is persisted.

Production Impact:
No durable deletion completion record.

Minimal Fix:
Persist completion and audit before deleting user row; keep deletion request independent from user cascade.

Risk: Eventual consistency hole in export URL issuance

Failure Scenario:
Concurrent reads issue multiple URLs for one job.

Production Impact:
Inconsistent export access auditability.

Minimal Fix:
Atomically persist `download_issued_at` and `download_nonce` on first issuance.

Risk: Cryptographic binding under-specified (AAD verification not deterministic)

Failure Scenario:
AAD hash is accepted without canonical server recomputation.

Production Impact:
Weak binding of ciphertext metadata.

Minimal Fix:
Require explicit AAD components and verify exact canonical AAD hash before insert.

Risk: Migration-time data corruption risk for immutable triggers

Failure Scenario:
Immutable triggers activate before corrective migrations.

Production Impact:
Operational risk from trigger disable/enable in production.

Minimal Fix:
Enforce migration ordering with pre-trigger correction and guard migration.

Risk: Observability blind spot for lock contention and stuck workers

Failure Scenario:
No direct metrics for lock waits and long-running jobs.

Production Impact:
Slow incident isolation during production pressure.

Minimal Fix:
Expose lock wait and job age histograms with alerts.

Risk: Operational deployment risk around key rotation and skew

Failure Scenario:
Key rotation and skew rules are undefined.

Production Impact:
Authentication instability during cutover.

Minimal Fix:
Use dual-key verify window and bounded skew verification.

Risk: 10K scale breakpoint — auth/idempotency hot-path write amplification

Failure Scenario:
Refresh and idempotency writes churn hot tables.

Production Impact:
P95 latency growth.

Minimal Fix:
Autovacuum tuning and minute-level TTL cleanup.

Risk: 100K scale breakpoint — vector table/index bloat

Failure Scenario:
Large vector table growth without pre-created partitions.

Production Impact:
Sync degradation and maintenance expansion.

Minimal Fix:
Pre-create monthly partitions and partition-local indexes.

Risk: 1M scale breakpoint — deletion/export worker throughput collapse

Failure Scenario:
Shared worker capacity saturates DB and storage.

Production Impact:
Deletion SLA breaches and queue backlog.

Minimal Fix:
Separate worker pools with fixed concurrency and deletion priority.

Risk: Category with no material risk detected

Failure Scenario:
No material risk detected for server-side raw usage log ingestion prohibition.

Production Impact:
No material risk detected.

Minimal Fix:
No change required.
>>>>>>> backend-plan-2
