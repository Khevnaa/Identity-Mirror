# Identity Mirror Phase 1 Backend Implementation Plan (Go + Postgres)

## 1) High-Level Backend Design

### Module boundaries and isolation

- `cmd/api`: process bootstrap only (config load, logger, DB pool, router, graceful shutdown).
- `internal/api`: transport boundary only (HTTP handlers, DTO decoding/validation, error mapping).
- `internal/middleware`: authn, idempotency key extraction, rate limiting, request size and content-type enforcement, correlation IDs.
- `internal/auth`: JWT issue/verify, refresh rotation, replay invalidation.
- `internal/sync`: identity declaration + derived vector persistence and invariant checks.
- `internal/deletion`: atomic user deletion orchestration.
- `internal/export`: export job lifecycle and signed URL issuance.
- `internal/subscription`: inactive scaffold reads/writes (`free`, `trial_reserved`, `pro_reserved`) only.
- `internal/db`: sqlc-generated query interfaces + explicit transaction helpers.
- `internal/crypto`: envelope metadata validators (server validates metadata and AAD bindings but does not decrypt vectors).
- `internal/audit`: append-only audit events with content-safe metadata only.

### Package structure

```text
server/
  cmd/api/main.go
  internal/
    api/
      handlers/
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
      token_signer.go
      refresh_store.go
    sync/
      declaration_service.go
      vector_service.go
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

### Interface definitions (contract-first)

```go
// internal/sync/declaration_service.go
type DeclarationService interface {
    PutIdentityDeclaration(ctx context.Context, in PutDeclarationInput) (PutDeclarationResult, error)
    GetLatestIdentityDeclaration(ctx context.Context, userID uuid.UUID) (DeclarationRecord, error)
}

// internal/sync/vector_service.go
type VectorService interface {
    PutDailyVector(ctx context.Context, in PutVectorInput) (PutVectorResult, error)
    ListDailyVectors(ctx context.Context, userID uuid.UUID, from, to civil.Date) ([]VectorRecord, error)
}

// internal/auth/service.go
type AuthService interface {
    Login(ctx context.Context, in LoginInput) (TokenPair, error)
    Refresh(ctx context.Context, in RefreshInput) (TokenPair, error)
    Logout(ctx context.Context, in LogoutInput) error
}

// internal/deletion/service.go
type DeletionService interface {
    RequestDeletion(ctx context.Context, userID uuid.UUID, reason string) (DeletionRequestResult, error)
}

// internal/export/service.go
type ExportService interface {
    RequestExport(ctx context.Context, userID uuid.UUID) (ExportJobAccepted, error)
    GetExportJob(ctx context.Context, userID uuid.UUID, jobID uuid.UUID) (ExportJobView, error)
}
```

Design rule: handlers depend only on interfaces; concrete services depend on sqlc query interfaces and explicit transactions.

---

## 2) Database Schema Design (Postgres)

### DDL

```sql
-- extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- users
CREATE TABLE users (
  user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  deleted_at TIMESTAMPTZ
);

-- device registrations
CREATE TABLE device_registrations (
  device_id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  device_fingerprint_hash BYTEA NOT NULL,
  platform TEXT NOT NULL CHECK (platform IN ('ios','android')),
  app_version TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, device_fingerprint_hash)
);

-- schema versions allowlist
CREATE TABLE schema_versions_allowlist (
  domain TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  PRIMARY KEY (domain, version)
);

-- identity declarations (immutable history)
CREATE TABLE identity_declarations (
  declaration_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  declaration_version BIGINT NOT NULL CHECK (declaration_version > 0),
  payload_ciphertext BYTEA NOT NULL,
  payload_sha256 BYTEA NOT NULL CHECK (octet_length(payload_sha256) = 32),
  envelope_alg TEXT NOT NULL,
  envelope_kid TEXT NOT NULL,
  envelope_nonce BYTEA NOT NULL,
  envelope_aad_hash BYTEA NOT NULL CHECK (octet_length(envelope_aad_hash) = 32),
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
CREATE TABLE encrypted_behavior_vectors (
  vector_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  vector_date DATE NOT NULL,
  payload_ciphertext BYTEA NOT NULL,
  payload_sha256 BYTEA NOT NULL CHECK (octet_length(payload_sha256) = 32),
  envelope_alg TEXT NOT NULL,
  envelope_kid TEXT NOT NULL,
  envelope_nonce BYTEA NOT NULL,
  envelope_aad_hash BYTEA NOT NULL CHECK (octet_length(envelope_aad_hash) = 32),
  schema_version INTEGER NOT NULL,
  domain TEXT NOT NULL DEFAULT 'daily_vector',
  client_created_at TIMESTAMPTZ NOT NULL,
  server_received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (vector_date >= DATE '2020-01-01' AND vector_date <= DATE '2100-12-31'),
  UNIQUE (user_id, vector_date),
  FOREIGN KEY (domain, schema_version) REFERENCES schema_versions_allowlist(domain, version)
);

CREATE TRIGGER trg_vectors_immutable_ud
BEFORE UPDATE OR DELETE ON encrypted_behavior_vectors
FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();

-- weekly summaries (optional sync, immutable by week bucket)
CREATE TABLE weekly_drift_summaries (
  summary_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  week_start_date DATE NOT NULL,
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
WHERE revoked_at IS NULL AND expires_at > now();

-- idempotency registry
CREATE TABLE idempotency_keys (
  idempotency_key TEXT NOT NULL,
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  route_fingerprint TEXT NOT NULL,
  request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
  response_code INTEGER NOT NULL,
  response_body JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (user_id, idempotency_key, route_fingerprint)
);

CREATE INDEX idx_idempotency_gc ON idempotency_keys(expires_at);

-- deletion requests and immutable audit
CREATE TABLE deletion_requests (
  deletion_request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE REFERENCES users(user_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('requested','in_progress','completed','failed')),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  failure_code TEXT
);

CREATE TABLE deletion_audit_log (
  audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  deletion_request_id UUID NOT NULL,
  action TEXT NOT NULL,
  action_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL,
  CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE TRIGGER trg_deletion_audit_immutable_ud
BEFORE UPDATE OR DELETE ON deletion_audit_log
FOR EACH ROW EXECUTE FUNCTION forbid_update_delete();

-- export jobs
CREATE TABLE export_jobs (
  export_job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('queued','running','ready','expired','failed')),
  object_key TEXT,
  content_sha256 BYTEA,
  byte_size BIGINT CHECK (byte_size >= 0),
  failure_code TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  UNIQUE (user_id, export_job_id)
);

CREATE INDEX idx_export_jobs_user_created ON export_jobs(user_id, created_at DESC);
CREATE INDEX idx_export_jobs_ready_expiry ON export_jobs(expires_at) WHERE status = 'ready';
```

### Ownership enforcement

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

---

## 3) API Contract Definitions

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
- Request:
  - `schemaVersion`
  - `ciphertext`
  - `sha256`
  - `envelope`
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

---

## 4) Auth & Token Rotation Strategy

- Access token TTL: 15 minutes.
- Refresh token TTL: 30 days absolute.
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

---

## 6) Sync & Conflict Enforcement

### Declaration version monotonicity

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
   - `idempotency_keys`
   - `refresh_token_sessions`
   - `export_jobs`
   - `weekly_drift_summaries`
   - `encrypted_behavior_vectors`
   - `identity_declarations`
   - `subscription_state`
   - `device_registrations`
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

---

## 8) Export Job Orchestration

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

---

## 9) Security Hardening

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

---

## 10) Failure Mode Handling

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

---

## 11) Scalability Boundaries

### 10K users

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

---

## 12) Observability (Minimal, Privacy-Safe)

### Allowed metrics

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

No PII fields, no payload fragments.

---

## Critical Flow Pseudocode

### A) `PUT /v1/identity/declaration`

```go
func PutIdentityDeclaration(ctx context.Context, req PutDeclarationRequest) Response {
  mustVersionHeader("1")
  claims := mustJWTClaims(ctx, "sync:write")
  mustIdempotencyKey(req.Headers)
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
      return Conflict("declaration_immutable_conflict")
    }
    mustNoErr(err)

    resp := Created(commitMeta)
    tx.IdempotencyFinalize(claims.UserID, routeFP, req.IdempotencyKey, resp)
    return resp
  })
}
```

### B) Refresh token rotation

```go
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
  })
}
```

### C) Deletion worker

```go
func RunDeletionJob(ctx context.Context, userID uuid.UUID) error {
  return WithTx(ctx, db, func(tx Tx) error {
    tx.AdvisoryUserLock(userID)
    tx.MarkDeletionInProgress(userID)
    tx.Audit(userID, "deletion_started", Meta{"phase": "phase1"})

    tx.DeleteIdempotency(userID)
    tx.DeleteRefreshSessions(userID)
    tx.DeleteExports(userID)
    tx.DeleteWeeklySummaries(userID)
    tx.DeleteDailyVectors(userID)
    tx.DeleteDeclarations(userID)
    tx.DeleteSubscription(userID)
    tx.DeleteDevices(userID)
    tx.DeleteUser(userID)

    tx.Audit(userID, "deletion_completed", Meta{"irreversible": true})
    tx.MarkDeletionCompleted(userID)
    return nil
  })
}
```
