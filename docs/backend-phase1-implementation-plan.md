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
      dto/
      errors/
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
      signer.go
      refresh_store.go
    sync/
      declaration_service.go
      vector_service.go
      summary_service.go
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

### Interface definitions (contract-driven)

```go
type DeclarationService interface {
    PutIdentityDeclaration(ctx context.Context, in PutDeclarationInput) (PutDeclarationResult, error)
    GetLatestIdentityDeclaration(ctx context.Context, userID uuid.UUID) (DeclarationRecord, error)
}

type VectorService interface {
    PutDailyVector(ctx context.Context, in PutVectorInput) (PutVectorResult, error)
    ListDailyVectors(ctx context.Context, userID uuid.UUID, from, to civil.Date) ([]VectorRecord, error)
}

type AuthService interface {
    Login(ctx context.Context, in LoginInput) (TokenPair, error)
    Refresh(ctx context.Context, in RefreshInput) (TokenPair, error)
    Logout(ctx context.Context, in LogoutInput) error
}

type DeletionService interface {
    RequestDeletion(ctx context.Context, userID uuid.UUID, reason string) (DeletionRequestResult, error)
}

type ExportService interface {
    RequestExport(ctx context.Context, userID uuid.UUID) (ExportJobAccepted, error)
    GetExportJob(ctx context.Context, userID uuid.UUID, jobID uuid.UUID) (ExportJobView, error)
}
```

Handlers depend on interfaces only. Services depend on sqlc query interfaces and explicit transactions only.

---

## 2) Database Schema Design (Postgres)

### Canonical DDL

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE device_registrations (
  device_id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  device_fingerprint_hash BYTEA NOT NULL,
  platform TEXT NOT NULL CHECK (platform IN ('ios', 'android')),
  app_version TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (user_id, device_fingerprint_hash)
);

CREATE TABLE schema_versions_allowlist (
  domain TEXT NOT NULL,
  version INTEGER NOT NULL CHECK (version > 0),
  PRIMARY KEY (domain, version)
);

CREATE TABLE user_sync_state (
  user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
  latest_declaration_version BIGINT NOT NULL DEFAULT 0 CHECK (latest_declaration_version >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE identity_declarations (
  declaration_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  declaration_version BIGINT NOT NULL CHECK (declaration_version > 0),
  domain TEXT NOT NULL DEFAULT 'identity_declaration' CHECK (domain = 'identity_declaration'),
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

CREATE TABLE encrypted_behavior_vectors (
  vector_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  vector_date DATE NOT NULL,
  domain TEXT NOT NULL DEFAULT 'daily_vector' CHECK (domain = 'daily_vector'),
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
  CHECK (vector_date >= DATE '2020-01-01' AND vector_date <= DATE '2100-12-31'),
  UNIQUE (user_id, vector_date),
  FOREIGN KEY (domain, schema_version) REFERENCES schema_versions_allowlist(domain, version),
  CHECK (aad_domain = domain),
  CHECK (aad_schema_version = schema_version),
  CHECK (aad_user_id = user_id),
  CHECK (aad_bucket = to_char(vector_date, 'YYYY-MM-DD'))
) PARTITION BY RANGE (vector_date);

CREATE TABLE weekly_drift_summaries (
  summary_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  week_start_date DATE NOT NULL,
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
WHERE revoked_at IS NULL;

CREATE INDEX idx_refresh_token_sessions_user_expiry
ON refresh_token_sessions(user_id, expires_at);

CREATE TABLE idempotency_keys (
  idempotency_key TEXT NOT NULL,
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  route_fingerprint TEXT NOT NULL,
  request_hash BYTEA NOT NULL CHECK (octet_length(request_hash) = 32),
  status TEXT NOT NULL CHECK (status IN ('in_progress', 'completed')),
  response_code INTEGER,
  response_body JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (user_id, idempotency_key, route_fingerprint),
  CHECK ((status = 'in_progress' AND response_code IS NULL AND response_body IS NULL)
      OR (status = 'completed' AND response_code IS NOT NULL AND response_body IS NOT NULL))
);

CREATE INDEX idx_idempotency_gc ON idempotency_keys(expires_at);

CREATE TABLE deletion_requests (
  deletion_request_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL UNIQUE,
  status TEXT NOT NULL CHECK (status IN ('requested', 'in_progress', 'completed', 'failed')),
  requested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  failure_code TEXT
);

CREATE TABLE deletion_audit_log (
  audit_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL,
  deletion_request_id UUID NOT NULL REFERENCES deletion_requests(deletion_request_id) ON DELETE RESTRICT,
  action TEXT NOT NULL,
  action_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  metadata JSONB NOT NULL,
  CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE TABLE export_jobs (
  export_job_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'ready', 'expired', 'failed')),
  object_key TEXT,
  content_sha256 BYTEA,
  byte_size BIGINT CHECK (byte_size >= 0),
  failure_code TEXT,
  download_issued_at TIMESTAMPTZ,
  download_nonce UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  UNIQUE (user_id, export_job_id)
);

CREATE INDEX idx_export_jobs_user_created ON export_jobs(user_id, created_at DESC);
CREATE INDEX idx_export_jobs_ready_expiry ON export_jobs(expires_at) WHERE status = 'ready';

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
```

### Ownership enforcement

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

---

## 3) API Contract Definitions

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
- Request:
  - `schemaVersion`
  - `ciphertext`
  - `sha256`
  - `envelope`
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

---

## 4) Auth & Token Rotation Strategy

- Access token TTL: 15 minutes.
- Refresh token TTL: 30 days absolute.
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

---

## 6) Sync & Conflict Enforcement

### Declaration version monotonicity

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
   - `idempotency_keys`
   - `refresh_token_sessions`
   - `export_jobs`
   - `weekly_drift_summaries`
   - `encrypted_behavior_vectors`
   - `identity_declarations`
   - `subscription_state`
   - `device_registrations`
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

---

## 8) Export Job Orchestration

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

---

## 9) Security Hardening

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

---

## 10) Failure Mode Handling

- DB outage: return `503 service_unavailable` with `Retry-After`; no buffering.
- Transaction failure: rollback and deterministic error mapping.
- Worker crash: resume via `requested/queued` scanning with `FOR UPDATE SKIP LOCKED`.
- Token replay store failure: fail closed with `503 auth_temporarily_unavailable`.
- Idempotency key hash mismatch: `409 idempotency_conflict`.
- Background lock starvation: bounded lock wait timeout; return retryable `503 lock_timeout`.

---

## 11) Scalability Boundaries

### 10K users

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

---

## 12) Observability (Minimal, Privacy-Safe)

### Allowed metrics

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

---

## Critical Flow Pseudocode

### A) `PUT /v1/identity/declaration`

```go
func PutIdentityDeclaration(ctx context.Context, req PutDeclarationRequest) Response {
  mustVersionHeader("1")
  claims := mustJWTClaims(ctx, "sync:write")
  mustIdempotencyKey(req.Headers)
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
      return Conflict("declaration_immutable_conflict")
    }
    mustNoErr(err)

    tx.UpdateLatestDeclarationVersion(claims.UserID, req.DeclarationVersion)
    resp := Created(CommitMetaFrom(req))
    tx.CompleteIdempotency(claims.UserID, routeFP, req.IdempotencyKey, resp)
    return resp
  })
}
```

### B) Refresh token rotation

```go
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
  })
}
```

### C) Deletion worker

```go
func RunDeletionJob(ctx context.Context, userID uuid.UUID) error {
  if err := WithTx(ctx, db, func(tx Tx) error {
    tx.AdvisoryUserLock(userID)

    req := tx.GetDeletionRequestForUpdate(userID)
    tx.MarkDeletionInProgress(req.ID)
    tx.InsertDeletionAudit(userID, req.ID, "deletion_started", Meta{"phase": "phase1"})

    tx.DeleteIdempotency(userID)
    tx.DeleteRefreshSessions(userID)
    tx.DeleteExports(userID)
    tx.DeleteWeeklySummaries(userID)
    tx.DeleteDailyVectors(userID)
    tx.DeleteDeclarations(userID)
    tx.DeleteSubscription(userID)
    tx.DeleteDevices(userID)
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
