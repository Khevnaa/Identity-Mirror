# Identity Mirror — Phase 1 System Architecture

## System Overview Diagram (textual)

```text
[Mobile App (React Native + TS)]
  ├── Identity Declaration Module
  ├── Permission Manager (Android Usage Access / iOS Device Activity)
  ├── Local Usage Capture Adapters
  ├── Local Feature Extraction Engine (deterministic)
  ├── Identity Drift Engine (deterministic)
  ├── Weekly Insight Generator
  ├── AI Summary Client (fixed prompt, derived metrics only)
  ├── Local Encrypted Store (derived vectors + declarations)
  ├── Raw Log Ephemeral Store (TTL + immediate purge after extraction)
  ├── Export/Delete Controller
  └── Sync Client (optional)
            │ TLS 1.3 + JWT
            ▼
[Backend API (Go)]
  ├── Auth Service (JWT issuance/refresh)
  ├── Vector Sync Service (encrypted payload storage)
  ├── Subscription Scaffold Service (inactive gating flags)
  ├── Deletion Orchestrator
  └── Export Job Service
            ▼
[Postgres]
  ├── users
  ├── device_registrations
  ├── encrypted_identity_snapshots
  ├── encrypted_behavior_vectors
  ├── weekly_drift_summaries
  ├── subscription_state
  └── deletion_audit_log
```

## Client Architecture Breakdown

1. **App Shell (React Native + TypeScript)**
   - Navigation for Identity, Weekly Mirror, Privacy Controls, Settings.
   - No engagement loops (no streaks, no badges, no nudges).

2. **Identity Declaration Module**
   - Captures:
     - `declared_roles: string[]`
     - `declared_traits: string[]`
     - `top_goals: string[]`
     - `priority_weights: {learning, building, social, health}`
   - Enforces weight normalization to sum exactly `1.0` (auto-normalize + user-visible validation).
   - Writes locally first; sync is explicit opt-in.

3. **Permission Manager**
   - Android: checks and requests Usage Access permission (user routed to Settings).
   - iOS: integrates Device Activity / Family Controls where allowed by entitlements; if unavailable, falls back to manual Screen Time import workflow (user-provided structured snapshot parsing).
   - Tracks permission state transitions to support graceful degradation.

4. **Local Usage Capture Adapters**
   - Android adapter reads foreground usage intervals from `UsageStatsManager`.
   - iOS adapter ingests allowed activity aggregates (no private API usage).
   - Outputs unified `RawUsageLog[]` into encrypted ephemeral local store.

5. **Raw Log Ephemeral Store**
   - Per-day partitioned local records.
   - Hard TTL (e.g., 24h max retention) and immediate purge after feature extraction commit.
   - Never synced, never sent to AI, never exported unless user explicitly chooses raw-included local export mode (off by default in Phase 1).

6. **Local Feature Extraction Engine**
   - Deterministically maps raw intervals to daily features.
   - Uses configurable app/category mapping table distributed as signed config.

7. **Identity Drift Engine**
   - Computes alignment and drift from normalized vectors.
   - Produces weekly metrics and flags only from derived values.

8. **Weekly Insight Generator**
   - Aggregates 7-day windows.
   - Produces deterministic narrative primitives (`flags`, `deltas`, `confidence tags`).

9. **AI Summary Client (optional rendering layer)**
   - Sends only precomputed metrics package.
   - Fixed prompt template, low temperature, bounded response schema.
   - If AI unavailable, deterministic text template used.

10. **Sync Client (optional)**
    - End-to-end encrypted payload submission of declarations + derived vectors.
    - Conflict handling via version vectors and deterministic merge policy.

11. **Privacy Controls**
    - One-tap local wipe.
    - Account-level cloud deletion request.
    - Data export (JSON + CSV derived metrics).

## Backend Architecture Breakdown

1. **API Gateway Layer (Go HTTP server)**
   - JWT middleware for stateless auth.
   - Request schema validation.
   - Rate limiting per token + device fingerprint hash.

2. **Auth Service**
   - Issues short-lived access JWT + rotating refresh token pair.
   - Stores refresh token hashes only.

3. **Vector Sync Service**
   - Accepts encrypted identity snapshots and encrypted behavior vectors.
   - Performs metadata validation (date ranges, version monotonicity, checksum).
   - Does not decrypt client-side encrypted vectors in Phase 1 (server stores ciphertext + envelope metadata).

4. **Weekly Summary Store Service**
   - Stores deterministic weekly summaries if client opts to sync them.
   - Supports fetch for multi-device continuity.

5. **Subscription Scaffold Service (inactive)**
   - Maintains entitlement state machine (`free`, `trial_reserved`, `pro_reserved`) without blocking core Phase 1 functions.
   - Exposes flags for future gating hooks only.

6. **Deletion Orchestrator**
   - Executes hard-delete workflow over user-scoped tables.
   - Writes immutable deletion audit record (non-content metadata only).

7. **Export Job Service**
   - Assembles encrypted export bundle from synced derived data.
   - Signed download URL with short expiry.

8. **Postgres**
   - Row-level ownership via `user_id`.
   - Strict migration discipline, soft constraints on schema version fields.

## Data Flow Lifecycle (step-by-step)

1. User declares identity and priorities in app.
2. App validates and normalizes priority weights to sum `1.0`.
3. Identity payload stored in local encrypted store.
4. User grants usage permission (Android/iOS-compliant path).
5. Usage adapter captures raw intervals into ephemeral raw store.
6. Daily extractor runs on-device scheduler.
7. Extractor computes `DailyBehaviorFeatures` and writes derived features locally.
8. Raw logs are immediately purged after successful feature commit.
9. Drift engine updates rolling vectors and weekly aggregates.
10. Weekly insight object generated deterministically.
11. Optional AI renderer receives only bounded derived metrics and returns formatted summary.
12. Optional sync uploads encrypted declarations + derived vectors + weekly summaries.
13. User can export derived data package at any time.
14. User can request deletion; local wipe is immediate, cloud deletion async with completion receipt.

## Folder Structure (Client + Server)

```text
mirror/
  client/
    src/
      app/
        navigation/
        screens/
          IdentityDeclarationScreen.tsx
          WeeklyMirrorScreen.tsx
          PrivacyControlScreen.tsx
      modules/
        identity/
          IdentityDeclarationService.ts
          identity.types.ts
          identity.validation.ts
        permissions/
          PermissionManager.ts
          androidUsagePermission.ts
          iosDeviceActivityPermission.ts
        capture/
          UsageCaptureAdapter.ts
          AndroidUsageStatsAdapter.ts
          IOSDeviceActivityAdapter.ts
          rawUsage.types.ts
        extraction/
          FeatureExtractionEngine.ts
          featureFormulas.ts
          categoryMappingStore.ts
        drift/
          DriftEngine.ts
          driftMath.ts
          weeklyAggregator.ts
        insights/
          InsightGenerator.ts
          DeterministicNarrative.ts
          AISummaryClient.ts
          aiPromptTemplate.ts
        sync/
          SyncClient.ts
          conflictResolver.ts
          sync.types.ts
        privacy/
          ExportService.ts
          DeletionService.ts
      storage/
        SecureKeyStore.ts
        EncryptedDatabase.ts
        EphemeralRawLogStore.ts
      config/
        appCategoryMap.v1.json
      tests/
        unit/
        integration/
  server/
    cmd/api/main.go
    internal/
      auth/
      middleware/
      sync/
      summary/
      subscription/
      deletion/
      export/
      db/
      api/
        handlers/
        dto/
    migrations/
    tests/
  docs/
    architecture-phase1.md
```

## Data Schemas (Type definitions)

```ts
type PriorityWeights = {
  learning: number;
  building: number;
  social: number;
  health: number;
}; // must sum to 1.0 after normalization

type IdentityDeclaration = {
  userId: string;
  declaredRoles: string[];
  declaredTraits: string[];
  topGoals: string[];
  priorityWeights: PriorityWeights;
  declarationVersion: number;
  updatedAt: string; // ISO8601
};

type RawUsageLog = {
  appIdentifier: string;
  startTimestamp: string; // ISO8601
  endTimestamp: string;   // ISO8601
};

type DailyBehaviorFeatures = {
  date: string; // YYYY-MM-DD
  categoryDistribution: Record<string, number>; // normalized proportions, sum=1
  deepWorkBlocksCount: number;
  avgContextSwitchIntervalMinutes: number;
  lateNightUsageRatio: number; // [0,1]
  fragmentationIndex: number;  // [0,1]
  totalActiveMinutes: number;
  featureQualityFlag: 'ok' | 'low_data' | 'no_data' | 'permission_missing';
};

type DriftMetricsWeekly = {
  weekStartDate: string;
  alignmentScore: number; // cosine similarity mapped to [0,1]
  volatilityIndex: number; // [0,1+]
  driftDirection: Record<string, number>; // delta vector components
  fragmentationImpactModifier: number; // [0.7,1.0]
  notablePatternFlags: string[];
};

type AISummaryInput = {
  alignmentScore: number;
  fragmentationIndex: number;
  driftDirection: Record<string, number>;
  notablePatternFlags: string[];
};
```

```go
type EncryptedVectorRecord struct {
    UserID            string
    DeviceID          string
    DateBucket        string
    CiphertextBase64  string
    KeyEnvelopeBase64 string
    SchemaVersion     int
    VectorChecksum    string
    CreatedAt         time.Time
}
```

## Identity Drift Engine Specification (mathematical detail)

Let identity dimensions be fixed as:

- `D = [learning, building, social, health]`

### 1) Declared identity vector

User-entered priority weights:

- `w = [w_l, w_b, w_s, w_h]`
- Constraint: `sum(w_i) = 1`, `w_i >= 0`

If user input is unnormalized:

- `w'_i = max(w_i, 0)`
- `W = sum(w'_i)`
- `I_i = w'_i / W` (if `W=0`, set `I = [0.25,0.25,0.25,0.25]` and flag invalid declaration)

`I` is declared identity vector.

### 2) Behavioral vector (daily)

From category distribution per day:

- Raw category minutes mapped to D: `m = [m_l, m_b, m_s, m_h]`
- `M = sum(m_i)`
- `B_i = m_i / M` for `M>0`, else `B = [0,0,0,0]` with `no_data` flag.

### 3) Weekly behavioral vector

For week `t` over days `d=1..7`, weighted by data quality `q_d in [0,1]`:

- `B_t = (sum_d q_d * B_d) / (sum_d q_d)` if denominator > 0.

### 4) Alignment score via cosine similarity

- `cos(I, B_t) = (I · B_t) / (||I|| * ||B_t||)`
- Map to `[0,1]`:
  - `alignment_raw = (cos(I,B_t) + 1) / 2`

If `||B_t|| = 0`, alignment is undefined -> set `alignment_raw = 0.5`, flag `no_behavior_data`.

### 5) Fragmentation impact modifier

Weekly fragmentation mean `F_t in [0,1]`.

- `f_mod = 1 - alpha * F_t`, with `alpha = 0.3`
- Clamp `f_mod` to `[0.7, 1.0]`

Final score:

- `alignment_score = alignment_raw * f_mod`

### 6) Drift direction

- `delta_t = B_t - I`
- Each component indicates over/under-allocation against declared identity.
  - Positive: behavior exceeds declaration in that dimension.
  - Negative: behavior under-indexes.

### 7) Volatility index

Across daily behavioral vectors in week:

- `v_t = mean_{d=2..7}( ||B_d - B_{d-1}||_1 / 2 )`

`L1/2` normalizes to `[0,1]` for simplex vectors.

### 8) Rolling weekly aggregation

Maintain last `k=4` weeks:

- `alignment_rolling = mean(alignment_score_{t-k+1..t})`
- `volatility_rolling = mean(v_{t-k+1..t})`
- Trend slope via least squares on weekly alignment scores (deterministic).

No AI or probabilistic inference is used in any step.

## Feature Extraction Specification

Input: `RawUsageLog[]` for a day.

### Preprocessing

1. Validate interval integrity (`end > start`, duration cap per interval).
2. Merge overlapping intervals per app.
3. Map each `appIdentifier` to category via signed config table.
4. Convert to minute-resolution timeline.

### Deterministic metrics

Let:
- `T_total` = total active minutes in day.
- `T_c` = minutes in category `c`.
- Switch points = minute where active app changes category.

1. **category_distribution[c]**
   - `T_c / T_total` for `T_total > 0`, else 0.

2. **deep_work_blocks_count**
   - Count contiguous blocks in `learning` or `building` categories with duration `>= 25` minutes and <= 2 minute interruption tolerance.

3. **avg_context_switch_interval_minutes**
   - If `N_switch > 0`: `T_total / N_switch`, else `T_total`.

4. **late_night_usage_ratio**
   - `T_00_05 / T_total`, where `T_00_05` is active minutes from 00:00–05:00 local time.

5. **fragmentation_index**
   - `1 - (mean_block_duration / max(mean_block_duration_reference, 1))`
   - Practical deterministic variant:
     - `fragmentation_index = min(1, N_switch / max(T_total/15, 1))`

6. **feature quality flag**
   - `no_data` if `T_total == 0`
   - `low_data` if `T_total < 20`
   - `permission_missing` when capture unavailable
   - otherwise `ok`

### Raw log purge rule

After successful persistence of `DailyBehaviorFeatures` and checksum verification:

- Delete all raw logs for that day immediately.
- If extraction fails, keep raw logs until next retry or TTL expiry (max 24h), whichever first.

## Permission & OS Compliance Strategy

1. **Android**
   - Use `UsageStatsManager` with explicit user opt-in via Usage Access settings.
   - Explain scope: only app usage duration and timestamps.
   - Detect revocation at app foreground and before scheduled extraction.

2. **iOS**
   - Primary: Device Activity / Screen Time APIs under proper entitlements.
   - If entitlement/path unavailable for deployment context, provide manual Screen Time export import by user action.
   - No private APIs, no background surveillance.

3. **Permission Revocation Handling**
   - Freeze new capture.
   - Preserve existing derived features.
   - Weekly insights marked as lower confidence.
   - Show deterministic, non-coercive prompt for re-enable.

4. **Compliance Artifacts**
   - In-app privacy notice with field-level data map.
   - Data Processing Record for GDPR.
   - App Store/Data Safety declarations aligned to derived-data sync only.

## Privacy & Encryption Model

1. **At Rest on Device**
   - Tokens/keys in iOS Keychain / Android Keystore.
   - Local DB encrypted (AES-256-GCM per record envelope).
   - Raw logs stored encrypted in ephemeral table with TTL metadata.

2. **In Transit**
   - TLS 1.3 only.
   - Certificate validation and pinning optional but recommended for production hardening.

3. **Cloud Storage**
   - Only derived vectors, declarations, weekly summaries.
   - Payload encrypted client-side with DEK (AES-256-GCM).
   - DEK wrapped by KEK (per-user key material derived from secure secret flow).

4. **Access Control**
   - JWT access token (short TTL).
   - Refresh token rotation with replay invalidation.
   - User-scoped row access by `user_id`.

5. **Data Minimization**
   - No raw usage log upload.
   - No AI access to raw logs/timestamps.
   - No third-party analytics SDK collecting behavioral content.

## Edge Case Matrix (technical + behavioral)

| Edge case | Detection | Mitigation | User-visible behavior |
|---|---|---|---|
| Permission revoked mid-cycle | Permission check fails before capture/extract | Mark day as `permission_missing`; stop capture | Insight includes “insufficient permission coverage” note |
| No usage data | `T_total=0` | Emit `no_data` features; exclude from strong scoring | Weekly report shows low confidence |
| Extremely low usage | `T_total < 20` | Set `low_data`; reduce day weight `q_d` | Report avoids over-interpretation |
| Device clock manipulation | Non-monotonic timestamps / large retrograde jump | Quarantine affected intervals; use monotonic sequence IDs | Warning in privacy diagnostics |
| Corrupted local storage | DB checksum mismatch/decrypt failure | Attempt restore from last valid snapshot; isolate bad partition | Prompt user to repair local store |
| Sync conflict | Version mismatch on upload | Deterministic merge by highest declarationVersion + per-day vector last-write-wins by server timestamp | “Synced with conflict resolution” message |
| Multi-device overlap | Same day vectors from multiple device IDs | Server computes union by device precedence + dedupe hash | Unified weekly summary after sync |
| AI API failure | Timeout/non-2xx/schema failure | Fall back to deterministic template summary | No blocking of weekly insight |
| Subscription downgrade | Entitlement transition event | Keep Phase 1 features active; disable only reserved premium flags | No data loss |
| Immediate data deletion request | User action/local or remote | Instant local wipe; enqueue cloud hard-delete job | Deletion receipt + completion timestamp |

## Failure Mode & Degradation Strategy

1. **Capture unavailable**: continue identity + prior derived insights; mark confidence low.
2. **Extractor crash**: retry with exponential backoff; purge raw logs on TTL if persistent failure.
3. **Drift engine error**: preserve last valid weekly output and recalculate next cycle.
4. **Sync offline**: local-first queue with signed retry packets.
5. **AI unavailable**: deterministic summary template always available.
6. **Backend outage**: app remains fully usable locally except cloud sync/export.
7. **Keychain/Keystore inaccessible**: lock sync operations, keep non-sensitive UI readable, prompt secure re-auth.

## Subscription Gating Architecture (future-ready only)

1. **Current Phase 1 behavior**
   - No core feature blocking by subscription.
   - Entitlement checks are no-op for identity, capture, extraction, drift, weekly insights, deletion, export.

2. **Scaffold components**
   - `EntitlementState` locally cached and synced (`free`, `trial_reserved`, `pro_reserved`).
   - Feature flags map reserved paths only (e.g., future comparative analytics) but unused in Phase 1 routes.

3. **Downgrade safety**
   - Downgrade never deletes user data.
   - Reserved flags disable access to future-only modules when introduced.

4. **Simplicity constraint**
   - Avoid payment SDK integration in core modules now; keep isolated interface for future billing provider adapter.

## API Route Definitions

### Auth
- `POST /v1/auth/register`
- `POST /v1/auth/login`
- `POST /v1/auth/refresh`
- `POST /v1/auth/logout`

### Identity & Vectors (encrypted payloads)
- `PUT /v1/identity/declaration`
- `GET /v1/identity/declaration`
- `PUT /v1/vectors/daily/:date`
- `GET /v1/vectors/daily/:date`
- `GET /v1/vectors/weekly/:weekStart`

### Weekly Insights
- `PUT /v1/insights/weekly/:weekStart`
- `GET /v1/insights/weekly/:weekStart`

### Subscription Scaffold
- `GET /v1/subscription/state`
- `POST /v1/subscription/webhook-placeholder` (server-to-server reserved)

### Privacy Operations
- `POST /v1/privacy/export`
- `GET /v1/privacy/export/:jobId`
- `POST /v1/privacy/delete`
- `GET /v1/privacy/delete/:requestId`

### Operational guarantees
- All non-auth routes require JWT.
- Idempotency key required on `PUT` vector/insight routes.
- Request/response schema version required in headers.

## Data Deletion & Export Protocol

1. **Local deletion**
   - User taps “Delete local data now”.
   - App clears encrypted DB, raw ephemeral store, cached keys, and auth tokens.
   - Completion shown immediately.

2. **Cloud deletion**
   - `POST /v1/privacy/delete` with signed JWT + device confirmation code.
   - Server marks account `deletion_pending` and starts transactionally ordered hard delete:
     1. `encrypted_behavior_vectors`
     2. `weekly_drift_summaries`
     3. `encrypted_identity_snapshots`
     4. `device_registrations`
     5. `subscription_state`
     6. `users` (or anonymize if legal retention requires account skeleton)
   - Write `deletion_audit_log` metadata record.

3. **Export**
   - `POST /v1/privacy/export` creates job.
   - Bundle includes declarations, derived daily vectors, weekly metrics, and deletion status history.
   - No raw logs included from server (none stored by design).

4. **SLA targets**
   - Local deletion: immediate.
   - Cloud deletion completion: < 24h.
   - Export job completion: < 15 min typical.

## Testing Strategy (unit + integration + adversarial)

1. **Unit tests (client)**
   - Weight normalization and validation edge cases.
   - Feature formula correctness (switch counting, deep-work block detection, fragmentation).
   - Drift math invariants (cosine bounds, zero-vector handling, volatility bounds).
   - Raw purge logic state transitions.

2. **Unit tests (server)**
   - JWT middleware validation and expiry handling.
   - Schema validation and idempotency behavior.
   - Deletion orchestration ordering.

3. **Integration tests**
   - End-to-end local lifecycle: declaration -> capture -> extraction -> purge -> drift.
   - Sync and conflict resolution across two simulated devices.
   - Export and delete APIs with real Postgres test container.

4. **Adversarial/privacy tests**
   - Attempt raw log exfiltration via sync payload (must fail validation).
   - Replay refresh tokens (must be rejected post-rotation).
   - Clock tampering scenarios.
   - Corrupted encrypted payload and checksum mismatch.

5. **Compliance tests**
   - Verify no route accepts raw timestamps beyond derived schema.
   - Verify AI client payload shape strictly equals approved fields.

## Scalability Considerations (Phase 2 readiness)

1. **Data growth control**
   - Store only derived daily vectors + weekly summaries.
   - Partition server tables by month (`date_bucket`) for efficient retention and delete operations.

2. **API scalability**
   - Stateless API replicas behind load balancer.
   - Redis optional for refresh token revocation cache and idempotency key cache.

3. **Sync throughput**
   - Batched daily vector upserts.
   - Compression at transport layer for encrypted blobs.

4. **Multi-device correctness**
   - Device registration with deterministic conflict keys.
   - Versioned vector schema to support backward compatibility.

5. **Operational resilience**
   - Background workers for export/deletion jobs with retry + dead-letter queue.
   - Metrics: sync latency, deletion SLA, extraction success rate, permission coverage rate.

6. **Complexity guardrail**
   - No predictive ML or social modules introduced in this design.
   - If future needs arise, keep deterministic core unchanged and add optional services behind separate interfaces.
