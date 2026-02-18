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

## Phase 1 Hardening Review (Risk-Focused)

### 1) Structural Integrity Review

- **Boundary weakness: extraction, drift, and insight generation can become tightly coupled through shared mutable data models.**
  - **Refinement:** enforce append-only handoff contracts: `RawUsageLog[] -> DailyBehaviorFeatures -> DriftMetricsWeekly -> InsightPrimitives`. No downstream module may mutate upstream artifacts.
- **Ownership ambiguity: both Sync Client and Privacy Controls can write/delete overlapping persisted entities.**
  - **Refinement:** require a single persistence coordinator with operation intents (`write_derived`, `sync_enqueue`, `local_wipe`, `deletion_lock`) and total ordering per `user_id` + `device_id`.
- **Responsibility leak: Permission Manager policy can drift into capture adapters.**
  - **Refinement:** adapters must be pure readers and return `permission_missing` sentinel outcomes; only Permission Manager owns permission state transitions and user messaging.

### 2) Determinism Audit

- **Hidden non-determinism risk: floating-point accumulation order during normalization and weekly aggregation can differ across platforms.**
  - **Refinement:** define canonical arithmetic policy: stable summation order by dimension index (`learning`, `building`, `social`, `health`) and fixed decimal quantization (e.g., 1e-6) at every persisted boundary.
- **Rounding edge risk: “sum exactly 1.0” can fail after independent rounding per component.**
  - **Refinement:** use deterministic residual assignment: round first `n-1` components then set final component to `1.0 - sum(previous)`.
- **Time-bucket non-determinism: local time-zone and DST transitions can shift day boundaries.**
  - **Refinement:** derive day partitions using device local offset captured at interval start and persist the offset with each derived record.

### 3) Data Integrity Audit

- **Raw purge safety gap: purge trigger says “successful persistence + checksum verification” but no explicit atomicity guarantee.**
  - **Refinement:** enforce single transaction: write derived record + write extraction receipt + mark purge-ready; purge only if receipt commit is durable.
- **Checksum scope gap: current vector checksum does not explicitly include schema version, date bucket, or mapping config version.**
  - **Refinement:** checksum input must be canonical serialization of (`payload`, `schema_version`, `date_bucket`, `category_map_version`, `device_id`).
- **Schema upgrade risk: “soft constraints” may admit mixed interpretation of old/new vectors.**
  - **Refinement:** reject cross-version arithmetic unless explicit deterministic migration function exists.
- **Corruption recovery ambiguity: “attempt restore from last valid snapshot” lacks replay ordering rules.**
  - **Refinement:** snapshot restore must replay only monotonic sequence IDs not yet committed in restored snapshot.

### 4) Security & Cryptography Hardening

- **Key lifecycle assumption gap: DEK/KEK rotation cadence and invalidation triggers are unspecified.**
  - **Refinement:** define mandatory rotation triggers (logout, device compromise signal, refresh token replay detection, scheduled key epoch rollover).
- **Envelope metadata tampering risk: if envelope metadata is unauthenticated, ciphertext swapping attacks remain possible.**
  - **Refinement:** bind associated data (AAD) to `user_id`, `device_id`, `date_bucket`, `schema_version`, `ciphertext_hash`.
- **Replay vector: idempotent `PUT` without strict nonce expiry can allow stale payload replay.**
  - **Refinement:** idempotency keys must be single-use per route + user + device, with server-side TTL and payload hash binding.
- **Refresh rotation gap: rotation is stated but race behavior for concurrent refresh requests is not.**
  - **Refinement:** accept only first refresh in family chain, revoke descendants on reuse, and force re-auth on detected replay.
- **Attack surface leak: export and deletion status endpoints can reveal account existence patterns.**
  - **Refinement:** return uniform timing-safe error envelopes for unauthorized and unknown resources.

### 5) Mobile OS Behavior Risk Analysis

- **iOS scheduling reality: background execution for extraction is not guaranteed daily.**
  - **Refinement:** extraction must run opportunistically on app foreground and process missed days deterministically.
- **Android OEM process killing: scheduled jobs can be deferred or dropped.**
  - **Refinement:** maintain durable “last successful extraction day” cursor and catch-up loop with bounded per-launch work budget.
- **Permission churn race: revocation can occur between pre-check and capture read.**
  - **Refinement:** adapters must re-check permission at read time and emit an auditable `permission_missing` day artifact.
- **Battery optimization effects: prolonged background limits can delay purge.**
  - **Refinement:** TTL enforcement must run on every app foreground and before sync/export.
- **Device time drift/manipulation: interval ordering and week assignment can be corrupted.**
  - **Refinement:** store monotonic capture sequence IDs and quarantine records with retrograde wall-clock jumps.

### 6) Sync & Multi-device Conflict Hardening

- **Last-write-wins flaw: server timestamp LWW can be semantically wrong for offline devices and clock skew.**
  - **Refinement:** use deterministic precedence tuple: (`declarationVersion`, `client_logical_counter`, `server_receive_order`).
- **Version vector incompleteness: day-level vectors from multiple devices can overwrite independent contributions.**
  - **Refinement:** merge unit must be `(user_id, date_bucket, device_id)` first, then deterministic weekly union with dedupe checksum.
- **Race condition: upload and delete can execute concurrently.**
  - **Refinement:** `deletion_pending` must hard-block all mutating sync writes at gateway middleware.
- **Partial failure: declaration upload success with vector upload failure can create cross-table inconsistency.**
  - **Refinement:** require sync batch manifests with per-item commit receipts and resumable retry from first unacknowledged item.

### 7) Performance & Resource Constraints

- **Low-end device memory risk: minute-resolution expansion can spike RAM for long active days.**
  - **Refinement:** process intervals as streaming iterators; avoid materializing full-day minute arrays.
- **CPU pressure risk: overlap merge + switch counting can be O(n log n) with large interval sets.**
  - **Refinement:** sort once, single linear pass merge, then single linear pass feature extraction.
- **Local DB growth drift: derived-only policy still accumulates indefinitely without retention controls.**
  - **Refinement:** define explicit retention horizons for local derived history and compaction checkpoints.
- **Background execution budget risk: catch-up work can starve UI launch responsiveness.**
  - **Refinement:** cap extraction workload per session and persist continuation cursor.

### 8) Compliance & Store Review Risk

- **App Store review risk: Screen Time / Device Activity claims can be rejected if user value proposition and data map are not explicit in UX.**
  - **Refinement:** permission pre-prompt must enumerate exact fields captured, retention TTL, and non-upload guarantee for raw logs.
- **Policy mismatch risk: privacy copy may promise “never exported raw data” while local raw-included export mode exists (even if off by default).**
  - **Refinement:** policy text must explicitly state raw export is local-only, explicit opt-in, and never cloud-synced.
- **Perceived surveillance risk: background collection without visible status can trigger trust/support escalations.**
  - **Refinement:** expose deterministic “data coverage + permission state + last extraction run” diagnostics in-app.

### 9) Scalability Reality Check

- **At 10K users: first pressure point is idempotency and refresh-token state lookups under bursty mobile retries.**
  - **Refinement:** bounded-size token family index + idempotency cache with strict TTL eviction.
- **At 100K users: first pressure point is deletion/export worker backlog and SLA misses.**
  - **Refinement:** isolate job queues per operation type, enforce retry ceilings, and dead-letter visibility.
- **At 1M users: first pressure point is hot partitions in daily vector tables and conflict-heavy multi-device merges.**
  - **Refinement:** partition by month + hashed user shard key, and precompute deterministic merge materializations incrementally.

### 10) Concrete Refinement Actions (Phase 1 only)

- Add explicit invariants and reject-write conditions (below) as normative contract.
- Add lifecycle and failure guarantees (below) to eliminate scheduler/permission ambiguity.
- Add cryptographic assumptions and AAD binding rules (below) to harden envelope integrity.
- Add deterministic conflict precedence tuple and deletion-write exclusion rule to sync contract.
- Add canonical numeric policy (summation order + quantization + residual assignment) to remove cross-platform drift.

## Explicit Phase 1 Invariants (Normative)

1. **Identity vector invariants**
   - Post-normalization `priorityWeights` must satisfy: all components `>= 0`, deterministic key order (`learning`, `building`, `social`, `health`), and exact sum `1.0` after residual assignment.
   - If all user-provided weights are non-positive, persist fallback `[0.25, 0.25, 0.25, 0.25]` and set `invalid_declaration` flag.

2. **Feature invariants**
   - `DailyBehaviorFeatures.categoryDistribution` must sum to `1.0 ± 1e-6` when `totalActiveMinutes > 0`, else all zeros.
   - `fragmentationIndex`, `lateNightUsageRatio` must remain within `[0,1]`; out-of-range computation is a hard extraction failure.
   - Each day has at most one committed derived feature record per `(user_id, device_id, local_date_bucket, schema_version)`.

3. **Purge invariants**
   - Raw logs are purge-eligible only after durable commit of derived record + checksum + extraction receipt.
   - No sync/export path may read raw logs.
   - Raw logs older than TTL must be deleted on first foreground after TTL breach, regardless of scheduler status.

4. **Sync invariants**
   - Mutating sync operations are rejected when account state is `deletion_pending`.
   - Conflict resolution precedence is deterministic and stable: (`declarationVersion`, `client_logical_counter`, `server_receive_order`).
   - Idempotency key reuse with payload mismatch is a hard reject.

5. **Schema invariants**
   - Cross-version arithmetic is forbidden unless a deterministic migration function is defined and version-pinned.
   - Checksums must cover schema version and mapping config version to prevent semantic collisions.

## Explicit Lifecycle Guarantees

1. **Capture-to-extract guarantee**
   - On every app foreground, system performs: permission re-check -> TTL enforcement -> extraction catch-up for missed days (bounded work budget).

2. **Extraction guarantee**
   - Extraction is deterministic for identical input logs, mapping version, timezone offset capture policy, and schema version.
   - Extraction must be restart-safe via persisted continuation cursor and idempotent day commit semantics.

3. **Permission-state guarantee**
   - Permission revocation immediately halts new capture and emits `permission_missing` quality artifacts; existing derived history remains readable.

4. **Deletion lifecycle guarantee**
   - Local wipe acquires `deletion_lock`, clears local encrypted stores and auth material, and blocks new local writes until completion marker is durable.
   - Cloud deletion request transitions account to `deletion_pending` before backend hard-delete workflow begins.

5. **Sync lifecycle guarantee**
   - Sync batches produce per-item commit receipts; retries resume from first unacknowledged item without reordering acknowledged items.

## Explicit Failure Mode Guarantees

1. **Extractor crash guarantee**
   - No partial derived writes are visible; either full day commit succeeds or day remains pending retry.

2. **Corruption guarantee**
   - Corrupted partitions are isolated by date bucket; healthy partitions remain readable.
   - Restore replay is monotonic by sequence ID to prevent duplicate or out-of-order recomputation.

3. **Network/backend outage guarantee**
   - Local deterministic pipeline (declaration, extraction, drift, weekly deterministic insight) remains fully functional without cloud availability.

4. **AI renderer failure guarantee**
   - Deterministic template summary is always produced from approved derived fields; no pipeline step depends on AI response for completion.

5. **Clock anomaly guarantee**
   - Records with retrograde jumps beyond defined threshold are quarantined and excluded from scoring until manual/automatic repair.

## Explicit Cryptographic Assumptions & Constraints

1. **Envelope encryption assumptions**
   - Payload encryption uses AES-256-GCM per record with unique nonce per encryption event.
   - AAD must bind: `user_id`, `device_id`, `date_bucket`, `schema_version`, `category_map_version`, `ciphertext_hash`.

2. **Key management assumptions**
   - DEKs are device-local ephemeral data keys used only for payload class scope; KEK wrapping keys are never persisted in plaintext application storage.
   - Key rotation triggers: logout, compromise signal, refresh replay detection, scheduled epoch rollover.

3. **Token/session assumptions**
   - Access JWT is short-lived and non-revocable by design; refresh token family enforces one-time-use rotation with replay invalidation.
   - Concurrent refresh requests for same token family must deterministically accept one and invalidate remainder.

4. **Replay resistance constraints**
   - Idempotency keys are single-use within TTL and bound to canonical payload hash + route + actor identifiers.
   - Replayed request with mismatched payload hash must be rejected and audited.

5. **Export/deletion confidentiality constraints**
   - Export artifacts require short-lived signed URLs and single-download invalidation where platform allows.
   - Deletion/export status endpoints must return uniform error envelopes to avoid account enumeration.

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