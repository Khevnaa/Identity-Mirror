# Identity Mirror Phase 1 — Invariant Enforcement Audit

Scope: enforceability audit only. This document maps invariants already defined in `README.md` to enforcement points/layers and required failure responses. No scope expansion.

## Enforcement Layer Legend

- **CT**: compile-time (types/static analysis)
- **RG**: runtime guard (application logic)
- **DB**: database constraint/index/check/trigger
- **TX**: transaction boundary
- **CB**: cryptographic binding (AAD/hash/signature)
- **LC**: logical contract only (currently unenforceable mechanically)

## A) Identity Vector Invariants

| Invariant | Primary enforcement point | Layer | Enforceable now? | Required mechanism | Failure response |
|---|---|---|---|---|---|
| Post-normalization weights non-negative | `client/modules/identity/identity.validation.ts` | RG | Yes | reject negative values before persist | block save + show validation error |
| Deterministic key order (`learning`,`building`,`social`,`health`) | `client/modules/identity/identity.types.ts` serialization path | RG + LC | Partially | canonical serialization function; do not rely on map iteration | reject serialization if unknown/missing keys |
| Exact sum `1.0` after residual assignment | `client/modules/identity/identity.validation.ts` | RG | Yes | deterministic residual-assignment algorithm + epsilon check | block save if invariant not met |
| All non-positive input -> fallback `[0.25,...]` + `invalid_declaration` flag | `IdentityDeclarationService.ts` persist path | RG | Yes | normalization branch with explicit status flag persisted | persist fallback and warning status |

## B) Feature Invariants

| Invariant | Primary enforcement point | Layer | Enforceable now? | Required mechanism | Failure response |
|---|---|---|---|---|---|
| `categoryDistribution` sums to `1.0 ± 1e-6` when `totalActiveMinutes>0` else all zero | `client/modules/extraction/FeatureExtractionEngine.ts` | RG | Yes | post-compute invariant assertion | mark extraction failed for day |
| `fragmentationIndex` and `lateNightUsageRatio` in `[0,1]` | `featureFormulas.ts` | RG | Yes | clamp only where spec allows; otherwise hard fail | `featureQualityFlag=low_data/no_data` only when applicable; else extraction error |
| At most one committed derived record per `(user_id,device_id,local_date_bucket,schema_version)` | local DB schema + server DB schema | DB + TX | Not fully | unique index on both local and server stores | reject duplicate commit; retry idempotently |

## C) Purge Invariants

| Invariant | Primary enforcement point | Layer | Enforceable now? | Required mechanism | Failure response |
|---|---|---|---|---|---|
| Purge only after durable derived commit + checksum + receipt | `EphemeralRawLogStore.ts` + extraction commit coordinator | TX + RG | Not fully | atomic transaction: derived write + receipt write + purge-ready marker | no purge on partial commit |
| No sync/export path reads raw logs | `SyncClient.ts`, `ExportService.ts`, server DTO validators | RG + LC | Partially | strict DTO schema excluding raw-log fields | reject request if raw timestamps/logs present |
| TTL hard delete on first foreground after breach | app foreground bootstrap path | RG | Yes | foreground TTL sweep job | immediate raw purge; log audit event |

## D) Sync Invariants

| Invariant | Primary enforcement point | Layer | Enforceable now? | Required mechanism | Failure response |
|---|---|---|---|---|---|
| Reject mutating sync when `deletion_pending` | `server/internal/middleware` + handlers | RG + DB | Yes | account state check before write routes | HTTP 409/423 semantic reject |
| Deterministic precedence tuple (`declarationVersion`,`client_logical_counter`,`server_receive_order`) | conflict resolver server-side | RG + DB | Not fully | persisted logical counter + stable receive sequence | deterministic winner selection |
| Idempotency key reuse with payload mismatch hard reject | API gateway/idempotency store | RG + DB | Yes | idempotency table keyed by `(actor,route,key)` with payload hash | HTTP 409 + security audit log |

## E) Schema Invariants

| Invariant | Primary enforcement point | Layer | Enforceable now? | Required mechanism | Failure response |
|---|---|---|---|---|---|
| No cross-version arithmetic without explicit migration | drift/extraction/sync services | RG + LC | Partially | version gate + migration registry | reject compute/sync with unsupported version |
| Checksum must include schema + mapping version | client checksum generator + server validator | CB + RG | Not fully | canonical checksum payload contract | reject payload checksum mismatch |

## F) Lifecycle Guarantees as Enforceable Contracts

| Contract | Primary enforcement point | Layer | Enforceable now? | Required mechanism | Failure response |
|---|---|---|---|---|---|
| Foreground sequence: permission re-check -> TTL enforcement -> catch-up extraction | app startup/foreground lifecycle hook | RG | Yes | ordered orchestration pipeline | skip downstream stage on failure and emit diagnostics |
| Extraction restart-safe + idempotent day commit | extractor job state store | TX + RG | Partially | continuation cursor + idempotent commit token | resume from cursor; no duplicate day writes |
| Permission revocation halts capture, emits `permission_missing` artifact | PermissionManager + adapters | RG | Yes | state machine transition + daily artifact emit | stop capture; lower-confidence outputs |
| Local wipe acquires `deletion_lock` and blocks writes until durable completion | local persistence coordinator | TX + RG | Not fully | global write lock + completion marker transaction | block writes; retry wipe |
| Sync batch receipts with ordered resume | SyncClient + server ack ledger | RG + DB | Not fully | per-item ack table with monotonic sequence | retry from first unacked item |

## G) Failure Guarantees as Enforceable Contracts

| Contract | Primary enforcement point | Layer | Enforceable now? | Required mechanism | Failure response |
|---|---|---|---|---|---|
| No partial derived writes visible on extractor crash | local DB transaction scope | TX + DB | Yes | transaction-per-day commit | rollback and mark pending |
| Corruption isolation by date bucket | encrypted DB partitioning | DB + RG | Partially | per-partition checksum and quarantine flag | isolate bucket, preserve others |
| Local pipeline works while backend offline | client modules only | RG + LC | Partially | strict offline-first dependency boundaries | queue sync; continue local outputs |
| AI failure never blocks deterministic summary | `AISummaryClient.ts` fallback path | RG | Yes | hard fallback to deterministic template | return deterministic narrative |
| Retrograde clock jumps quarantined from scoring | capture/extraction preprocessing | RG | Yes | timestamp anomaly detector + quarantine table | exclude from scoring + diagnostics flag |

## H) Cryptographic Assumptions / Constraints

| Constraint | Primary enforcement point | Layer | Enforceable now? | Required mechanism | Failure response |
|---|---|---|---|---|---|
| AES-256-GCM per record with unique nonce | encryption wrapper (`EncryptedDatabase.ts`, sync payload encryptor) | CB + RG | Yes | nonce uniqueness tracker per key | encryption abort + rotate key material |
| AAD binds `user_id`,`device_id`,`date_bucket`,`schema_version`,`category_map_version`,`ciphertext_hash` | client encrypt + server metadata validator | CB | Not fully | strict AAD schema and verify on decrypt/accept | reject ciphertext/metadata mismatch |
| KEK never persisted plaintext in app storage | key manager | RG + LC | Partially | keystore/keychain-only key handles | block startup of sync if unavailable |
| Rotation triggers: logout/compromise/replay/epoch | auth + key manager | RG + LC | Partially | key-epoch state machine and trigger hooks | rotate keys, invalidate sessions |
| Refresh token one-time family rotation with replay invalidation | Auth service | RG + DB | Yes | refresh family table + used-token marker | revoke family and force re-auth |
| Concurrent refresh: one winner only | Auth service refresh endpoint | TX + DB | Yes | compare-and-swap or serializable tx on family row | reject losers; security log |
| Idempotency single-use within TTL + payload hash binding | API gateway/idempotency store | DB + RG | Yes | unique index + TTL + stored hash | reject mismatch/replay |
| Export signed URL short TTL + single download (where possible) | Export service/object store policy | RG + LC | Partially | one-time token invalidation callback | expire URL; deny subsequent access |
| Uniform error envelopes to prevent account enumeration | all privacy status endpoints | RG | Yes | constant-structure errors + timing normalization | generic 404/401 response envelope |

## I) Required Database Artifacts (from invariants)

1. **Unique indexes**
   - `encrypted_behavior_vectors(user_id, device_id, date_bucket, schema_version)`.
   - `idempotency_keys(actor_id, route, idempotency_key)`.
   - `refresh_tokens(token_hash)` and/or `(family_id, rotation_counter)` for one-time rotation.

2. **Check constraints**
   - `schema_version > 0` and accepted-set checks.
   - Bounded metric checks where stored server-side (`fragmentation_index BETWEEN 0 AND 1`, etc., if denormalized).
   - `declaration_version >= 1` monotonicity enforced via write logic + optional trigger.

3. **Transaction boundaries**
   - Derived write + extraction receipt + purge-ready marker in one transaction.
   - Refresh token rotate-and-invalidate in one transaction.
   - Deletion state transition to `deletion_pending` before any delete worker actions.

4. **Idempotency persistence**
   - Store payload hash + terminal response snapshot + expiry timestamp.

5. **Schema-version rejection**
   - Server request middleware must reject unsupported request/response schema headers before handler logic.

## J) Currently Unenforceable / Logical-Contract-Only Items

These require process discipline unless implementation artifacts are added:

- Deterministic map key ordering if serialization bypasses canonical encoder (**LC risk**).
- “No sync/export raw-log reads” without strict type-level DTO segregation and runtime schema rejection (**partially enforceable**).
- “Offline pipeline fully functional” if future modules accidentally introduce online dependencies in extraction/drift paths (**LC risk**).
- KEK non-persistence if platform wrappers expose export APIs not disabled by policy (**partially enforceable**).
- Single-download export invalidation where storage backend lacks atomic first-read revoke primitive (**partially enforceable**).

## K) Minimum Enforcement Ownership Map

- **Client identity/extraction team**: deterministic rounding, normalization, feature bounds, purge transaction orchestration.
- **Client platform team**: lifecycle ordering, foreground TTL sweeps, permission churn handling, deletion lock.
- **Server API/auth team**: idempotency hash-binding, schema-version rejection, refresh race serialization.
- **Server data team**: unique indexes/check constraints/partition integrity.
- **Security team**: AAD contract, nonce uniqueness guarantees, key rotation triggers and audits.
