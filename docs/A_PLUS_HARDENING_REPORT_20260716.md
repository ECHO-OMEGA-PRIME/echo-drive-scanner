# Intelligent Drive Scanner v2.1 — A+ Hardening Report

**Date:** 2026-07-16
**Repository:** `C:\Users\bobmc\echo-drive-scanner`
**Starting commit:** `769f7f455e86b97d246ba2bb0cbe4d357fbc444e`

## Verdict

The governed scanner service and its security-critical integration surface pass the repository A+ quality gate. This does not certify Echo Desktop integration, physical SMART/device health, or destructive storage actions. Desktop integration still depends on its main-process Capability Policy Broker and deployment of the v2.1 schemas to the central SDK registry.

## Verification

| Gate | Result |
|---|---:|
| Python compilation | PASS |
| Dependency integrity | PASS |
| Ruff repository scan | PASS |
| Critical-surface mypy | PASS |
| Full unit/contract suite | **86 passed** |
| Security-critical branch coverage | **90.97%** |
| Enforced coverage floor | **85%** |
| Live staged scan/API smoke | **25/25 passed** |
| Dependency vulnerability audit | No known vulnerabilities |
| Deterministic quality gate | PASS |
| Live local service | v2.1.0 / healthy |
| Live FORGE SDK proposal dispatch | PASS |
| Live absolute-path redaction | PASS |

## Primary evidence

- `artifacts/quality/quality-gate-report.json`
- `artifacts/quality/quality-gate-report.sha256`
- `artifacts/quality/*.log`
- `artifacts/critical-coverage.json`
- `contracts/sdk_capability_schemas.json`

## Delivered upgrades

1. Exact trusted-client IP enforcement.
2. Optional constant-time internal service token.
3. Bounded request size.
4. Request IDs on all responses.
5. Expanded CSP, CORP, COOP, and security headers.
6. Strict mutation contracts with unknown-field rejection.
7. Path count, length, and duplicate-root validation.
8. Explicit profile validation.
9. Configurable bind host and port.
10. Exact FORGE Tailscale client configuration.
11. Protected personal, memory, and vault roots.
12. Durable scan IDs before background execution.
13. One authoritative database shared by API and orchestrator.
14. One-active-scan concurrency gate.
15. Run-specific status endpoint.
16. Run-specific stage endpoint.
17. Run-specific cancellation endpoint.
18. Persisted stage outcomes.
19. Truthful warning/degraded terminal states.
20. Fixed Python AST argument extraction.
21. Complete positional-only, varargs, keyword-only, and kwargs signatures.
22. Immutable per-scan file observations.
23. Immutable per-scan score observations.
24. Duplicate-cluster scan ownership.
25. Consistent latest-completed-scan resolution.
26. Redacted file DTOs.
27. Removal of content samples from public responses.
28. Opaque path fingerprints and protected flags.
29. Redacted proposal source evidence.
30. Redaction of absolute paths embedded in proposal prose.
31. Removal of scanner-side queue mutation.
32. Removal of sovereign-key use from the service.
33. Rejection of legacy `queue=true` side effects.
34. Filesystem-capacity summary endpoint.
35. Explicit unknown health when SMART telemetry is unavailable.
36. Accurate scan counts and subsystem health.
37. WebSocket access enforcement.
38. Quarantine partial-failure protection.
39. Versioned `api_version=2.1` envelopes.
40. Strict SDK input/output schema manifest.
41. Deterministic one-command quality gate.
42. Runtime dependency integrity gate.
43. Repository-wide Ruff enforcement.
44. Critical-surface mypy gate.
45. Strict warning handling with the supported test client.
46. Enforced 85% security-critical branch coverage.
47. Expanded 25-check live smoke test.
48. Dependency vulnerability audit.
49. Credential-free Git remote.
50. Hash-complete quality evidence.

## Live proof

The final service reported version `2.1.0`, API contract `2.1`, status `healthy`, and the exact persisted scan count. Loopback access succeeded, a non-trusted HAMMER Tailscale request was denied, and the FORGE SDK call succeeded. The live proposal response replaced an absolute directory with an opaque `[path:...]` identity and returned redacted evidence paths.

## Transparent remaining debt

### Full legacy coverage

The full-repository baseline measured **34.65%** because several large legacy or optional intelligence modules have little or no test coverage. The enforced 85% threshold applies to the governed security-critical boundary, which measured **90.97%**. The report does not represent 90.97% as whole-repository coverage.

### Full legacy typing

A full mypy scan identified **66 legacy errors**, concentrated in older classifier, engine-client, content-sampler, and model-adapter paths. The changed governed boundary is clean under its enforced mypy gate. The legacy errors require a separate compatibility/refactor phase.

### Central SDK registry

The repository contains strict v2.1 schemas for all current Drive Scanner capabilities plus the storage-summary contract. The governed database mutation lane was blocked before execution, so no unapproved fallback was used.

Required central deployment:

- point `echo.drivescan.scan` to `/api/scan/start`;
- deploy strict input and output schemas from `contracts/sdk_capability_schemas.json`;
- register `echo.drivescan.storage`;
- replace TCP/schema-only health with real response validation.

### Deliberately blocked features

- No destructive delete capability is exposed.
- Reclaim/quarantine remains unavailable to Echo Desktop until exact hashes, signed approval, restore support, and post-action verification exist.
- Queue insertion belongs to the Echo Desktop main-process broker, not this scanner.
- Certification controls remain disabled until Certification Forge has a versioned production contract.

## Scoped final verdict

| Surface | Verdict |
|---|---|
| Governed scanner service core | **A+ GATE PASS** |
| Local and staged runtime | **PASS** |
| Security-critical contract implementation | **PASS** |
| Central SDK registry reconciliation | **PENDING GOVERNED DEPLOYMENT** |
| Echo Desktop integration | **CONDITIONAL — WAIT FOR DESKTOP P1 BROKER** |
| Destructive/reclaim actions | **BLOCKED** |
| Whole legacy intelligence codebase | **CONDITIONAL — DEBT RECORDED** |

## Certification Forge dependency status

Certification Forge P2 completed on `main` at commit `917df7594d6f152ecbdfd27d03eb2fc26fe7a2f6`, with local and remote parity verified. Its P2 foundation passed 40 tests, 88.36% branch coverage, and nine real FORGE hostile-execution cases. The complete Certification Forge product remains **NOT_READY** because production signing separation, external Merkle anchoring, worker-image supply-chain qualification, applied-adapter proof, central `echo.certforge.*` and `echo.builds.log` registration, exact-digest deployment enforcement, commercial/retention controls, and hosted CI root-cause resolution remain open. Echo Desktop P8C has not started.

This scanner report therefore does not claim downstream certification or Desktop readiness.
