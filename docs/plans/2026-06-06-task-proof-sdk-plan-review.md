### Adversarial Review Report

**Phase:** plan
**Artifact:** `docs/plans/2026-06-06-task-proof-sdk.md`
**Status:** PASS

**Findings (Critical):**
- None.

**Findings (Important):**
- None.

**Findings (Minor):**
- `P1` [Missing integration proof] [Task 5]: The compatibility proof is an in-repo symbol/shape test, not a full downstream product-capture repo compile. Recommendation: keep this as the compute-core PR proof, but require the actual product-capture import switch and live plugin proof in the successor phase. _Resolution: Successor Hand-Off explicitly requires product-capture compile proof and staging workload evidence._
- `P2` [Over-decomposition / under-decomposition] [Tasks 1-4]: TDD steps are larger than the ideal 2-5 minute slices because each task groups related tests. Recommendation: acceptable for this repo because the grouped tests cover one artifact class each; implementer should still commit after each task. _Resolution: accepted as review-size trade-off._
- `P3` [Rollback wiring] [Successor Hand-Off]: Release rollback is mentioned in the design, but this compute-core PR does not execute a release. Recommendation: do not tag from this PR until merged and green; release/tag remains successor work. _Resolution: Scope Manifest excludes release/tag and Successor Hand-Off gates it after merge._

**Bug-class scan transcript:**

| Class | Result | Note |
|---|---|---|
| Project-guidance conflicts | Clean | README boundary is preserved; app scheduling/admin/dashboard/settlement remain out of scope. |
| Assumptions under attack | Clean | Stable `/v1/tasks` and `/v1/proofs` assumption is deferred to workflow-compute drift tests before live usage. |
| Repo-precedent conflicts | Clean | Plan follows prior compute-core contract extraction pattern with protocol tests first. |
| Artifact-class precedent | Clean | Public protocol contracts and tests stay under `protocol/`. |
| YAGNI violations | Clean | Lease is a type only; no lease client methods or agent admin APIs are planned. |
| Missing failure modes | Clean | Plan tests HTTPS token guard, strict decode, status errors, missing task snapshot, malformed task, and malformed lease. |
| Security / privacy at architecture level | Clean | Token-bearing HTTP guard and status error no-body-leak test cover the client security edge. |
| Infrastructure impact | Clean | No infra, deployment, migration, queue, or secret changes in this PR. |
| Multi-component validation | Minor | `httptest.Server` crosses HTTP boundary; full downstream product-capture compile/live proof is successor work. |
| Rollback story | Clean | Additive PR can be reverted before release; release rollback is outside this PR. |
| Simpler alternative not considered | Clean | Types-only and full SDK alternatives were considered in the design. |
| User-intent drift | Clean | PR advances public reusable compute platform without moving managed app behavior out of workflow-compute. |
| Existence / runtime-validity | Clean | Existing symbols verified by repo grep; new client targets real existing `/v1/tasks` and `/v1/proofs` paths. |
| Over-decomposition / under-decomposition | Minor | Tests are grouped by artifact class rather than per assertion. |
| Verification-class mismatch | Clean | Protocol types use unit tests; HTTP client uses real `httptest.Server`; docs use full suite and diff check. |
| Auth/authz chain composition | Clean | No server-side auth chain is implemented; client only carries bearer token. |
| Hidden serial dependencies | Clean | Tasks are intentionally serial; no parallel execution is claimed. |
| Missing rollback wiring | Minor | Release rollback is successor work, not PR work. |
| Infrastructure verification mismatch | Clean | No infra change. |
| Plugin-loader runtime layout | Clean | No plugin process is spawned or loaded. |
| Config-validation schema rules | Clean | No config/schema artifact is created. |
| Identifier / naming-convention match | Clean | Planned names match existing Go/exported-type conventions and product-capture imports. |

**Options the author may not have considered:**
1. Use a generated OpenAPI client from workflow-compute. This might produce stronger API drift checks later, but it would add generation/release complexity before the public contract is stable.
2. Put the client in `protocol/client` instead of `protocol`. This narrows package surface, but forces users to import two packages for a single task/proof workflow and diverges from existing protocol helper placement.

**Verdict reasoning:** PASS. The plan is scoped to one compute-core PR, contains a valid manifest, uses TDD, and keeps full workflow-compute/product-capture/staging proof as explicit successor work rather than silently claiming it here. User feedback that GoCodeAlone may eventually want a reusable control plane is incorporated as a future platform phase; this PR remains the lower-level task/proof wire SDK that such a control plane would consume.
