### Adversarial Review Report

**Phase:** design
**Artifact:** `docs/plans/2026-06-06-task-proof-sdk-design.md`
**Status:** PASS

**Findings (Critical):**
- None.

**Findings (Important):**
- None.

**Findings (Minor):**
- `D1` [YAGNI violations] [Design]: `Lease` is not required by product-capture's immediate import switch. Recommendation: keep `Lease` as a wire type only, and keep lease acquisition/client methods out of this phase. _Resolution: already constrained by the design and Deferred Issues sections._
- `D2` [Missing failure modes] [Design]: client error taxonomy is named only as "typed errors"; the design does not say whether response bodies are bounded or surfaced. Recommendation: plan an explicit status error test that avoids leaking response bodies and captures status/method/path. _Resolution: plan task must include the test._
- `D3` [Existence / runtime-validity] [Multi-Component Validation]: downstream compatibility is stated, but the design does not name the exact product-capture import surface to compile. Recommendation: plan a temporary downstream compile proof covering `Task`, `TaskStatus`, `ProofReceipt`, `WorkloadSpec`, `ProviderWorkload`, `ProviderConfig`, `ProductCaptureMode`, `SignatureEnvelope`, and `DecodeStrict`/client replacement. _Resolution: plan task must enumerate these symbols._

**Bug-class scan transcript:**

| Class | Result | Note |
|---|---|---|
| Project-guidance conflicts | Clean | `README.md` keeps scheduling/task state/settlement/dashboard/supervision outside compute-core; design excludes those surfaces. |
| Assumptions under attack | Clean | The design names the stable `/v1/tasks` and `/v1/proofs` assumption and requires workflow-compute drift tests before live usage. |
| Repo-precedent conflicts | Clean | Prior compute-core plans add additive protocol types plus validation and defer workflow-compute consumption. |
| Artifact-class precedent | Clean | Sibling protocol contracts live under `protocol/` with tests in `protocol/*_test.go`; design follows that shape. |
| YAGNI violations | Minor | `Lease` is future-facing for agent interop, but constrained to a type without lease client methods. |
| Missing failure modes | Minor | Status error/body behavior needs explicit plan coverage. |
| Security / privacy at architecture level | Clean | HTTPS requirement for token-bearing non-loopback URLs and no token/body logging are explicit. |
| Infrastructure impact | Clean | Compute-core-only PR has no infra or runtime process impact; workflow-compute consumer phase owns staging. |
| Multi-component validation | Clean | Requires `httptest.Server` boundary and downstream product-capture compile proof. |
| Rollback story | Clean | Revert additive commit before release; patch tag/pin rollback if already released. |
| Simpler alternative not considered | Clean | Types-only and full control-plane SDK alternatives are considered and rejected. |
| User-intent drift | Clean | Design serves the requested public reusable platform boundary and product-capture compatibility. |
| Existence / runtime-validity | Minor | Needs exact downstream compile symbols in the plan. |

**Options the author may not have considered:**
1. Keep the client in product-capture and publish only task/proof types. This is smaller but preserves duplicated auth/strict-decode behavior across future plugins.
2. Publish client methods in a separate `client` package. That reduces `protocol` package breadth, but this repo already keeps protocol helpers such as canonical hashing and strict decode alongside contracts, so a small client is acceptable if it stays transport-thin.

**Verdict reasoning:** PASS. The design has no open Critical or Important issue. Minor findings are plan-level constraints: avoid lease methods, test status errors, and compile the exact product-capture symbol surface.
