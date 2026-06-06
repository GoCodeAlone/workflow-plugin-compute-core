### Alignment Report

**Status:** PASS

**Coverage:**

| Design Requirement | Plan Task(s) | Status |
|---|---|---|
| Expose portable task, lease, proof-listing, and minimal HTTP client contracts | Task 1, Task 2, Task 3, Task 4 | Covered |
| Remove immediate private-protocol dependency blocker for product-capture | Task 5 | Covered |
| Keep scheduling, task mutation, agent supervision, settlement, dashboards, and deployment policy outside compute-core | Task 5, Scope Manifest out-of-scope | Covered |
| Future reusable control plane must be its own phase/component, not compute-core expansion | Scope Manifest out-of-scope, Successor Hand-Off item 5 | Covered |
| Add `TaskStatus`, `Task`, `Lease`, wrappers, and client methods named in design | Task 1, Task 2, Task 3, Task 4 | Covered |
| Token-bearing clients reject non-HTTPS non-loopback URLs | Task 3, Task 4 | Covered |
| Strict decode and typed status errors without response-body leakage | Task 3, Task 4 | Covered |
| Prove HTTP boundary with `httptest.Server` | Task 3, Task 4 | Covered |
| Prove exact product-capture public symbol surface | Task 5 | Covered |
| No infra/staging action in compute-core PR; staging belongs workflow-compute consumer phase | Scope Manifest, Successor Hand-Off | Covered |
| Rollback by reverting additive SDK before release; tag rollback only if published | Successor Hand-Off, Final PR Verification | Covered |

**Scope Check:**

| Plan Task | Design Requirement | Status |
|---|---|---|
| Task 1 | Public task/lease contract tests and representative wire validation | Justified |
| Task 2 | Public `TaskStatus`, `Task`, `Lease`, and portable validation | Justified |
| Task 3 | HTTP client tests for auth, strict decode, status errors, and proof/task endpoints | Justified |
| Task 4 | Transport-thin public client implementation | Justified |
| Task 5 | Product-capture compatibility proof and boundary documentation | Justified |

**Manifest Trace:**

- `PR Count: 1` matches the single PR Grouping row.
- `Tasks: 5` matches `### Task 1` through `### Task 5`.
- Every task appears exactly once in the PR Grouping table.
- `plan-scope-check.sh --plan <absolute plan path>` returned `PASS: scope-manifest checks succeeded.`

**Drift Items:** None.
