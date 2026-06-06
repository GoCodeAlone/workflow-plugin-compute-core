# Task Proof SDK Implementation Plan

> **For the implementing agent:** REQUIRED SUB-SKILL: Use autodev:executing-plans to implement this plan task-by-task.

**Goal:** Add the public task/proof SDK surface needed for external compute workload plugins to submit tasks and observe proof receipts without importing private workflow-compute packages.

**Architecture:** Additive protocol contracts and a transport-thin HTTP client live in `protocol/`. The SDK covers task/proof wire shapes only; workflow-compute keeps scheduling, task mutation policy, agent lifecycle, settlement, dashboards, and deployment.

**Tech Stack:** Go, `net/http`, `httptest`, existing `protocol.DecodeStrict`, existing workload/proof/policy structs.

**Base branch:** main

---

## Scope Manifest

**PR Count:** 1
**Tasks:** 5
**Estimated Lines of Change:** ~450

**Out of scope:**
- workflow-compute alias/delegate changes.
- product-capture import switch and BMW live usage docs.
- lease acquisition, worker registration, agent updater, scheduler/admin/dashboard/settlement APIs.
- reusable control-plane extraction or control-plane storage/scheduling/authz design.
- staging deployment or local-agent registration changes.

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | feat: add task proof sdk | Task 1, Task 2, Task 3, Task 4, Task 5 | feat/task-proof-sdk |

**Status:** Draft

## Requirements Trace

| Design requirement | Plan task |
|---|---|
| Public `TaskStatus`, `Task`, `Lease`, task/proof response wrappers | Task 1, Task 2 |
| Portable validation without scheduler/admin policy | Task 1, Task 2 |
| Transport-thin client for submit/list/snapshot/proof lookup | Task 3, Task 4 |
| HTTPS requirement for token-bearing non-loopback URLs | Task 3, Task 4 |
| Strict decode and typed status errors | Task 3, Task 4 |
| Product-capture compatibility symbol proof | Task 5 |
| No workflow-compute/app behavior in compute-core | Task 5 |

### Task 1: Task and Lease Contract Tests

**Files:**
- Create: `protocol/task_test.go`
- Modify: none

**Step 1: Write failing tests**

Add tests:

- `TestTaskValidatesPortableWorkloadContract`
  - Builds a queued provider task with `ProtocolVersion: protocol.Version`,
    workload kind `WorkloadProvider`, a product-capture-style
    `ProviderWorkload`, input hash, requested time, positive timeout, and
    signature.
  - Expects `task.Validate()` to return nil.
- `TestTaskRejectsMalformedPortableContract`
  - Uses wrong protocol version, unknown status, missing IDs, invalid workload,
    negative timeout, and invalid resource limits.
  - Expects the error string to include `protocol_version`, `status`,
    `org_id`, `workload`, `timeout_seconds`, and `resource_limits`.
- `TestLeaseValidatesAgentWireContract`
  - Builds a lease with task/worker/pool IDs, executor provider/version,
    capability OS/arch, network policy, residue policy with session key,
    explicit worker binding, policy hash, and valid timestamps.
  - Expects `lease.Validate()` to return nil.
- `TestLeaseRejectsMalformedAgentWireContract`
  - Uses missing IDs, missing executor provider/version, missing capability
    OS/arch, bad residue policy, and `ExpiresAt` before `LeasedAt`.
  - Expects the error string to include `executor.provider`,
    `capability_snapshot.os`, `residue_policy`, and `expires_at`.

**Step 2: Verify RED**

Run:

```bash
GOWORK=off go test ./protocol -run 'Test(TaskValidatesPortableWorkloadContract|TaskRejectsMalformedPortableContract|LeaseValidatesAgentWireContract|LeaseRejectsMalformedAgentWireContract)' -count=1
```

Expected: FAIL because `Task`, `TaskStatus`, `Lease`, and validation methods are not defined.

**Step 3: Commit tests**

```bash
git add protocol/task_test.go
git commit -m "test: cover public task lease contracts"
```

### Task 2: Public Task and Lease Contracts

**Files:**
- Modify: `protocol/types.go`
- Test: `protocol/task_test.go`

**Step 1: Implement minimal contracts**

Add:

- `TaskStatus` constants: queued, leased, running, succeeded, failed, stalled,
  canceled.
- `Task` struct with the JSON shape from the design.
- `Task.Validate() error`.
- `Lease` struct with the JSON shape from the design.
- `Lease.Validate() error`.

Validation rules:

- `Task.ProtocolVersion` must equal `Version`.
- `Task.ID`, `OrgID`, `PoolID`, and `PolicyID` are required.
- `Task.Status` may be empty or one of the public constants.
- `Task.Workload.Validate()` must pass.
- `Task.Requirements`, proof/network/access/residue/resource policies validate
  through existing helpers where available.
- `Task.RequestedAt` is required.
- `Task.TimeoutSeconds` must be positive.
- `Task.Signature` is shape-carried only; server-side signature trust remains
  out of scope.
- `Lease` requires IDs, executor provider/version, capability OS/arch, valid
  network/P2P/residue policies, and `ExpiresAt` after `LeasedAt`.

**Step 2: Verify GREEN**

Run the Task 1 command again.

Expected: PASS.

**Step 3: Verify invariant**

Temporarily remove the `Task.Status` validation or the `Lease.ExpiresAt`
validation, rerun the focused command, and confirm the matching malformed test
fails. Restore the validation and rerun to PASS.

**Step 4: Commit implementation**

```bash
git add protocol/types.go protocol/task_test.go
git commit -m "feat: add public task lease contracts"
```

### Task 3: HTTP Client Contract Tests

**Files:**
- Create: `protocol/client_test.go`
- Modify: none

**Step 1: Write failing tests**

Add tests using `httptest.Server`:

- `TestClientSubmitTaskUsesStrictJSONAndBearerAuth`
  - Server expects `POST /v1/tasks`, `Authorization: Bearer test-token`, and
    JSON task body.
  - Server responds `201 {"task": <task>}`.
  - Expects returned task ID to match.
- `TestClientListSnapshotAndProofLookup`
  - Server handles `GET /v1/tasks` returning `{"tasks":[...],"stalls":[...]}`.
  - Server handles `GET /v1/proofs` returning `{"proofs":[...]}`.
  - Expects `ListTasks`, `TaskSnapshot`, `ListProofs`, and `FindProof` to use
    those responses.
- `TestClientRejectsTokenOverNonLoopbackHTTP`
  - Expects `NewClient(ClientConfig{ServerURL:"http://example.test", Token:"x"})`
    to fail.
- `TestClientStatusErrorDoesNotExposeBody`
  - Server returns non-201 with a response body containing a sentinel secret.
  - Expects `StatusError` with method/path/status and no sentinel secret in
    `Error()`.
- `TestClientStrictDecodeRejectsUnknownFields`
  - Server responds with an unknown field in the task wrapper.
  - Expects decode failure.

**Step 2: Verify RED**

Run:

```bash
GOWORK=off go test ./protocol -run 'TestClient(SubmitTaskUsesStrictJSONAndBearerAuth|ListSnapshotAndProofLookup|RejectsTokenOverNonLoopbackHTTP|StatusErrorDoesNotExposeBody|StrictDecodeRejectsUnknownFields)' -count=1
```

Expected: FAIL because client config, client methods, wrappers, and status error are not defined.

**Step 3: Commit tests**

```bash
git add protocol/client_test.go
git commit -m "test: cover public task proof client"
```

### Task 4: Public Task Proof Client

**Files:**
- Create: `protocol/client.go`
- Modify: `protocol/client_test.go`
- Test: `protocol/client_test.go`

**Step 1: Implement minimal client**

Add:

- `ClientConfig{ServerURL string, Token string, HTTPClient *http.Client, Timeout time.Duration}`.
- `Client`.
- `NewClient(ClientConfig) (*Client, error)`.
- `StatusError{Method string, Path string, StatusCode int}`.
- `TaskResponse`, `TaskList`, `TaskStall`, and `ProofList`.
- `SubmitTask(ctx context.Context, task Task) (Task, error)`.
- `ListTasks(ctx context.Context) (TaskList, error)`.
- `TaskSnapshot(ctx context.Context, id string) (Task, bool, []TaskStall, error)`.
- `ListProofs(ctx context.Context) ([]ProofReceipt, error)`.
- `FindProof(ctx context.Context, taskID string) (ProofReceipt, bool, error)`.

Client rules:

- `ServerURL` must be absolute `http` or `https`.
- Token-bearing non-loopback URLs must use `https`.
- Default timeout is 30 seconds when no HTTP client or timeout is supplied.
- Request bodies use JSON and set `Content-Type: application/json`.
- Token config sets `Authorization: Bearer <token>`.
- Responses decode with `DecodeStrict`.
- Non-expected status returns `StatusError` without reading or exposing the body.

**Step 2: Verify GREEN**

Run the Task 3 command again.

Expected: PASS.

**Step 3: Verify invariant**

Temporarily remove the HTTPS guard and rerun
`TestClientRejectsTokenOverNonLoopbackHTTP`; confirm FAIL. Restore the guard and
rerun to PASS.

**Step 4: Commit implementation**

```bash
git add protocol/client.go protocol/client_test.go
git commit -m "feat: add public task proof client"
```

### Task 5: Product-Capture Compatibility and Boundary Proof

**Files:**
- Create: `protocol/product_capture_compat_test.go`
- Modify: `README.md`
- Modify: `docs/plans/2026-06-06-task-proof-sdk-design.md` only if execution
  reveals a false assumption; do not change the Scope Manifest without an
  explicit amendment.

**Step 1: Write compatibility test**

Add `TestProductCapturePublicSDKSurface` in package `protocol_test` that builds
the exact public symbol surface product-capture needs:

- `protocol.WorkloadSpec`
- `protocol.WorkloadProvider`
- `protocol.ProviderWorkload`
- `protocol.ProviderConfig`
- `protocol.ProductCaptureModeBrowser`
- `protocol.Task`
- `protocol.TaskQueued`
- `protocol.SignatureEnvelope`
- `protocol.ProofReceipt`
- `protocol.VerificationAccepted`
- `protocol.TaskList`
- `protocol.TaskStall`
- `protocol.NewClient`

The test should validate a product-capture-style provider workload and task,
round-trip a `TaskList` with `json.Marshal`/`DecodeStrict`, and assert the
client constructor accepts an HTTPS URL.

**Step 2: Verify compatibility test**

Run:

```bash
GOWORK=off go test ./protocol -run TestProductCapturePublicSDKSurface -count=1
```

Expected: PASS after Tasks 2 and 4.

**Step 3: Update docs**

Update `README.md` to state that compute-core now includes portable task/proof
wire contracts and a minimal task/proof HTTP client, while scheduling, agent
lifecycle, settlement, dashboards, and worker supervision remain outside.

**Step 4: Full verification**

Run:

```bash
GOWORK=off go test ./protocol -count=1
GOWORK=off go test ./... -count=1
git diff --check
```

Expected: all tests pass and diff check is clean.

**Step 5: Commit compatibility proof and docs**

```bash
git add protocol/product_capture_compat_test.go README.md docs/plans/2026-06-06-task-proof-sdk-design.md
git commit -m "docs: document task proof sdk boundary"
```

## Successor Hand-Off

After this compute-core PR is merged and green:

1. Open a workflow-compute PR that aliases/delegates matching task/proof/lease
   types to the released compute-core version and verifies JSON/API drift.
2. Run product-capture compile proof against the workflow-compute consumer PR.
3. Refresh staging and run a real product-capture-compatible workload through
   registered local agents.
4. Tag the next compute-core release only after the compute-core PR is merged
   and CI is green; update downstream pins in the workflow-compute consumer PR.
5. Plan reusable control-plane extraction as a later platform phase once the
   public task/proof, product-capture, scenarios, staging rollout, and
   reconnecting-agent phases have produced enough real-boundary evidence.

## Final PR Verification

Before PR creation:

```bash
GOWORK=off go test ./protocol -count=1
GOWORK=off go test ./... -count=1
git diff --check
```

Expected: all commands exit 0.
