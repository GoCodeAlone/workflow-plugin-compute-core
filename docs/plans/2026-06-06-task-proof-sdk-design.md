# Task and Proof SDK Design

## Goal

Expose the portable task, lease, proof-listing, and minimal HTTP client
contracts in `workflow-plugin-compute-core/protocol` so public Workflow plugins
can submit compute tasks and observe proof receipts without importing the
private `workflow-compute/pkg/protocol` package.

This is Phase 1 of the public distributed-compute platform roadmap. It removes
the immediate private-protocol dependency blocker for `workflow-plugin-product-capture`
while keeping `workflow-compute` as the managed product assembly that owns
scheduling, task mutation, agent supervision, settlement, dashboards, and
deployment policy until a later reusable control-plane component is designed and
extracted.

## Global Design Guidance

Source: `README.md`

| Guidance | Design response |
|---|---|
| Compute-core is the public Go module for compute protocol and provider catalog contracts. | Add wire contracts and client helpers to `protocol`, not app behavior. |
| Workflow applications should treat declarations as portable provider-facing base contracts. | Define task/proof request and response shapes that external plugins can compile against. |
| Application-specific scheduling, task state, settlement, dashboards, and worker supervision remain outside compute-core. | Do not add scheduler queues, admin APIs, dashboard models, worker registration, service leasing methods, or settlement helpers here; future reusable control-plane extraction must be its own phase/component. |

## Approaches Considered

1. **Recommended: additive public SDK in compute-core.** Add task/lease/status
   structs, public response wrappers, and a minimal HTTP client that only
   covers task submission, task listing/snapshot, proof listing, and proof
   lookup. This satisfies product-capture and preserves the private app
   boundary.
2. **Types only, no client.** This is smaller but leaves each plugin copying
   HTTP auth, strict decoding, response wrappers, and timeout behavior. That is
   the current product-capture problem in a different file.
3. **Full control-plane SDK.** This would centralize more code, but it would
   move scheduler/agent/admin concerns into compute-core prematurely and blur
   the public product boundary.

## Design

Add a new public protocol surface:

- `TaskStatus` constants matching the existing wire values.
- `Task` with only the current portable JSON fields: protocol version,
  product/org/pool/policy IDs, status, workload, placement/proof/network/access
  policies, residue/resource limits, input hash, requested time, timeout,
  labels, and signature.
- `Lease` for the task-agent wire contract, including capability snapshot,
  executor, network/P2P/residue policies, and lease timestamps.
- `TaskStall`, legacy `TaskList`, and additive `TaskListWithSummary` response
  wrappers for `/v1/tasks`.
- `TaskResponse`, legacy `ProofList`, and additive `ProofListWithSummary`
  response wrappers for `/v1/tasks` and `/v1/proofs`.
- `Client` with `SubmitTask`, `ListTasks`, `ListTasksWithSummary`,
  `TaskSnapshot`, `ListProofs`, `ListProofsWithSummary`, and `FindProof`.

The client will be transport-thin. It will set bearer auth when configured,
require HTTPS for token-bearing non-loopback URLs, use `DecodeStrict`, and
return typed errors for unexpected status codes. It will not implement task
creation policy, retries, async watches, lease acquisition, worker
registration, admin endpoints, provider registration, or dashboard/settlement
views.

`workflow-compute` will consume these types in a follow-up PR by aliasing its
public protocol package to compute-core where the wire shape is identical.
`workflow-plugin-product-capture` will then switch imports to compute-core in a
later downstream phase and use the public client.

Long-term, GoCodeAlone may extract a reusable control plane that other managed
products can assemble. This SDK is intentionally narrower: it supplies the
shared wire contract that such a control plane would also consume, without
deciding that control plane's storage model, scheduling policy, deployment
shape, authz chain, or operational UI.

## Security Review

- Auth token flow stays caller-owned; compute-core only places a configured
  token into `Authorization: Bearer`.
- Token-bearing clients reject non-HTTPS URLs unless the host is loopback.
- Strict JSON decode rejects unrecognized response fields so plugins detect
  contract drift early.
- The client does not log token values, request bodies, task payloads, or proof
  payloads.
- Server-side authorization remains in `workflow-compute`; client-side config
  is not treated as authority.

## Infrastructure Impact

This phase changes only the public Go module. It creates no cloud resources,
secrets, databases, queues, migrations, deployment environments, or runtime
processes. Release impact is limited to a compute-core tag after the PR merges.

No staging deployment is required for the compute-core PR by itself. The
follow-up `workflow-compute` consumer PR must refresh staging and run a real
product-capture-compatible submission/proof smoke because that PR changes the
managed app assembly.

## Multi-Component Validation

The compute-core PR must prove:

- `protocol.Task` and `protocol.Lease` validate representative real task/agent
  wire shapes.
- The HTTP client crosses a real `httptest.Server` boundary for submit, list,
  snapshot, proof list, auth header, strict decode, and status errors.
- A downstream compatibility check can compile the product-capture client
  shape against compute-core types without importing `workflow-compute`.

The follow-up app PR must prove:

- `workflow-compute` aliases or delegates matching types to compute-core
  without changing API JSON.
- product-capture can compile against the public contract.
- staging accepts a product-capture-style workload from registered local agents
  and returns a proof or explicit typed failure.

## Assumptions

- The existing `/v1/tasks` and `/v1/proofs` JSON response shapes are intended
  public surfaces for plugins.
- Product-capture needs task submission and proof lookup, not agent lease
  acquisition.
- `Lease` belongs in compute-core as a public wire type, but lease acquisition
  methods are a later agent SDK concern.
- Existing host validation remains stricter than compute-core portable
  validation where policy decisions require server state.

## Self-Challenge

1. The laziest solution is to keep product-capture copying its private client
   and only switch type imports. That reduces code movement now but repeats
   auth/strict-decode drift across every future workload plugin.
2. The fragile assumption is that `/v1/tasks` and `/v1/proofs` are stable enough
   for public clients. The plan must add drift tests in `workflow-compute` before
   downstream live usage.
3. The main YAGNI risk is adding leasing/admin methods. This design excludes
   them and records them as a deferred agent SDK concern.

## Backport 2026-07-14: Complete list wrappers

A live BMW staging proof disproved the assumption that testing only the list
items was sufficient for strict clients. The control plane also returns typed
`summary` objects from `/v1/tasks` and `/v1/proofs`; omitting either summary from
compute-core makes `DisallowUnknownFields` reject an otherwise compatible
response before any task can run.

Invariant: every strict list-response client must model and test the complete
server-owned wrapper, including additive typed summary fields, while continuing
to reject fields outside that declared contract.

Compatibility invariant: complete envelopes use additive `WithSummary` types
and methods; existing exported wrappers and method signatures retain their
source shape and zero-value JSON encoding.

## Rollback

Rollback the compute-core PR by reverting the additive public SDK commit and
tagging no release. Because no downstream app code is changed in this PR, no
server deployment rollback is needed.

If a compute-core tag has already been published, publish a patch tag that
removes or marks the SDK unstable, then keep `workflow-compute` pinned to the
previous known-good compute-core version until the replacement tag is verified.

## Deferred Issues

- Switch `workflow-compute` to compute-core aliases/delegates in the next PR.
- Switch `workflow-plugin-product-capture` imports and docs after the
  `workflow-compute` consumer PR verifies API compatibility.
- Add lease acquisition, worker registration, and resilient agent upgrade APIs
  to the future public agent plugin phase, not this SDK.
- Design reusable control-plane extraction as its own future platform phase,
  not as an expansion of compute-core's protocol/client package.
- Keep live staging refresh/local-agent registration evidence in the
  `workflow-compute` consumer phase where the server actually changes.
