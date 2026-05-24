# Runtime Executor Contracts Design

## Goal

Move the smallest runtime execution boundary that provider plugins need into
`workflow-plugin-compute-core`: executor identity, proof-relevant runtime
metadata, and resource usage/limit evidence. This supports future runtime
plugins without forcing `workflow-compute` host internals such as leases,
workspace paths, network bindings, or process supervision into the public core
contract.

## Design

`RuntimeDescriptor` is the public descriptor shape a runtime provider can
advertise. It carries provider name, version, execution security tier, proof
tier, and optional image/rootfs digests. It can produce an `ExecutorRef`, which
is the proof-facing executor identity already used by `workflow-compute`.

`ExecutorRef` moves with its `ValidateForProof` and attestation requirement
helpers so proof validation and runtime advertisement share one contract.

`ResourceUsage` and `ResourceLimits` become compute-core contracts because
runtime plugins need to report measured usage and receive hard limits without
depending on `workflow-compute` task execution structs.

## Assumptions

- Runtime plugins need shared metadata and evidence contracts before they need
  shared process execution APIs.
- `workflow-compute` remains responsible for host-only execution context:
  workspace preparation, lease authorization, network binding, and supervisor
  integration.
- Existing runtime providers can alias these contracts without changing
  behavior.

## Rollback

Rollback is reverting this contract addition and restoring local
`workflow-compute` type ownership. No stored data format changes are introduced
because the JSON field names intentionally match the existing
`workflow-compute` structs.

## Self-Challenge

- Laziest solution: leave these structs local until the runtime plugin repos
  exist. Rejected because provider plugins already need a stable advertised
  runtime and proof evidence shape.
- Fragile assumption: `RuntimeDescriptor` may need workload-kind or network
  mode declarations later. Those are intentionally left in
  `ProviderRuntimeProfile` and provider contracts for now to avoid duplicating
  catalog policy.
- Partial failure risk: moving execution request structs too early would expose
  host workspace and network internals as public API. This slice explicitly
  avoids that.
