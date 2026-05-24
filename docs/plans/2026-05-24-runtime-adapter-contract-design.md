# Runtime Adapter Contract Design

## Goal

Define the public, host-independent contract a runtime execution plugin can
advertise before `workflow-compute` moves concrete executors into plugin repos.
The contract should let hosts compare adapter capability, workspace policy,
runtime descriptor identity, workload kinds, and conformance evidence without
leaking server-owned task, lease, mount, network binding, or verifier state.

## Design

`RuntimeAdapterContract` is a declaration, not an execution API. It includes
the compute protocol version, adapter ID, runtime descriptor, adapter kinds,
supported workload kinds, optional runtime profiles, workspace policy,
conformance profiles, residue policy, optional provider config, and metadata.

`RuntimeAdapterKind` separates short-lived execution, one-shot service run, and
long-lived service session support. `RuntimeWorkspacePolicy` is explicit because
some workloads, especially WASM-style adapters, may not have a workspace.
Service adapter kinds must declare `service` or `node-service` workload support
so a plugin cannot advertise long-lived service capability for only command-like
workloads.

`RuntimeDescriptor.Validate` is added so adapter contracts can validate runtime
identity, security tier, proof tier, and non-native image/rootfs digest
requirements before a host accepts a plugin declaration.

## Assumptions

- A declaration contract is the right next step before moving executor process
  code out of `workflow-compute`.
- Runtime plugins can describe capability with workload kinds and adapter kinds
  while the host still decides task authorization, lease state, workspace
  mounts, network capability, and proof verification.
- Residue policy may describe reusable non-workspace state, so workspace policy
  must not blindly reject all residue for workspace-less adapters.

## Rollback

Rollback is reverting the additive adapter contract types and keeping
`workflow-compute` executor capability discovery local. No persisted state or
wire format migration is introduced by this slice.

## Self-Challenge

- Laziest solution: rely on `ProviderRuntimeContract` only. Rejected because it
  describes provider runtime profiles, not what an executor plugin adapter can
  register or whether it supports service sessions.
- Fragile assumption: adapter kinds are enough for the first plugin boundary.
  The mitigation is that execution payloads remain in `RuntimeExecutionRequest`
  and host-only capability handles stay out of compute-core.
- Security risk: plugin metadata could be mistaken for authorization. The
  contract is declarative only; hosts must keep authorization and lease checks
  local.
