# Runtime Execution Contracts Design

## Goal

Expose the public request/result shapes runtime plugins need without moving
`workflow-compute` host execution internals into compute-core. This is the next
step after runtime descriptor extraction: plugin authors can now share the same
invocation metadata, result evidence, resource usage, and service health
evidence while `workflow-compute` keeps lease authorization, workspace paths,
network binding, mounts, and supervisor integration local.

## Design

`RuntimeExecutionRequest` carries host-independent invocation metadata:
protocol version, task and lease IDs, workload kind, optional provider config,
operation, JSON input, environment values, and resource limits. It deliberately
does not include `Task`, `Lease`, workspace paths, mounted volumes, or network
callback functions.

`RuntimeExecutionResult` carries generic short-lived runtime output: timing,
exit code, stdout/stderr bytes, artifacts, result preview, artifact hash, and
resource usage.

`RuntimeServiceResult` carries service runtime health and response evidence:
timing, request/response hashes, resource usage, SLO evidence, and optional
status evidence. `SLOEvidence` and `ServiceStatusEvidence` move to compute-core
because service runtime plugins and hosts both need the same health contract.
Hashes in service status evidence are validated with the same canonical
`sha256:<64 hex chars>` shape as request and response evidence.

## Assumptions

- Runtime plugins need a stable public envelope before they need full host
  execution adapters.
- Runtime output may include bytes and previews, but host policy still decides
  retention, upload, signing, proof verification, and reward handling.
- Service health evidence is generic enough for compute-core; service leases,
  ingress claims, and durable session lifecycle remain host/application
  concerns for now.

## Rollback

Rollback is reverting these additive contracts and keeping the equivalent
runtime result/evidence structs local in `workflow-compute`. The JSON fields
match the existing host structs, so no state migration is introduced.

## Self-Challenge

- Laziest solution: keep only descriptors in compute-core. Rejected because a
  runtime plugin cannot be useful without a stable result and evidence shape.
- Fragile assumption: `RuntimeExecutionRequest` may be too generic for every
  runtime. The mitigation is that provider-specific payload stays in JSON
  `input`, while host-only capabilities stay out of the contract.
- Security risk: exposing env values could normalize secret passing through
  plugin contracts. This contract only describes already-resolved runtime env;
  secret resolution and authorization remain host-owned.
- Validation gap: status evidence has its own hashes. The contract validates
  those hashes so service health probes cannot accidentally emit ambiguous
  digest strings while request and response hashes remain strict.
