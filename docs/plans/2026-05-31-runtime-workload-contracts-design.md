# Runtime Workload Contracts Design

## Goal

Expose the command and container-build workload payload contracts in
`workflow-plugin-compute-core/protocol` so public runtime plugins can decode and
validate the same input shape that `workflow-compute` currently sends through
`RuntimeExecutionRequest.Input`.

This is the prerequisite phase for workflow-compute RTE-1
`workflow-plugin-compute-container`: without these contracts, the public plugin
would have to copy host-local workload structs and validation before the
in-core runtime fallback can be deleted.

## Boundary

Compute-core owns only host-independent payload contracts:

- `EnvRef`
- `ConfidentialPayloadRef`
- `CommandWorkload`
- `ContainerBuildWorkload`

The host keeps task admission, lease authorization, secret resolution,
workspace path resolution, network policy binding, registry allowlists, proof
verification, and reward/proof mutation.

## Validation

Validation mirrors the current host contract:

- command workloads require args, validate env refs, scoped artifact refs, and
  optional confidential payload metadata;
- container-build workloads require context directory and tags, validate env
  refs, and carry registry target refs without deciding whether they are
  allowed;
- env refs may point to a value or a secret, not both.

## Rollback

Rollback removes the additive compute-core types and keeps the equivalent
payload contracts local in `workflow-compute`. No persisted data migration is
introduced.
