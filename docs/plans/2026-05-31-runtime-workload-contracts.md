# Runtime Workload Contracts Plan

## Scope

Add the public command/container-build workload contracts needed before
`workflow-compute` can migrate RTE-1 runtime adapters into
`workflow-plugin-compute-container`.

## Tasks

1. Add failing protocol tests for command and container-build workload payloads.
2. Add public protocol types and validation in `protocol/types.go`.
3. Prove the tests fail when the production types are reverted and pass when
   restored.
4. Run the full compute-core suite.

## Deferred Issues

- `workflow-compute` still needs a follow-up PR to alias its local workload
  structs to compute-core after this module is released.
- `workflow-plugin-compute-container` repo creation and in-core fallback
  deletion remain in the RTE-1 phase after workflow-compute consumes the
  released compute-core contract.

## Verification

```bash
GOWORK=off go test ./protocol -run 'Test(CommandWorkloadContractUsesResolvedRefs|ContainerBuildWorkloadContractUsesRegistryRefs)' -count=1
GOWORK=off go test ./... -count=1
```
