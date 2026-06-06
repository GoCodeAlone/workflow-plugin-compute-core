# workflow-plugin-compute-core

Public Workflow plugin and Go module for compute protocol and provider catalog
contracts.

Provider and workload plugins use this module for shared compute protocol data
types, provider-catalog data types, validation helpers, canonical hashing, and a
minimal task/proof HTTP client. They also declare a plugin dependency on
`workflow-plugin-compute-core` in `plugin.json`, giving Workflow a registry
dependency anchor separate from runtime execution plugins.

This is distinct from the Workflow plugin runtime contract: external plugins
still expose their runtime capabilities through Workflow's gRPC/protobuf plugin
service contracts. The provider-catalog structs in `protocol/` are the typed
declaration data that provider plugins publish and `workflow-plugin-compute`
validates.

The public contract includes task/proof/lease wire shapes, provider identity,
org/pool scoping, access visibility, supported workload and network modes,
runtime profiles, operation schemas, artifact declarations, residue policy, and
upstream client conformance evidence. Workflow applications should treat these
declarations as the portable provider-facing base contract.

The task/proof client covers submission and read-only observation:

- `SubmitTask`
- `ListTasks`
- `TaskSnapshot`
- `ListProofs`
- `FindProof`

Application-specific scheduling, task mutation policy, settlement, dashboards,
worker supervision, local-agent rollout, and control-plane storage/authz remain
outside this core plugin. Those concerns may be extracted into a reusable
control-plane component later, but they are not implemented by compute-core.

This plugin intentionally advertises no module, step, trigger, or IaC runtime
capabilities.

## Build & Test

```sh
go build ./...
go test ./... -race -count=1
```

## Release

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow validates `plugin.json`, builds cross-platform binaries
with GoReleaser, and verifies the runtime plugin manifest against the shipped
contract metadata.
