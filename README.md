# workflow-plugin-compute-core

Public Workflow plugin and Go module for compute protocol and provider catalog
contracts.

Provider plugins use this module for shared JSON-compatible protocol types,
validation helpers, and canonical hashing. They also declare a plugin dependency
on `workflow-plugin-compute-core` in `plugin.json`, giving Workflow a registry
dependency anchor separate from runtime execution plugins.

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
