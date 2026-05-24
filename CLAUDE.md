# CLAUDE.md — workflow-plugin-compute-core

External gRPC plugin and public Go module for compute protocol and provider
catalog contracts.

## Build & Test

```sh
go build ./...
go test ./... -v -race -count=1
```

## Cross-compile

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o workflow-plugin-compute-core ./cmd/workflow-plugin-compute-core/
```

## Structure

- `cmd/workflow-plugin-compute-core/main.go` — external plugin entrypoint
- `internal/plugin.go` — Workflow plugin manifest
- `protocol/types.go` — public compute protocol and provider catalog types
- `plugin.json` — registry-facing plugin manifest
- `.goreleaser.yaml` — GoReleaser v2 config for releases
- `.github/workflows/ci.yml` — build, test, vet, and plugin contract validation
- `.github/workflows/release.yml` — tagged release pipeline
