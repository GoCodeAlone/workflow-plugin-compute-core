#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

export PATH="${PATH}:${HOME}/go/bin"

if ! command -v buf >/dev/null 2>&1; then
  GOWORK=off go install github.com/bufbuild/buf/cmd/buf@v1.47.2
fi

if ! command -v protoc-gen-go >/dev/null 2>&1; then
  GOWORK=off go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.11
fi

if ! command -v protoc-gen-go-grpc >/dev/null 2>&1; then
  GOWORK=off go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.6.1
fi

buf generate
mkdir -p descriptors
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
cat > "$tmpdir/write-network-audit-descriptor.go" <<'GO'
package main

import (
	"os"

	"github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	"google.golang.org/protobuf/proto"
)

func main() {
	data, err := (proto.MarshalOptions{Deterministic: true}).Marshal(protocol.NetworkAuditDescriptorSet())
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("descriptors/network_audit.pb", data, 0o644); err != nil {
		panic(err)
	}
}
GO
GOWORK=off go run "$tmpdir/write-network-audit-descriptor.go"
