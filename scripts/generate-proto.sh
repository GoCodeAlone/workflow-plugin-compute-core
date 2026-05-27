#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

buf generate
mkdir -p descriptors
protoc -I proto --descriptor_set_out=descriptors/network_audit.pb workflow_plugin_compute_core/protocol/v1/network_audit.proto
