#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

./scripts/generate-proto.sh
export PATH="${PATH}:${HOME}/go/bin"
buf lint
git diff --exit-code -- proto protocol/pb descriptors
