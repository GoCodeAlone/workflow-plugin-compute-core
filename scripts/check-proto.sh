#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

buf lint
./scripts/generate-proto.sh
git diff --exit-code -- proto protocol/pb descriptors
