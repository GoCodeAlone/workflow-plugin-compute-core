#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

mode="public"
wfctl_version=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      mode="${2:?missing --mode value}"
      shift 2
      ;;
    --wfctl-version)
      wfctl_version="${2:?missing --wfctl-version value}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$wfctl_version" ]]; then
  echo "--wfctl-version is required" >&2
  exit 2
fi

if [[ "$mode" == "public" && -n "${WORKFLOW_REPO:-}" ]]; then
  echo "public mode must not use WORKFLOW_REPO" >&2
  exit 1
fi

run_wfctl() {
  if [[ "$mode" == "public" ]]; then
    GOWORK=off go run "github.com/GoCodeAlone/workflow/cmd/wfctl@${wfctl_version}" "$@"
    return
  fi
  if command -v wfctl >/dev/null 2>&1 && [[ "$(wfctl version 2>/dev/null | tr -d '[:space:]')" == "$wfctl_version" ]]; then
    wfctl "$@"
    return
  fi
  GOWORK=off go run "github.com/GoCodeAlone/workflow/cmd/wfctl@${wfctl_version}" "$@"
}

GOWORK=off go test ./protocol -run 'NetworkAuditStaticMessageContractMetadata' -count=1
run_wfctl plugin validate-contract --require-contract-kind message .
