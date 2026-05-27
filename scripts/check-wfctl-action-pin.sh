#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

wfctl_version=""
workflows=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workflow)
      workflows+=("${2:?missing --workflow value}")
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

if [[ -z "$wfctl_version" || "${#workflows[@]}" -eq 0 ]]; then
  echo "--workflow and --wfctl-version are required" >&2
  exit 2
fi

for workflow in "${workflows[@]}"; do
  if ! [[ -f "$workflow" ]]; then
    echo "$workflow: workflow file not found" >&2
    exit 1
  fi
  if rg -n 'GoCodeAlone/setup-wfctl@v[0-9]+\b|GoCodeAlone/setup-wfctl@main\b' "$workflow"; then
    echo "$workflow: setup-wfctl must be pinned to an immutable commit SHA" >&2
    exit 1
  fi
  if ! rg -n 'GoCodeAlone/setup-wfctl@[0-9a-f]{40}\b' "$workflow" >/dev/null; then
    echo "$workflow: missing immutable setup-wfctl commit pin" >&2
    exit 1
  fi
  if rg -n "version:[[:space:]]*${wfctl_version}\\b" "$workflow" >/dev/null; then
    continue
  fi
  if rg -n 'wfctl_version:' "$workflow" >/dev/null &&
     rg -n 'version:[[:space:]]*\$\{\{ inputs\.wfctl_version \}\}' "$workflow" >/dev/null; then
    continue
  fi
  echo "$workflow: missing wfctl version ${wfctl_version}" >&2
  exit 1
done
