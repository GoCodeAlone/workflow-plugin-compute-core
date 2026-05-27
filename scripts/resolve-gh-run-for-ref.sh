#!/usr/bin/env bash
set -euo pipefail

workflow=""
commit=""
event=""
branch=""
created_after=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workflow)
      workflow="${2:?missing --workflow value}"
      shift 2
      ;;
    --commit)
      commit="${2:?missing --commit value}"
      shift 2
      ;;
    --event)
      event="${2:?missing --event value}"
      shift 2
      ;;
    --branch)
      branch="${2:?missing --branch value}"
      shift 2
      ;;
    --created-after)
      created_after="${2:?missing --created-after value}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$workflow" || -z "$commit" || -z "$event" || -z "$branch" || -z "$created_after" ]]; then
  echo "--workflow, --commit, --event, --branch, and --created-after are required" >&2
  exit 2
fi

runs="$(
  gh run list \
    --workflow "$workflow" \
    --branch "$branch" \
    --event "$event" \
    --created ">=$created_after" \
    --limit 20 \
    --json databaseId,headSha,createdAt \
  | jq --arg commit "$commit" '[.[] | select(.headSha == $commit)]'
)"

count="$(jq 'length' <<<"$runs")"
if [[ "$count" != "1" ]]; then
  echo "expected exactly one matching run, found $count" >&2
  jq -r '.[] | "\(.databaseId) \(.headSha) \(.createdAt)"' <<<"$runs" >&2
  exit 1
fi

jq -r '.[0].databaseId' <<<"$runs"
