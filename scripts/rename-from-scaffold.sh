#!/usr/bin/env bash
# Usage: bash scripts/rename-from-scaffold.sh <your-plugin-name> [--mode iac|non-iac]
#
# Renames scaffold-workflow-plugin internals to workflow-plugin-<your-plugin-name>:
#   1. Picks the IaC or non-IaC main.go variant; deletes the other.
#   2. Renames cmd/scaffold-workflow-plugin*/ → cmd/workflow-plugin-<name>/.
#   3. Updates go.mod module path.
#   4. Bulk sed across .go/.yaml/.yml/.md/.json files (find-based; safe with
#      paths containing spaces; doesn't rely on bash globstar).
#   5. Resets plugin.json: type "scaffold" → "external"; name → workflow-plugin-<name>.
#   6. Removes the rename script itself + scaffold-rename-test workflow.
#
# Requires: jq.
#
# Tested by .github/workflows/scaffold-rename-test.yml which runs this against
# a tmp copy in both --mode iac and --mode non-iac, then `go build ./...`.
set -euo pipefail

NEW_NAME="${1:?Usage: rename-from-scaffold.sh <name> [--mode iac|non-iac]}"
MODE="non-iac"
if [[ "${2:-}" == "--mode" ]]; then
  MODE="${3:?Mode required}"
fi
case "$MODE" in
  iac|non-iac) ;;
  *) echo "Mode must be iac or non-iac" >&2; exit 1 ;;
esac

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required" >&2
  exit 1
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# 1+2. Pick main.go variant; delete the other; rename to workflow-plugin-<name>.
if [[ "$MODE" == "iac" ]]; then
  rm -rf cmd/scaffold-workflow-plugin
  mv cmd/scaffold-workflow-plugin-iac "cmd/workflow-plugin-$NEW_NAME"
else
  rm -rf cmd/scaffold-workflow-plugin-iac
  mv cmd/scaffold-workflow-plugin "cmd/workflow-plugin-$NEW_NAME"
fi

# 3. go.mod
go mod edit -module "github.com/GoCodeAlone/workflow-plugin-$NEW_NAME"

# 4. Bulk sed via find (safe for paths with spaces; no globstar dependency).
find . \( -name '*.go' -o -name '*.yaml' -o -name '*.yml' -o -name '*.md' -o -name 'plugin.json' \) \
  -not -path './vendor/*' -not -path './_worktrees/*' -not -path './.git/*' -print0 \
  | while IFS= read -r -d '' f; do
      sed -i.bak "s|scaffold-workflow-plugin|workflow-plugin-$NEW_NAME|g" "$f"
      rm -f "$f.bak"
    done

# 5. plugin.json: reset type + name (jq-based; idempotent).
tmp="$(mktemp)"
jq --arg name "workflow-plugin-$NEW_NAME" '.type = "external" | .name = $name' plugin.json > "$tmp"
mv "$tmp" plugin.json

# 6. Remove the rename script itself + scaffold-rename-test workflow.
rm -f scripts/rename-from-scaffold.sh
rm -f .github/workflows/scaffold-rename-test.yml

echo "Renamed to workflow-plugin-$NEW_NAME ($MODE mode)."
echo "Next steps:"
echo "  1. Review changes: git status / git diff"
echo "  2. Edit plugin.json: replace TEMPLATE.* placeholders with real capabilities"
echo "  3. Commit: git add -A && git commit -m 'feat: initial plugin scaffold'"
echo "  4. Tag: git tag v0.1.0 && git push origin main v0.1.0"
