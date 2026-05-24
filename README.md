# scaffold-workflow-plugin

This is a SCAFFOLD repo. It is NOT an installable plugin.

Use it to create a new workflow plugin via GitHub's "Use this template" button.

(A future `wfctl plugin init --from-scaffold` subcommand is tracked at
[workflow#762](https://github.com/GoCodeAlone/workflow/issues/762) but
not yet implemented; use the GitHub UI path below.)

## After creating your new repo from this template

1. **Enable GitHub Actions**: Settings → Actions → "I understand my workflows, enable them".
   New repos created from a template ship with workflows DISABLED by
   default; you must enable them once before any release.yml run can
   succeed.

2. **Run the rename script**:

   ```bash
   bash scripts/rename-from-scaffold.sh <your-plugin-name> --mode [iac|non-iac]
   ```

   This:
   - Picks the IaC or non-IaC main.go variant; deletes the other.
   - Renames `cmd/scaffold-workflow-plugin*/` → `cmd/workflow-plugin-<your-name>/`.
   - Updates `go.mod` module path.
   - Bulk-sed of `scaffold-workflow-plugin` → `workflow-plugin-<your-name>`
     across `.go`/`.yaml`/`.md`/`plugin.json` files.
   - Resets `plugin.json.type` from `"scaffold"` to `"external"`; sets `.name`.
   - Removes the rename script itself + scaffold-rename-test workflow.

3. **Edit `plugin.json`**: replace `TEMPLATE.module` / `TEMPLATE.step` /
   `TEMPLATE.resource` placeholder capabilities with your plugin's actual
   types. Update `minEngineVersion` if you depend on a newer workflow.

4. **Implement your plugin** in `internal/`:
   - **non-IaC mode**: extend `internal/plugin.go`'s `NewPlugin()` with
     real ModuleFactories / StepFactories / TriggerFactories. Delete
     `internal/iacserver.go` (unused in non-IaC mode).
   - **IaC mode**: replace `internal/iacserver.go`'s stub
     `pb.UnimplementedIaCProviderRequiredServer` embed with your real
     IaC provider implementation (Initialize, Plan, Destroy, etc.).
     Delete `internal/plugin.go`'s NewPlugin (unused in IaC mode).

5. **Commit + tag**:

   ```bash
   git add -A && git commit -m "feat: initial plugin scaffold from scaffold-workflow-plugin"
   git tag v0.1.0 && git push origin main v0.1.0
   ```

   `release.yml`'s `wfctl plugin validate-contract --for-publish` gate
   verifies your tag (must be release-grade semver `^v\d+\.\d+\.\d+$`)
   and contract (capabilities populated, minEngineVersion set, main.go
   wires `sdk.ResolveBuildVersion`, goreleaser ldflag present).

## Modes

- `--mode non-iac` (default): for module/step/trigger plugins that use
  `sdk.Serve`. Suitable for MOST plugins.
- `--mode iac`: for IaC provider plugins that use `sdk.ServeIaCPlugin`
  and satisfy `pb.IaCProviderRequiredServer`. Use ONLY if your plugin
  provisions infrastructure (cloud resources, databases, etc.).

## What's pre-baked in (workflow#758 + #762 compliance)

- `plugin.json.version = "0.0.0"` sentinel (release tag injected at build
  time via goreleaser).
- `internal/plugin.go`'s `var Version = "0.0.0"` (ldflag-injected at
  release; surfaced through `sdk.ResolveBuildVersion`).
- `release.yml` pre-build + post-build `wfctl plugin validate-contract`
  gates.
- No `sync-plugin-version.yml` (the discarded sync mechanism is not
  shipped in scaffolds; goreleaser's `before:` hook rewrites
  `plugin.json.version` from the tag at release time).
- `sdk.WithBuildVersion(sdk.ResolveBuildVersion(internal.Version))`
  wired in main.go so the binary surfaces its release version through
  `GetManifest` at runtime.
- `setup-wfctl@v1 with version: v0.62.0` pinned for the release pipeline.

## Build & test (during plugin development)

```bash
go build ./...
go test ./... -race -count=1
```

## Releasing

```bash
git tag v0.1.0 && git push origin v0.1.0
```

`release.yml` runs `wfctl plugin validate-contract --for-publish`,
goreleaser builds cross-platform binaries, and the post-build gate
verifies the shipped tarball's `plugin.json` carries the tag.

## References

- Plugin release contract: [docs/PLUGIN_RELEASE_GATES.md](https://github.com/GoCodeAlone/workflow/blob/main/docs/PLUGIN_RELEASE_GATES.md)
- Plugin version discipline: [workflow#758](https://github.com/GoCodeAlone/workflow/issues/758)
- Registry sync subcommand: [workflow#762](https://github.com/GoCodeAlone/workflow/issues/762)
