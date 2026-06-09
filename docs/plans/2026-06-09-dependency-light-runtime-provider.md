# Dependency-Light Runtime Provider Implementation Plan

> **For the implementing agent:** REQUIRED SUB-SKILL: Use autodev:executing-plans to implement this plan task-by-task.

**Goal:** Complete T544 by making protected agent workload capability advertisement depend on evidence-backed local runtime providers without requiring Docker as an external-user prerequisite.

**Architecture:** Add additive runtime backend evidence contracts in compute-core, implement Docker-compatible runtime backend probing and conformance in the container runtime plugin, then consume those reports in workflow-compute agent advertisement, server placement, setup UX, and cross-OS proof. workflow-compute remains the assembled product: it stores, displays, schedules, and proves runtime capability, but reusable runtime contract and adapter logic lives in plugins.

**Tech Stack:** Go 1.26+, workflow-plugin-compute-core, workflow-plugin-compute-container, workflow-compute, workflow-plugin-compute, workflow-compute-scenarios, GitHub Actions manual runner proof, shell/PowerShell proof scripts.

**Base branch:** main

---

## Scope Manifest

**PR Count:** 10
**Tasks:** 14
**Estimated Lines of Change:** ~3300

**Out of scope:**
- Shipping a bundled/tailored embedded container engine.
- Claiming Windows protected workload support without a real Hyper-V/WSL/containerd/Podman conformance run.
- Adding trusted-native fallback for protected command, container-build, product-capture, or service workloads.
- Moving admin/auth/authz plugin adoption or run-log retention work into this T544 runtime phase.

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | Add runtime backend evidence contracts to compute-core | Task 1, Task 2 | feat/t544-runtime-core |
| 2 | Add runtime backend probes to compute-container | Task 3, Task 4 | feat/t544-runtime-container |
| 3 | Consume runtime evidence in workflow-compute placement | Task 5, Task 6, Task 7 | feat/t544-runtime-consume |
| 4 | Surface runtime selection in workflow-compute setup UX | Task 8 | feat/t544-runtime-setup-ux |
| 5 | Add projectless setup UX to workflow-plugin-compute | Task 9 | feat/t544-runtime-plugin-ux |
| 6 | Prove workflow-compute cross-OS runtime behavior | Task 10 | feat/t544-runtime-proof |
| 7 | Verify product-capture plugin compatibility | Task 11 | feat/t544-product-capture-compat |
| 8 | Keep workflow-compute-scenarios real and current | Task 12 | feat/t544-runtime-scenarios |
| 9 | Publish rollout records and deferred embedded-runtime issue | Task 13 | chore/t544-runtime-rollout |
| 10 | Audit smoke workflow cloud credential noise | Task 14 | chore/t544-smoke-env-audit |

**Status:** Locked 2026-06-09T14:13:31Z

## Design Requirements Trace

| Design requirement | Plan task(s) |
|---|---|
| Runtime provider contract is additive and reusable in compute-core | 1, 2 |
| Backend probes distinguish supported, degraded, unsupported | 1, 3, 4 |
| Runtime CLI behavior is verified against actual help/docs before adapter implementation | 3 |
| Agents advertise protected executor refs only for supported backend reports | 5, 6 |
| Server placement refuses protected leases when only degraded/unsupported reports exist | 7 |
| Dashboard/setup visibility preserves degraded/unsupported evidence | 7, 8 |
| workflow-compute stays thin; reusable runtime code moves to plugins | 3, 4, 5 |
| Manual cross-OS proof installs/registers/reinstalls agents and submits protected workloads only where supported evidence exists | 10 |
| workflow-plugin-product-capture remains compatible with wfcompute provider execution | 11 |
| workflow-compute-scenarios stays functional and uses real product-capture/runtime paths | 12 |
| Staging rollout, local agents, SPEC/T544 closure, and releases are recorded without production deploy by default | 13 |
| Smoke workflow output does not imply unused cloud-provider secrets are required | 14 |

### Task 1: Core Runtime Backend DTOs

**Files:**
- Modify: `workflow-plugin-compute-core:protocol/types.go`
- Modify: `workflow-plugin-compute-core:protocol/types_test.go`
- Modify: `workflow-plugin-compute-core:plugin.contracts.json`
- Modify: `workflow-plugin-compute-core:README.md`

**TDD steps:**
1. Add failing tests in `protocol/types_test.go` for `RuntimeBackendReport.Validate`.
   Expected failures before implementation:
   - missing `backend_id`, `family`, `status`, `isolation_mode`, or `generated_at` is rejected;
   - `supported` requires at least one executor provider, runtime profile, conformance profile, workspace/network/env/proof/cleanup evidence, and a `sha256:` evidence digest;
   - `degraded` and `unsupported` require a reason and must not imply supported executor providers;
   - report redaction rejects home-directory-looking paths, token/cookie substrings, runtime socket paths, and secret-looking evidence.
2. Implement additive types in `protocol/types.go`:
   - `RuntimeBackendStatus`;
   - `RuntimeBackendFamily`;
   - `RuntimeIsolationMode`;
   - `RuntimeInstallBurden`;
   - `RuntimeBackendEvidence`;
   - `RuntimeBackendReport`;
   - `RuntimeBackendReportsSupportedExecutors(reports []RuntimeBackendReport) []ExecutorRef`;
   - `ProviderCapabilityReportsFromRuntimeBackends(reports []RuntimeBackendReport) []ProviderCapabilityReport`.
3. Add README contract examples showing a supported Podman-style report and a degraded Windows Hyper-V/WSL candidate report.
4. Run `GOWORK=off go test ./protocol -run 'TestRuntimeBackend|TestProviderCapabilityReportsFromRuntimeBackends' -count=1`.
   Expected: targeted tests pass.
5. Run `GOWORK=off go test ./...`.
   Expected: all compute-core tests pass.
6. Run the repo's real plugin contract consumer/loader validation:
   - if `scripts/check-workflow-engine-load.sh` exists, run it;
   - if `wfctl` exposes plugin contract validation locally, run that command against `plugin.contracts.json`;
   - otherwise record the absence in the PR body and keep `plugin.contracts.json` JSON-valid by decoding it in a Go test.
7. Commit.

**Rollback:** revert this PR or pin workflow-compute to the previous compute-core release; fields are append-only and consumers ignore them until Task 5.

### Task 2: Core Contract Drift And Release Prep

**Files:**
- Modify: `workflow-plugin-compute-core:docs/plans/2026-06-09-dependency-light-runtime-provider.md` if this repo requires a local plan copy
- Modify: `workflow-plugin-compute-core:docs/retros/` only after merge if CI/review requires a repo-local closure note

**TDD steps:**
1. Add the repo-local plan copy only if compute-core convention requires accepted cross-repo implementation plans to be present in the plugin repo.
2. Run `GOWORK=off go test ./...`.
   Expected: all tests pass.
3. Run any existing repository contract helper:
   - if `scripts/check-proto.sh` exists and runtime backend types touch protobuf, run `bash scripts/check-proto.sh`;
   - otherwise record `not applicable: JSON-only additive contract`.
4. Run `git diff --check`.
   Expected: no whitespace errors.
5. Commit.

**Rollback:** revert contract metadata and continue consuming the prior compute-core version.

### Task 3: Container Runtime Probe Contract

**Files:**
- Modify: `workflow-plugin-compute-container:container/adapters.go`
- Modify: `workflow-plugin-compute-container:container/adapters_test.go`
- Create: `workflow-plugin-compute-container:container/runtime_probe.go`
- Create: `workflow-plugin-compute-container:container/runtime_probe_test.go`
- Modify: `workflow-plugin-compute-container:README.md`

**TDD steps:**
1. Verify current runtime command surfaces before coding:
   - run `docker --help` if Docker is installed;
   - run `podman --help` if Podman is installed;
   - run `nerdctl --help` if nerdctl is installed;
   - for missing tools, record missing status in the PR body rather than failing.
   Expected: at least local missing/present state is documented; no adapter behavior is based only on memory.
2. Add failing fake-probe tests for:
   - missing executable -> unsupported report;
   - executable present but `version` fails -> degraded report;
   - version succeeds but conformance command fails -> degraded report;
   - conformance passes -> supported report with executor refs for `sandboxed-command` and `sandboxed-container-build` only when requested profiles pass.
3. Add a real conformance runner path that uses the existing distroless static sandbox probe image where available; support claims remain experimental until self-hosted conformance evidence records the backend as official.
4. Implement `RuntimeBackendProbe`, `RuntimeBackendProbeOptions`, `RuntimeCommandRunner`, and a fakeable Docker-compatible probe family for Podman, nerdctl/containerd, and Docker.
5. Ensure probe summaries redact local paths and secret-looking values before producing core reports.
6. Run `GOWORK=off go test ./container -run 'TestRuntimeBackendProbe|TestDockerCompatibleRuntimeProbe' -count=1`.
   Expected: targeted tests pass.
7. Run a real backend conformance smoke when Docker, Podman, or nerdctl is present:
   - build or pull the distroless static probe image;
   - execute network/mount/env/proof/cleanup checks through the selected runtime;
   - record whether the result is `experimental` or `official`.
   Expected: at least one present local backend either passes with supported evidence or emits a structured degraded report; missing tools are not treated as test failure.
8. Run `GOWORK=off go test ./...`.
   Expected: all compute-container tests pass.
9. Commit.

**Rollback:** remove probe registration and keep existing adapter contracts unchanged.

### Task 4: Container Runtime Adapter Ownership

**Files:**
- Modify: `workflow-plugin-compute-container:container/adapters.go`
- Create: `workflow-plugin-compute-container:container/docker_compatible_runtime.go`
- Create: `workflow-plugin-compute-container:container/docker_compatible_runtime_test.go`
- Modify: `workflow-plugin-compute-container:runtime-adapters.json`
- Modify: `workflow-plugin-compute-container:plugin.contracts.json`

**TDD steps:**
1. Port the current Docker-compatible sandbox argument builder into compute-container with tests covering:
   - default-deny network;
   - no secret env values in argv;
   - read-only rootfs by default;
   - explicit writable rootfs only for known build profiles;
   - cleanup env file behavior;
   - Podman host-user namespace handling;
   - nerdctl scoped runtime args.
2. Keep runtime execution behind existing `SandboxRuntime`/`SandboxedCommandRuntime` interfaces so workflow-compute can alias the plugin type instead of reimplementing it.
3. Run `GOWORK=off go test ./container -run 'TestDockerCompatible|TestSandboxRuntime' -count=1`.
   Expected: targeted tests pass.
4. Run `GOWORK=off go test ./...`.
   Expected: all compute-container tests pass.
5. Commit.

**Rollback:** release/pin workflow-compute back to the previous compute-container version; no workflow-compute consumption happens until Task 5.

### Task 5: Workflow-Compute Protocol Aliases And Dependency Pins

**Files:**
- Modify: `workflow-compute:go.mod`
- Modify: `workflow-compute:go.sum`
- Modify: `workflow-compute:pkg/protocol/types.go`
- Modify: `workflow-compute:pkg/protocol/compute_core_contract_drift_test.go`
- Modify: `workflow-compute:pkg/protocol/types_test.go`

**TDD steps:**
1. Add failing drift tests proving workflow-compute aliases the new compute-core runtime backend types and does not define an incompatible local copy.
2. Add protocol validation tests that worker capabilities may carry runtime backend evidence while existing `CapabilityReport` remains scheduler-visible.
3. Update module pins to released or local-replaced compute-core/compute-container while developing; before commit, remove all committed `replace` directives.
4. Run `GOWORK=off go test ./pkg/protocol -run 'Test.*RuntimeBackend|TestComputeCoreContractDrift' -count=1`.
   Expected: targeted tests pass.
5. Run `GOWORK=off go test ./pkg/protocol`.
   Expected: package tests pass.
6. Run `rg -n '^replace ' go.mod`.
   Expected: no output.
7. Commit.

**Rollback:** revert module pins and alias additions; older agents keep using existing capability reports.

### Task 6: Agent Runtime Probe And Advertisement

**Files:**
- Modify: `workflow-compute:internal/agent/agent.go`
- Modify: `workflow-compute:internal/agent/agent_test.go`
- Modify: `workflow-compute:cmd/compute-agent/main.go`
- Modify: `workflow-compute:cmd/compute-agent/main_test.go`
- Modify: `workflow-compute:internal/executor/sandboxed_command.go`
- Modify: `workflow-compute:internal/executor/sandboxed_command_test.go`

**TDD steps:**
1. Add failing tests for `compute-agent runtime probe -json`:
   - missing runtime emits unsupported/degraded backend reports and no protected executor providers;
   - supported fake backend emits executor providers `sandboxed-command` and `sandboxed-container-build`, execution tier `sandboxed-container`, and proof tier `artifact-hash` in their exact fields;
   - report output redacts host paths, token/cookie words, socket paths, and registry credential references.
2. Wire startup/enroll/heartbeat capability generation to call the runtime probe when protected workload availability is enabled.
3. Map only supported backend reports into `ExecutorProviders`, `Executors`, `ExecutionTiers`, and `ProofTiers`.
4. Keep availability-disabled registration free of protected executor claims.
5. Replace workflow-compute-owned Docker-compatible runtime implementation with aliases/delegation to compute-container where Task 4 supplied equivalent behavior.
6. Run `GOWORK=off go test ./internal/agent ./cmd/compute-agent ./internal/executor -run 'Test.*RuntimeProbe|Test.*Capability|Test.*SandboxRuntime' -count=1`.
   Expected: targeted tests pass.
7. Run `GOWORK=off go test ./internal/agent ./cmd/compute-agent ./internal/executor`.
   Expected: packages pass.
8. Run `rg -n 'func .*prepareRun|type DockerSandboxRuntime|DockerSandboxRuntime\\{' internal/executor`.
   Expected: only compatibility aliases or tests remain; no second production implementation.
9. Commit.

**Rollback:** disable runtime probe mapping and pin back to the prior compute-container version; protected work remains fail-closed when no old runtime path is configured.

### Task 7: Server Placement, Storage, And Active-View Visibility

**Files:**
- Modify: `workflow-compute:internal/server/server.go`
- Modify: `workflow-compute:internal/server/state.go`
- Modify: `workflow-compute:internal/server/state_postgres.go`
- Modify: `workflow-compute:internal/server/api_test.go`
- Modify: `workflow-compute:internal/server/server_test.go`
- Modify: `workflow-compute:internal/server/dashboard_static_test.go`
- Modify: `workflow-compute:internal/control/client_test.go`

**TDD steps:**
1. Add placement tests where a worker advertises only degraded/unsupported runtime backend reports.
   Expected before implementation: server incorrectly leases or hides useful reason.
2. Add negative tests for stale generated-at timestamps, mismatched worker IDs/runtime versions, unsupported conformance profile IDs, and replayed evidence digests bound to a different worker.
3. Implement server-side enforcement that protected executor leases require supported runtime backend evidence matching the executor/security floor, generated within the allowed freshness window, and bound to the worker/runtime version/profile allowlist.
4. Preserve degraded/unsupported reports in worker snapshots, list APIs, dashboard active view, and setup visibility.
5. Add dashboard test assertions that active worker rows show runtime backend status/reason without leaking machine-local details.
6. Run `GOWORK=off go test ./internal/server -run 'Test.*RuntimeBackend|Test.*Placement|Test.*Dashboard|Test.*Active' -count=1`.
   Expected: targeted tests pass.
7. Run `GOWORK=off go test ./internal/server ./internal/control`.
   Expected: packages pass.
8. Commit.

**Rollback:** revert placement enforcement and visibility changes together; previous fail-closed setup remains available.

### Task 8: Setup Wizard Runtime Selection

**Files:**
- Modify: `workflow-compute:cmd/compute/main.go`
- Modify: `workflow-compute:cmd/compute/main_test.go`
- Modify: `workflow-compute:internal/server/onboarding.go`
- Modify: `workflow-compute:internal/server/setup_invites_test.go`

**TDD steps:**
1. Add failing tests for `compute agent setup`:
   - `-runtime auto` probes and selects the first supported backend;
   - `-runtime none` installs/registers with availability disabled and no protected executor claims;
   - `-runtime podman|nerdctl|docker` records unsupported/degraded reason when the selected backend cannot pass conformance;
   - non-interactive mode fails closed before server mutation if required runtime flags are inconsistent.
2. Update setup invite command rendering so dashboard commands explain that worker ID, org ID, pool ID, and agent token come from the setup invite claim, not manual user guessing.
3. Ensure setup summary JSON includes sanitized `runtime_backend_reports` and selected backend ID.
4. Run `GOWORK=off go test ./cmd/compute ./internal/server -run 'Test.*AgentSetup|Test.*SetupInvite' -count=1`.
   Expected: targeted tests pass.
5. Run `GOWORK=off go test ./cmd/compute ./internal/server`.
   Expected: packages pass.
6. Commit.

**Rollback:** hide new runtime-selection flags from setup rendering and keep registration-only install path.

### Task 9: Workflow Plugin Projectless UX

**Files:**
- Modify: `workflow-plugin-compute:internal/cli.go`
- Modify: `workflow-plugin-compute:internal/cli_test.go`
- Modify: `workflow-plugin-compute:README.md`

**TDD steps:**
1. Add failing plugin CLI tests for `wfctl plugin run --ensure-installed workflow-plugin-compute -- compute agent setup --help` and a dry-run/projectless install command that forwards server URL, invite URL, runtime selection, and install flags without requiring a wfctl project manifest.
2. Implement the smallest plugin wrapper needed to invoke the workflow-compute setup command or render exact commands for users who already have `wfctl`.
3. Validate against the installed `wfctl` surface with `wfctl --version` and `wfctl plugin run --ensure-installed workflow-plugin-compute -- compute agent setup --help`.
   Expected: help exits 0 and does not require a project manifest.
4. Require workflow/wfctl `v0.76.0` or newer for first-run projectless `--ensure-installed` validation, unless a local `wfctl --help`/dry-run proves the installed version supports the same surface. Do not rely on `v0.74.3` for this acceptance gate.
5. Run `GOWORK=off go test ./internal -run 'Test.*AgentSetup|Test.*CLI' -count=1` in workflow-plugin-compute.
   Expected: targeted tests pass.
6. Run `GOWORK=off go test ./...` in workflow-plugin-compute.
   Expected: all plugin tests pass.
7. Commit workflow-plugin-compute changes in the plugin repo branch/PR for this phase.

**Rollback:** dashboard continues rendering the direct `compute agent setup` command; plugin wrapper can be reverted independently.

### Task 10: Cross-OS Runner Proof

**Files:**
- Modify: `workflow-compute:scripts/agent-runner-lifecycle-proof.sh`
- Modify: `workflow-compute:scripts/agent-runner-lifecycle-proof.ps1`
- Modify: `workflow-compute:scripts/install-runtime-tool.sh`
- Modify: `workflow-compute:scripts/staging-product-capture-proof.sh`
- Modify: `workflow-compute:.github/workflows/manual-agent-runner-proof.yml`
- Modify: `workflow-compute:.github/workflows/staging-product-capture-proof.yml`
- Modify: `workflow-compute:docs/validation/2026-06-09-runtime-backend-runner-proof.md`

**TDD steps:**
1. Update shell and PowerShell proof scripts to consume `compute-agent runtime probe -json` instead of ad hoc `tool version` checks.
2. Preserve current lifecycle behavior: install/register, stop, unregister/uninstall, reinstall/register.
3. Submit protected command workload only when a supported runtime backend report exists.
4. On Windows, keep proof green with structured degraded evidence if no supported backend is available; do not claim Windows protected workload support.
5. Add workflow inputs for `runtime_tool`, `install_runtime`, and `run_command_workload`; default to auto/probe behavior.
6. Update staging product-capture proof to consume runtime backend evidence and skip protected execution with structured degraded evidence if no backend is supported.
7. Run `bash -n scripts/agent-runner-lifecycle-proof.sh scripts/install-runtime-tool.sh scripts/staging-product-capture-proof.sh`.
   Expected: shell syntax OK.
8. Run `pwsh -NoProfile -Command "Get-Command pwsh | Out-Null; \$null = [scriptblock]::Create((Get-Content -Raw scripts/agent-runner-lifecycle-proof.ps1)); 'ok'"` when PowerShell is available.
   Expected: prints `ok`.
9. Dispatch the manual workflow on Linux/macOS/Windows self-hosted runners after the PR is open.
   Expected: lifecycle steps succeed on all OSes; protected command workload succeeds only on OSes with supported backend reports; artifacts include sanitized runtime backend reports.
10. Dispatch staging product-capture proof after workflow-compute staging is updated.
   Expected: proof succeeds when a supported runtime exists; otherwise it emits structured runtime precondition evidence without fake success.
11. Commit.

**Rollback:** disable new workflow inputs and revert proof scripts; no production deployment impact.

### Task 11: Product-Capture Plugin Compatibility

**Files:**
- Modify: `workflow-plugin-product-capture:internal/provider/provider.go`
- Modify: `workflow-plugin-product-capture:internal/provider/provider_test.go`
- Modify: `workflow-plugin-product-capture:contracts/product-capture-provider.json`
- Modify: `workflow-plugin-product-capture:docs/buymywishlist-live-usage.md`
- Modify: `workflow-plugin-product-capture:README.md`

**TDD steps:**
1. Add compatibility tests proving the provider accepts the real wfcompute provider execution request shape, including runtime profile/executor metadata from compute-core where applicable.
2. Add schema tests that reject mocked/demo-only product-capture inputs and accept the BuyMyWishlist live-use fields needed by workflow-compute.
3. Verify no test fixture relies on internal agent nicknames or local machine names.
4. Run `GOWORK=off go test ./internal/provider -run 'Test.*WorkflowCompute|Test.*ProviderSchema|Test.*BuyMyWishlist' -count=1`.
   Expected: targeted tests pass.
5. Run `GOWORK=off go test ./...`.
   Expected: all product-capture plugin tests pass.
6. Update live-usage docs with the wfcompute setup path, required server URL/invite flow, runtime support expectations, and result payload handoff details for BuyMyWishlist.
7. Commit.

**Rollback:** revert plugin compatibility changes; workflow-compute keeps generic provider execution but product-capture live usage remains pinned to the prior working plugin version.

### Task 12: Scenarios And Product-Capture Compatibility

**Files:**
- Modify: `workflow-compute-scenarios:scripts/product-capture-scenario.mjs`
- Modify: `workflow-compute-scenarios:scripts/run-product-capture-scenario.sh`
- Modify: `workflow-compute-scenarios:README.md`

**TDD steps:**
1. Add scenario assertions that product-capture uses real workflow-plugin-product-capture/workflow-compute paths, not mocked payloads.
2. Ensure scenario runtime selection consumes supported backend evidence and skips protected execution with structured degraded evidence if no backend is supported.
3. Add an existence check for `workflow-plugin-product-capture:contracts/product-capture-provider.json` and the scenario's consumed plugin manifest before updating scenario wiring.
4. Run `npm test -- --runInBand` or the repo's existing scenario test command if present; otherwise run `npm run test` only if defined in `package.json`.
   Expected: scenarios pass or missing test script is recorded.
5. Run `bash scripts/run-product-capture-scenario.sh` in workflow-compute-scenarios with local/staging configuration only when credentials are available.
   Expected: product details payload is captured by an agent path and submitted back through wfcompute.
6. Commit scenario changes in the scenarios repo branch/PR for this phase.

**Rollback:** revert scenario runtime evidence checks; previous product-capture scenario remains available.

### Task 13: Release, Rollout, And Deferred Embedded Runtime

**Files:**
- Modify: `workflow-compute:SPEC.md`
- Modify: `workflow-compute:docs/validation/2026-06-09-runtime-backend-rollout.md`
- Modify: `workflow-compute:docs/plans/deferred.md`
- Modify: `workflow-compute:docs/retros/2026-06-09-dependency-light-runtime-provider.md`

**TDD steps:**
1. After PRs 1 and 2 merge green, tag compute-core and compute-container releases as needed and record exact versions in the rollout note.
2. After PRs 3 through 8 merge green, update staging and local agents using the existing non-destructive staging rollout process.
   Expected: staging agents reconnect and report current runtime backend evidence.
3. Verify no production deploy is performed without separate approval.
4. Update `SPEC.md` to close or split T544 based on verified evidence:
   - close T544 only if install/registration/update readiness is dependency-light, runtime backend evidence gates protected claims, manual cross-OS proof is green, and non-Docker protected path evidence exists where claimed;
   - add a follow-up §T row for any still-open Windows supported-workload or embedded runtime work;
   - keep deferred Windows/embedded-runtime work explicit instead of implied complete.
5. Add a deferred issue/plan row for embedded managed runtime exploration:
   - candidate approaches: OS-backed VM providers, containerd/nerdctl bundle, tailored engine fork;
   - security floors: no trusted-native fallback, no user-visible global container store reliance for private payloads, signed/updateable runtime bundle, CVE patch process;
   - acceptance gate: supported backend report plus cross-OS conformance proof.
6. Run `git diff --check`.
   Expected: no whitespace errors.
7. Run a repo hygiene scan for newly introduced operator-local paths, hostnames,
   cloud credential env names, and internal-only agent nicknames without writing
   those literal values into committed docs.
   Expected: no newly introduced machine/internal strings. If older unrelated
   hits exist, record and do not expand them.
8. Commit.

**Rollback:** revert rollout/deferred docs; released plugin tags remain immutable but workflow-compute pins can be reverted.

### Task 14: Smoke Workflow Cloud Credential Noise Audit

**Files:**
- Modify: `workflow-compute:.github/workflows/staging-smoke.yml`
- Modify: `workflow-compute:.github/workflows/build.yml`
- Modify: `workflow-compute:docs/validation/2026-06-09-smoke-env-audit.md`
- Modify: `workflow-compute:ci_workflows_test.go` if workflow structure tests live there on the target branch

**TDD steps:**
1. Inspect the latest staging smoke and build logs for cloud-provider access/secret env names that are not actually used by workflow-compute.
2. Trace whether those names come from workflow/wfctl generated env projection, DigitalOcean Spaces compatibility wiring, or stale workflow env blocks.
3. Add workflow tests or static assertions that unused cloud-provider credential names are not printed as required app envs for this repo.
4. If the names are legitimate compatibility aliases for object storage, hide them from smoke output unless the app actually requires them.
5. Run `GOWORK=off go test ./... -run 'Test.*Workflow|Test.*Smoke|Test.*Env'`.
   Expected: targeted workflow/env tests pass.
6. Run the relevant workflow render/validation command if wfctl exposes one locally; otherwise run `actionlint` if available and record if missing.
7. Commit.

**Rollback:** revert workflow/env-output changes; no runtime provider behavior depends on this audit.

## Execution Order

1. Open PR 1 in workflow-plugin-compute-core; monitor CI/review, merge, tag release if needed.
2. Open PR 2 in workflow-plugin-compute-container against the released core version; monitor CI/review, merge, tag release if needed.
3. Open PR 3 in workflow-compute consuming released plugin versions; monitor CI/review, merge only when placement and agent proofs are green.
4. Open PR 4 in workflow-compute for setup runtime UX; monitor CI/review to green.
5. Open PR 5 in workflow-plugin-compute for projectless setup UX; monitor CI/review to green.
6. Open PR 6 in workflow-compute for runner and staging proof updates; run manual staging proofs before merge.
7. Open PR 7 in workflow-plugin-product-capture for compatibility/live-usage proof; monitor CI/review to green.
8. Open PR 8 in workflow-compute-scenarios for real scenario updates; run scenario proof before merge.
9. Open PR 9 in workflow-compute for rollout records and deferred embedded-runtime issue after prior runtime PRs merge.
10. Open PR 10 in workflow-compute for the smoke workflow env audit.

## Verification Matrix

| Component | Required verification |
|---|---|
| compute-core | `GOWORK=off go test ./...` |
| compute-container | `GOWORK=off go test ./...`; real runtime smoke when Podman/Docker/nerdctl is present |
| workflow-compute | `GOWORK=off go test ./pkg/protocol ./internal/agent ./internal/executor ./internal/server ./cmd/compute ./cmd/compute-agent`; then broader `GOWORK=off go test ./...` before PR |
| workflow-plugin-compute | `GOWORK=off go test ./...`; `wfctl plugin run --ensure-installed workflow-plugin-compute -- compute agent setup --help` with wfctl `v0.76.0` or newer |
| workflow-plugin-product-capture | `GOWORK=off go test ./...`; live-usage docs updated with real wfcompute incorporation path |
| workflow-compute-scenarios | real scenario runner command when environment is available; otherwise no fake replacement |
| staging | manual agent runner proof and product-capture proof after staging update |

## Deferred Phases

- Embedded managed runtime bundle remains deferred until the provider contract and conformance proof are stable.
- Full Windows protected workload support remains deferred unless the current self-hosted Windows runner can execute a real supported backend conformance workload.
- Runtime backend support for confidential CPU/GPU remains under the confidential hardware roadmap and must not be claimed by VM-backed containers alone.
