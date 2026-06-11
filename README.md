# workflow-plugin-compute-core

Public Workflow plugin and Go module for compute protocol and provider catalog
contracts.

Provider and workload plugins use this module for shared compute protocol data
types, provider-catalog data types, validation helpers, canonical hashing, and a
minimal task/proof HTTP client. They also declare a plugin dependency on
`workflow-plugin-compute-core` in `plugin.json`, giving Workflow a registry
dependency anchor separate from runtime execution plugins.

This is distinct from the Workflow plugin runtime contract: external plugins
still expose their runtime capabilities through Workflow's gRPC/protobuf plugin
service contracts. The provider-catalog structs in `protocol/` are the typed
declaration data that provider plugins publish and `workflow-plugin-compute`
validates.

The public contract includes task/proof/lease wire shapes, provider identity,
org/pool scoping, access visibility, supported workload and network modes,
runtime profiles, operation schemas, artifact declarations, residue policy, and
upstream client conformance evidence. Runtime plugins can also report concrete
execution backends through `protocol.RuntimeBackendReport`; control planes can
derive supported executor providers and provider capability reports from those
backend reports. Workflow applications should treat these declarations as the
portable provider-facing base contract.

Managed runtime bundles use `protocol.ManagedRuntimeBundleDescriptor`. The
descriptor is only contract metadata: artifact signing, download, installation,
doctor, and real conformance execution belong in runtime plugins such as
`workflow-plugin-compute-container`. A `RuntimeBackendReport` with
`install_burden: "bundled"` can only validate as `supported` when it includes a
valid signed, updateable, scoped bundle descriptor. Degraded or unsupported
reports may omit the bundle and must continue to avoid executor advertisements.

The task/proof client covers submission and read-only observation:

- `SubmitTask`
- `ListTasks`
- `TaskSnapshot`
- `ListProofs`
- `FindProof`

Application-specific scheduling, task mutation policy, settlement, dashboards,
worker supervision, local-agent rollout, and control-plane storage/authz remain
outside this core plugin. Those concerns may be extracted into a reusable
control-plane component later, but they are not implemented by compute-core.

This plugin intentionally advertises no module, step, trigger, or IaC runtime
capabilities.

## Runtime Backend Reports

`RuntimeBackendReport` is JSON protocol metadata for dependency-light agent
runtime discovery. A backend can only claim `supported` after it supplies
executor providers, runtime profiles, conformance profiles, evidence for
workspace/network/env/proof/cleanup behavior, and a `sha256:` evidence digest.
Degraded or unsupported backends must explain why and must not advertise usable
executors.

Supported rootless/container-style report:

```json
{
  "protocol_version": "compute.v1alpha1",
  "backend_id": "podman-rootless",
  "family": "podman",
  "tool": "podman",
  "version": "v5.0.0",
  "os": "linux",
  "arch": "amd64",
  "status": "supported",
  "isolation_mode": "user-namespace",
  "install_burden": "system-installed",
  "runtime_profiles": ["sandboxed-oci-v1", "container-build-v1"],
  "executor_providers": ["sandboxed-command", "sandboxed-container-build"],
  "executors": [
    {
      "provider": "sandboxed-command",
      "version": "v1.2.3",
      "execution_security_tier": "sandboxed-container",
      "proof_tier": "artifact-hash",
      "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "rootfs_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  ],
  "conformance_profiles": ["workspace-network-env-proof-cleanup"],
  "evidence": {
    "digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "workspace": true,
    "network": true,
    "env": true,
    "proof": true,
    "cleanup": true,
    "details": ["distroless-static-conformance"]
  },
  "generated_at": "2026-06-09T00:00:00Z"
}
```

Degraded Windows Hyper-V/WSL candidate:

```json
{
  "protocol_version": "compute.v1alpha1",
  "backend_id": "windows-hyper-v-candidate",
  "family": "hyper-v",
  "os": "windows",
  "arch": "amd64",
  "status": "degraded",
  "reason": "runtime candidate detected but conformance has not completed",
  "isolation_mode": "vm-backed-container",
  "install_burden": "wsl-hyper-v",
  "generated_at": "2026-06-09T00:00:00Z"
}
```

Bundled managed containerd/nerdctl report:

```json
{
  "protocol_version": "compute.v1alpha1",
  "backend_id": "managed-containerd-linux-amd64",
  "family": "containerd",
  "tool": "nerdctl",
  "version": "v1.2.3",
  "os": "linux",
  "arch": "amd64",
  "status": "supported",
  "isolation_mode": "user-namespace",
  "install_burden": "bundled",
  "runtime_profiles": ["sandboxed-oci-v1", "container-build-v1"],
  "executor_providers": ["sandboxed-command"],
  "executors": [
    {
      "provider": "sandboxed-command",
      "version": "v1.2.3",
      "execution_security_tier": "sandboxed-container",
      "proof_tier": "artifact-hash",
      "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "rootfs_digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
  ],
  "conformance_profiles": ["workspace-network-env-proof-cleanup"],
  "bundle": {
    "protocol_version": "compute.v1alpha1",
    "bundle_id": "managed-containerd-linux-amd64",
    "family": "containerd",
    "tool": "nerdctl",
    "version": "v1.2.3",
    "os": "linux",
    "arch": "amd64",
    "artifact_name": "managed-containerd-linux-amd64.tar.zst",
    "artifact_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
    "checksum_name": "managed-containerd-linux-amd64.sha256",
    "checksum_digest": "sha256:2222222222222222222222222222222222222222222222222222222222222222",
    "signature_name": "managed-containerd-linux-amd64.sig",
    "signature_digest": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
    "signature_issuer": "workflow-plugin-compute-container-release",
    "signature_key_id": "workflow-compute-container-stable",
    "trust_root_digest": "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    "signature_subject": {
      "artifact_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
      "runtime_family": "containerd",
      "os": "linux",
      "arch": "amd64",
      "version": "v1.2.3",
      "channel": "stable",
      "conformance_profile": "workspace-network-env-proof-cleanup",
      "scoped_store_policy_digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555"
    },
    "valid_until": "2100-01-01T00:00:00Z",
    "update_policy": {
      "channel": "stable",
      "min_supported_version": "v1.2.0"
    },
    "cve_policy": {
      "policy_digest": "sha256:6666666666666666666666666666666666666666666666666666666666666666",
      "blocked_versions": ["v1.1.0"],
      "revoked_key_ids": ["old-workflow-compute-container-stable"],
      "updated_by_version": "v1.2.3"
    },
    "scoped_store": {
      "required": true,
      "namespace_strategy": "opaque-worker-pool-scope",
      "store_strategy": "workflow-owned-content-store",
      "policy_digest": "sha256:5555555555555555555555555555555555555555555555555555555555555555",
      "cleanup_required": true,
      "host_global_visibility_forbidden": true
    },
    "supported_targets": [
      {
        "os": "linux",
        "arch": "amd64"
      }
    ],
    "conformance_profile": "workspace-network-env-proof-cleanup",
    "install_burden": "bundled"
  },
  "evidence": {
    "digest": "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
    "workspace": true,
    "network": true,
    "env": true,
    "proof": true,
    "cleanup": true
  },
  "generated_at": "2026-06-11T00:00:00Z"
}
```

## Build & Test

```sh
go build ./...
go test ./... -race -count=1
```

## Release

```sh
git tag v0.1.0
git push origin v0.1.0
```

The release workflow validates `plugin.json`, builds cross-platform binaries
with GoReleaser, and verifies the runtime plugin manifest against the shipped
contract metadata.
