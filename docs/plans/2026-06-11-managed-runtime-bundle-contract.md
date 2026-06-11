# Managed Runtime Bundle Contract Plan

## Scope

This PR implements Task 3 from the locked workflow-compute dependency-light
protected runtime plan. It adds public compute-core protocol contracts for
managed runtime bundle evidence only. It does not build, sign, publish, install,
doctor, or execute a managed containerd/nerdctl runtime bundle.

## Contract

`ManagedRuntimeBundleDescriptor` records signed, updateable, scoped runtime
bundle metadata:

- artifact/checksum/signature names and `sha256:` digests
- signature issuer, key id, pinned trust-root digest, and signature subject
- `valid_until`, update channel, minimum supported version, and CVE blocklist
- scoped-store policy requiring opaque namespace/store strategies, cleanup, and
  no host-global visibility
- OS/arch support targets, runtime family, tool, version, conformance profile, and
  `install_burden: "bundled"`

`RuntimeBackendReport` now carries an optional `bundle` field. A supported
report with `install_burden: "bundled"` requires a valid bundle descriptor; this
keeps workflow-compute fail-closed until `workflow-plugin-compute-container`
publishes real managed containerd/nerdctl artifacts and conformance evidence.

## Verification

- RED: `GOWORK=off go test ./protocol -run 'ManagedRuntimeBundle|RuntimeBackendReportRequiresValidManagedBundle' -count=1`
- GREEN: same command after implementation.
- Final: `GOWORK=off go test ./...`
