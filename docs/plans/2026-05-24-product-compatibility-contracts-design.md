# Product Compatibility Contracts Design

## Goal

Make `workflow-plugin-compute-core` the canonical home for the provider/product
compatibility contract used by `workflow-compute` and provider plugins. This
lets `workflow-compute` become thinner without maintaining local copies of
public provider, product, session, proof, residue, access, and settlement
shapes.

## Design

Compute-core owns the public JSON contract and validation helpers for:

- `NetworkProduct`, including proof policy, access policy, residue policy,
  contribution policy, admission metadata, and creation timestamp;
- `ProviderConfig` and `SessionPolicy` validation;
- product proof policy validation;
- product placement, storage guidance, settlement target, crypto reward
  routing, and contribution policy validation.

`workflow-compute` still owns host-specific placement evaluation against live
worker capabilities and task network policy. That logic depends on scheduler
state, executor capability reports, and worker-side observations, so it should
stay in the application host until a separate runtime/placement plugin contract
exists.

## Assumptions

- Provider and product declarations are public plugin contracts, not private
  server persistence models.
- Settlement and contribution fields remain part of product declarations for
  now because existing product catalog entries already expose them.
- Moving validation into compute-core should preserve the current
  `workflow-compute` behavior before aliases are introduced.
- Host runtime placement checks can be kept as host helpers without weakening
  the public product contract.

## Rollback

Revert the compute-core product contract expansion and return
`workflow-compute` to its local product-contract copies. No data migration is
required because the JSON field names are unchanged.

## Self-Challenge

- Smaller option: only add the missing fields and no validation. Rejected
  because aliases would silently weaken `workflow-compute` admission checks.
- Risk: compute-core may absorb too much marketplace/settlement policy. Kept
  acceptable because these fields are already product contract data; runtime
  settlement execution remains out of scope.
- Risk: `ProviderContract.SupportsProduct` has historically differed between
  repos. The follow-up `workflow-compute` PR must either preserve the existing
  behavior or explicitly update tests for the stricter core semantics.
