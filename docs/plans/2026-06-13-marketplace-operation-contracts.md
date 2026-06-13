# Marketplace Operation Contracts Plan

## Scope

This PR implements Task 2 from the locked workflow-compute marketplace
operations plan. It adds public compute-core protocol contracts for marketplace
operation control data only.

## Contract

`protocol/` now owns portable data shapes and validators for:

- settlement holds and payout holdback requests
- marketplace suspensions
- marketplace operator policy and trust-root rotation requests
- marketplace operations policy and payout-key rotation requests
- reputation events and summaries
- marketplace abuse cases with safe evidence references

The contracts intentionally do not implement admission, authorization, ledger
mutation, payout dispatch, audit persistence, dashboard rendering, or operator
workflow behavior. Those remain control-plane responsibilities for
workflow-compute or a future reusable control-plane component.

## Verification

- RED: `GOWORK=off go test ./protocol -run 'TestMarketplace' -count=1`
  failed on missing marketplace operation contract types.
- INVARIANT: with the production contract block reverted, the same command
  failed on the missing contract types; with the block restored, it passed.
- INVARIANT: with payout scope validation removed,
  `GOWORK=off go test ./protocol -run 'TestMarketplaceContractsRejectMissingScopeIdentifiers' -count=1`
  failed because the missing org/product/account identifiers were accepted.
- GREEN: `GOWORK=off go test ./protocol -run 'TestMarketplace' -count=1`
