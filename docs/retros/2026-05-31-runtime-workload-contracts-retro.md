# Retro: Runtime Workload Contracts

**PR:** #31 - feat: add runtime workload contracts
**Merged:** 2026-05-31
**Branch:** feat/runtime-workload-contracts
**Design:** docs/plans/2026-05-31-runtime-workload-contracts-design.md
**Plan:** docs/plans/2026-05-31-runtime-workload-contracts.md
**Related ADRs:** none

## Adversarial-review findings, scored

| Phase | Finding | Severity | Outcome |
|---|---|---|---|
| plan | New compute-core tag required after merge before workflow-compute can consume the contracts | Important | Prescient - `v0.3.1` was tagged from the merge commit and release CI was monitored. |

## Gate misses

No gate misses this PR. All downstream issues were caught by the gate they were assigned to, or were genuinely novel and not in any gate's bug-class scope.

| Issue | Gate that missed | Why it slipped | Fix idea |
|---|---|---|---|
| none | none | CI and review remained green; no review threads or changes-requested reviews were opened. | none |

## Missed skill activations

| Gate | Fired? | Notes |
|---|---|---|
| brainstorming | yes | Runtime workload contracts were scoped as the prerequisite for workflow-compute RTE-1 extraction. |
| adversarial-design-review (design) | partial | The committed design was attacked in the PR adversarial-review comment rather than as a separate committed report. |
| writing-plans | yes | Plan doc committed with tasks, deferred issues, and verification commands. |
| adversarial-design-review (plan) | partial | Plan findings were recorded in the PR adversarial-review comment. |
| alignment-check | not recorded | No `.claude/autodev-state` audit file exists in this repo for this PR. |
| subagent-driven-development | not recorded | No `.claude/autodev-state` audit file exists in this repo for this PR. |
| finishing-a-development-branch | yes | PR #31 was created, monitored, merged, and tagged. |
| pr-monitoring | yes | PR checks, review threads, and changes-requested reviews were monitored until clean. |
| post-merge-retrospective | yes | This file. |

## What worked

- The design kept host-owned authorization, secret resolution, allowlists, and proof mutation out of compute-core.
- CI covered both the public protocol tests and the wfctl contract validation before merge.
- The adversarial review identified the release dependency, and the merge was followed by a `v0.3.1` tag.

## What didn't

- The design and plan adversarial reviews were captured as a PR comment instead of committed phase reports, so later retros have less structured evidence.
- The repo has no skill activation audit log for this PR, so missed-activation scoring depends on visible artifacts and command history.

## Plugin-level follow-ups

No plugin-level changes are warranted from this single PR.

## Project guidance updates

| Guidance file | Change | Reason |
|---|---|---|
| `docs/design-guidance.md` | no change | No durable cross-design lesson was found; this was an additive public contract release. |
