# OD-26 (DRAFT): ObserveX Managed greenfield baseline

**Status: DRAFT, not approved.** Drafted by Claude for akash on 15 October 2026.
Only akash can approve, change or reject it. Nothing in this repository treats
OD-26 as approved until akash records it in the approval log of record.

## 1. Directions akash has already given (to be recorded)

| Date | Direction, in akash's words where available |
| --- | --- |
| 14 Oct 2026 | "we are not migrating now we are building from scratch". ObserveX Managed is built in the new repository Voxmatic/observe, on the customer's own premises or cloud. |
| 15 Oct 2026, 10:11 | ObserveX serves all sectors, not only banking; it is an AI-native full-stack observability platform for Managed environments; every feature, including akash's own suggestions, is judged on its merit. |
| 15 Oct 2026, 11:26 | Plan all phases first; write code together with test cases; build each module first; middleware in Go; Claude proposes other technologies for akash's approval. |
| 15 Oct 2026, 11:39 | "now i approved implementiation and ask me when you think necessary". |

## 2. What this supersedes

The direction of 11 October 2026 to transform the existing codebase
(Voxmatic/observex) into ObserveX Managed in two stages, and the provisional
choice of `services/oneagent` as the canonical agent.

## 3. What carries forward unchanged

- OD-25 in full: its twelve policies, D1 to D7, IMP-1 to IMP-6, DEV-02 to DEV-04.
- No Kafka or other message bus.
- No durable delivery until DR-07 and DR-08 are approved.
- ClickHouse is not primary storage or transport without an ADR, a benchmark and
  akash's approval.
- No push or deploy without akash's explicit approval.
- Role split of 12 October: Claude designs and implements; Codex Astra validates
  on akash's machine; no claim of Windows or real-Docker validation without
  Astra's evidence.
- Goal by goal: implement, build, test, report evidence and limits, commit to
  main with its hash, then stop for akash's approval.

## 4. Open items from the old codebase: proposed disposition

These items belong to Voxmatic/observex. None has code in the new repository.

| Item | Proposed disposition | akash's choice |
| --- | --- | --- |
| Old roadmap G02, Safety and Verification Baseline | Close as superseded. Its intent is carried by the new G00 gates (ADR 0003, ADR 0007, threat model). | |
| DR-06, activegate kept as a temporary compatibility wrapper | Close as not applicable: no activegate code exists here; the Unified Gateway is built new in G04. | |
| F19 fix (and F9b, F17, F18, Q1 investigation) | Close as not applicable to the new repository; keep open only if the old repository stays in use. | |
| Goal 01's deferred K2 check (ClickHouse 24.3 comparison) | Close as not applicable: the new repository has no ClickHouse code. Remains DEFERRED BY OWNER, never passed. | |
| P-01 to P-12 and the paused items (A1 evidence pack, S1-01, D4 processor fix, OPS-1) | Leave parked against the old repository; no action in the new one. | |

## 5. Decisions requested from akash

| # | Question | Claude's recommendation | akash's decision |
| --- | --- | --- | --- |
| 1 | Accept ADRs 0001 to 0008? | Accept | |
| 2 | Accept technology choices T1 to T20 (development plan)? | Accept | |
| 3 | Accept Go language level 1.24 in `go.mod` until the workspace can reach the module proxy? | Accept; CI tests 1.27 and 1.24 | |
| 4 | Allow proxy.golang.org and sum.golang.org in Claude's network settings? | Yes, needed for Go 1.27, dependencies and tools | |
| 5 | ObserveX's own licence | akash's commercial choice; none set until then | |
| 6 | Where the approval log of record lives for the new repository | `docs/governance/record/approval-log.md` in Voxmatic/observe, append-only | |
| 7 | Delivery of each goal: git bundle only, or also a push to a branch | Bundle now; push to a branch per goal once akash allows push access | |
| 8 | Default for sending telemetry to an external AI model | Forbidden by default; customer can enable per environment | |
