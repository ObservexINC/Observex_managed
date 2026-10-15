# ADR 0006: Two clocks on every recorded change

Status: Proposed.

## Context

Agents and Gateways buffer data on disk when links drop (IMP-1), so data often
reaches the cluster minutes after it happened. Postmortems, regulators and the
AI Scorecard need to know both when something happened and when ObserveX could
have known it.

## Decision

- Every recorded change carries a `clock.Stamp` with **valid time** (when it was
  true in the monitored system) and **record time** (when ObserveX recorded it).
- Readers choose a view: **as it was** (valid time only) or **as known then**
  (valid time, and record time no later than the moment being looked at).
- All code takes a `clock.Clock` instead of calling `time.Now`, so tests control
  time. Times are stored in UTC.
- The wire format carries both clocks (`observex.common.v1.Stamp`).

## Consequences

- Storage grows by one timestamp per change.
- The AI Scorecard can replay an incident showing the AI only what was known
  at the time, which prevents hindsight from inflating its grade.
- A source whose clock runs ahead produces negative lag; it is shown, not hidden.
