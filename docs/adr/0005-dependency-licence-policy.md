# ADR 0005: Dependency licence policy

Status: Proposed. Row T20 of the development plan.

## Context

Customers install ObserveX Managed on their own infrastructure, so every
dependency is redistributed to them.

## Decision

- Allowed: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC, MPL-2.0.
- Blocked: AGPL, SSPL, BSL, Elastic License, Commons Clause and other
  source-available licences.
- `make licenses` runs go-licenses in CI and fails on forbidden, restricted or
  unknown licences.
- This excludes, among others, Grafana Loki, Tempo and Mimir (AGPLv3) and
  ScyllaDB releases after 6.2.x (source-available).

## Current state

At G00 the module has no dependencies outside the Go standard library.

## Open

ObserveX's own licence is akash's decision and is not set in this repository
yet. With no licence file, all rights are reserved by default.
