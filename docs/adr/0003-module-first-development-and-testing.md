# ADR 0003: Module-first development and testing

Status: Proposed.

## Context

akash asked for every module to be built first, with its test cases, before
integration. Codex Astra validates every goal on akash's machine.

## Decision

1. Every module is built with its tests in the same commit and must run on its
   own against fakes before it is integrated. Phase 1 (G01 to G05) builds the
   platform modules; integration starts only in Phase 2 (G06, G07).
2. Test levels: L1 unit, L2 fuzz and property, L3 contract, L4 single-node
   integration, L5 3-node cluster, L6 fault, L7 performance, L8 security,
   L9 Console end to end, L10 acceptance by Astra.
3. A module is done when it builds through the module proxy, passes unit tests
   with the race detector, meets coverage targets (80% in store, intake,
   buffer, history and audit packages; 70% overall), has time-boxed fuzz tests
   for parsers and decoders, passes the contract suite where it is a store,
   runs on its own, reports its health, passes the secret-leak test and the
   security and licence checks, and has a README and any ADRs it needed.
4. Every goal ends with a handoff for Astra: commits, a git bundle with its
   SHA-256, file manifest, run instructions, test manifest (which tests ran
   where), evidence, limits and tests not run, and rollback steps.
5. Results from Claude's workspace are labelled as such. Nothing is reported as
   passing on Windows, WSL2 or real Docker without Astra's evidence.

## Consequences

Goals are smaller and slower to integrate, but each failure is found in the
module that caused it.
