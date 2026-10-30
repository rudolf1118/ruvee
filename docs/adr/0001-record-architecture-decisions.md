# ADR-0001: Record architecture decisions

- Status: Proposed
- Date: 2026-10-22

## Context

Ruvee is security-critical software. The master prompt requires that major decisions be recorded
as ADRs, and that nothing security-sensitive is implemented before its design is reviewed.

## Decision

Record each significant decision as a numbered ADR in `docs/adr/`. The ADR holds the reasoning;
the specification stays in the authoritative document it links to. ADRs start as Proposed and
become Accepted only after owner approval.

## Consequences

- Reviewers can see why a choice was made without reading the full specifications.
- Specifications and ADRs must be kept in step. A change to a decision is a new ADR.
