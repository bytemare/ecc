# Governance

This document explains how the `github.com/bytemare/ecc` project is stewarded, how decisions are made, and how contributors can advance into larger roles.

## Project Roles

- **Maintainer** – Owns the technical direction, reviews and merges pull requests, and cuts releases. The canonical maintainer is Daniel Bourdrez ([@bytemare](https://github.com/bytemare)), as recorded in `LICENSE` and `.github/CODEOWNERS`.
- **Contributor** – Anyone submitting issues, documentation, or code changes through the standard contribution process.
- **Reviewer** – Maintainers may delegate review responsibilities to trusted contributors for specific areas (e.g., curve backends, tooling).

## Decision-Making

- The maintainer seeks consensus on issues and pull requests. Discussion happens in GitHub Issues/PRs so decisions remain transparent.
- When consensus cannot be reached in a reasonable time, the maintainer makes the final call with a written rationale referencing project goals (correctness, safety, long-term maintainability).
- Breaking API changes require an open discussion outlining impact, migration paths, and a SemVer plan before implementation proceeds.

## Becoming a Maintainer

The maintainer periodically evaluates active contributors. Candidates should demonstrate:

1. Consistent, high-quality contributions (tests, docs, or code) over several review cycles.
2. Responsiveness to review feedback and constructive collaboration with others.
3. Ownership of at least one subsystem or documentation area.

Potential maintainers are nominated via a governance issue outlining evidence. Existing maintainers review the nomination and document the outcome. New maintainers are added to `.github/CODEOWNERS` and relevant GitHub teams.

## Maintainer Offboarding

- Maintainers may step down voluntarily via an issue documenting the transition and handing off outstanding responsibilities.
- Inactivity for more than three months without notice triggers a check-in. After six months, the maintainer may be moved to emeritus status to keep ownership current.

## Conflict Resolution

- Most disagreements should be resolved in the relevant GitHub thread.
- For interpersonal conflicts or conduct concerns, refer to the escalation path in the [Code of Conduct](../.github/CODE_OF_CONDUCT.md). If multiple maintainers are added in the future, a neutral maintainer will mediate.
- If a technical dispute escalates, the maintainer makes the final decision after summarising arguments and ensuring all voices are heard.

## Amendments

Governance updates follow the same contribution process as other documentation: open an issue describing the proposed change, gather feedback, and land the update via pull request after consensus is reached.
