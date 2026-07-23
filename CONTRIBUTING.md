# Contributing

Every contribution is evaluated against the current governance plan.

1. Create a branch.
2. Add or select an approved typed change contract.
3. Reference the accepted ADRs and specifications that authorize the scope.
4. Keep facts, inferences, assumptions, and unknowns explicit.
5. Implement only the declared Slice and observable success criteria.
6. Run `npm run governance:check`, `npm run check`, and `npm run build`.
7. Open a pull request and preserve failed experiments as evidence.

Accepted ADRs, specifications, and implemented change contracts are immutable. A successor receives
a new identifier and records explicit supersession.

Contributions intentionally submitted for inclusion are provided under the Apache License 2.0, as
described in section 5 of [LICENSE](LICENSE).
