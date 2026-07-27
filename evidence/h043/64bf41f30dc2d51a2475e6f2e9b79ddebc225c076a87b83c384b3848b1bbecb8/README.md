# H-043 accepted evidence anchor

This is a non-normative, content-addressed index for the exact evidence accepted by the
human principal on 2026-07-26. The governance acceptance successor remains the normative
record.

- Hypothesis: `H-043`
- Run: `h043-2026-07-26T22-13-38-193Z-b4158eab`
- Outcome: `supported`
- Stage: `offline-worker-eligibility`
- Reason: `canonical-candidate-and-hostile-matrix-exact`
- Semantic evidence SHA-256:
  `64bf41f30dc2d51a2475e6f2e9b79ddebc225c076a87b83c384b3848b1bbecb8`
- Run file SHA-256:
  `4a5754eddcd5672072d1ce0dc68c7a42694eafdc3eab5cddc4bf3e9ce5a57328`
- Verification file SHA-256:
  `f75726992c88d45b9d43bab3443005cdaed05464d303f05a8356e0ccecc81023`
- Source-bound `CHG-0015` SHA-256:
  `b2cd667fad87b366163549cdb3b0ffaac95ffd591fc53d6158c229a516ae7e25`
- Historical governance plan SHA-256:
  `bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4`
- Historical manifest content hash:
  `b29bde1b9f24a5c0ddaaa6b18cb577de859d6d9577b6636148c4ebeb021b8917`

The accepted candidate is historical and capability-free:
`requiresRevalidation: true`, `authority: "none"`, and `action: null`.

## Git-preserved replay closure

The same Git commit that carries this index preserves the exact 21-file replay closure in:

`replay-fbe7e841a7319328b253e414f93abd3a17ab47506b783b652c6624aae3b68dec.tar.gz`

The deterministic archive is 389,084 bytes and its SHA-256 is:

`fbe7e841a7319328b253e414f93abd3a17ab47506b783b652c6624aae3b68dec`

It contains:

- all 18 files in the canonical run's `collector.sources` map;
- the canonical H-043 `run.json` and `verification.json`; and
- the exact accepted H-042 replay archive used as H-043 input.

The H-043 verifier independently reconstructs source admission, causal prefix, all predicates,
the one candidate, 25 hostile cases, tail independence, side-effect audit, claim boundary, and
semantic digest. In a clean checkout of the source-anchor commit, restore the ignored H-043
artifacts and replay with Node 22:

```bash
tar -xzf \
  evidence/h043/64bf41f30dc2d51a2475e6f2e9b79ddebc225c076a87b83c384b3848b1bbecb8/replay-fbe7e841a7319328b253e414f93abd3a17ab47506b783b652c6624aae3b68dec.tar.gz \
  --wildcards 'artifacts/h043/*'

node --input-type=module -e \
  "import { verifyRun } from './lab/h043/verify.mjs'; console.log(await verifyRun(process.argv[1]))" \
  artifacts/h043/h043-2026-07-26T22-13-38-193Z-b4158eab/run.json
```

The expected result is `supported` with `sourceSetExact`, `archiveExact`, `prefixExact`,
`predicatesExact`, `candidateExact`, `hostileMatrixExact`, `tailIndependent`,
`sideEffectAuditExact`, `claimBoundaryExact`, and `verified` all true.

The two preliminary H-043 receipts with semantic SHA-256 prefixes `7f74f149` and `6622657f`
are withdrawn. They are not included and must never be cited as accepted evidence.

## Disclosure and authority boundary

A bounded scan found no credentials, bearer values, passwords, cookies, private keys, or API
keys in the new H-043 text receipts and source closure. The transitive H-042 archive retains its
previously reviewed local path, physical device serial, host and Docker identifiers, group
membership, process identifiers, and experiment timestamps. The H-043 receipt also retains the
same bounded hardware and runtime identities because they are part of the accepted claim.

The human principal accepted the exact H-043 receipt and authorized content-addressed
preservation, repository merge, and opening H-044 read-only. This does not authorize a signal,
actuator, restart, installation, production policy, npm publication, release, or product
specification expansion.
