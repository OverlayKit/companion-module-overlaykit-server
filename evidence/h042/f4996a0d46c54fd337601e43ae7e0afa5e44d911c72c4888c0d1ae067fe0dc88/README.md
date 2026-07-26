# H-042 accepted evidence anchor

This is a non-normative, content-addressed index for the exact evidence accepted by the
human principal on 2026-07-26. The governance decision and acceptance contract remain the
normative records.

- Hypothesis: `H-042`
- Run: `h042-2026-07-26T16-19-05-858Z-efaf85fa`
- Semantic evidence SHA-256:
  `f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88`
- Run file SHA-256:
  `be39e69140f733e7f56e371f144b6e7b0cd43c05b7be6bfea9850c440679a7b6`
- Verification file SHA-256:
  `0fc4f3cd7f78fe1184331a40f97874521d97d6f5c677a4829588a6dc676e6919`
- Source-bound `CHG-0013` SHA-256:
  `6e7050e85f5fa94c2677b1f1a6a400ca1ed0136fffd860c851d6aa8975514b87`

## Git-preserved replay closure

The same Git commit that carries this index preserves the exact 70-file replay closure in:

`replay-15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36.tar.gz`

The deterministic archive is 290,821 bytes and its SHA-256 is:

`15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36`

The archive retains these original repository-relative paths:

- `artifacts/h037/acquisition-2026-07-25.json`
- `artifacts/h039/h039-2026-07-25T22-12-14-212Z-e6c2b45e/run.json`
- `artifacts/h040/h040-2026-07-25T22-53-48-398Z-94d8ac80/run.json`
- every file in
  `artifacts/h041/h041-2026-07-26T00-56-42-118Z-0423725f/`
- every file in
  `artifacts/h042/h042-2026-07-26T16-19-05-858Z-efaf85fa/`
- every source listed by `collector.requiredSources` in the H-042 `run.json`

The H-042 verifier freshly verifies H-041 and validates all transitive receipts and artifact
hashes used by the accepted claim. The sources are also ordinary files in the containing Git
commit. In a clean checkout at the original absolute repository path, restore only the ignored
artifact paths and replay with Node 22:

```bash
tar -xzf \
  evidence/h042/f4996a0d46c54fd337601e43ae7e0afa5e44d911c72c4888c0d1ae067fe0dc88/replay-15b2589976cb3a4cff95af807d52728fee83a2f5b9983969f61e0663bfcc3b36.tar.gz \
  --wildcards 'artifacts/*'

node lab/h042/verify.mjs \
  artifacts/h042/h042-2026-07-26T16-19-05-858Z-efaf85fa/run.json
```

The expected result is `supported`, `sourceSetExact: true`, `artifactHashesValid: true`,
`cleaned: true`, and `verified: true`. The canonical run records the original absolute
repository path; replay at another path requires an isolated path mapping or a separately
governed portable verifier. Canonical files must not be redacted or rewritten.

## Disclosure review

A bounded scan found no credentials, bearer tokens, passwords, cookies, or private keys in
this replay closure. The evidence necessarily contains the accepted physical device serial,
the local principal path `/home/rod`, host and container identifiers, process identifiers,
and experiment timestamps. Human acceptance authorized local Git preservation only; it did
not authorize push, publication, merge, installation, or release.

This anchor does not broaden the H-042 claim boundary and does not authorize a production
signal, supervisor, restart, device-bind, or cgroup policy.
