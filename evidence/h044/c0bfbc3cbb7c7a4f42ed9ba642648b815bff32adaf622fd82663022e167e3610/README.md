# H-044 restricted evidence receipt

This directory records the public, non-authorizing identity of the accepted H-044
live read-only revalidation. The raw replay bundle is deliberately not tracked.

## Canonical result

- Run: `h044-2026-07-27T02-46-55-692Z-799230e4`
- Hypothesis outcome: `supported`
- Live classification: `withheld`
- Stage: `not-eligible`
- Reason: `historical-container-absent`
- Candidate receipts: `0`
- Semantic evidence SHA-256:
  `c0bfbc3cbb7c7a4f42ed9ba642648b815bff32adaf622fd82663022e167e3610`
- `run.json` SHA-256:
  `5cdc565e0c3db181435e86eaf3932b02aec7c67da2dddbe653052af588af3a5d`
- `verification.json` SHA-256:
  `cfa31401dd5981df4129956797ce6ab879ec01436efc8ad664f9e65ce0086d59`
- Frozen source commit:
  `99c5d5c4bf1e5a8be464b9701f86276fd31a6f67`
- Pre-experiment contract commit:
  `9e2156e7ddc38ebe223824a07f682421b7ee0589`

The independent verifier reconstructed two complete frames, an exposure interval
of `46.766966` milliseconds, one exact `lsusb` invocation, Docker reads bound to
`unix:///var/run/docker.sock`, zero prohibited capabilities, exact classification,
and producer agreement.

## Restricted replay preservation

The deterministic 26-member replay closure is preserved locally at:

```text
artifacts/h044-preserved/c0bfbc3cbb7c7a4f42ed9ba642648b815bff32adaf622fd82663022e167e3610/replay-7783de86dc9fe18edbca1faa7767af7ddf1dbb3a126bb968ebec9aa9d6c4f9bf.tar.gz
```

- Archive SHA-256:
  `7783de86dc9fe18edbca1faa7767af7ddf1dbb3a126bb968ebec9aa9d6c4f9bf`
- Size: `594063` bytes
- Filesystem mode: `0600`
- Git status: ignored by the repository's `artifacts/` rule

The raw bundle contains current host and hardware identifiers required for exact
independent reconstruction. Human acceptance authorizes local content-addressed
preservation but does not authorize publishing that bundle. A bounded scan of the
new run and verification receipts found no private-key, cloud-key, GitHub-token,
Slack-token, credential-URL, authorization-field, password, or API-key signature.

## Claim boundary

H-044 supports only the capability-bounded read-only classification mechanism.
The absent historical container makes the H-043 candidate non-eligible at both
observed cutoffs. This receipt grants no signal target, action, watcher, restart,
installation, production policy, product acceptance, or future authority.
