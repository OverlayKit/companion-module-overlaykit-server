# H-045/H-046 restricted post-live evidence receipt

This directory records the public, non-authorizing identity of the accepted H-045
canonical evidence and its H-046 offline prerequisite. The raw replay bundle is
deliberately not tracked.

## Canonical results

- H-046 outcome: `supported` only within the offline environment-seam boundary
- H-045 run: `h045-2026-07-27T18-07-03-825Z-eb0471d0`
- H-045 outcome: `supported` only within its dynamic read-only acquisition claim
  boundary
- Live classification: `withheld`
- Stage: `not-eligible`
- Reason: `accepted-image-deployment-absent`
- Candidate receipts: `0`
- Authority: `none`
- Action: `null`
- Semantic evidence SHA-256:
  `e88dab701123cd23c4c18b480af7303b9242f93b022299493320c04144072fd7`
- `run.json` SHA-256:
  `ea913d8c577b85cad52070ab3f8e41b3373881e1308fcadd492180d56f53fbcc`
- `verification.json` SHA-256:
  `a2214d8d9c6377fa3776b01be0671ff221198b65b344ceacd14d8381f96c8c06`

The independent verifier reports `verified: true`, exact predecessor and
replacement ledgers, exact and stable repaired sources, exact classification,
zero candidate receipts, producer agreement, and no prohibited capability.

## Signed source anchor

- Exact source count: `24`
- Source-set SHA-256:
  `8db21fe91325c03aa19cb10937f64b61b2e7de9b80205a581107ac099d0db55b`
- Signed source commit:
  `9fc605d428808b571ac5f1709071b4da9c183aef`
- Source commit signature: valid OpenPGP signature
- CHG-0019 SHA-256:
  `6c83d4b15e82ee3727cc941ffc2b8a9023052ea8a306f2e441953fe044a277fa`
- CHG-0020 SHA-256:
  `e8c00014e79af95a9a567cbcfca2f054b25c4b807f549df58b7591aca8ae0c6b`

## Immutable attempt history

- Predecessor reservation SHA-256:
  `27ee9aa2c70adb56682564c6ddc80c43cc40e6a5c5e1edacc23327648aad2f24`
- Predecessor failure SHA-256:
  `710b3b28760239f5971c961f8b0011a18c439c10a4974f548c435ff2a4507fc0`
- Replacement reservation SHA-256:
  `f1eec0451f3c894221e5efa22eb7533a3806af73ba60ab0630d23ae28b004da8`
- Replacement completion SHA-256:
  `d84660770beb011f11b7d08d0cd8002cf7eb71e5809a3efb20edd87b42fa0ae2`

The predecessor ledger remains reservation-plus-failure with no completion or
run. The replacement ledger remains reservation-plus-completion with no failure
and exactly one canonical run. Neither grant is reusable.

## Restricted post-live preservation

The deterministic 11-member replay closure is preserved locally at:

```text
artifacts/h045/post-live-closures/e88dab701123cd23c4c18b480af7303b9242f93b022299493320c04144072fd7/replay-ebc6b52c4cd138082532cac4ee2288a7ab749f8d5a8763ee82b6c51747d3f690.tar
```

- Archive SHA-256:
  `ebc6b52c4cd138082532cac4ee2288a7ab749f8d5a8763ee82b6c51747d3f690`
- Size: `1699840` bytes
- Filesystem mode: `0600`
- Post-live closure receipt SHA-256:
  `89dcad0c6e1fa2c8b26f6f41522fcf5995e93d01af0de88969da89a65d0e4023`
- Local manifest SHA-256:
  `0e67009e93bbf81699e93677f76f33ed86e42451ef25b5ab7c81ddb2b7e4217c`
- Human-acceptance record SHA-256:
  `51be01b76fa0c977235af2db06b6c546002f5b4689aafa92cfeda7a6f59455d0`
- Git status: ignored by the repository's `artifacts/` rule

Two independent builds produced byte-identical POSIX ustar archives. Inspection
confirmed exact member order and hashes, normalized member modes, zero duplicate
or traversal paths, zero links, and byte identity for the historical pre-live
inputs.

The pre-live closure remains byte-identical at SHA-256
`3f6f3c4ff5ade745f6195d2c877098eb7ad0bdebd891b4e89c04ed468016ac5e`.
Its assertions about absent replacement evidence and an unconsumed grant remain
historical pre-live assertions; only the distinct closure above records the
post-live state.

A bounded scan of the JSON evidence, ledger, metadata, and pre-live closure
members found no private-key, cloud-key, GitHub-token, Slack-token,
credential-URL, or credential-field signature. The nested pre-live source
archive retains its separately reviewed disclosure boundary.

## Claim boundary

H-046 establishes only the offline command-environment seam repair. H-045
establishes only the accepted dynamic read-only acquisition mechanism and its
cutoff-bound withheld classification. This receipt grants no signal target,
action, retry, watcher, restart, installation, configuration change, deployment
policy, product-specification expansion, raw publication, push, merge, or H-047
authority.
