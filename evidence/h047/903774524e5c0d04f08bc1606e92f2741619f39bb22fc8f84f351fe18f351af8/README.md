# H-047 restricted post-review evidence receipt

This is a non-normative, non-authorizing receipt for the exact H-047 repository
inventory and its separate human review. The raw evidence and replay bundle
remain local and deliberately untracked.

## Frozen mechanical evidence

- Subject commit:
  `a68ab8f2c8a64828c1c685161ef9319bd8a837c7`
- Subject tree:
  `9ee6e2f74f7fd6272559d1b91fe4005726cc5b18`
- Subject paths: `238`
- Source anchor:
  `8e2a30c0d6ccf9e70d6654498b490ee623a9f56c`
- Source-set SHA-256:
  `c8f3a6dd4643287460b6f9d623dd5c240d28208628cf017c8b29d679de32ce54`
- Semantic evidence SHA-256:
  `903774524e5c0d04f08bc1606e92f2741619f39bb22fc8f84f351fe18f351af8`
- `run.json` SHA-256:
  `a8d89d2ab4bac0fcbb2a154d036caacdb2ef4424e3acccc1d8d1f01160165a96`
- `candidate-index.json` SHA-256:
  `7054c1990b55cc931d9b0e409772fbb35b5346b255a8c36c6a91fbd9c6a518d9`
- `source-map.json` SHA-256:
  `84172fc400d801e4dfbd439cc37c03118cb177e87fc6c230c885eb5e6ec94ea1`
- `verification.json` SHA-256:
  `58cc15ba5de1cd75527789cba6693a66820f5c0c888c60450364977c41d17ac3`

The two canonical directories are byte-identical. The independent verifier
reports complete mechanical coverage, `101` candidates, `106` edges, `2`
atoms, `3` archive roots, zero chain components, and zero eligible chains.

The frozen producer and verifier outcome remains `inconclusive`, at
`source-admission`, for reason
`incomplete-ambiguous-or-unknown-coverage`. It is not rewritten after review:
its seven unknowns consist of one pending acceptance and six pending human
semantic judgments.

## Canonical human review

- Review-map raw SHA-256:
  `d38ad8bbe9149afdae4590886cc92935261eca4fed3fe1c865d1cf16e3cc7139`
- Review-map canonical JSON SHA-256:
  `fbd9176a3d63694bd0bda91b3f2e60c4ac00e0770024470df871cb9cdebd4c73`
- Canonical human-motion SHA-256:
  `96ba495b155fa70a7ea18338863f38c8679135a89b417ff56397702b82601482`
- Human-acceptance record SHA-256:
  `b79b6a2573f081ef73545d501480a9a303af2b33dcb5ebbdd510db8794e8b98e`
- Post-review assessment SHA-256:
  `be753e0bac489ac8480730dbb8bc971d664dc0de3208e06c0f12f45e3a5618c5`

The registered human principal accepted the exact map, every individual
classification and dismissal, and the six pending judgments. That separate
review layer adjudicates H-047 as `refuted` exclusively inside the exact
repository boundary because zero complete eight-predicate desired-state chains
remain.

## Restricted local preservation

The deterministic 23-member POSIX ustar closure is preserved locally at:

```text
artifacts/h047/post-review-closures/903774524e5c0d04f08bc1606e92f2741619f39bb22fc8f84f351fe18f351af8/replay-c7eca4b7f7030104aab4488e8e9c931f0d6d1e99dc1224b236746e8c8aa03890.tar
```

- Archive SHA-256:
  `c7eca4b7f7030104aab4488e8e9c931f0d6d1e99dc1224b236746e8c8aa03890`
- Size: `1136640` bytes
- Filesystem mode: `0600`
- Manifest SHA-256:
  `986f46826173a2d10f620d6e776931e0e6466aeecea6814b46646c588e33fbfa`
- External closure SHA-256:
  `37caabe82ca7a0c3a639484be86a62cc819cb3bb16c7e1b3db388a9ae4c269d5`
- Git status: ignored by the repository's `artifacts/` rule

Two independent builds were byte-identical. Inspection confirmed exact member
order, hashes and lengths, normalized `0600` modes, zero duplicates, zero
traversal paths, and zero non-regular members. A bounded scan of the canonical
evidence JSON and post-review metadata found zero private-key, cloud-key,
GitHub-token, Slack-token, or credential-URL signatures. The signed tracked
sources retain their repository disclosure boundary.

## Claim boundary

The post-review result establishes only that the exact immutable repository
subject contains zero complete desired-state chains for the exact accepted
Companion image. It does not establish absence of external policy, operator
intent, host compliance, drift, cause, or actual external operational
ownership.

No ADR candidate is activated. Authority remains `none` and action remains
`null`. CHG-0023 records only the acceptance transition; this receipt grants no
installation, configuration, signal, restart, reconciliation, remediation,
production policy, raw publication, or product-specification authority.
