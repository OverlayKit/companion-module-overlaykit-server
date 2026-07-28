# H-048 restricted bounded-inconclusive evidence receipt

This is a non-normative, non-authorizing receipt for the exact H-048
Git-boundary inventory and its separate human acceptance. The raw evidence and
replay bundle remain local and deliberately untracked.

## Frozen source anchor

- Signed source commit:
  `60da0d9e450f8b2d9253a9dd9ec6d9efa871de43`
- Parent:
  `2d46d1c60e7aced224b47a8857d93015c5fb5c91`
- Tree:
  `8a44fc2f1efddf28323e30c7a4cda5c0f32517c7`
- Source-set SHA-256:
  `e8f25bcbba666dd4cdf5dae1bb037e446dcc55d2da57d6ed39a6bd167c558b31`
- Sources: `14`
- Signature: valid OpenPGP signature by signing subkey
  `7D72DEBDA1D36D34`

The canonical run truthfully recorded its sources as local, content-addressed,
and unsigned because commit was prohibited during execution. The later signed
commit authenticates the same exact bytes without rewriting that temporal
record.

## Canonical evidence

- Semantic evidence SHA-256:
  `f2a5a932afcb4dcfbe85c099b86965c7fc51092ab901689510c50e0c7449fae5`
- `run.json` SHA-256:
  `ee809020b6be365595f174e51751bf81a98a2a96b9a5aac43cbabd86b8a2e28f`
- `verification.json` SHA-256:
  `66741a97480cec3ba050e68106a8f83eb57ea5c7f38eefbc73a2d792c31107c9`
- `candidate-index.json` SHA-256:
  `3632620b92fb2002165c09e54f230180136494a1eff606c155b271ccb2ee2205`
- `review-universe.json` SHA-256:
  `0ec6250798859bafa5228f4eb1b64995f51ce78b506abfe1f7c28e16bbb60f5e`
- `source-closure.json` SHA-256:
  `f4415ed1a4fd53f77ff34a57bc5e06e76dd3097d4da199c0332638c54311df45`
- `source-map.json` SHA-256:
  `bf99277c2e0532aa624bc33734fb594275d32404c9a2308fecb9d8237c8766f2`

The two v3 canonical directories are byte-identical and independently
verified. The closed inventory contains 904 sources, 599 default candidates,
1,508 indirections, 83 unresolved indirections, six unknown groups, zero
eligible chains, and all eight predicates missing.

## Human acceptance boundary

- Canonical response text SHA-256:
  `f897bb6b7a6bcf636d6d325150371977f50cafbb747035345ceb81863f8407d0`
- Local human-acceptance record SHA-256:
  `182a4617b7542531b914ae9caf0b9044ac8105c0896819b0575cf2a3c49f38e5`
- Local post-review assessment SHA-256:
  `582f24a6b8257bd5ad389cb5d9d88a491770516b507573cecf315ccf6d59b702`

The principal accepted the exact evidence only as:

```text
inconclusive / source-admission / accepted-source-anchor-opaque
```

The acceptance does not close or accept the five pending review-map
judgments. `lab/h048/review-map.json` remains byte-identical with status
`agent-proposed-pending-human-acceptance` and `humanAcceptanceRef: null`.
Therefore zero eligible chains are not promoted to refutation.

## Restricted local preservation

- Local replay archive SHA-256:
  `34a695993275182f3536c5e454df48ce9de32e448de486e27f23a4bbcc5b6810`
- Archive length: `7,693,312` bytes
- Archive members: `58`
- Local manifest SHA-256:
  `78eb9f250fa2a03f02e1409e772fad209df8ade931309bd4262eb09c4a59ce0c`
- Local closure SHA-256:
  `fce1df7a580f6658479f917053e7998e70a4fd62b3dac8f7fb197283a74f81ae`

The restricted POSIX ustar replay is preserved locally at:

```text
artifacts/h048/post-review-closures/f2a5a932afcb4dcfbe85c099b86965c7fc51092ab901689510c50e0c7449fae5/replay-34a695993275182f3536c5e454df48ce9de32e448de486e27f23a4bbcc5b6810.tar
```

Two independent in-process builds were byte-identical. Independent extraction
confirmed exact member order, hashes, lengths, normalized mode `0600`, no
duplicates, no symlinks, no non-regular entries, and no traversal paths. A
bounded scan of canonical JSON and post-review metadata found zero private-key,
cloud-key, GitHub-token, Slack-token, or credential-URL signatures.

## Claim boundary

This receipt establishes only that the exact nominated accessible Git evidence
produced the accepted bounded inconclusive result. It does not establish the
existence or absence of desired-state policy, operator intent, host compliance,
drift, cause, actual external ownership, or a remedy.

No ADR candidate is activated. Authority remains `none` and action remains
`null`. Raw-artifact publication, live observation, installation,
configuration, reconciliation, signal, restart, and production mutation remain
unauthorized.
