# Node 22 boundary-preflight bounded review receipt

This tracked receipt preserves only the identities and claim boundary of the accepted Node 22
successor-boundary preflight and its later Git transition. It is non-normative and
non-authorizing: it contains no raw replay bytes, closes no blocker, creates no production rule,
and grants no operational action.

## Frozen preflight review

- Study: `NODE22-BOUNDARY-PREFLIGHT-001`
- Run: `node22-boundary-preflight-4101216b06f6ba66eb02f80e`
- Raw evidence SHA-256:
  `7840707ad717258316355745f27536414074cc1922eadf260ecfa2e1770ac3d2`
- Semantic evidence SHA-256:
  `4101216b06f6ba66eb02f80e919b9718c412968a3b936afcd5ddedf23b8dc164`
- Persisted 25-layer source-root SHA-256:
  `ef647fc46402021191054e33ee5ce2182e0980f94b20efc3109da37813b6653a`
- Proposed `CHG-0036` raw SHA-256:
  `2ff88d94d8768b23548e64d066922aec3e1d0b8ba7aaab27907f8af0432bf492`
- Pre-publication governance manifest raw SHA-256:
  `5f4f3882371e7f504c15b25d5e3fa7a9bc11c77d34fb51412d0b2bf10c4589d0`
- Subject-lock raw SHA-256:
  `c909b2c5736c1b50ee03b03ac29dc3d4881db04d455fab05f93e6685486692e6`
- Apparatus content SHA-256:
  `d8feddf63984d04854e98b52c547ca93baf813b49488ec04d1a5605fb21aebcd`
- Accepted H-054 raw SHA-256:
  `250e6115b9e9dc6d9e750788c16626657feca5577c102b84a48e4fb4bf2444f2`
- Accepted H-054 semantic SHA-256:
  `8547552f833c37664099febcc0ad5ab081a277806e129a4b9dba98cdd39b8ec0`

The accepted result remains `inconclusive` for
`known-boundary-completeness-blockers-remain`. The exact blockers are:

1. `exhaustive-esm-and-open-file-trace-not-admitted`
2. `content-addressed-effective-seccomp-policy-not-admitted`
3. `kernel-vdso-and-late-loaded-object-closure-not-established`
4. `bubblewrap-host-dynamic-library-and-effective-kernel-enforcement-not-independently-traced`
5. `worker-and-child-process-cardinality-not-independently-traced`
6. `universal-successor-absence-not-provable-without-exhaustive-trace`
7. `anchor-resolver-host-dynamic-library-and-git-object-read-closure-not-independently-traced`
8. `path-execution-image-identity-not-atomically-bound`
9. `successor-apparatus-and-accepted-h054-layer-source-lock-not-established`
10. `failed-attempt-evidence-preservation-and-outcome-derivation-not-established`

The producer raw remains byte-identical with `humanReview.accepted: null`, all 31 controls
`deferred-to-independent-verifier`, no ADR candidate, `authority: none`, and `action: null`.
Human review separately accepted two deterministic producer attempts, two independent reruns, and
31/31 independent controls only within the nominated boundary. The independent rerun receipt bytes
are not tracked or claimed here.

`sourceClosureQualification:
current-state-pre-post-observation-not-precontract-anchor` and `failureBranch:
not-materializable-by-current-producer` are verifier-derived findings accepted by the human
principal; they are not represented as fields from the canonical producer raw.

## Local unsigned post-review closure

The deterministic closure remains local and ignored under `artifacts/`. Its identities are:

- Human acceptance:
  `7c31039768172edcadd9296e4954125eb6a1df1e661d370290c35335f7817f3e`
- Post-review assessment:
  `328f47b09fbca6049c2bc0e2cb85e16aa22c3f968a71eadee451790af434432b`
- Local source anchor:
  `7bdec54f47264b9b9c4c1fa81ee4e6cfa8e5c52eafe0291f7ed92c23cdafb410`
- Local closure manifest:
  `2663a3075b887e7e42d03783f28e88f2452db29f9a4944c67f988c54274fabc6`
- Eighteen-member POSIX-ustar replay:
  `e891e09ade7c7801653677e8624e1e0b615cf37ed84f18d923e624d224a633c3`
- External closure:
  `2ba4571e27b59e1e4aa59482ff752405d206d87f1713346302c60866b3424ca9`
- Fourteen-source pre-review descriptor set:
  `72d5995a395ee5e59b133e98a1a26cee151cc1e15ba3753ed1b2375930f0cb00`

A later Git signature authenticates only the exact tracked publication tree. It cannot
retroactively sign this local closure or publish any member under `artifacts/`.

## Later Git transition

After the complete closure handoff, the human principal supplied the model-visible text
`dale commit merge y lo que sigue`. Its represented UTF-8 value is 32 bytes with SHA-256
`b333198077fe4bd0dbce41b88c59baaf612fe5b05c5742c5ba9667a8e9bd98df`. No inaccessible transport
bytes are claimed.

Bound to the immediately preceding handoff, this later response authorizes a signed commit of the
reviewed tracked boundary, an instrumental non-force branch push, the protected pull request and
required validation, an allowed merge commit, and only a separately governed read-only discovery
after merge.

## Publication and continuation boundary

The atomic tracked publication boundary consists of `CHG-0036`, publication successor
`CHG-0037`, the deterministic governance manifest, all ten files in
`lab/node22-boundary-preflight/`, and this receipt. Before `CHG-0037` and this receipt were added,
the twelve reviewed tracked paths had canonical descriptor-set SHA-256
`c0db6742e86bee2e2963a242386bf687a6c710d70d36a71c90e02c1190008710`.

The raw run, H-054 raw, post-review metadata, replay archive, and external closure remain local,
ignored, and absent from Git publication.

After protected merge, continuation is limited to governed discovery of the exact source-lock and
failure-preservation questions against the new immutable commit and tree. It does not authorize a
failure-branch harness, H-055, another experiment, ADR, SPEC, policy, product implementation, live
observation, USB/hidraw, Docker, host configuration, release, or package publication.
