# Node 22 pre-attempt binding execution receipt

This tracked receipt preserves only the identities and bounded interpretation of the
identity-bound CHG-0042 execution. It is non-normative and non-authorizing: it does
not publish raw bytes, close H-055, create an ADR or SPEC, change product behavior,
grant operational authority, or close the independent global verification blocker.

## Bounded execution

- Study: `NODE22-PRE-ATTEMPT-BINDING-PREFLIGHT-001`
- Status: `candidate-pre-attempt-binding-executed`
- Apparatus commit: `05b7726ab5ce42501544777bcf4b2ef6f2b4fbe64`
- Apparatus tree: `62a3709375d450f4c5706a519f3da454e7770635`
- Plan raw SHA-256:
  `2c63fbcb2e5d5c4a763080ac174783582960edb70a48b29a97b000c5aff0f243`
- Plan hash:
  `bae4dad18ef70e54e5a6c0f28109d20b27de0840cd0c94d86a9381b4521699e4`
- Manifest raw SHA-256:
  `bd786dcbe38a5b5cfc6a76c80b5b5fb7836eb6092fababfca8bc21109daefdd1`
- Manifest contentHash:
  `705bce8d515fdd20366b4ecf356bada7195a03b99f699f8eee0217152acb4688`
- CHG-0042 raw SHA-256:
  `1d4e674bbbfc770a6de9c6d9902e8f1153374ee2d2c65d193ece39e613319774`
- Subject raw SHA-256:
  `e10b666bb6eef1f954f5fce70df6c43b491a75877af658d269b4c000db6c30cd`
- Source-set descriptor SHA-256:
  `be0f3db52c34b2ee982df09cb5195c229684604c62b784d8b8c70477fab7948b`

The model-visible human response `autorizo` followed an explicit request to authorize
only CHG-0042 execution bound to the identities above. No inaccessible transport bytes,
external identity signature, H-055 authorization, ADR/SPEC acceptance, product change, or
blocker closure by extrapolation is claimed.

## Local raw identities

The raw artifacts are local and ignored under
`artifacts/node22-pre-attempt-binding-preflight/b428e93e70f8e9e7b275c4c1135ee77b2b8ebc3f5bc9eac6220fd2f3ae95ccbe/`.
They are intentionally absent from Git.

- External launcher raw SHA-256:
  `a8d847cf867773705d93de69c27a34a4d230eb913e41da79a0170f2ab26e62a4`
- Run raw SHA-256:
  `cec0df97eb9bb04aabb08f9bec153ed4b614de95fe359d3e3d0735b34b8b41ac`
- Run semantic SHA-256:
  `b428e93e70f8e9e7b275c4c1135ee77b2b8ebc3f5bc9eac6220fd2f3ae95ccbe`
- Precontract raw SHA-256:
  `bc932b4f45932e140c3b36f8f230b9a7d933643265adfa7e7eb3576a8461a90b`
- Summary raw SHA-256:
  `4fe6baf1854f423f2a7c6849adf954d0b5c4f050afaa352188aac438aa34497d`
- Grant string SHA-256:
  `1055410f721192746f2acca80b75eeded4c0bdf2fbcf3535105fa9bbcab4d4c1`

## Observed branch and control

The launch-failure branch materialized reservation
`b67b4413447402780ffe58336b8d3c4f3712a9e2ded82b8776c169862ea989a3`
before stage-1 load and invocation. The ordered events were
`reservation-durable`, `stage1-load`, `stage1-invoke`. It observed zero attempts
and terminal raw SHA-256
`cbc6ab7f18c99fe9a6ef995f6a79a727e5b1163584b8cdc0e0a1e73dda309772`.
The independent verifier reconstructed `candidate-launch-failure-reconstructed`
with terminal semantic SHA-256
`5724e2e7d238828ee85b477465ee3ef27f45bbc1233c6f9cd26dc225981ad705`.

The partial-write control wrote a strict 31-byte reservation prefix with raw
SHA-256 `5c8a160edbca41e58c061721a9cccfc54509d675330792c40b27001faa6a41eb`,
returned `synthetic-partial-write-injected`, consumed the slot so retry returned
`reservation-already-consumed`, and preserved zero stage-1 events. The independent
verifier classified this as `candidate-control-envelope-consistent` with
`assessed: false`.

## Interpretation

Within only this synthetic commit/tree/source-set/grant boundary, the execution answers
the first CHG-0042 blocking unknown: stage-0 can create, fsync, read back and independently
verify a completely bound reservation before stage-1 loading.

The second CHG-0041 blocker remains open: independent global run-and-control verification
preservation is still unresolved. This receipt does not make H-055 or real-source execution
eligible.
