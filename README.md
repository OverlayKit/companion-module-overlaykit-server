# OverlayKit Companion Module

This repository contains the governed Bitfocus Companion module for controlling an
[OverlayKit](https://github.com/OverlayKit/overlaykit) production from Linux.

The accepted H-031 boundary connects one module instance to one OverlayKit Show, learns controls
from signed server state, and exposes component visibility actions and feedback through Companion
Module API 2.0. The accepted H-034 boundary reproduces the complete Companion 4.3.3 application
against the real OverlayKit OSS server on isolated Ubuntu 24.04 LTS nodes. The accepted H-042
boundary observes one post-login MK.2 reacquisition after replacement of one revalidated
SurfaceThread under the exact Fedora 43 and Companion 4.3.3 identities. It does not establish
physical button delivery, pixels, complete recovery, or a production signal or restart policy.

## Development Status

- Governance and legal provenance: active
- Companion adapter host boundary: accepted
- Complete Companion application lab: H-034 accepted for the pinned emulator boundary
- Physical reacquisition mechanism: H-042 accepted only for one bounded worker replacement
- npm publication: not established
- Bitfocus module registry: not established
- Physical button delivery, pixels, and production recovery: not established

## Accepted Adapter Boundary

- Node 22 ESM and Companion Module API 2.0
- Exact, digest-pinned `@overlaykit/protocol` tarball from signed OverlayKit commit `201cd15`
- `visibility.show`, `visibility.hide`, and `visibility.toggle`
- Signed `active`, `inactive`, `unknown`, `disconnected`, `failed`, and `unavailable` feedback
- Secure `wss://` by default; loopback `ws://` and explicit trusted-LAN opt-in
- No persisted operational state and no optimistic visibility changes

## Development

Use Node 22.20 or newer within the Node 22 line.

```bash
npm ci --engine-strict
npm run check
npm run build
```

`npm run check` verifies governance, licensing, the exact protocol artifact, source boundaries,
runtime dependency audit, lint, types, tests, official-host behavior, and the generated Companion
archive.

## Governance

The compiled contract under `.overlaykit/governance/` is normative. Read [AGENTS.md](AGENTS.md)
before changing the repository.

## License and Attribution

Licensed under the Apache License 2.0.

Copyright 2026 [Rodrigo Vicente (@rodrigoteamx)](https://x.com/rodrigoteamx).
See [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
