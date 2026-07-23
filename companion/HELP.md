## OverlayKit Server

Create a Show-scoped device credential in OverlayKit and obtain its matching
public Device Trust Bundle.

Configure the fixed `/device` WebSocket endpoint, the bearer in the secret
field, and the complete Trust Bundle JSON. `wss:` is required unless the
endpoint is loopback or Trusted LAN mode is explicitly enabled.

Each module instance learns exactly one Show and its available component
visibility controls from signed server bootstrap. Rotate or revoke the
credential from OverlayKit when the Companion host should lose authority.
