import { canonicalJson, sha256, sha256Canonical } from '../h035/inventory-lib.mjs';

export const COMPANION_IMAGE =
  'ghcr.io/bitfocus/companion/companion:v4.3.3@sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';

export const CLAIM_BOUNDARY = Object.freeze({
  proves: [
    'official Companion 4.3.3 discovery and acquisition behavior in the exact bounded container process',
    'causal differences among no-device, device-without-group, and device-with-group controls',
    'non-root Companion surface process file-descriptor ownership of the exact hidraw node',
    'application log identity for MK.2 serial, model, firmware, open, and ready events',
    'release of the bounded process and temporary configuration after stop',
  ],
  excludes: [
    'native Fedora packaging or production container architecture',
    'stable USB bus, device number, or hidraw index across reconnect or reboot',
    'physical key event delivery, rendered button pixels, or operator perception',
    'USB reconnect, reboot, login, startup, or visual-state recovery',
    'OverlayKit module, command, or production-state behavior',
    'OBS output truth or complete production support',
  ],
});

export function stripAnsi(value) {
  return value.replace(/\u001b\[[0-9;]*m/gu, '');
}

export function parseProcessTable(value) {
  return value
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const match = /^([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+(\S+)\s+(.*)$/u.exec(line);
      if (!match) return { raw: line };
      return {
        pid: Number(match[1]),
        ppid: Number(match[2]),
        uid: Number(match[3]),
        gid: Number(match[4]),
        command: match[5],
        args: match[6],
      };
    });
}

export function parseFdListing(value) {
  return value
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .filter((line) => line.includes(' -> '))
    .map((line) => {
      const [description, target] = line.split(' -> ', 2);
      const descriptor = description.trim().split(/\s+/u).at(-1);
      return { descriptor, target };
    });
}

export function acquisitionSignals(logs, devicePath, serial) {
  const plain = stripAnsi(logs);
  return {
    serialDiscovered: plain.includes(`streamdeck:${serial}`),
    openFailed: plain.includes(`cannot open device with path ${devicePath}`),
    firmware: /StreamDeck firmware version:\s+([^\s]+)/u.exec(plain)?.[1] ?? null,
    panelOpening: plain.includes(`Opening surface panel: streamdeck:${serial}`),
    panelReady: plain.includes(`Surface panel ready: streamdeck:${serial}`),
  };
}

export { canonicalJson, sha256, sha256Canonical };
