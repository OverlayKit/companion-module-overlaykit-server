import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { sha256, sha256Canonical } from './inventory-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');

function assertion(condition, message) {
  if (!condition) throw new Error(message);
}

function validDateTime(value) {
  return (
    typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(value) &&
    Number.isFinite(Date.parse(value))
  );
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

async function verifySourceHashes(sourceSha256) {
  for (const [relativePath, expected] of Object.entries(sourceSha256)) {
    const absolutePath = path.resolve(REPOSITORY_ROOT, relativePath);
    assertion(
      absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
      `Collector source escaped repository: ${relativePath}`
    );
    assertion(
      sha256(await readFile(absolutePath)) === expected,
      `Collector source hash mismatch: ${relativePath}`
    );
  }
}

export async function verifyInventory(filePath) {
  const inventory = await readJson(filePath);
  const schema = await readJson(path.join(LAB_DIRECTORY, 'schemas', 'inventory.schema.json'));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addFormat('date-time', validDateTime);
  const validate = ajv.compile(schema);
  assertion(
    validate(inventory),
    `Inventory schema failed: ${(validate.errors ?? [])
      .map((error) => `${error.instancePath || '/'} ${error.message}`)
      .join('; ')}`
  );

  const { evidenceSha256, ...evidence } = inventory;
  assertion(
    sha256Canonical(evidence) === evidenceSha256,
    'Inventory self-hash does not match its canonical evidence'
  );
  await verifySourceHashes(inventory.collector.sourceSha256);
  const manifest = await readJson(
    path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json')
  );
  assertion(
    manifest.contentHash === inventory.collector.governanceManifestContentHash,
    'Governance manifest content hash differs from the inventory'
  );
  assertion(inventory.host.osRelease.VERSION_ID === '43', 'Host is not exact Fedora 43');
  assertion(
    inventory.usb.observed && inventory.usb.matches.length > 0,
    'USB target 0fd9:0080 was not observed'
  );
  assertion(
    inventory.hidraw.observed && inventory.hidraw.matches.length > 0,
    'No matching hidraw node was observed'
  );

  for (const node of inventory.hidraw.matches) {
    assertion(node.udev.observed, `${node.devicePath}: udev properties were not observed`);
    assertion(
      node.udev.properties.ID_VENDOR_ID?.toLowerCase() === '0fd9' &&
        node.udev.properties.ID_MODEL_ID?.toLowerCase() === '0080',
      `${node.devicePath}: udev USB identity mismatch`
    );
    assertion(node.identityStable, `${node.devicePath}: identity changed during collection`);
    assertion(
      node.access.read.allowed && node.access.write.allowed,
      `${node.devicePath}: principal lacks effective read/write access`
    );
    assertion(
      node.opens.readOnlyNonblocking.opened && node.opens.readWriteNonblocking.opened,
      `${node.devicePath}: nonblocking open probes did not both succeed`
    );
    assertion(
      node.ioOperations.bytesRead === 0 && node.ioOperations.bytesWritten === 0,
      `${node.devicePath}: collector performed HID I/O`
    );
    assertion(
      node.owners.before.observed &&
        node.owners.after.observed &&
        !node.owners.before.usageError &&
        !node.owners.after.usageError,
      `${node.devicePath}: process ownership observation failed`
    );
  }
  assertion(inventory.companionProcesses.observed, 'Companion process observation failed');
  assertion(
    inventory.claimBoundary.excludes.some((claim) => claim.includes('Companion acquisition')),
    'Claim boundary omits Companion acquisition exclusion'
  );
  assertion(
    inventory.claimBoundary.excludes.some((claim) => claim.includes('physical key')),
    'Claim boundary omits physical behavior exclusion'
  );

  return {
    schemaVersion: 'overlaykit-h035-verification/v1',
    hypothesis: inventory.hypothesis,
    evidenceSha256,
    verified: true,
    fedoraVersion: inventory.host.osRelease.VERSION_ID,
    kernel: inventory.host.kernel,
    usbMatches: inventory.usb.matches.length,
    hidrawMatches: inventory.hidraw.matches.length,
    ownerPids: inventory.hidraw.matches.flatMap((node) =>
      node.owners.processes.map((process) => process.pid)
    ),
    companionProcesses: inventory.companionProcesses.matches,
    claimBoundary: inventory.claimBoundary,
  };
}

const inputPath = process.argv[2];
if (!inputPath) throw new Error('Usage: node lab/h035/verify.mjs <inventory.json>');
process.stdout.write(
  `${JSON.stringify(await verifyInventory(path.resolve(inputPath)), null, 2)}\n`
);
