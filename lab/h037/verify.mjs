import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import { sha256, sha256Canonical } from './acquisition-lib.mjs';

const LAB_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(LAB_DIRECTORY, '../..');
const IMAGE_DIGEST = 'sha256:2ff41215ab2ed77b5ec3dd74c5e6ec3b01354f57a7ca301b16017444d395544e';

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

export async function verifyAcquisition(filePath) {
  const run = await readJson(filePath);
  const schema = await readJson(path.join(LAB_DIRECTORY, 'schemas', 'acquisition.schema.json'));
  const ajv = new Ajv2020({ allErrors: true, strict: false });
  ajv.addFormat('date-time', validDateTime);
  const validate = ajv.compile(schema);
  assertion(
    validate(run),
    `H-037 schema failed: ${(validate.errors ?? [])
      .map((error) => `${error.instancePath || '/'} ${error.message}`)
      .join('; ')}`
  );
  const { evidenceSha256, ...evidence } = run;
  assertion(sha256Canonical(evidence) === evidenceSha256, 'H-037 canonical evidence hash mismatch');
  for (const [relativePath, expected] of Object.entries(run.collector.sourceSha256)) {
    const absolutePath = path.resolve(REPOSITORY_ROOT, relativePath);
    assertion(
      absolutePath.startsWith(`${REPOSITORY_ROOT}${path.sep}`),
      `H-037 source escaped repository: ${relativePath}`
    );
    assertion(
      sha256(await readFile(absolutePath)) === expected,
      `H-037 source hash mismatch: ${relativePath}`
    );
  }
  const manifest = await readJson(
    path.join(REPOSITORY_ROOT, '.overlaykit/governance/manifest.json')
  );
  assertion(
    manifest.contentHash === run.collector.governanceManifestContentHash,
    'H-037 governance manifest mismatch'
  );
  const h035Path = path.resolve(REPOSITORY_ROOT, run.input.h035Path);
  const h035Bytes = await readFile(h035Path);
  const h035 = JSON.parse(h035Bytes);
  assertion(
    sha256(h035Bytes) === run.input.h035FileSha256 &&
      h035.evidenceSha256 === run.input.h035EvidenceSha256,
    'H-037 does not bind the current H-035 input'
  );
  assertion(run.input.host.osVersion === '43', 'H-037 host is not Fedora 43');
  assertion(
    run.input.device.usbVendorId === '0fd9' && run.input.device.usbProductId === '0080',
    'H-037 device is not exact MK.2 0fd9:0080'
  );
  assertion(
    run.input.companion.repoDigests.some((digest) => digest.endsWith(`@${IMAGE_DIGEST}`)),
    'H-037 Companion image digest mismatch'
  );
  assertion(
    run.input.companion.version === 'v4.3.3' &&
      run.input.companion.revision === '06a7406709d6a858039333a8988047296ef3aa4a',
    'H-037 Companion version or revision mismatch'
  );
  assertion(
    run.before.owner.observed &&
      run.before.owner.pids.length === 0 &&
      !run.before.noDeviceContainerExists &&
      !run.before.noGroupContainerExists &&
      !run.before.positiveContainerExists,
    'H-037 did not start from an unowned clean boundary'
  );
  for (const control of [run.noDevice, run.deviceWithoutGroup, run.positive]) {
    assertion(
      control.container.imageId === run.input.companion.imageId &&
        control.container.state === 'running' &&
        control.container.healthy &&
        control.container.user === 'companion' &&
        control.container.autoRemove &&
        !control.container.privileged &&
        control.process.surfaceUid === 1000,
      `H-037 control ${control.name} identity or isolation mismatch`
    );
  }
  assertion(
    run.noDevice.container.devices.length === 0 &&
      run.noDevice.container.groupAdd.length === 0 &&
      !run.noDevice.process.groups.includes(run.input.host.supplementaryGroupId),
    'H-037 no-device control received device or supplementary group access'
  );
  assertion(
    run.noDevice.signals.serialDiscovered &&
      run.noDevice.signals.openFailed &&
      !run.noDevice.signals.panelReady &&
      !run.noDevice.process.ownsDevice,
    'H-037 no-device control did not fail acquisition as expected'
  );
  assertion(
    run.deviceWithoutGroup.container.devices.length === 1 &&
      run.deviceWithoutGroup.container.devices[0].PathOnHost === run.input.device.devicePath &&
      run.deviceWithoutGroup.container.devices[0].PathInContainer === run.input.device.devicePath &&
      run.deviceWithoutGroup.container.devices[0].CgroupPermissions === 'rwm' &&
      run.deviceWithoutGroup.container.groupAdd.length === 0 &&
      !run.deviceWithoutGroup.process.groups.includes(run.input.host.supplementaryGroupId),
    'H-037 device-without-group control exposure mismatch'
  );
  assertion(
    run.deviceWithoutGroup.signals.serialDiscovered &&
      run.deviceWithoutGroup.signals.openFailed &&
      !run.deviceWithoutGroup.signals.panelReady &&
      !run.deviceWithoutGroup.process.ownsDevice,
    'H-037 device-without-group control did not fail acquisition as expected'
  );
  assertion(
    run.positive.container.user === 'companion' &&
      !run.positive.container.privileged &&
      run.positive.container.devices.length === 1 &&
      run.positive.container.devices[0].PathOnHost === run.input.device.devicePath &&
      run.positive.container.devices[0].PathInContainer === run.input.device.devicePath &&
      run.positive.container.devices[0].CgroupPermissions === 'rwm' &&
      run.positive.container.groupAdd.includes(String(run.input.host.supplementaryGroupId)) &&
      run.positive.process.groups.includes(run.input.host.supplementaryGroupId),
    'H-037 positive control identity or device exposure mismatch'
  );
  assertion(
    run.positive.process.surfaceUid === 1000 &&
      run.positive.process.ownsDevice &&
      run.positive.signals.serialDiscovered &&
      run.positive.signals.panelOpening &&
      run.positive.signals.panelReady &&
      run.positive.signals.firmware !== null &&
      !run.positive.signals.openFailed,
    'H-037 positive control did not causally acquire the MK.2'
  );
  assertion(
    run.noDevice.stop.stopped &&
      run.deviceWithoutGroup.stop.stopped &&
      run.positive.stop.stopped &&
      run.after.owner.observed &&
      run.after.owner.pids.length === 0 &&
      !run.after.noDeviceContainerExists &&
      !run.after.noGroupContainerExists &&
      !run.after.positiveContainerExists,
    'H-037 cleanup or device release failed'
  );
  assertion(
    run.claimBoundary.excludes.some((claim) => claim.includes('physical key')) &&
      run.claimBoundary.excludes.some((claim) => claim.includes('reconnect')),
    'H-037 claim boundary is incomplete'
  );
  return {
    schemaVersion: 'overlaykit-h037-verification/v1',
    hypothesis: run.hypothesis,
    evidenceSha256,
    verified: true,
    companionVersion: run.input.companion.version,
    companionRevision: run.input.companion.revision,
    device: run.input.device,
    noDeviceOpenFailed: run.noDevice.signals.openFailed,
    noGroupOpenFailed: run.deviceWithoutGroup.signals.openFailed,
    positiveFirmware: run.positive.signals.firmware,
    positiveReady: run.positive.signals.panelReady,
    positiveOwnsDevice: run.positive.process.ownsDevice,
    cleaned:
      !run.after.noDeviceContainerExists &&
      !run.after.noGroupContainerExists &&
      !run.after.positiveContainerExists,
    claimBoundary: run.claimBoundary,
  };
}

const inputPath = process.argv[2];
if (!inputPath) throw new Error('Usage: node lab/h037/verify.mjs <acquisition.json>');
process.stdout.write(
  `${JSON.stringify(await verifyAcquisition(path.resolve(inputPath)), null, 2)}\n`
);
