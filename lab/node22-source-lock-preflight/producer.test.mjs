import assert from 'node:assert/strict';
import { test } from 'node:test';

import { makeExpectedEvidence, makeObservationSnapshot } from './fixtures/synthetic-boundary.mjs';
import { produceSourceLock } from './producer.mjs';

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function expectProducerRejection(snapshot, code) {
  assert.throws(
    () => produceSourceLock(snapshot),
    (error) => error?.name === 'SourceLockProducerError' && error?.code === code
  );
}

test('producer deterministically closes the exact synthetic topology', () => {
  const first = produceSourceLock(makeObservationSnapshot());
  const second = produceSourceLock(makeObservationSnapshot());

  assert.deepEqual(first, makeExpectedEvidence());
  assert.deepEqual(first, second);
  assert.equal(
    first.semanticSha256,
    'bdcb8d49f6b3b34605a868b4f12b07766bb612d536a716cbe6d14967ee28e983'
  );
  assert.deepEqual(first.counts, {
    descriptors: 687,
    directories: 74,
    indirections: 26,
    layers: 25,
    mounts: 25,
    regularFiles: 613,
  });
  assert.deepEqual(
    first.layers.map((layer) => layer.entryCount),
    [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 12, 56, 10, 5, 511, 13, 42, 17, 5]
  );
  assert.deepEqual(
    first.layers.map((layer) => layer.resolutionChain.length),
    [0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 2, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  );
});

test('producer preserves 26 occurrences as 12 unique synthetic link nodes', () => {
  const evidence = produceSourceLock(makeObservationSnapshot());
  const occurrences = evidence.layers.flatMap((layer) => layer.resolutionChain);
  const uniqueNodes = new Set(
    occurrences.map(
      (entry) => `${entry.requestedPath}\u0000${entry.linkTarget}\u0000${entry.resolvedPath}`
    )
  );

  assert.equal(occurrences.length, 26);
  assert.equal(
    occurrences.filter(
      (entry) => entry.requestedPath === '/__overlaykit_source_lock_fixture__/aliases'
    ).length,
    15
  );
  assert.equal(uniqueNodes.size, 12);
});

test('producer output is detached from the mutable observation object', () => {
  const snapshot = makeObservationSnapshot();
  const evidence = produceSourceLock(snapshot);

  snapshot.layers[3].resolutionChain[0].linkTarget = 'post-return-mutation';
  snapshot.layers[20].entries[1].bytesUtf8 = 'post-return-mutation';
  snapshot.mounts[0].target = '/__overlaykit_source_lock_fixture__/mounts/post-return-mutation';

  assert.deepEqual(evidence, makeExpectedEvidence());
});

test('producer rejects layer, mount, descriptor, and indirection omission in memory', () => {
  const missingLayer = makeObservationSnapshot();
  missingLayer.layers.pop();
  missingLayer.mounts.pop();
  expectProducerRejection(missingLayer, 'layer-roster-incomplete');

  const missingMount = makeObservationSnapshot();
  missingMount.mounts.pop();
  expectProducerRejection(missingMount, 'mount-roster-incomplete');

  const missingDescriptor = makeObservationSnapshot();
  missingDescriptor.layers[20].entries.pop();
  expectProducerRejection(missingDescriptor, 'descriptor-roster-incomplete');

  const missingIndirection = makeObservationSnapshot();
  missingIndirection.layers[3].resolutionChain.pop();
  expectProducerRejection(missingIndirection, 'indirection-roster-incomplete');
});

test('producer rejects symlink drift before emitting a closure', () => {
  const snapshot = makeObservationSnapshot();
  snapshot.layers[3].resolutionChain[0].linkTarget = 'drifted';
  expectProducerRejection(snapshot, 'symlink-chain-drift');
});

test('producer rejects layer, descriptor, and mount collision', () => {
  const layerCollision = makeObservationSnapshot();
  layerCollision.layers[1].id = layerCollision.layers[0].id;
  expectProducerRejection(layerCollision, 'layer-id-collision');

  const descriptorCollision = makeObservationSnapshot();
  descriptorCollision.layers[16].entries[1].logicalPath =
    descriptorCollision.layers[16].entries[0].logicalPath;
  expectProducerRejection(descriptorCollision, 'descriptor-key-collision');

  const mountCollision = makeObservationSnapshot();
  mountCollision.mounts[1].target = mountCollision.mounts[0].target;
  expectProducerRejection(mountCollision, 'mount-target-collision');
});

test('producer rejects source path rebinding and mount rebinding', () => {
  const sourceRebinding = makeObservationSnapshot();
  sourceRebinding.layers[0].sourceRealPath = '/__overlaykit_source_lock_fixture__/sources/rebound';
  expectProducerRejection(sourceRebinding, 'source-path-rebound');

  const mountRebinding = makeObservationSnapshot();
  mountRebinding.mounts[0].layerId = mountRebinding.mounts[1].layerId;
  expectProducerRejection(mountRebinding, 'mount-layer-collision');
});

test('producer rejects real-source and authority overclaims', () => {
  const realSource = makeObservationSnapshot();
  realSource.synthetic = false;
  expectProducerRejection(realSource, 'real-source-observation-forbidden');

  const authority = makeObservationSnapshot();
  authority.authority = 'producer';
  expectProducerRejection(authority, 'authority-overclaim');

  const unexpected = clone(makeObservationSnapshot());
  unexpected.expectedRootSha256 = '0'.repeat(64);
  expectProducerRejection(unexpected, 'observation-shape-invalid');
});
