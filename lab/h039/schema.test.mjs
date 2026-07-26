import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

test('H-039 schema compiles with supported/refuted and fail-closed boundaries', async () => {
  const schema = JSON.parse(
    await readFile(new URL('./schemas/reconnect-run.schema.json', import.meta.url), 'utf8')
  );
  const ajv = new Ajv2020({ strict: false });
  assert.doesNotThrow(() => ajv.compile(schema));
  assert.equal(schema.properties.outcome.oneOf.length, 2);
  assert.equal(
    schema.properties.collector.properties.node.pattern,
    '^v22\\.(?:2[0-9]|[3-9][0-9])\\.[0-9]+$'
  );
  assert.equal(schema.properties.invocationAudit.properties.virtualInvocationCount.const, 0);
  assert.equal(schema.properties.quietAudit.properties.commandCount.const, 0);
  assert.equal(schema.properties.cleanup.properties.successful.const, true);
  assert.equal(
    schema.$defs.absentHostSnapshot.allOf[1].properties.lsusb.properties.matches.maxItems,
    0
  );
  const physicalRefutation = schema.allOf.find(
    (rule) => rule.if.properties.outcome.properties.stage?.const === 'post-reconnect-physical-input'
  );
  const waitResults =
    physicalRefutation.then.properties.postReconnect.properties.waitResults.allOf[1].properties;
  assert.equal(waitResults.satellite.properties.status.const, 'fulfilled');
  assert.equal(waitResults.causal.properties.status.const, 'rejected');
  assert.equal(
    physicalRefutation.then.properties.postReconnect.properties.causalReceipt.type,
    'null'
  );
});
