import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

test('H-038 evidence schema compiles with required fail-closed boundaries', async () => {
  const schema = JSON.parse(
    await readFile(new URL('./schemas/physical-run.schema.json', import.meta.url), 'utf8')
  );
  const ajv = new Ajv2020({ strict: false });
  assert.doesNotThrow(() => ajv.compile(schema));
  assert.equal(schema.properties.invocationAudit.properties.virtualInvocationCount.const, 0);
  assert.equal(schema.properties.invocationAudit.properties.forbidden.maxItems, 0);
  assert.equal(schema.properties.cleanup.properties.successful.const, true);
});
