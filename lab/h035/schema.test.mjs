import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const labDirectory = path.dirname(fileURLToPath(import.meta.url));

test('compiles the H-035 inventory schema in strict mode', async () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addFormat('date-time', () => true);
  const schema = JSON.parse(
    await readFile(path.join(labDirectory, 'schemas', 'inventory.schema.json'), 'utf8')
  );
  assert.equal(typeof ajv.compile(schema), 'function');
});
