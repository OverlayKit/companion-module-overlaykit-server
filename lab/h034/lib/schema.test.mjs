import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import Ajv2020 from 'ajv/dist/2020.js';

const labDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

test('compiles the H-034 run and receipt schemas in strict mode', async () => {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  ajv.addFormat('date-time', () => true);
  const schemas = await Promise.all(
    ['run.schema.json', 'receipt.schema.json'].map(async (name) =>
      JSON.parse(await readFile(path.join(labDirectory, 'schemas', name), 'utf8'))
    )
  );

  for (const schema of schemas) {
    assert.equal(typeof ajv.compile(schema), 'function');
  }
});
