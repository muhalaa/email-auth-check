import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const run = promisify(execFile);
const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist', 'cli.js');
const env = { ...process.env, NO_COLOR: '1' };

/* The dmarc subcommand and --help need no network, so they can be run end to end. */

test('cli: --help', async () => {
  const { stdout } = await run(process.execPath, [CLI, '--help'], { env });
  assert.match(stdout, /email-auth-check/);
  assert.match(stdout, /roimaxi\.com/);
});

test('cli: dmarc builds a record', async () => {
  const { stdout } = await run(process.execPath, [CLI, 'dmarc', '--policy', 'reject', '--rua', 'mailto:dmarc@example.com', '--domain', 'example.com'], { env });
  assert.match(stdout, /_dmarc\.example\.com/);
  assert.match(stdout, /v=DMARC1; p=reject; rua=mailto:dmarc@example\.com/);
});

test('cli: dmarc --json', async () => {
  const { stdout } = await run(process.execPath, [CLI, 'dmarc', '--policy', 'quarantine', '--pct', '50', '--json'], { env });
  const j = JSON.parse(stdout);
  assert.equal(j.value, 'v=DMARC1; p=quarantine; pct=50');
});

test('cli: bad policy exits 2', async () => {
  await assert.rejects(run(process.execPath, [CLI, 'dmarc', '--policy', 'block'], { env }), (e) => e.code === 2 && /must be none/.test(e.stderr));
});

test('cli: bad domain exits 2', async () => {
  await assert.rejects(run(process.execPath, [CLI, 'not a domain'], { env }), (e) => e.code === 2 && /not a domain/.test(e.stderr));
});
