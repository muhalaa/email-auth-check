import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildDmarcRecord, validateDmarc, optionsFromRecord } from '../dist/index.js';

test('minimal record', () => {
  const r = buildDmarcRecord();
  assert.equal(r.value, 'v=DMARC1; p=none');
  assert.equal(r.host, null);
  assert.equal(r.issues[0].level, 'warn');
});

test('reject with rua and domain', () => {
  const r = buildDmarcRecord({ domain: 'example.com', policy: 'reject', rua: 'dmarc@example.com' });
  assert.equal(r.host, '_dmarc.example.com');
  assert.equal(r.value, 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com');
  assert.deepEqual(r.authorisations, []);
  assert.equal(r.issues.length, 0);
});

test('defaults are left out, non-defaults are written in order', () => {
  const r = buildDmarcRecord({
    policy: 'quarantine',
    subdomainPolicy: 'reject',
    pct: 50,
    rua: ['a@example.com', 'mailto:b@example.com'],
    ruf: 'f@example.com',
    fo: ['1', 's'],
    adkim: 's',
    aspf: 's',
  });
  assert.equal(
    r.value,
    'v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:a@example.com,mailto:b@example.com; ruf=mailto:f@example.com; fo=1:s; adkim=s; aspf=s'
  );
  const same = buildDmarcRecord({ policy: 'reject', subdomainPolicy: 'reject', pct: 100, adkim: 'r', aspf: 'r', fo: ['0'] });
  assert.equal(same.value, 'v=DMARC1; p=reject');
});

test('pct is left out at p=none, bad pct is an error', () => {
  assert.equal(buildDmarcRecord({ policy: 'none', pct: 30 }).value, 'v=DMARC1; p=none');
  const bad = buildDmarcRecord({ policy: 'reject', pct: '150' });
  assert.equal(bad.value, 'v=DMARC1; p=reject');
  assert.equal(bad.issues.find((i) => i.field === 'pct').level, 'error');
});

test('fo is only written with a ruf address', () => {
  const r = buildDmarcRecord({ policy: 'reject', fo: ['1'] });
  assert.equal(r.value, 'v=DMARC1; p=reject');
  assert.ok(r.issues.some((i) => i.field === 'fo'));
  assert.equal(buildDmarcRecord({ policy: 'reject', ruf: 'f@example.com', fo: ['0', '1'] }).value, 'v=DMARC1; p=reject; ruf=mailto:f@example.com; fo=1');
});

test('external report address needs an authorisation record', () => {
  const r = buildDmarcRecord({ domain: 'example.com', policy: 'none', rua: 'x@reports.dmarcvendor.net' });
  assert.deepEqual(r.authorisations, [{ host: 'example.com._report._dmarc.reports.dmarcvendor.net', value: 'v=DMARC1' }]);
  const sub = buildDmarcRecord({ domain: 'mail.example.co.uk', policy: 'none', rua: 'x@example.co.uk' });
  assert.deepEqual(sub.authorisations, []);
});

test('bad addresses are left out with an error', () => {
  const r = buildDmarcRecord({ policy: 'none', rua: 'not-an-address, ok@example.com' });
  assert.equal(r.value, 'v=DMARC1; p=none; rua=mailto:ok@example.com');
  assert.match(r.issues.find((i) => i.level === 'error').text, /not-an-address/);
});

test('p=reject with sp=none warns', () => {
  const r = buildDmarcRecord({ policy: 'reject', subdomainPolicy: 'none', rua: 'a@example.com' });
  assert.equal(r.value, 'v=DMARC1; p=reject; sp=none; rua=mailto:a@example.com');
  assert.ok(r.issues.some((i) => i.field === 'subdomainPolicy' && i.level === 'warn'));
});

test('invalid policy throws', () => {
  assert.throws(() => buildDmarcRecord({ policy: 'block' }), /policy must be/);
});

test('validateDmarc', () => {
  const ok = validateDmarc('v=DMARC1; p=reject; rua=mailto:a@example.com; adkim=s');
  assert.equal(ok.usable, true);
  assert.equal(ok.policy, 'reject');
  assert.equal(ok.issues.length, 0);

  const noV = validateDmarc('p=reject');
  assert.equal(noV.usable, false);

  const fallback = validateDmarc('v=DMARC1; rua=mailto:a@example.com');
  assert.equal(fallback.usable, true);
  assert.equal(fallback.policy, 'none');

  const ignored = validateDmarc('v=DMARC1; pct=100');
  assert.equal(ignored.usable, false);

  const order = validateDmarc('v=DMARC1; rua=mailto:a@example.com; p=none');
  assert.ok(order.issues.some((i) => /second place/.test(i.text)));

  const bad = validateDmarc('v=DMARC1; p=reject; pct=200; adkim=x; fo=9; ri=abc; rua=a@example.com; foo=bar');
  const texts = bad.issues.map((i) => i.text).join('\n');
  assert.match(texts, /pct=200/);
  assert.match(texts, /adkim=x/);
  assert.match(texts, /fo=9/);
  assert.match(texts, /ri=abc/);
  assert.match(texts, /mailto: in front/);
  assert.match(texts, /foo/);
});

test('optionsFromRecord round-trips', () => {
  const record = 'v=DMARC1; p=quarantine; sp=reject; pct=25; rua=mailto:a@example.com!10m; adkim=s';
  const opts = optionsFromRecord(record, 'example.com');
  assert.equal(opts.policy, 'quarantine');
  assert.equal(opts.subdomainPolicy, 'reject');
  assert.equal(opts.pct, '25');
  assert.deepEqual(opts.rua, ['a@example.com']);
  assert.equal(opts.adkim, 's');
  assert.equal(buildDmarcRecord(opts).value, 'v=DMARC1; p=quarantine; sp=reject; pct=25; rua=mailto:a@example.com; adkim=s');
});
