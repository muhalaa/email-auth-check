import { test } from 'node:test';
import assert from 'node:assert/strict';
import { checkDomain, gradeFrom, normalizeDomain, parseDmarc, txtData, rsaBits } from '../dist/index.js';
import { fakeResolver, healthy, txt } from './fixtures.mjs';

const section = (r, key) => r.sections.find((s) => s.key === key);

test('healthy Google Workspace domain grades A', async () => {
  const r = await checkDomain('good.example', { resolver: fakeResolver(healthy) });
  assert.equal(r.exists, true);
  assert.equal(r.grade, 'A');
  assert.equal(section(r, 'mx').state, 'pass');
  assert.equal(section(r, 'spf').state, 'pass');
  assert.equal(section(r, 'spf').lookups, 4);
  assert.deepEqual(section(r, 'spf').includes, [{ target: '_spf.google.com', lookups: 4 }]);
  assert.equal(section(r, 'dmarc').state, 'pass');
  assert.equal(section(r, 'dkim').graded, false);
  assert.deepEqual(section(r, 'dkim').selectors, ['google']);
  assert.match(section(r, 'mx').notes[0].text, /Google Workspace/);
});

test('no DMARC is one fail: grade D', async () => {
  const zone = { ...healthy };
  delete zone['_dmarc.good.example|TXT'];
  const r = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  assert.equal(r.grade, 'D');
  const d = section(r, 'dmarc');
  assert.equal(d.state, 'fail');
  assert.equal(d.notes[0].value, 'v=DMARC1; p=none; rua=mailto:dmarc@good.example');
});

test('no SPF and no DMARC: grade F', async () => {
  const zone = { ...healthy };
  delete zone['_dmarc.good.example|TXT'];
  zone['good.example|TXT'] = [txt('google-site-verification=abc')];
  const r = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  assert.equal(r.grade, 'F');
  assert.equal(section(r, 'spf').notes[0].value, 'v=spf1 include:_spf.google.com ~all');
});

test('p=none with rua is one warning: grade B', async () => {
  const zone = { ...healthy, '_dmarc.good.example|TXT': [txt('v=DMARC1; p=none; rua=mailto:dmarc@good.example')] };
  const r = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  assert.equal(r.grade, 'B');
  assert.equal(section(r, 'dmarc').notes[0].value, 'v=DMARC1; p=quarantine; rua=mailto:dmarc@good.example');
});

test('?all and p=none: two warnings, grade C', async () => {
  const zone = {
    ...healthy,
    'good.example|TXT': [txt('v=spf1 include:_spf.google.com ?all')],
    '_dmarc.good.example|TXT': [txt('v=DMARC1; p=none')],
  };
  const r = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  assert.equal(r.grade, 'C');
  assert.equal(section(r, 'spf').notes[0].value, 'v=spf1 include:_spf.google.com ~all');
});

test('+all fails SPF', async () => {
  const zone = { ...healthy, 'good.example|TXT': [txt('v=spf1 include:_spf.google.com +all')] };
  const r = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  assert.equal(section(r, 'spf').state, 'fail');
  assert.equal(r.grade, 'D');
});

test('two SPF records fail', async () => {
  const zone = { ...healthy, 'good.example|TXT': [txt('v=spf1 include:_spf.google.com ~all'), txt('v=spf1 ip4:1.2.3.4 -all')] };
  const r = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  assert.equal(section(r, 'spf').state, 'fail');
  assert.match(section(r, 'spf').notes[0].text, /2 SPF records/);
});

test('SPF syntax error fails', async () => {
  const zone = { ...healthy, 'good.example|TXT': [txt('v=spf1 include: _spf.google.com ~all')] };
  const r = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  const s = section(r, 'spf');
  assert.equal(s.state, 'fail');
  assert.match(s.notes[0].text, /include:/);
});

test('over 10 lookups warns but does not fail', async () => {
  const incs = Array.from({ length: 11 }, (_, i) => `include:s${i}.example`).join(' ');
  const zone = { ...healthy, 'good.example|TXT': [txt(`v=spf1 ${incs} ~all`)] };
  for (let i = 0; i < 11; i++) zone[`s${i}.example|TXT`] = [txt('v=spf1 ip4:10.0.0.1 ~all')];
  const r = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  const s = section(r, 'spf');
  assert.equal(s.state, 'warn');
  assert.equal(s.lookups, 11);
  assert.equal(r.grade, 'B');
});

test('pct below 100 and sp=none each warn', async () => {
  const zone = { ...healthy, '_dmarc.good.example|TXT': [txt('v=DMARC1; p=reject; sp=none; pct=50; rua=mailto:d@good.example')] };
  const r = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  const d = section(r, 'dmarc');
  assert.equal(d.state, 'warn');
  assert.equal(d.notes.filter((n) => n.state === 'warn').length, 2);
  assert.equal(r.grade, 'B');
});

test('DMARC with no p= but rua= warns; with neither fails', async () => {
  const a = await checkDomain('good.example', {
    resolver: fakeResolver({ ...healthy, '_dmarc.good.example|TXT': [txt('v=DMARC1; rua=mailto:d@good.example')] }),
  });
  assert.equal(section(a, 'dmarc').state, 'warn');
  const b = await checkDomain('good.example', {
    resolver: fakeResolver({ ...healthy, '_dmarc.good.example|TXT': [txt('v=DMARC1; pct=100')] }),
  });
  assert.equal(section(b, 'dmarc').state, 'fail');
});

test('subdomain inherits DMARC from the parent, sp= applies', async () => {
  const zone = {
    'mail.good.example|TXT': [txt('v=spf1 include:_spf.google.com -all')],
    'mail.good.example|MX': ['10 mx.good.example.'],
    '_dmarc.good.example|TXT': [txt('v=DMARC1; p=reject; sp=none')],
    '_spf.google.com|TXT': healthy['_spf.google.com|TXT'],
    '_netblocks.google.com|TXT': healthy['_netblocks.google.com|TXT'],
    '_netblocks2.google.com|TXT': healthy['_netblocks2.google.com|TXT'],
    '_netblocks3.google.com|TXT': healthy['_netblocks3.google.com|TXT'],
  };
  const r = await checkDomain('mail.good.example', { resolver: fakeResolver(zone) });
  const d = section(r, 'dmarc');
  assert.equal(d.where, '_dmarc.good.example');
  assert.equal(d.state, 'warn');
  assert.match(d.notes.find((n) => n.state === 'warn').text, /sp=none/);
});

test('null MX fails; no MX fails', async () => {
  const a = await checkDomain('good.example', { resolver: fakeResolver({ ...healthy, 'good.example|MX': ['0 .'] }) });
  assert.equal(section(a, 'mx').state, 'fail');
  const zone = { ...healthy };
  delete zone['good.example|MX'];
  const b = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  assert.equal(section(b, 'mx').state, 'fail');
});

test('domain that does not exist', async () => {
  const r = await checkDomain('nope.example', { resolver: fakeResolver({}) });
  assert.equal(r.exists, false);
  assert.equal(r.grade, null);
  assert.equal(r.sections.length, 0);
});

test('a failed graded lookup gives no grade', async () => {
  const r = await checkDomain('good.example', { resolver: fakeResolver(healthy, { fail: ['_dmarc.good.example'] }) });
  assert.equal(r.grade, null);
  assert.ok(section(r, 'dmarc').error);
  const t = await checkDomain('good.example', { resolver: fakeResolver(healthy, { reject: ['good.example'] }) });
  assert.equal(t.grade, null);
  assert.ok(section(t, 'spf').error);
});

test('weak DKIM key warns, empty key is reported as revoked', async () => {
  const zone = {
    ...healthy,
    'google._domainkey.good.example|TXT': [txt('v=DKIM1; k=rsa; p=' + 'A'.repeat(136))],
    'k1._domainkey.good.example|TXT': [txt('v=DKIM1; k=rsa; p=')],
  };
  const r = await checkDomain('good.example', { resolver: fakeResolver(zone) });
  const d = section(r, 'dkim');
  assert.equal(d.state, 'warn');
  assert.match(d.notes.find((n) => n.state === 'warn').text, /1024 bits/);
  assert.match(d.notes.find((n) => /revoked/.test(n.text)).text, /k1/);
  assert.equal(r.grade, 'A', 'DKIM never affects the grade');
});

test('gradeFrom thresholds', () => {
  assert.equal(gradeFrom(['pass', 'pass', 'pass']), 'A');
  assert.equal(gradeFrom(['warn', 'pass', 'pass']), 'B');
  assert.equal(gradeFrom(['warn', 'warn', 'pass']), 'C');
  assert.equal(gradeFrom(['fail', 'warn', 'warn']), 'D');
  assert.equal(gradeFrom(['fail', 'fail', 'pass']), 'F');
});

test('txtData joins split strings and unescapes', () => {
  assert.equal(txtData('"v=spf1 " "include:a.example " "~all"'), 'v=spf1 include:a.example ~all');
  assert.equal(txtData('v=spf1 -all'), 'v=spf1 -all');
  assert.equal(txtData('"a\\"b"'), 'a"b');
});

test('parseDmarc keeps the first of a repeated tag', () => {
  assert.deepEqual(parseDmarc('v=DMARC1; p=reject; p=none; rua=mailto:a@b.example;'), {
    v: 'DMARC1',
    p: 'reject',
    rua: 'mailto:a@b.example',
  });
});

test('normalizeDomain', () => {
  assert.deepEqual(normalizeDomain('  HTTPS://www.Example.co.uk/path?x=1 '), { domain: 'example.co.uk' });
  assert.deepEqual(normalizeDomain('someone@mail.example.com'), { domain: 'mail.example.com' });
  assert.deepEqual(normalizeDomain('münchen.de'), { domain: 'xn--mnchen-3ya.de' });
  assert.ok('error' in normalizeDomain('localhost'));
  assert.ok('error' in normalizeDomain(''));
});

test('rsaBits snaps to common sizes', () => {
  assert.equal(rsaBits('A'.repeat(216)), 1024);
  assert.equal(rsaBits('A'.repeat(392)), 2048);
  assert.equal(rsaBits('not base64!'), null);
});
