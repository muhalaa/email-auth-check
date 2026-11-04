import { test } from 'node:test';
import assert from 'node:assert/strict';
import { countSpfLookups, parseSpf } from '../dist/index.js';
import { fakeResolver, healthy, txt } from './fixtures.mjs';

const finding = (r, state) => r.findings.filter((f) => f.state === state);

test('counts nested includes', async () => {
  const r = await countSpfLookups('good.example', { resolver: fakeResolver(healthy) });
  assert.equal(r.lookups, 4);
  assert.equal(r.all, '~');
  assert.equal(r.voids, 0);
  assert.equal(finding(r, 'fail').length, 0);
  assert.equal(r.heaviest[0].text, 'include:_spf.google.com');
  assert.equal(r.heaviest[0].total, 4);
  assert.equal(r.root.terms[0].child.terms.length, 4);
});

test('over the limit fails, at the limit warns', async () => {
  const mk = (n) => {
    const zone = { 'x.example|TXT': [txt(`v=spf1 ${Array.from({ length: n }, (_, i) => `include:s${i}.example`).join(' ')} -all`)] };
    for (let i = 0; i < n; i++) zone[`s${i}.example|TXT`] = [txt('v=spf1 ip4:10.0.0.1 -all')];
    return zone;
  };
  const over = await countSpfLookups('x.example', { resolver: fakeResolver(mk(11)) });
  assert.equal(over.lookups, 11);
  assert.match(finding(over, 'fail')[0].text, /over the limit/);
  const at = await countSpfLookups('x.example', { resolver: fakeResolver(mk(10)) });
  assert.equal(at.lookups, 10);
  assert.match(finding(at, 'warn')[0].text, /exactly at the limit/);
});

test('a, mx, ptr, exists each cost one; ip4, ip6, all cost nothing', async () => {
  const zone = {
    'x.example|TXT': [txt('v=spf1 a mx ptr exists:%{i}.x.example ip4:1.2.3.4 ip6:::1 -all')],
    'x.example|A': ['1.2.3.4'],
    'x.example|MX': ['10 mx1.x.example.', '20 mx2.x.example.'],
  };
  const r = await countSpfLookups('x.example', { resolver: fakeResolver(zone) });
  assert.equal(r.lookups, 4);
  assert.equal(r.root.terms.find((t) => t.mechanism === 'mx').mxHosts, 2);
  assert.equal(finding(r, 'warn').some((f) => /ptr/.test(f.text)), true);
  assert.equal(finding(r, 'info').some((f) => /macro/.test(f.text)), true);
});

test('void lookups are counted; more than two fail', async () => {
  const zone = {
    'x.example|TXT': [txt('v=spf1 a:gone1.example a:gone2.example mx:gone3.example -all')],
  };
  const r = await countSpfLookups('x.example', { resolver: fakeResolver(zone) });
  assert.equal(r.voids, 3);
  assert.match(finding(r, 'fail')[0].text, /3 void lookups/);
  assert.equal(r.root.terms.filter((t) => t.void).length, 3);
});

test('include with no SPF record is a permerror and a void', async () => {
  const zone = {
    'x.example|TXT': [txt('v=spf1 include:gone.example -all')],
  };
  const r = await countSpfLookups('x.example', { resolver: fakeResolver(zone) });
  assert.equal(r.lookups, 1);
  assert.equal(r.voids, 1);
  assert.equal(r.root.terms[0].child.error, 'no-spf');
  assert.match(finding(r, 'fail')[0].text, /gone\.example/);
});

test('redirect is followed when there is no all, ignored otherwise', async () => {
  const zone = {
    'x.example|TXT': [txt('v=spf1 redirect=y.example')],
    'y.example|TXT': [txt('v=spf1 include:z.example -all')],
    'z.example|TXT': [txt('v=spf1 ip4:10.0.0.1 -all')],
    'w.example|TXT': [txt('v=spf1 ip4:10.0.0.1 ~all redirect=y.example')],
  };
  const a = await countSpfLookups('x.example', { resolver: fakeResolver(zone) });
  assert.equal(a.lookups, 2);
  assert.equal(a.all, '-');
  const b = await countSpfLookups('w.example', { resolver: fakeResolver(zone) });
  assert.equal(b.lookups, 0);
  assert.equal(b.all, '~');
  assert.match(b.root.terms.find((t) => t.mechanism === 'redirect').note, /Ignored/);
});

test('loops are detected', async () => {
  const zone = {
    'x.example|TXT': [txt('v=spf1 include:y.example -all')],
    'y.example|TXT': [txt('v=spf1 include:x.example -all')],
  };
  const r = await countSpfLookups('x.example', { resolver: fakeResolver(zone) });
  assert.match(finding(r, 'fail').find((f) => /loops/.test(f.text)).text, /x\.example/);
});

test('duplicate includes warn', async () => {
  const zone = {
    'x.example|TXT': [txt('v=spf1 include:y.example include:y.example -all')],
    'y.example|TXT': [txt('v=spf1 ip4:10.0.0.1 -all')],
  };
  const r = await countSpfLookups('x.example', { resolver: fakeResolver(zone) });
  assert.equal(r.lookups, 2);
  assert.match(finding(r, 'warn').find((f) => /more than once/.test(f.text)).text, /y\.example/);
});

test('no SPF record and no domain', async () => {
  const none = await countSpfLookups('x.example', { resolver: fakeResolver({ 'x.example|TXT': [txt('hello')] }) });
  assert.equal(none.records.length, 0);
  assert.equal(none.lookups, 0);
  assert.match(none.findings[0].text, /publishes no SPF record/);
  const nx = await countSpfLookups('x.example', { resolver: fakeResolver({}) });
  assert.equal(nx.exists, false);
});

test('a failed top lookup throws', async () => {
  await assert.rejects(countSpfLookups('x.example', { resolver: fakeResolver({}, { fail: ['x.example'] }) }), /failed/);
});

test('parseSpf', () => {
  const p = parseSpf('v=spf1 include:a.example ip4:1.2.3.4/24 -all redirect=b.example exp=explain.a.example bogus');
  assert.deepEqual(p.terms.map((t) => t.mechanism), ['include', 'ip4', 'all']);
  assert.equal(p.terms[2].qualifier, '-');
  assert.equal(p.redirect, 'b.example');
  assert.deepEqual(p.invalid, ['bogus']);
  assert.deepEqual(parseSpf('v=spf1 include: a.example all:x').invalid, ['include:', 'a.example', 'all:x']);
});
