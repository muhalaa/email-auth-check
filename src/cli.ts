#!/usr/bin/env node
/**
 * email-auth-check CLI.
 *
 *   email-auth-check <domain> [--json]
 *   email-auth-check spf <domain> [--json]
 *   email-auth-check dmarc --policy reject --rua mailto:dmarc@example.com [--domain example.com] [--json]
 */

import { normalizeDomain, dohResolver } from './dns.js';
import { checkDomain, type Report, type Section } from './check.js';
import { countSpfLookups, type SpfNode, type SpfReport } from './spfCount.js';
import { buildDmarcRecord, type DmarcOptions, type FoOption, type Policy } from './dmarc.js';

// The package ships no @types/node; this is the slice of `process` the CLI uses.
declare const process: {
  argv: string[];
  exitCode: number | undefined;
  stdout: { write(s: string): unknown };
  stderr: { write(s: string): unknown };
  env: Record<string, string | undefined>;
};

const VERSION = '0.1.0';

const out = (s: string) => process.stdout.write(s + '\n');
const err = (s: string) => process.stderr.write(s + '\n');

const HELP = `email-auth-check ${VERSION}
Check a domain's MX, SPF, DMARC and DKIM from public DNS.

Usage
  email-auth-check <domain> [--json]          Full report with a grade A-F
  email-auth-check spf <domain> [--json]      SPF lookup count and the include chain
  email-auth-check dmarc [options] [--json]   Build a DMARC record

dmarc options
  --policy none|quarantine|reject   p= (default none)
  --sp none|quarantine|reject       sp= (left out when equal to --policy)
  --rua <address>[,<address>]       Aggregate report address(es); mailto: optional
  --ruf <address>[,<address>]       Failure report address(es)
  --pct <0-100>                     pct= (left out at 100)
  --adkim r|s  --aspf r|s           Alignment (default r)
  --fo 0|1|d|s[:...]                Failure report options (only with --ruf)
  --domain <domain>                 Sets the host name and authorisation records

General
  --json        Machine-readable output
  --no-colour   Plain text
  -h, --help    This help
  -v, --version Version

DNS goes to Cloudflare's public resolver (cloudflare-dns.com) with Google's
(dns.google) as a fallback. Nothing is sent anywhere else.
The same engine as the free tools at https://roimaxi.com/tools/email-setup-checker`;

/* ---------- argument parsing ---------- */

interface Args {
  positional: string[];
  flags: Record<string, string | true>;
}

const parseArgs = (argv: string[]): Args => {
  const a: Args = { positional: [], flags: {} };
  for (let i = 0; i < argv.length; i++) {
    const x = argv[i];
    if (x === '--') {
      a.positional.push(...argv.slice(i + 1));
      break;
    }
    if (x.startsWith('--')) {
      const eq = x.indexOf('=');
      if (eq > 0) {
        a.flags[x.slice(2, eq)] = x.slice(eq + 1);
        continue;
      }
      const key = x.slice(2);
      const next = argv[i + 1];
      if (next !== undefined && !next.startsWith('-')) {
        a.flags[key] = next;
        i++;
      } else {
        a.flags[key] = true;
      }
      continue;
    }
    if (x === '-h') a.flags.help = true;
    else if (x === '-v') a.flags.version = true;
    else a.positional.push(x);
  }
  return a;
};

/* ---------- colour ---------- */

const useColour = (flags: Args['flags']) =>
  !flags['no-colour'] && !flags['no-color'] && !process.env.NO_COLOR && process.env.TERM !== 'dumb';

const paint = (on: boolean) => {
  const c = (code: string) => (s: string) => (on ? `\x1b[${code}m${s}\x1b[0m` : s);
  return { bold: c('1'), dim: c('2'), green: c('32'), yellow: c('33'), red: c('31'), cyan: c('36') };
};
type Paint = ReturnType<typeof paint>;

const stateMark = (p: Paint, state: string) => {
  switch (state) {
    case 'pass':
      return p.green('PASS');
    case 'warn':
      return p.yellow('WARN');
    case 'fail':
      return p.red('FAIL');
    default:
      return p.dim('INFO');
  }
};

const gradeColour = (p: Paint, g: string | null) => {
  if (!g) return p.dim('none');
  if (g === 'A') return p.green(g);
  if (g === 'B' || g === 'C') return p.yellow(g);
  return p.red(g);
};

const wrap = (s: string, indent: string, width = 78): string => {
  const words = s.split(/\s+/);
  const lines: string[] = [];
  let line = '';
  for (const w of words) {
    if ((line + ' ' + w).trim().length > width - indent.length && line) {
      lines.push(line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) lines.push(line);
  return lines.map((l) => indent + l).join('\n');
};

/* ---------- full report ---------- */

const printSection = (p: Paint, s: Section) => {
  const head = s.error ? p.dim('ERROR') : stateMark(p, s.state);
  const extra =
    s.key === 'spf' && s.lookups !== undefined
      ? p.dim(`  ${s.lookups} DNS lookup${s.lookups === 1 ? '' : 's'} of 10`)
      : s.key === 'dkim'
        ? p.dim(s.graded ? '' : '  reported, not graded')
        : '';
  out(`${p.bold(s.label.padEnd(6))} ${head}${extra}`);
  out(p.dim(`  at ${s.where}`));
  if (s.error) {
    out(wrap(s.error, '  '));
    out('');
    return;
  }
  for (const r of s.records) out(`  ${p.cyan(r)}`);
  if (s.key === 'spf' && s.includes?.length) {
    for (const inc of s.includes) out(p.dim(`    include:${inc.target}  ${inc.lookups} lookup${inc.lookups === 1 ? '' : 's'}`));
  }
  for (const n of s.notes) {
    out(wrap(`${stateMark(p, n.state)} ${n.text}`, '  '));
    if (n.fix) out(wrap(`Fix: ${n.fix}`, '       '));
    if (n.value) out(`       ${p.cyan(n.value)}`);
  }
  out('');
};

const printReport = (p: Paint, r: Report) => {
  out('');
  out(`${p.bold(r.domain)}   grade ${p.bold(gradeColour(p, r.grade))}`);
  out(wrap(r.verdict, '  '));
  out('');
  if (!r.exists) return;
  for (const s of r.sections) printSection(p, s);
  out(p.dim('Grading: SPF, DMARC and MX each pass/warn/fail. Two or more fails F, one fail D,'));
  out(p.dim('two or more warnings C, one warning B, otherwise A. DKIM is reported, not graded.'));
  out(p.dim('One day\'s snapshot from public DNS. Same engine as roimaxi.com/tools/email-setup-checker'));
};

/* ---------- spf tree ---------- */

const printTree = (p: Paint, n: SpfNode, indent = '  ') => {
  for (const t of n.terms) {
    const cost = t.total > 0 ? p.dim(`  (${t.total})`) : '';
    const flag = t.void ? p.yellow('  void') : '';
    const note = t.note ? p.dim(`  ${t.note}`) : '';
    out(`${indent}${t.text}${cost}${flag}${note}`);
    if (t.child) {
      const c = t.child;
      if (c.error) {
        out(`${indent}  ${p.red(`[${c.error}]`)} ${p.dim(c.domain)}`);
      } else {
        out(`${indent}  ${p.dim(c.record ?? '')}`);
        printTree(p, c, indent + '    ');
      }
    }
  }
};

const printSpf = (p: Paint, r: SpfReport) => {
  out('');
  const over = r.lookups > 10;
  const count = over ? p.red(String(r.lookups)) : r.lookups >= 8 ? p.yellow(String(r.lookups)) : p.green(String(r.lookups));
  out(`${p.bold(r.domain)}   ${count} of 10 DNS lookups${r.incomplete ? p.dim(' (at least)') : ''}${r.voids ? p.dim(`, ${r.voids} void`) : ''}`);
  out('');
  if (!r.exists || !r.records.length || !r.root) {
    for (const f of r.findings) out(wrap(`${stateMark(p, f.state)} ${f.text}`, '  '));
    return;
  }
  for (const rec of r.records) out(`  ${p.cyan(rec)}`);
  out('');
  printTree(p, r.root);
  out('');
  for (const f of r.findings) {
    out(wrap(`${stateMark(p, f.state)} ${f.text}`, '  '));
    if (f.fix) out(wrap(`Fix: ${f.fix}`, '       '));
  }
  if (r.heaviest.length) {
    out('');
    out(p.bold('  Heaviest includes'));
    for (const h of r.heaviest.slice(0, 8)) out(`    ${String(h.total).padStart(2)}  ${'  '.repeat(h.depth)}${h.text}`);
  }
  out('');
  out(p.dim(`${r.queries} DNS queries. Same engine as roimaxi.com/tools/spf-lookup-counter`));
};

/* ---------- dmarc ---------- */

const policyArg = (v: string | true | undefined, name: string): Policy | undefined => {
  if (v === undefined) return undefined;
  if (v === true || !['none', 'quarantine', 'reject'].includes(v)) {
    throw new Error(`--${name} must be none, quarantine or reject`);
  }
  return v as Policy;
};

const alignArg = (v: string | true | undefined, name: string): 'r' | 's' | undefined => {
  if (v === undefined) return undefined;
  if (v !== 'r' && v !== 's') throw new Error(`--${name} must be r or s`);
  return v;
};

const str = (v: string | true | undefined): string | undefined => (typeof v === 'string' ? v : undefined);

const runDmarc = (a: Args, p: Paint) => {
  const opts: DmarcOptions = {
    policy: policyArg(a.flags.policy ?? a.flags.p, 'policy'),
    subdomainPolicy: policyArg(a.flags.sp, 'sp'),
    pct: str(a.flags.pct),
    rua: str(a.flags.rua),
    ruf: str(a.flags.ruf),
    adkim: alignArg(a.flags.adkim, 'adkim'),
    aspf: alignArg(a.flags.aspf, 'aspf'),
  };
  const fo = str(a.flags.fo);
  if (fo) opts.fo = fo.split(':').filter((x): x is FoOption => ['0', '1', 'd', 's'].includes(x));
  const dom = str(a.flags.domain);
  if (dom) {
    const n = normalizeDomain(dom);
    if ('error' in n) throw new Error(n.error);
    opts.domain = n.domain;
  }
  const rec = buildDmarcRecord(opts);
  if (a.flags.json) {
    out(JSON.stringify(rec, null, 2));
    return;
  }
  out('');
  out(`${p.dim('Host  ')} ${rec.host ?? '_dmarc.<your domain>'}`);
  out(`${p.dim('Type  ')} TXT`);
  out(`${p.dim('Value ')} ${p.cyan(rec.value)}`);
  if (rec.authorisations.length) {
    out('');
    out(p.bold('  Also publish, at the report domain (RFC 7489 section 7.1):'));
    for (const au of rec.authorisations) out(`    ${au.host}  TXT  ${au.value}`);
  }
  if (rec.issues.length) {
    out('');
    for (const i of rec.issues) {
      const mark = i.level === 'error' ? p.red('ERROR') : i.level === 'warn' ? p.yellow('WARN') : p.dim('INFO');
      out(wrap(`${mark} ${i.text}`, '  '));
    }
  }
  out('');
  out(p.dim('Same engine as roimaxi.com/tools/dmarc-record-generator'));
};

/* ---------- main ---------- */

const main = async () => {
  const a = parseArgs(process.argv.slice(2));
  const p = paint(useColour(a.flags) && !a.flags.json);

  if (a.flags.version) {
    out(VERSION);
    return;
  }
  if (a.flags.help || (!a.positional.length && !a.flags.policy && !a.flags.rua)) {
    out(HELP);
    return;
  }

  const cmd = a.positional[0];

  if (cmd === 'dmarc') {
    runDmarc(a, p);
    return;
  }

  const target = cmd === 'spf' || cmd === 'check' ? a.positional[1] : cmd;
  if (!target) throw new Error(`Give a domain: email-auth-check ${cmd} example.com`);
  const n = normalizeDomain(target);
  if ('error' in n) throw new Error(n.error);
  const resolver = dohResolver();

  if (cmd === 'spf') {
    const r = await countSpfLookups(n.domain, { resolver });
    if (a.flags.json) out(JSON.stringify(r, null, 2));
    else printSpf(p, r);
    if (r.findings.some((f) => f.state === 'fail')) process.exitCode = 1;
    return;
  }

  const r = await checkDomain(n.domain, { resolver });
  if (a.flags.json) out(JSON.stringify(r, null, 2));
  else printReport(p, r);
  if (!r.exists || r.grade === 'D' || r.grade === 'F') process.exitCode = 1;
  else if (r.grade === null) process.exitCode = 2;
};

main().catch((e: unknown) => {
  err(`error: ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 2;
});
