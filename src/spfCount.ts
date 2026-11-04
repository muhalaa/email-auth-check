/**
 * SPF lookup counter: reads a domain's SPF record and counts the DNS lookups
 * it costs, following every include and redirect, against the limits in
 * RFC 7208 section 4.6.4: ten DNS-querying terms (include, a, mx, ptr,
 * exists, redirect), at most ten MX hosts per mx term, and, as the RFC
 * recommends, at most two void lookups. This is the engine behind
 * https://roimaxi.com/tools/spf-lookup-counter.
 *
 * The count is the worst case: what a receiver spends when it has to evaluate
 * every term, which is what happens to mail that matches late or not at all.
 * Macros (%{...}) are counted but not followed: what they cost depends on the
 * sender.
 */

import { answered, dohResolver, txtRecords, TYPE_CODE, type DnsResult, type RecordType, type Resolver } from './dns.js';
import { isSpf, parseSpf, SPF_LOOKUP_LIMIT, SPF_MX_HOST_LIMIT, SPF_VOID_LIMIT, type Qualifier, type SpfTerm } from './spfParse.js';

export interface TermRow {
  /** The term as written, e.g. "include:_spf.google.com" or "~all". */
  text: string;
  mechanism: SpfTerm['mechanism'] | 'redirect';
  qualifier: Qualifier | null;
  /** Lookups this term costs on its own: 1 for a DNS-querying term, else 0. */
  cost: number;
  /** cost plus everything below it, for include and redirect. */
  total: number;
  void?: boolean;
  /** For mx: how many MX hosts it names (each needs an address lookup; at most 10). */
  mxHosts?: number;
  /** A plain note: "macro, not followed", "redirect ignored: the record has an all", and so on. */
  note?: string;
  child?: SpfNode;
}

export interface SpfNode {
  domain: string;
  record: string | null;
  terms: TermRow[];
  /** Lookups in this record and everything it pulls in. */
  total: number;
  /** Why this record could not be read or followed. */
  error?: 'no-spf' | 'multiple-spf' | 'lookup-failed' | 'loop' | 'too-deep' | 'budget';
  /** Words in the record that are neither a mechanism nor a modifier. */
  invalid: string[];
}

export type FindingState = 'fail' | 'warn' | 'pass' | 'info';

export interface Finding {
  state: FindingState;
  text: string;
  fix?: string;
}

export interface SpfReport {
  domain: string;
  /** False when the domain itself does not exist (NXDOMAIN). */
  exists: boolean;
  /** Every SPF record at the domain (more than one is a permerror). */
  records: string[];
  root: SpfNode | null;
  lookups: number;
  voids: number;
  /** The `all` that ends evaluation, from the record or its redirect target. */
  all: Qualifier | null;
  findings: Finding[];
  /** True when some part could not be read, so the count is a floor. */
  incomplete: boolean;
  /** The includes and redirects, flattened, heaviest first. */
  heaviest: Array<{ text: string; total: number; depth: number }>;
  /** DNS queries this check made. */
  queries: number;
}

export interface CountOptions {
  /** Defaults to dohResolver(): Cloudflare DoH, Google fallback. */
  resolver?: Resolver;
}

interface Ctx {
  query: Resolver;
  budget: { queries: number; used: number };
  voids: { n: number };
  ptr: { n: number };
  macros: { n: number };
  missing: string[];
  mxOver: string[];
  loops: string[];
  incomplete: boolean;
  seen: Map<string, number>;
}

const MAX_QUERIES = 80;
const MAX_DEPTH = 10;

/** A void lookup (RFC 7208 section 4.6.4): NXDOMAIN, or NOERROR with no answer of the type asked. */
const isVoid = (r: DnsResult, type: RecordType) => r.status === 3 || !r.answers.some((a) => a.type === TYPE_CODE[type]);
const clean = (d: string) => d.trim().toLowerCase().replace(/\.+$/, '');

const ask = async (ctx: Ctx, name: string, type: RecordType): Promise<DnsResult | null> => {
  if (ctx.budget.queries <= 0) {
    ctx.incomplete = true;
    return null;
  }
  ctx.budget.queries--;
  ctx.budget.used++;
  try {
    const r = await ctx.query(name, type);
    if (!answered(r)) {
      ctx.incomplete = true;
      return null;
    }
    return r;
  } catch {
    ctx.incomplete = true;
    return null;
  }
};

/** Read and walk the SPF record at `domain`. `path` holds the domains above it, for loop detection. */
const walk = async (ctx: Ctx, domain: string, path: string[], given?: string): Promise<SpfNode> => {
  const node: SpfNode = { domain, record: null, terms: [], total: 0, invalid: [] };
  if (path.includes(domain)) {
    ctx.loops.push(domain);
    return { ...node, error: 'loop' };
  }
  if (path.length >= MAX_DEPTH) return { ...node, error: 'too-deep' };

  let record = given;
  if (record === undefined) {
    const r = await ask(ctx, domain, 'TXT');
    if (!r) return { ...node, error: ctx.budget.queries <= 0 ? 'budget' : 'lookup-failed' };
    const spf = txtRecords(r).filter(isSpf);
    if (spf.length === 0) {
      // The include target answered but publishes no SPF: a void lookup when
      // there was nothing at all, and a permerror either way (RFC 7208 5.2).
      if (isVoid(r, 'TXT')) ctx.voids.n++;
      ctx.missing.push(domain);
      return { ...node, error: 'no-spf' };
    }
    if (spf.length > 1) {
      ctx.missing.push(domain);
      return { ...node, record: spf[0], error: 'multiple-spf' };
    }
    record = spf[0];
  }
  node.record = record;

  const parsed = parseSpf(record);
  node.invalid = parsed.invalid;
  // The terms as written, CIDR suffix and case included, for display.
  const written = record
    .trim()
    .split(/\s+/)
    .slice(1)
    .filter((w) => parseSpf(`v=spf1 ${w}`).terms.length === 1);
  const hasAll = parsed.terms.some((t) => t.mechanism === 'all');
  const here = [...path, domain];

  const rows = await Promise.all(
    parsed.terms.map(async (t, i): Promise<TermRow> => {
      const q = t.qualifier === '+' ? '' : t.qualifier;
      const text = written.length === parsed.terms.length ? written[i] : `${q}${t.mechanism}${t.value ? `:${t.value}` : ''}`;
      const row: TermRow = { text, mechanism: t.mechanism, qualifier: t.qualifier, cost: 0, total: 0 };
      const target = clean(t.value || domain);
      const macro = t.value.includes('%');

      switch (t.mechanism) {
        case 'include': {
          row.cost = 1;
          if (macro) {
            ctx.macros.n++;
            row.note = 'Macro: what it costs depends on the sender, so it is not followed.';
            break;
          }
          ctx.seen.set(target, (ctx.seen.get(target) ?? 0) + 1);
          row.child = await walk(ctx, target, here);
          break;
        }
        case 'a': {
          row.cost = 1;
          if (macro) {
            ctx.macros.n++;
            row.note = 'Macro: not looked up.';
            break;
          }
          const [a4, a6] = await Promise.all([ask(ctx, target, 'A'), ask(ctx, target, 'AAAA')]);
          if (a4 && a6 && isVoid(a4, 'A') && isVoid(a6, 'AAAA')) {
            row.void = true;
            ctx.voids.n++;
            row.note = `${target} has no A or AAAA record: a void lookup that can never match.`;
          }
          break;
        }
        case 'mx': {
          row.cost = 1;
          if (macro) {
            ctx.macros.n++;
            row.note = 'Macro: not looked up.';
            break;
          }
          const r = await ask(ctx, target, 'MX');
          if (r) {
            if (isVoid(r, 'MX')) {
              row.void = true;
              ctx.voids.n++;
              row.note = `${target} has no MX record: a void lookup that can never match.`;
            } else {
              row.mxHosts = r.answers.filter((x) => x.type === TYPE_CODE.MX).length;
              if (row.mxHosts > SPF_MX_HOST_LIMIT) {
                ctx.mxOver.push(target);
                row.note = `${row.mxHosts} MX hosts: over the limit of ${SPF_MX_HOST_LIMIT} for one mx term.`;
              } else {
                row.note = `${row.mxHosts} MX ${row.mxHosts === 1 ? 'host' : 'hosts'}, each looked up again for its address. Those do not count towards the 10.`;
              }
            }
          }
          break;
        }
        case 'ptr':
          row.cost = 1;
          ctx.ptr.n++;
          row.note = 'ptr is slow and unreliable; RFC 7208 says not to use it.';
          break;
        case 'exists':
          row.cost = 1;
          if (macro) {
            ctx.macros.n++;
            row.note = 'Macro: what it looks up depends on the sender.';
          }
          break;
        default:
          // ip4, ip6 and all cost nothing.
          break;
      }
      row.total = row.cost + (row.child?.total ?? 0);
      return row;
    })
  );
  node.terms = rows;

  if (parsed.redirect) {
    const target = clean(parsed.redirect);
    const row: TermRow = { text: `redirect=${parsed.redirect}`, mechanism: 'redirect', qualifier: null, cost: 0, total: 0 };
    if (hasAll) {
      // RFC 7208 section 6.1: redirect is ignored when the record has an all.
      row.note = 'Ignored: the record has an all, so the redirect never runs.';
    } else if (target.includes('%')) {
      row.cost = 1;
      ctx.macros.n++;
      row.note = 'Macro: not followed.';
    } else {
      row.cost = 1;
      ctx.seen.set(target, (ctx.seen.get(target) ?? 0) + 1);
      row.child = await walk(ctx, target, here);
    }
    row.total = row.cost + (row.child?.total ?? 0);
    node.terms.push(row);
  }

  node.total = node.terms.reduce((s, r) => s + r.total, 0);
  return node;
};

/** The `all` that ends evaluation: the record's own, or its redirect target's. */
const effectiveAll = (n: SpfNode | undefined | null): Qualifier | null => {
  if (!n) return null;
  const all = n.terms.find((t) => t.mechanism === 'all');
  if (all) return all.qualifier;
  const red = n.terms.find((t) => t.mechanism === 'redirect');
  return red?.child ? effectiveAll(red.child) : null;
};

/** Every include and redirect in the tree, with its depth. */
const flatten = (n: SpfNode, depth = 0, out: Array<{ text: string; total: number; depth: number }> = []) => {
  for (const t of n.terms) {
    if (t.mechanism === 'include' || t.mechanism === 'redirect') {
      if (t.total > 0) out.push({ text: t.text, total: t.total, depth });
      if (t.child) flatten(t.child, depth + 1, out);
    }
  }
  return out;
};

const anyInvalid = (n: SpfNode | undefined): string[] =>
  n ? [...n.invalid, ...n.terms.flatMap((t) => anyInvalid(t.child))] : [];

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/**
 * Count the lookups in `domain`'s SPF record. `domain` should be a bare,
 * lower-case host name; use normalizeDomain() on raw input first. Throws
 * when the domain's own TXT lookup fails.
 */
export const countSpfLookups = async (domain: string, opts: CountOptions = {}): Promise<SpfReport> => {
  const query = opts.resolver ?? dohResolver();
  const ctx: Ctx = {
    query,
    budget: { queries: MAX_QUERIES, used: 0 },
    voids: { n: 0 },
    ptr: { n: 0 },
    macros: { n: 0 },
    missing: [],
    mxOver: [],
    loops: [],
    incomplete: false,
    seen: new Map(),
  };
  const report: SpfReport = {
    domain,
    exists: true,
    records: [],
    root: null,
    lookups: 0,
    voids: 0,
    all: null,
    findings: [],
    incomplete: false,
    heaviest: [],
    queries: 0,
  };

  // The domain's own TXT lookup is the check itself, not one of the 10.
  ctx.budget.queries--;
  ctx.budget.used++;
  let top: DnsResult;
  try {
    top = await query(domain, 'TXT');
  } catch {
    throw new Error(`The TXT lookup for ${domain} failed.`);
  }
  if (!answered(top)) throw new Error(`The TXT lookup for ${domain} failed (rcode ${top.status}).`);
  if (top.status === 3) {
    report.exists = false;
    report.queries = ctx.budget.used;
    report.findings.push({ state: 'fail', text: `${domain} does not exist in DNS. Check the spelling.` });
    return report;
  }

  report.records = txtRecords(top).filter(isSpf);
  const F = report.findings;

  if (report.records.length === 0) {
    report.queries = ctx.budget.used;
    F.push({
      state: 'fail',
      text: `${domain} publishes no SPF record, so there is nothing to count. Receivers cannot tell which servers may send as ${domain}.`,
      fix: 'Publish one TXT record at the domain that starts with v=spf1 and lists the services that send for you, ending in ~all or -all.',
    });
    return report;
  }

  // Walk the first; two or more is a permerror whatever they contain.
  report.root = await walk(ctx, domain, [], report.records[0]);
  const root = report.root;
  report.lookups = root.total;
  report.voids = ctx.voids.n;
  report.all = effectiveAll(root);
  report.incomplete = ctx.incomplete;
  report.heaviest = flatten(root).sort((a, b) => b.total - a.total || a.depth - b.depth);
  report.queries = ctx.budget.used;

  const L = report.lookups;
  if (report.records.length > 1) {
    F.push({
      state: 'fail',
      text: `${domain} has ${report.records.length} SPF records. RFC 7208 allows one; with two or more, every receiver returns a permerror and SPF fails for all your mail. The count below is for the first one.`,
      fix: 'Merge them into a single v=spf1 record: keep every include and ip4/ip6 term once, and one all at the end. Then delete the others.',
    });
  }

  if (L > SPF_LOOKUP_LIMIT) {
    F.push({
      state: 'fail',
      text: `${L} DNS lookups: over the limit of ${SPF_LOOKUP_LIMIT} (RFC 7208, section 4.6.4). A receiver that has to evaluate the whole record returns a permerror, and most treat that as an SPF fail.`,
      fix: `Cut ${plural(L - SPF_LOOKUP_LIMIT, 'lookup')} or more. Start with the heaviest includes.`,
    });
  } else if (L === SPF_LOOKUP_LIMIT) {
    F.push({
      state: 'warn',
      text: `${L} DNS lookups: exactly at the limit of ${SPF_LOOKUP_LIMIT}. One more include, or one of your providers adding a nested include, tips it over.`,
      fix: 'Free up one or two lookups now, before you add another sending service.',
    });
  } else if (L >= SPF_LOOKUP_LIMIT - 2) {
    F.push({
      state: 'warn',
      text: `${L} DNS lookups, ${plural(SPF_LOOKUP_LIMIT - L, 'lookup')} under the limit of ${SPF_LOOKUP_LIMIT}. Providers change their own records, so leave some room.`,
    });
  } else {
    F.push({ state: 'pass', text: `${L} of ${SPF_LOOKUP_LIMIT} DNS lookups. Within the limit.` });
  }

  if (report.voids > SPF_VOID_LIMIT) {
    F.push({
      state: 'fail',
      text: `${report.voids} void lookups: names that return nothing. RFC 7208 recommends that receivers stop after ${SPF_VOID_LIMIT} and return a permerror.`,
      fix: 'Remove the terms marked "void". They point at names with no record, so they can never match anyway.',
    });
  } else if (report.voids > 0) {
    F.push({
      state: 'warn',
      text: `${plural(report.voids, 'void lookup')} (a name that returns nothing). Up to ${SPF_VOID_LIMIT} are tolerated; each one is a term that can never match.`,
      fix: 'Remove the terms marked "void".',
    });
  }

  const missing = [...new Set(ctx.missing)];
  if (missing.length) {
    F.push({
      state: 'fail',
      text: `${missing.join(', ')} ${missing.length === 1 ? 'is' : 'are'} included but ${missing.length === 1 ? 'does' : 'do'} not publish exactly one SPF record. An include that finds no record is a permerror (RFC 7208, section 5.2).`,
      fix: 'Remove the include, or correct the name to the one your provider documents today.',
    });
  }

  const invalid = anyInvalid(root);
  if (invalid.length) {
    F.push({
      state: 'fail',
      text: `Syntax error: ${invalid.map((w) => `"${w}"`).join(', ')} ${invalid.length === 1 ? 'is' : 'are'} not valid SPF. A receiver returns a permerror.`,
      fix: 'Correct or remove those words. Mechanisms are all, include, a, mx, ptr, ip4, ip6 and exists; modifiers are redirect= and exp=.',
    });
  }

  const loops = [...new Set(ctx.loops)];
  if (loops.length) {
    F.push({
      state: 'fail',
      text: `The record loops: ${loops.join(', ')} ${loops.length === 1 ? 'is' : 'are'} included again from inside itself. A receiver follows the loop until it runs out of lookups and returns a permerror.`,
      fix: 'Remove the include that points back up the tree.',
    });
  }

  if (ctx.mxOver.length) {
    F.push({
      state: 'fail',
      text: `The mx term for ${ctx.mxOver.join(', ')} names more than ${SPF_MX_HOST_LIMIT} mail servers. RFC 7208 makes that a permerror.`,
      fix: "Replace mx with ip4/ip6 ranges for the servers that actually send, or with your provider's include.",
    });
  }

  if (report.all === '+') {
    F.push({
      state: 'fail',
      text: 'The record ends in +all, which authorises every server on the internet to send as your domain. SPF then protects nothing.',
      fix: 'Change +all to ~all (soft fail) or -all (fail).',
    });
  } else if (report.all === '?') {
    F.push({
      state: 'warn',
      text: 'The record ends in ?all (neutral): mail from servers you did not list is treated as if there were no SPF record.',
      fix: 'Change ?all to ~all, or to -all once you are sure every sender is listed.',
    });
  } else if (report.all === null) {
    F.push({
      state: 'warn',
      text: 'The record has no all at the end, and no redirect that supplies one. Unlisted servers get a neutral result.',
      fix: 'End the record with ~all or -all.',
    });
  } else {
    F.push({
      state: 'pass',
      text: report.all === '-' ? 'Ends in -all: mail from unlisted servers fails SPF.' : 'Ends in ~all: mail from unlisted servers soft-fails SPF.',
    });
  }

  if (ctx.ptr.n) {
    F.push({
      state: 'warn',
      text: `${plural(ctx.ptr.n, 'ptr term')} in the tree. RFC 7208 says ptr should not be used: it is slow, unreliable, and some receivers skip it.`,
      fix: 'Replace ptr with the ip4/ip6 ranges of the servers it was meant to cover.',
    });
  }

  const dupes = [...ctx.seen.entries()].filter(([, n]) => n > 1).map(([d]) => d);
  if (dupes.length) {
    F.push({
      state: 'warn',
      text: `${dupes.join(', ')} ${dupes.length === 1 ? 'is' : 'are'} included more than once in the tree, and every copy is counted again.`,
      fix: "Keep each include once. If a provider's include already contains another, drop your own copy of the inner one.",
    });
  }

  if (ctx.macros.n) {
    F.push({
      state: 'info',
      text: `${plural(ctx.macros.n, 'term uses', 'terms use')} a macro (%{...}). Each is counted once here, but what it looks up depends on the sending IP and address.`,
    });
  }

  if (report.incomplete) {
    F.push({
      state: 'info',
      text: 'Some lookups did not return in time or the check hit its query cap, so the true count may be higher. Run it again in a minute.',
    });
  }

  return report;
};
