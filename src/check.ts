/**
 * Email setup check: MX, SPF, DMARC and DKIM for one domain, read from public
 * DNS. This is the engine behind https://roimaxi.com/tools/email-setup-checker
 * and the grading is identical to the site's.
 *
 * GRADING
 * - Three graded signals, SPF, DMARC and MX, each pass / warn / fail.
 * - Capped by the worst finding, never averaged: two or more fails F, one fail
 *   D, two or more warnings C, one warning B, otherwise A.
 * - SPF: none or +all fails, ?all warns, ~all and -all pass. DMARC: none fails,
 *   p=none warns, p=quarantine and p=reject pass unless pct is below 100 or
 *   sp=none (warn), and a record with no valid p= warns when it has rua=
 *   (RFC 7489 then reads it as p=none), otherwise fails. MX: none or a null
 *   MX fails.
 * - DKIM is reported but never graded: a key we cannot find may still exist.
 * - Each of these can only lower a signal, never raise one: two SPF or two
 *   DMARC records, or an SPF syntax error (fail); an SPF record with no `all`,
 *   an estimated lookup count over 10, or an include that has no SPF record
 *   (warn). A subdomain's DMARC is read from its parent when it has none of
 *   its own.
 *
 * Everything that parses a record is a pure function; checkDomain() takes the
 * resolver as an option, so it can be tested without the network.
 */

import { answered, dohResolver, orgDomain, txtRecords, TYPE_CODE, type DnsResult, type Resolver } from './dns.js';
import { allOf, isSpf, parseSpf, SPF_LOOKUP_LIMIT, withAll, type Qualifier } from './spfParse.js';

export type State = 'pass' | 'warn' | 'fail' | 'info';
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface Note {
  state: State;
  text: string;
  /** What to do, in plain words. */
  fix?: string;
  /** A DNS value to publish. */
  value?: string;
}

export interface Section {
  key: 'mx' | 'spf' | 'dmarc' | 'dkim';
  label: string;
  /** The worst state among the notes; 'info' only for DKIM. */
  state: State;
  /** Counts towards the grade. */
  graded: boolean;
  /** The DNS name that was read. */
  where: string;
  /** The records as published. */
  records: string[];
  notes: Note[];
  /** SPF only: what each top-level include costs in DNS lookups. */
  includes?: Array<{ target: string; lookups: number }>;
  /** SPF only: the estimated lookup count for the whole record. */
  lookups?: number;
  /** DKIM only: selectors at which a key was found. */
  selectors?: string[];
  /** Set when the lookup itself failed. The section then says nothing about the record. */
  error?: string;
}

export interface Report {
  domain: string;
  /** False when the domain does not exist in DNS. */
  exists: boolean;
  /** Null when a graded lookup failed, so a grade would be a guess. */
  grade: Grade | null;
  verdict: string;
  sections: Section[];
}

export interface CheckOptions {
  /** Defaults to dohResolver(): Cloudflare DoH, Google fallback. */
  resolver?: Resolver;
}

/** Selectors tried for DKIM. Real selectors are private; these are common defaults. */
export const DKIM_SELECTORS = ['google', 'selector1', 'selector2', 'default', 'k1', 's1', 's2', 'resend', 'mail', 'dkim'];

/* ------------------------------------------------------------------ */
/* MX                                                                  */
/* ------------------------------------------------------------------ */

export interface Mx {
  priority: number;
  host: string;
}

export const parseMx = (data: string): Mx => {
  const [p, h = ''] = data.trim().split(/\s+/);
  return { priority: Number(p), host: h.toLowerCase().replace(/\.$/, '') };
};

/** The mail provider behind an MX host, when it is one of the two we can name for sure. */
export const mxProvider = (hosts: string[]): 'google' | 'microsoft' | null => {
  if (hosts.some((h) => /(^|\.)(google\.com|googlemail\.com)$/.test(h))) return 'google';
  if (hosts.some((h) => /(^|\.)outlook\.com$/.test(h))) return 'microsoft';
  return null;
};

const PROVIDER = {
  google: { name: 'Google Workspace', spf: 'include:_spf.google.com' },
  microsoft: { name: 'Microsoft 365', spf: 'include:spf.protection.outlook.com' },
};

/* ------------------------------------------------------------------ */
/* SPF                                                                 */
/* ------------------------------------------------------------------ */

export interface Walk {
  lookups: number;
  /** The `all` that ends evaluation: the record's own, or its redirect target's. */
  all: Qualifier | null;
  /** Include or redirect targets that publish no SPF record. */
  missing: string[];
  macros: boolean;
  ptr: boolean;
  /** Lookups we could not finish, so the count is a floor. */
  incomplete: boolean;
  includes: Array<{ target: string; lookups: number }>;
}

/**
 * Count the DNS-querying terms an SPF check would hit: include, a, mx, ptr,
 * exists and redirect, following includes and redirects into their records.
 * An estimate, labelled as one: a receiver stops at the first match, counts
 * macros after expanding them and also limits void lookups. For the full
 * tree with void lookups and MX host counts, see countSpfLookups().
 */
export const walkSpf = async (
  record: string,
  resolve: Resolver,
  path: string[] = [],
  budget = { queries: 40 }
): Promise<Walk> => {
  const parsed = parseSpf(record);
  const w: Walk = { lookups: 0, all: allOf(parsed), missing: [], macros: false, ptr: false, incomplete: false, includes: [] };

  const follow = async (target: string): Promise<Walk | null> => {
    if (target.includes('%')) {
      w.macros = true;
      return null;
    }
    if (path.includes(target) || path.length >= 10 || budget.queries <= 0) {
      w.incomplete = true;
      return null;
    }
    budget.queries--;
    let r: DnsResult;
    try {
      r = await resolve(target, 'TXT');
    } catch {
      w.incomplete = true;
      return null;
    }
    if (!answered(r)) {
      w.incomplete = true;
      return null;
    }
    const spf = txtRecords(r).filter(isSpf);
    if (spf.length !== 1) {
      w.missing.push(target);
      return null;
    }
    return walkSpf(spf[0], resolve, [...path, target], budget);
  };

  const absorb = (child: Walk | null) => {
    if (!child) return 0;
    w.missing.push(...child.missing);
    w.macros ||= child.macros;
    w.ptr ||= child.ptr;
    w.incomplete ||= child.incomplete;
    return child.lookups;
  };

  const includes = parsed.terms.filter((t) => t.mechanism === 'include');
  const children = await Promise.all(includes.map((t) => follow(t.value)));
  includes.forEach((t, i) => {
    const cost = 1 + absorb(children[i]);
    w.lookups += cost;
    w.includes.push({ target: t.value, lookups: cost });
  });
  for (const t of parsed.terms) {
    if (t.mechanism === 'a' || t.mechanism === 'mx' || t.mechanism === 'ptr' || t.mechanism === 'exists') w.lookups++;
    if (t.mechanism === 'ptr') w.ptr = true;
    if (t.mechanism === 'exists' && t.value.includes('%')) w.macros = true;
  }
  // redirect= only applies when the record has no `all` (RFC 7208 section 6.1).
  if (parsed.redirect && w.all === null) {
    w.lookups++;
    const child = await follow(parsed.redirect);
    w.lookups += absorb(child);
    w.all = child ? child.all : null;
  }
  return w;
};

const spfSection = async (
  domain: string,
  txt: DnsResult | Error,
  provider: 'google' | 'microsoft' | null,
  resolve: Resolver
): Promise<Section> => {
  const s: Section = { key: 'spf', label: 'SPF', state: 'pass', graded: true, where: domain, records: [], notes: [] };
  if (txt instanceof Error || !answered(txt)) {
    return { ...s, state: 'info', error: `The TXT lookup for ${domain} failed, so SPF could not be checked. Try again in a minute.` };
  }
  const spf = txtRecords(txt).filter(isSpf);
  s.records = spf;

  if (spf.length === 0) {
    const inc = provider ? PROVIDER[provider].spf : 'include:<your sending service>';
    s.notes.push({
      state: 'fail',
      text: `No SPF record on ${domain}. Receivers have no list of the servers allowed to send as you, so they cannot tell your mail from a forgery.`,
      fix:
        `Publish one TXT record at ${domain} that names every service you send through and ends in ~all.` +
        (provider ? ` Your MX points at ${PROVIDER[provider].name}; if you send through it too, this is the record.` : " Your provider's help pages give the include to use."),
      value: `v=spf1 ${inc} ~all`,
    });
  } else if (spf.length > 1) {
    s.notes.push({
      state: 'fail',
      text: `${spf.length} SPF records on ${domain}. A domain may publish only one, and with two or more, SPF fails for every message (RFC 7208).`,
      fix: 'Merge them into one record: one v=spf1 at the start, every include from all of them, and one ~all at the end.',
    });
  } else {
    const record = spf[0];
    const parsed = parseSpf(record);
    const walk = await walkSpf(record, resolve, [domain]);
    s.includes = walk.includes;
    s.lookups = walk.lookups;

    if (parsed.invalid.length) {
      s.notes.push({
        state: 'fail',
        text: `The record has ${parsed.invalid.length === 1 ? 'a term' : 'terms'} receivers will not understand: ${parsed.invalid.join(', ')}. A syntax error makes SPF fail for every message.`,
        fix: 'Correct or remove it. A common cause is a space after a colon, as in "include: _spf.google.com".',
      });
    }

    if (walk.all === '+') {
      s.notes.push({
        state: 'fail',
        text: `The record ends in +all, which allows every server on the internet to send as ${domain}. That is worse than no SPF record.`,
        fix: 'Change +all to ~all.',
        value: withAll(record, '~'),
      });
    } else if (walk.all === '?') {
      s.notes.push({
        state: 'warn',
        text: 'The record ends in ?all (neutral). Receivers treat a server that is not on your list the same as one that is.',
        fix: 'Change ?all to ~all.',
        value: withAll(record, '~'),
      });
    } else if (walk.all === null) {
      s.notes.push({
        state: 'warn',
        text: 'The record has no all at the end, so a server that is not on the list gets a neutral result, the same as ?all.',
        fix: 'Add ~all at the end.',
        value: parsed.redirect ? undefined : withAll(record, '~'),
      });
    } else if (!parsed.invalid.length) {
      s.notes.push({
        state: 'pass',
        text:
          walk.all === '-'
            ? 'One SPF record, ending in -all (fail): mail from a server that is not on the list should be rejected.'
            : 'One SPF record, ending in ~all (softfail): mail from a server that is not on the list is treated as suspect.',
      });
    }
    if (parsed.redirect && allOf(parsed) === null) {
      s.notes.push({ state: 'info', text: `The record hands over to ${parsed.redirect} with redirect=, so its ending comes from that record.` });
    }

    for (const t of [...new Set(walk.missing)]) {
      s.notes.push({
        state: 'warn',
        text: `${t} is included but publishes no single SPF record. Receivers treat that as an error, and SPF fails for any message that gets that far.`,
        fix: 'Remove it, or replace it with the include your provider gives you now.',
      });
    }

    const n = walk.lookups;
    const floor = walk.macros || walk.incomplete ? ' at least' : ' about';
    if (n > SPF_LOOKUP_LIMIT) {
      s.notes.push({
        state: 'warn',
        text: `DNS lookups:${floor} ${n}, over the limit of ${SPF_LOOKUP_LIMIT} in RFC 7208. Receivers that count the same way return an error, and SPF fails for any message not matched before the limit. This count is an estimate.`,
        fix: 'Remove includes for services you no longer send through. The cost of each include is listed under the record.',
      });
    } else {
      s.notes.push({
        state: 'info',
        text:
          n >= 8
            ? `DNS lookups:${floor} ${n} of the ${SPF_LOOKUP_LIMIT} allowed. One more sending service could push it over. This count is an estimate.`
            : `DNS lookups:${floor} ${n} of the ${SPF_LOOKUP_LIMIT} allowed. This count is an estimate.`,
      });
    }
    if (walk.macros) s.notes.push({ state: 'info', text: 'The record uses SPF macros, which only resolve for a real message, so the lookup count is a floor.' });
    if (walk.incomplete) s.notes.push({ state: 'info', text: 'Some includes could not be followed, so the lookup count may be low.' });
    if (walk.ptr) {
      s.notes.push({
        state: 'info',
        text: 'The record uses ptr, which RFC 7208 says not to use. It is slow, and some receivers skip it.',
        fix: 'Replace it with ip4, ip6 or include.',
      });
    }
  }
  s.state = worst(s.notes.map((x) => x.state));
  return s;
};

/* ------------------------------------------------------------------ */
/* DMARC                                                               */
/* ------------------------------------------------------------------ */

export const isDmarc = (txt: string): boolean => /^v\s*=\s*DMARC1\s*(;|$)/i.test(txt.trim());

/** DMARC tags, lower-case names, values trimmed. The first of a repeated tag wins. */
export const parseDmarc = (record: string): Record<string, string> => {
  const tags: Record<string, string> = {};
  for (const part of record.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim().toLowerCase();
    if (k && !(k in tags)) tags[k] = part.slice(i + 1).trim();
  }
  return tags;
};

const POLICIES = ['none', 'quarantine', 'reject'];

/** The record with tag k set to v: replaced where it is, or appended. */
const withTag = (record: string, k: string, v: string): string => {
  const parts = record.split(';').map((p) => p.trim()).filter(Boolean);
  const i = parts.findIndex((p) => p.split('=')[0].trim().toLowerCase() === k);
  if (i >= 0) parts[i] = `${k}=${v}`;
  else parts.push(`${k}=${v}`);
  return parts.join('; ');
};

const dmarcSection = async (domain: string, own: DnsResult | Error, resolve: Resolver): Promise<Section> => {
  const where = `_dmarc.${domain}`;
  const s: Section = { key: 'dmarc', label: 'DMARC', state: 'pass', graded: true, where, records: [], notes: [] };
  if (own instanceof Error || !answered(own)) {
    return { ...s, state: 'info', error: `The lookup for ${where} failed, so DMARC could not be checked. Try again in a minute.` };
  }
  let records = txtRecords(own).filter(isDmarc);
  let inherited: string | null = null;

  const org = orgDomain(domain);
  if (records.length === 0 && org !== domain) {
    try {
      const parent = await resolve(`_dmarc.${org}`, 'TXT');
      if (answered(parent)) {
        const pr = txtRecords(parent).filter(isDmarc);
        if (pr.length) {
          records = pr;
          inherited = org;
        }
      }
    } catch {
      // No parent answer: report the subdomain as it stands.
    }
  }
  s.records = records;
  if (inherited) s.where = `_dmarc.${inherited}`;

  const starter = `v=DMARC1; p=none; rua=mailto:dmarc@${inherited ?? domain}`;

  if (records.length === 0) {
    s.notes.push({
      state: 'fail',
      text: `No DMARC record at ${where}. Receivers get no instruction for mail that fails SPF and DKIM, and you get no reports.`,
      fix: `Publish this TXT record at ${where}. p=none changes no delivery; it turns on the reports. Make sure the rua mailbox exists, or point it at a DMARC report service.`,
      value: starter,
    });
  } else if (records.length > 1) {
    s.notes.push({
      state: 'fail',
      text: `${records.length} DMARC records at ${s.where}. With more than one, receivers ignore DMARC altogether (RFC 7489).`,
      fix: 'Delete all but one.',
    });
  } else {
    const record = records[0];
    const tags = parseDmarc(record);
    const rua = tags.rua ? tags.rua.split(',').map((x) => x.trim().replace(/^mailto:/i, '')).filter(Boolean) : [];
    if (inherited) {
      s.notes.push({
        state: 'info',
        text: `No record at ${where}. The record at _dmarc.${inherited} covers it${tags.sp ? ', through its sp= tag' : ''}.`,
      });
    }
    const pRaw = (tags.p || '').toLowerCase();
    const spRaw = (tags.sp || '').toLowerCase();
    const p = POLICIES.includes(pRaw) ? pRaw : null;
    const sp = POLICIES.includes(spRaw) ? spRaw : null;
    // A subdomain gets sp= when the parent sets it (RFC 7489 section 6.3).
    const policy = inherited ? (sp ?? p) : p;

    if (!p) {
      if (rua.length) {
        s.notes.push({
          state: 'warn',
          text: 'The record has no valid p= tag. Because it has a rua= address, receivers treat it as p=none: they do nothing with mail that fails.',
          fix: 'Add p=none now, and move to p=quarantine once the reports show your mail passing.',
          value: withTag(record, 'p', 'none'),
        });
      } else {
        s.notes.push({
          state: 'fail',
          text: 'The record has no valid p= tag and no rua= address, so receivers discard it. In effect there is no DMARC.',
          fix: 'Replace it with a record that has both.',
          value: starter,
        });
      }
    } else if (policy === 'none') {
      s.notes.push(
        rua.length
          ? {
              state: 'warn',
              text: `Policy ${inherited && sp ? 'sp' : 'p'}=none: receivers are asked to do nothing with mail that fails. Reports are on, so you can see what fails.`,
              fix: 'Read two weeks of reports. When every service you send through passes, move to p=quarantine.',
              value: inherited ? undefined : withTag(record, 'p', 'quarantine'),
            }
          : {
              state: 'warn',
              text: `Policy ${inherited && sp ? 'sp' : 'p'}=none with no rua= address. The record asks receivers to do nothing and sends you no reports.`,
              fix: 'Add a rua= address so you get reports. Yahoo strongly recommends one for bulk senders.',
              value: inherited ? undefined : withTag(record, 'rua', `mailto:dmarc@${domain}`),
            }
      );
    } else {
      const tag = inherited && sp ? 'sp' : 'p';
      s.notes.push({
        state: 'pass',
        text:
          policy === 'reject'
            ? `Policy ${tag}=reject: receivers are asked to refuse mail that fails.`
            : `Policy ${tag}=quarantine: receivers are asked to put mail that fails in spam.`,
      });
      const pct = tags.pct !== undefined ? Number(tags.pct) : 100;
      if (Number.isFinite(pct) && pct < 100) {
        s.notes.push({
          state: 'warn',
          text: `pct=${tags.pct}: the policy covers only ${Math.max(0, pct)}% of mail that fails.`,
          fix: 'Raise pct to 100, or remove it; 100 is the default.',
          value: inherited ? undefined : withTag(record, 'pct', '100'),
        });
      }
      if (!inherited && sp === 'none') {
        s.notes.push({
          state: 'warn',
          text: `sp=none: mail claiming to come from a subdomain of ${domain} gets no policy, so the subdomains can be spoofed.`,
          fix: 'Remove sp=none, or set it to quarantine or reject.',
        });
      }
      if (!rua.length) {
        s.notes.push({ state: 'info', text: 'No rua= address, so you get no reports on what fails.' });
      }
    }
    if (rua.length) s.notes.push({ state: 'info', text: `Reports go to ${rua.join(', ')}.` });
  }
  s.state = worst(s.notes.map((x) => x.state));
  return s;
};

/* ------------------------------------------------------------------ */
/* DKIM                                                                */
/* ------------------------------------------------------------------ */

export const parseDkim = (record: string): Record<string, string> => parseDmarc(record);

const isDkim = (txt: string) => /(^|;)\s*p\s*=/i.test(txt) || /^v\s*=\s*DKIM1/i.test(txt.trim());

/**
 * Rough RSA key size from the base64 public key in p=. An RSA
 * SubjectPublicKeyInfo is about 38 bytes plus the modulus, so 162 bytes is
 * 1024-bit and 294 bytes is 2048-bit. Snapped to the common sizes.
 */
export const rsaBits = (p: string): number | null => {
  const b64 = p.replace(/\s+/g, '');
  if (!b64 || !/^[A-Za-z0-9+/]+=*$/.test(b64)) return null;
  const bytes = Math.floor((b64.length * 3) / 4) - (b64.match(/=+$/)?.[0].length ?? 0);
  const raw = (bytes - 38) * 8;
  const sizes = [512, 768, 1024, 1536, 2048, 3072, 4096];
  return sizes.reduce((a, b) => (Math.abs(b - raw) < Math.abs(a - raw) ? b : a));
};

const dkimSection = (domain: string, found: Array<{ selector: string; result: DnsResult | Error }>): Section => {
  const s: Section = {
    key: 'dkim',
    label: 'DKIM',
    state: 'info',
    graded: false,
    where: `<selector>._domainkey.${domain}`,
    records: [],
    notes: [],
    selectors: [],
  };
  let failed = 0;
  const revoked: string[] = [];
  for (const { selector, result } of found) {
    if (result instanceof Error || !answered(result)) {
      failed++;
      continue;
    }
    const rec = txtRecords(result).find(isDkim);
    if (!rec) continue;
    s.selectors!.push(selector);
    // The key itself is hundreds of characters of base64 and says nothing to a reader.
    s.records.push(
      `${selector}._domainkey: ${rec.replace(/(p\s*=\s*)([A-Za-z0-9+/=\s]{40,})/, (_, k: string, v: string) => `${k}${v.replace(/\s+/g, '').slice(0, 24)}... (${v.replace(/\s+/g, '').length} characters)`)}`
    );
    const tags = parseDkim(rec);
    const k = (tags.k || 'rsa').toLowerCase();
    const p = tags.p ?? '';
    if (!p.trim()) {
      revoked.push(selector);
      continue;
    }
    if (k !== 'rsa') {
      s.notes.push({ state: 'pass', text: `DKIM key found at ${selector}._domainkey.${domain} (${k}).` });
      continue;
    }
    const bits = rsaBits(p);
    if (bits !== null && bits < 1024) {
      s.notes.push({
        state: 'warn',
        text: `The key at ${selector}._domainkey is about ${bits}-bit. Google and Yahoo both ask for 1024 bits or longer.`,
        fix: 'Generate a new 2048-bit key in your email provider and publish it.',
      });
    } else {
      s.notes.push({
        state: 'pass',
        text: `DKIM key found at ${selector}._domainkey.${domain}${bits ? `, about ${bits}-bit RSA` : ''}.`,
      });
    }
  }
  if (revoked.length) {
    s.notes.push({
      state: 'info',
      text: `Empty key (p=) at ${revoked.join(', ')}. An empty key means it was revoked, so it signs nothing.`,
    });
  }
  if (failed === found.length) {
    s.notes.push({ state: 'info', text: 'The DKIM lookups failed, so no selector could be checked. Try again in a minute.' });
    s.state = 'info';
    return s;
  }
  if (!s.notes.some((n) => n.state === 'pass' || n.state === 'warn')) {
    s.notes.push({
      state: 'info',
      text: `No DKIM key at the ${DKIM_SELECTORS.length} common selectors tried. That does not mean DKIM is missing. Your email provider picks the selector name, and DNS has no way to list them.`,
      fix: `Open an email you sent from ${domain} and show the original. In the DKIM-Signature line, s= is your selector and d= should be ${domain}. If d= shows your provider's domain instead, set up DKIM for your own domain in the provider's settings.`,
    });
  }
  if (failed) s.notes.push({ state: 'info', text: `${failed} of the selector lookups failed, so a key may have been missed.` });
  s.state = worst(s.notes.map((x) => x.state));
  return s;
};

/* ------------------------------------------------------------------ */
/* Grade                                                               */
/* ------------------------------------------------------------------ */

const RANK: Record<State, number> = { info: 0, pass: 1, warn: 2, fail: 3 };

export const worst = (states: State[]): State => states.reduce<State>((a, b) => (RANK[b] > RANK[a] ? b : a), 'info');

/** Two or more fails F, one fail D, two or more warnings C, one warning B, otherwise A. */
export const gradeFrom = (states: State[]): Grade => {
  const fails = states.filter((x) => x === 'fail').length;
  const warns = states.filter((x) => x === 'warn').length;
  return fails >= 2 ? 'F' : fails === 1 ? 'D' : warns >= 2 ? 'C' : warns === 1 ? 'B' : 'A';
};

export const VERDICT: Record<Grade, string> = {
  A: 'Nothing in these records will stop your mail. They are published and they enforce.',
  B: 'Mail should land, but one setting does less than it seems to.',
  C: 'Two settings do less than they seem to. Fix them before you add volume.',
  D: 'One required record is missing or broken. Fix it before you send cold email from this domain.',
  F: 'Two or more essentials are missing or broken. Cold email from this domain will not work until they are fixed.',
};

/* ------------------------------------------------------------------ */
/* The check                                                           */
/* ------------------------------------------------------------------ */

const settle = <T>(p: Promise<T>): Promise<T | Error> =>
  p.catch((e: unknown) => (e instanceof Error ? e : new Error(String(e))));

/**
 * Check one domain's MX, SPF, DMARC and DKIM. `domain` should be a bare,
 * lower-case host name; use normalizeDomain() on raw input first.
 */
export const checkDomain = async (domain: string, opts: CheckOptions = {}): Promise<Report> => {
  const resolve = opts.resolver ?? dohResolver();
  const [txt, mx, dmarc, ...dkim] = await Promise.all([
    settle(resolve(domain, 'TXT')),
    settle(resolve(domain, 'MX')),
    settle(resolve(`_dmarc.${domain}`, 'TXT')),
    ...DKIM_SELECTORS.map((sel) => settle(resolve(`${sel}._domainkey.${domain}`, 'TXT'))),
  ]);

  const nx = (r: DnsResult | Error) => !(r instanceof Error) && r.status === 3;
  if (nx(txt) && nx(mx)) {
    return {
      domain,
      exists: false,
      grade: null,
      verdict: `${domain} does not exist in DNS. Check the spelling, or register it before you send from it.`,
      sections: [],
    };
  }

  // MX
  const mxS: Section = { key: 'mx', label: 'MX', state: 'pass', graded: true, where: domain, records: [], notes: [] };
  let provider: 'google' | 'microsoft' | null = null;
  if (mx instanceof Error || !answered(mx)) {
    mxS.state = 'info';
    mxS.error = `The MX lookup for ${domain} failed, so MX could not be checked. Try again in a minute.`;
  } else {
    const list = mx.answers
      .filter((a) => a.type === TYPE_CODE.MX)
      .map((a) => parseMx(a.data))
      .sort((a, b) => a.priority - b.priority);
    mxS.records = list.map((m) => `${m.priority} ${m.host || '.'}`);
    provider = mxProvider(list.map((m) => m.host));
    if (list.length === 0) {
      mxS.notes.push({
        state: 'fail',
        text: `No MX records, so ${domain} cannot receive mail. Every reply to a cold email sent from it bounces.`,
        fix: 'Add the MX records your mail provider gives you.',
      });
    } else if (list.length === 1 && list[0].host === '') {
      mxS.notes.push({
        state: 'fail',
        text: `A null MX record (0 .): ${domain} says it accepts no mail at all, so replies bounce.`,
        fix: 'Replace it with the MX records your mail provider gives you.',
      });
    } else {
      mxS.notes.push({
        state: 'pass',
        text:
          `${list.length} MX record${list.length === 1 ? '' : 's'}. Replies have somewhere to land.` +
          (provider ? ` Mail is handled by ${PROVIDER[provider].name}.` : ''),
      });
    }
    mxS.state = worst(mxS.notes.map((x) => x.state));
  }

  const spfS = await spfSection(domain, txt, provider, resolve);
  const dmarcS = await dmarcSection(domain, dmarc, resolve);
  const dkimS = dkimSection(
    domain,
    DKIM_SELECTORS.map((selector, i) => ({ selector, result: dkim[i] }))
  );

  const graded = [spfS, dmarcS, mxS];
  const grade = graded.some((x) => x.error) ? null : gradeFrom(graded.map((x) => x.state));
  return {
    domain,
    exists: true,
    grade,
    verdict: grade ? VERDICT[grade] : 'A lookup failed, so there is no grade. The records that did load are below. Try again in a minute.',
    sections: [mxS, spfS, dmarcS, dkimS],
  };
};
