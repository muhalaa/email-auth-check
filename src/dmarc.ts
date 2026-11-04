/**
 * DMARC record generator and validator. Pure functions, no network. This is
 * the engine behind https://roimaxi.com/tools/dmarc-record-generator.
 *
 * buildDmarcRecord() turns options into the TXT record to publish at
 * _dmarc.<domain>, and validateDmarc() reads any record against RFC 7489,
 * sections 6.3 (the tags) and 6.4 (the format):
 * - v=DMARC1 must be the first tag, spelled exactly so, or the record is
 *   ignored.
 * - p= comes right after it. A record with no valid p= is read as p=none if
 *   it has a valid rua= (section 6.6.3), and ignored otherwise.
 * - p and sp: none, quarantine or reject. adkim and aspf: r or s. pct: a whole
 *   number 0 to 100. fo: 0, 1, d or s, joined by colons. rf: afrf. ri: a whole
 *   number of seconds. rua and ruf: comma-separated URIs, normally mailto:,
 *   each with an optional !size such as !10m.
 * - Unknown tags are ignored by receivers, so they are flagged, not failed.
 *
 * The generated record leaves out every tag at its default (sp equal to p,
 * pct=100, adkim=r, aspf=r, fo=0), so it is as short as it can be and says
 * only what was chosen. Tag order: v, p, sp, pct, rua, ruf, fo, adkim, aspf.
 *
 * Report addresses on another organisational domain need that domain to
 * publish an authorisation record (section 7.1):
 * <your domain>._report._dmarc.<their domain>  TXT  "v=DMARC1".
 */

import { orgDomain } from './dns.js';

export type Policy = 'none' | 'quarantine' | 'reject';
export type Align = 'r' | 's';
export type FoOption = '0' | '1' | 'd' | 's';

export const POLICIES: Policy[] = ['none', 'quarantine', 'reject'];
export const FO_OPTIONS: FoOption[] = ['0', '1', 'd', 's'];

export interface DmarcOptions {
  /** The domain the record is for. Optional; sets `host` and the authorisation records. */
  domain?: string;
  /** p=. Default none. */
  policy?: Policy;
  /** sp=. Left out when equal to the policy. */
  subdomainPolicy?: Policy;
  /** pct=. Left out at 100 or at p=none. */
  pct?: number | string;
  /** Aggregate report addresses: an array, or one string with commas, spaces or new lines between them. mailto: optional. */
  rua?: string | string[];
  /** Failure report addresses, as rua. */
  ruf?: string | string[];
  /** adkim=. Default r. */
  adkim?: Align;
  /** aspf=. Default r. */
  aspf?: Align;
  /** fo=. Default ['0']. Only written when there is a ruf address. */
  fo?: FoOption[];
}

export type IssueLevel = 'error' | 'warn' | 'info';

export interface Issue {
  level: IssueLevel;
  text: string;
  /** The option it is about. */
  field?: keyof DmarcOptions;
}

export interface BuiltRecord {
  /** _dmarc.<domain>, or null when no usable domain was given. */
  host: string | null;
  /** The TXT value to publish. */
  value: string;
  issues: Issue[];
  /** Authorisation records the report domains need (RFC 7489 section 7.1). */
  authorisations: Array<{ host: string; value: string }>;
}

const EMAIL = /^[^\s@,;!]+@([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)$/i;

const isHost = (d: string) =>
  /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i.test(d);

/** Addresses as typed, split on commas, semicolons, spaces and new lines, mailto: removed. */
export const splitAddresses = (raw: string | string[] | undefined): string[] =>
  (Array.isArray(raw) ? raw.join(',') : raw ?? '')
    .split(/[\s,;]+/)
    .map((s) => s.trim().replace(/^mailto:/i, ''))
    .filter(Boolean);

const domainOf = (email: string) => email.slice(email.lastIndexOf('@') + 1).toLowerCase().replace(/\.+$/, '');

/** Addresses whose organisational domain is not the policy domain's: they need an authorisation record. */
const external = (domain: string, emails: string[]): string[] => {
  const own = orgDomain(domain);
  return [...new Set(emails.map(domainOf))].filter((d) => orgDomain(d) !== own);
};

export const POLICY_PLAIN: Record<Policy, string> = {
  none: 'Deliver it as usual and send me reports. Nothing changes for your mail; you start seeing who sends as your domain.',
  quarantine: 'Treat it as suspicious: usually the spam folder. Forged mail stops reaching inboxes, and a misconfigured sender of yours lands in spam rather than vanishing.',
  reject: 'Refuse it at the door. Forged mail is never delivered. So is real mail from any service of yours that is not set up yet.',
};

export const buildDmarcRecord = (opts: DmarcOptions = {}): BuiltRecord => {
  const issues: Issue[] = [];
  const p: Policy = opts.policy ?? 'none';
  if (!POLICIES.includes(p)) throw new Error(`policy must be one of ${POLICIES.join(', ')}`);
  const sp = opts.subdomainPolicy;
  if (sp !== undefined && !POLICIES.includes(sp)) throw new Error(`subdomainPolicy must be one of ${POLICIES.join(', ')}`);
  const domain = opts.domain?.trim().toLowerCase().replace(/\.+$/, '') || null;

  const parts = ['v=DMARC1', `p=${p}`];

  if (sp && sp !== p) parts.push(`sp=${sp}`);

  const pctRaw = opts.pct === undefined ? '' : String(opts.pct).trim();
  if (pctRaw !== '') {
    const n = Number(pctRaw);
    if (!/^\d{1,3}$/.test(pctRaw) || n > 100) {
      issues.push({ level: 'error', field: 'pct', text: 'pct must be a whole number from 0 to 100. Left out of the record until it is.' });
    } else if (n !== 100) {
      if (p === 'none') {
        issues.push({ level: 'info', field: 'pct', text: 'pct has no effect at p=none: there is nothing to apply to a share of the mail. Left out.' });
      } else {
        parts.push(`pct=${n}`);
        issues.push({
          level: 'info',
          field: 'pct',
          text: `pct=${n} applies ${p} to ${n}% of failing mail; the rest is treated one step softer. Use it to ramp up, then remove it.`,
        });
      }
    }
  }

  const ruaList = splitAddresses(opts.rua);
  const rufList = splitAddresses(opts.ruf);
  const badRua = ruaList.filter((e) => !EMAIL.test(e));
  const badRuf = rufList.filter((e) => !EMAIL.test(e));
  const goodRua = ruaList.filter((e) => EMAIL.test(e));
  const goodRuf = rufList.filter((e) => EMAIL.test(e));
  if (badRua.length) issues.push({ level: 'error', field: 'rua', text: `Not an email address: ${badRua.join(', ')}. Left out.` });
  if (badRuf.length) issues.push({ level: 'error', field: 'ruf', text: `Not an email address: ${badRuf.join(', ')}. Left out.` });
  if (goodRua.length) parts.push(`rua=${goodRua.map((e) => `mailto:${e}`).join(',')}`);
  if (goodRuf.length) parts.push(`ruf=${goodRuf.map((e) => `mailto:${e}`).join(',')}`);

  const foIn = (opts.fo ?? ['0']).filter((x) => FO_OPTIONS.includes(x));
  if (goodRuf.length) {
    const fo = foIn.length ? foIn : ['0'];
    // fo=0 is the default; 1 already covers what 0 asks for.
    const kept = fo.includes('1') ? fo.filter((x) => x !== '0') : fo;
    if (!(kept.length === 1 && kept[0] === '0')) parts.push(`fo=${kept.join(':')}`);
  } else if (foIn.some((x) => x !== '0')) {
    issues.push({ level: 'info', field: 'fo', text: 'fo only shapes failure reports, so it is left out until there is a ruf address.' });
  }

  if (opts.adkim === 's') parts.push('adkim=s');
  if (opts.aspf === 's') parts.push('aspf=s');

  if (!goodRua.length) {
    issues.push({
      level: p === 'none' ? 'warn' : 'info',
      field: 'rua',
      text:
        p === 'none'
          ? 'With no rua address, p=none does nothing you can see: the reports are the point of it. Add a mailbox you read, or a DMARC report service.'
          : 'No rua address: the policy works, but you will not see what it blocks.',
    });
  }

  if (goodRuf.length) {
    issues.push({
      level: 'info',
      field: 'ruf',
      text: 'Most large mailbox providers send no failure (ruf) reports, and those that do can include message headers and addresses. Many senders leave ruf out.',
    });
  }

  const authorisations: BuiltRecord['authorisations'] = [];
  if (domain) {
    for (const d of external(domain, [...goodRua, ...goodRuf])) {
      authorisations.push({ host: `${domain}._report._dmarc.${d}`, value: 'v=DMARC1' });
    }
  }

  if (p === 'reject' && sp === 'none') {
    issues.push({ level: 'warn', field: 'subdomainPolicy', text: 'sp=none leaves every subdomain open to spoofing while the main domain is protected.' });
  }

  return { host: domain && isHost(domain) ? `_dmarc.${domain}` : null, value: parts.join('; '), issues, authorisations };
};

/* ------------------------------------------------------------------ */
/* Validation of any record                                            */
/* ------------------------------------------------------------------ */

export interface Validation {
  /** False when receivers would ignore the record. */
  usable: boolean;
  tags: Array<{ k: string; v: string }>;
  /** The policy a receiver applies, after section 6.6.3's fallback. */
  policy: Policy | null;
  issues: Issue[];
}

const KNOWN = new Set(['v', 'p', 'sp', 'pct', 'rua', 'ruf', 'adkim', 'aspf', 'fo', 'rf', 'ri']);
const URI = /^[a-z][a-z0-9+.-]*:[^\s,!]+(?:![0-9]+[kmgt]?)?$/i;

export const validateDmarc = (record: string): Validation => {
  const issues: Issue[] = [];
  const tags = record
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const i = s.indexOf('=');
      return i < 0 ? { k: s.toLowerCase(), v: '' } : { k: s.slice(0, i).trim().toLowerCase(), v: s.slice(i + 1).trim() };
    });

  const first = tags[0];
  if (!first || first.k !== 'v') {
    issues.push({ level: 'error', text: 'The record must start with v=DMARC1. Receivers ignore a record that does not.' });
    return { usable: false, tags, policy: null, issues };
  }
  if (first.v !== 'DMARC1') {
    issues.push({ level: 'error', text: `v=${first.v} is not v=DMARC1, spelled exactly so. Receivers ignore the record.` });
    return { usable: false, tags, policy: null, issues };
  }

  const seen = new Set<string>();
  for (const t of tags) {
    if (seen.has(t.k)) issues.push({ level: 'warn', text: `${t.k}= appears more than once. Receivers read the first and may ignore the rest.` });
    seen.add(t.k);
  }
  const get = (k: string) => tags.find((t) => t.k === k)?.v;

  const p = get('p');
  const pOk = p !== undefined && (POLICIES as string[]).includes(p.toLowerCase());
  const rua = get('rua');
  const ruaOk = !!rua && rua.split(',').every((u) => URI.test(u.trim()));

  if (p === undefined) {
    issues.push({ level: 'error', text: 'No p= tag. The policy is required, right after v=DMARC1.' });
  } else if (!pOk) {
    issues.push({ level: 'error', text: `p=${p} is not valid. Use none, quarantine or reject.` });
  } else if (tags[1]?.k !== 'p') {
    issues.push({ level: 'error', text: 'p= must come right after v=DMARC1. Move it to second place.' });
  }

  const sp = get('sp');
  if (sp !== undefined && !(POLICIES as string[]).includes(sp.toLowerCase())) {
    issues.push({ level: 'error', text: `sp=${sp} is not valid. Use none, quarantine or reject.` });
  }
  const pct = get('pct');
  if (pct !== undefined && (!/^\d{1,3}$/.test(pct) || Number(pct) > 100)) {
    issues.push({ level: 'error', text: `pct=${pct} is not valid. Use a whole number from 0 to 100.` });
  }
  for (const k of ['adkim', 'aspf']) {
    const v = get(k);
    if (v !== undefined && !/^[rs]$/i.test(v)) issues.push({ level: 'error', text: `${k}=${v} is not valid. Use r (relaxed) or s (strict).` });
  }
  const fo = get('fo');
  if (fo !== undefined && !/^[01ds](?::[01ds])*$/i.test(fo)) {
    issues.push({ level: 'error', text: `fo=${fo} is not valid. Use 0, 1, d or s, joined by colons, such as 1 or d:s.` });
  }
  const rf = get('rf');
  if (rf !== undefined && rf.toLowerCase() !== 'afrf') issues.push({ level: 'warn', text: `rf=${rf}: the only format RFC 7489 defines is afrf.` });
  const ri = get('ri');
  if (ri !== undefined && !/^\d+$/.test(ri)) issues.push({ level: 'error', text: `ri=${ri} is not valid. Use a whole number of seconds.` });
  for (const k of ['rua', 'ruf']) {
    const v = get(k);
    if (v === undefined) continue;
    const bad = v.split(',').map((u) => u.trim()).filter((u) => !URI.test(u));
    if (bad.length) issues.push({ level: 'error', text: `${k}= has an address that is not a URI: ${bad.join(', ')}. Each needs mailto: in front.` });
    else if (v.split(',').some((u) => !/^mailto:/i.test(u.trim()))) issues.push({ level: 'warn', text: `${k}= uses a scheme other than mailto:. Receivers send reports by email.` });
  }

  const unknown = tags.filter((t) => !KNOWN.has(t.k)).map((t) => t.k);
  if (unknown.length) {
    issues.push({ level: 'warn', text: `Not RFC 7489 tags: ${[...new Set(unknown)].join(', ')}. Receivers that follow it ignore them.` });
  }

  let policy: Policy | null = pOk ? (p!.toLowerCase() as Policy) : null;
  let usable = true;
  if (!pOk) {
    if (ruaOk) {
      policy = 'none';
      issues.push({ level: 'warn', text: 'With no valid p= but a valid rua=, receivers treat the record as p=none (RFC 7489, section 6.6.3).' });
    } else {
      usable = false;
    }
  }
  if (policy === 'none' && !rua) {
    issues.push({ level: 'warn', text: 'p=none with no rua= address: nothing is enforced and no reports come back.' });
  }
  return { usable, tags, policy, issues };
};

/** Options filled from an existing record, so a caller can start from what is published. */
export const optionsFromRecord = (record: string, domain?: string): DmarcOptions => {
  const v = validateDmarc(record);
  const get = (k: string) => v.tags.find((t) => t.k === k)?.v ?? '';
  const pol = (x: string): Policy | undefined =>
    (POLICIES as string[]).includes(x.toLowerCase()) ? (x.toLowerCase() as Policy) : undefined;
  const addrs = (x: string) => x.split(',').map((u) => u.trim().replace(/^mailto:/i, '').replace(/!.*$/, '')).filter(Boolean);
  const fo = get('fo').toLowerCase().split(':').filter((x): x is FoOption => (FO_OPTIONS as string[]).includes(x));
  const pct = get('pct');
  const out: DmarcOptions = {
    policy: pol(get('p')) ?? v.policy ?? 'none',
    adkim: get('adkim').toLowerCase() === 's' ? 's' : 'r',
    aspf: get('aspf').toLowerCase() === 's' ? 's' : 'r',
    fo: fo.length ? fo : ['0'],
  };
  if (domain) out.domain = domain;
  const sp = pol(get('sp'));
  if (sp) out.subdomainPolicy = sp;
  if (pct && pct !== '100') out.pct = pct;
  const rua = addrs(get('rua'));
  if (rua.length) out.rua = rua;
  const ruf = addrs(get('ruf'));
  if (ruf.length) out.ruf = ruf;
  return out;
};
