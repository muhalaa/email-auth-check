/**
 * DNS types, the DNS-over-HTTPS resolver and the TXT decoder shared by every
 * check in this package.
 *
 * The resolver asks Cloudflare's DoH JSON API first (cloudflare-dns.com) and
 * falls back to Google's (dns.google) when Cloudflare fails or answers
 * SERVFAIL. Nothing is sent anywhere else and nothing is stored. Answers are
 * cached for the life of one resolver, so build one per check.
 */

export type RecordType = 'TXT' | 'MX' | 'A' | 'AAAA';

/** One DNS answer set, as the DoH JSON APIs return it. */
export interface DnsResult {
  /** DNS RCODE: 0 NOERROR, 2 SERVFAIL, 3 NXDOMAIN. */
  status: number;
  answers: Array<{ type: number; data: string }>;
}

/** Any function that answers a DNS question. Pass your own to avoid the network. */
export type Resolver = (name: string, type: RecordType) => Promise<DnsResult>;

export const TYPE_CODE: Record<RecordType, number> = { A: 1, MX: 15, TXT: 16, AAAA: 28 };

export const DOH_URL = {
  cloudflare: (name: string, type: RecordType) =>
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`,
  google: (name: string, type: RecordType) =>
    `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`,
};

export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface DohOptions {
  /** Defaults to the global fetch (Node 18 and later). */
  fetch?: FetchLike;
  /** Per-request timeout in milliseconds. Default 8000. */
  timeoutMs?: number;
}

/**
 * A resolver over Cloudflare's DoH JSON API, falling back to Google's when
 * Cloudflare fails or answers SERVFAIL.
 */
export const dohResolver = (opts: DohOptions = {}): Resolver => {
  const fetchImpl: FetchLike = opts.fetch ?? ((u, i) => fetch(u, i));
  const timeoutMs = opts.timeoutMs ?? 8000;
  const cache = new Map<string, Promise<DnsResult>>();

  const ask = async (url: string): Promise<DnsResult> => {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const r = await fetchImpl(url, {
        headers: { accept: 'application/dns-json' },
        signal: ctrl.signal,
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d = (await r.json()) as { Status?: number; Answer?: Array<{ type: number; data: string }> };
      if (typeof d.Status !== 'number') throw new Error('Malformed DNS answer');
      return {
        status: d.Status,
        answers: (d.Answer || []).map((a) => ({ type: Number(a.type), data: String(a.data ?? '') })),
      };
    } finally {
      clearTimeout(timer);
    }
  };

  const lookup = async (name: string, type: RecordType): Promise<DnsResult> => {
    try {
      const first = await ask(DOH_URL.cloudflare(name, type));
      if (first.status !== 2) return first;
      try {
        return await ask(DOH_URL.google(name, type));
      } catch {
        return first;
      }
    } catch (err) {
      return ask(DOH_URL.google(name, type)).catch(() => {
        throw err;
      });
    }
  };

  return (name, type) => {
    const key = `${name.toLowerCase()}|${type}`;
    let p = cache.get(key);
    if (!p) {
      p = lookup(name, type);
      cache.set(key, p);
    }
    return p;
  };
};

/**
 * One TXT record's text. Cloudflare returns the character-strings quoted and
 * space-separated ("v=spf1 ..." "include:..."); Google returns them already
 * joined. A long SPF or DKIM record is split across strings, and the strings
 * join with nothing between them (RFC 7208 section 3.3).
 */
export const txtData = (data: string): string => {
  const s = data.trim();
  if (!s.startsWith('"')) return s;
  const parts = s.match(/"((?:[^"\\]|\\.)*)"/g) || [];
  return parts
    .map((p) =>
      p
        .slice(1, -1)
        .replace(/\\(\d{3})/g, (_, d: string) => String.fromCharCode(Number(d)))
        .replace(/\\(.)/g, '$1')
    )
    .join('');
};

export const txtRecords = (r: DnsResult): string[] =>
  r.answers.filter((a) => a.type === TYPE_CODE.TXT).map((a) => txtData(a.data));

/** NOERROR and NXDOMAIN are answers. Anything else means the lookup failed. */
export const answered = (r: DnsResult): boolean => r.status === 0 || r.status === 3;

/**
 * The domain in what someone typed: a bare domain, a web address or an email
 * address. Lower case, punycode for international names, no www., no trailing
 * dot. Returns an error message instead when there is no usable domain.
 */
export const normalizeDomain = (input: string): { domain: string } | { error: string } => {
  let s = input.trim().toLowerCase();
  if (!s) return { error: 'Type a domain, such as acme.com.' };
  s = s.replace(/^mailto:/, '');
  if (s.includes('@')) s = s.slice(s.lastIndexOf('@') + 1);
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  s = s.split(/[/?#\s]/)[0].replace(/:\d+$/, '').replace(/\.+$/, '');
  let host = s;
  try {
    host = new URL(`http://${s}`).hostname;
  } catch {
    return { error: `"${input.trim().slice(0, 80)}" is not a domain. Type one such as acme.com.` };
  }
  host = host.replace(/^www\./, '').replace(/\.+$/, '');
  const label = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
  const parts = host.split('.');
  if (
    host.length > 253 ||
    parts.length < 2 ||
    !parts.every((p) => label.test(p)) ||
    !/^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.test(parts[parts.length - 1])
  ) {
    return { error: `"${input.trim().slice(0, 80)}" is not a domain. Type one such as acme.com.` };
  }
  return { domain: host };
};

/**
 * The organisational domain, roughly: the last two labels, or three under a
 * two-level public suffix such as co.uk. Used to find a parent DMARC record
 * when a subdomain is checked. A full answer needs the Public Suffix List.
 */
export const orgDomain = (domain: string): string => {
  const p = domain.split('.');
  if (p.length <= 2) return domain;
  const sld = p[p.length - 2];
  const tld = p[p.length - 1];
  const twoLevel = tld.length === 2 && /^(co|com|org|net|ac|gov|edu|ltd|plc|me|nhs|sch|nic|or|ne|go)$/.test(sld);
  return p.slice(twoLevel ? -3 : -2).join('.');
};
