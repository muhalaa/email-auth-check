/** SPF record parsing (RFC 7208). Pure functions, no network. */

export type Qualifier = '+' | '-' | '~' | '?';

export interface SpfTerm {
  qualifier: Qualifier;
  mechanism: 'all' | 'include' | 'a' | 'mx' | 'ptr' | 'ip4' | 'ip6' | 'exists';
  value: string;
}

export interface SpfRecord {
  terms: SpfTerm[];
  redirect: string | null;
  /** Terms that are neither a mechanism nor a modifier: a syntax error. */
  invalid: string[];
}

/** RFC 7208 section 4.6.4. */
export const SPF_LOOKUP_LIMIT = 10;
export const SPF_VOID_LIMIT = 2;
export const SPF_MX_HOST_LIMIT = 10;

export const isSpf = (txt: string): boolean => /^v=spf1(\s|$)/i.test(txt.trim());

export const parseSpf = (record: string): SpfRecord => {
  const out: SpfRecord = { terms: [], redirect: null, invalid: [] };
  const words = record.trim().split(/\s+/).slice(1);
  for (const w of words) {
    const mech = /^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?=$|[:/])(?::([^/]*))?(\/.*)?$/i.exec(w);
    if (mech) {
      const mechanism = mech[2].toLowerCase() as SpfTerm['mechanism'];
      const value = mech[3] ?? '';
      const needsValue = mechanism === 'include' || mechanism === 'exists' || mechanism === 'ip4' || mechanism === 'ip6';
      const takesNone = mechanism === 'all';
      if ((needsValue && !value) || (takesNone && (mech[3] !== undefined || mech[4])) || (mech[3] !== undefined && !value)) {
        out.invalid.push(w);
        continue;
      }
      out.terms.push({ qualifier: (mech[1] || '+') as Qualifier, mechanism, value: value.toLowerCase() });
      continue;
    }
    const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(w);
    if (mod) {
      if (mod[1].toLowerCase() === 'redirect') {
        if (!mod[2]) out.invalid.push(w);
        else out.redirect = mod[2].toLowerCase();
      }
      // exp= and unknown modifiers are allowed and ignored (RFC 7208 section 6).
      continue;
    }
    out.invalid.push(w);
  }
  return out;
};

export const allOf = (r: SpfRecord): Qualifier | null => r.terms.find((t) => t.mechanism === 'all')?.qualifier ?? null;

/** The record with its `all` replaced, or added at the end. */
export const withAll = (record: string, q: Qualifier): string => {
  const words = record.trim().split(/\s+/);
  const i = words.findIndex((x) => /^[+\-~?]?all$/i.test(x));
  const all = `${q === '+' ? '' : q}all`;
  if (i >= 0) words[i] = all;
  else words.push(all);
  return words.join(' ');
};
