/**
 * A fake resolver built from a zone table, so the tests never touch the
 * network. Keys are "<name>|<type>"; values are arrays of record data in the
 * form the DoH JSON APIs return (TXT quoted, MX "priority host.").
 * A missing name answers NXDOMAIN (status 3); a name listed under `fail`
 * answers SERVFAIL (status 2); a name listed under `throw` rejects.
 */

const TYPE = { A: 1, MX: 15, TXT: 16, AAAA: 28 };

export const fakeResolver = (zone, { fail = [], reject = [] } = {}) => {
  const calls = [];
  const resolver = async (name, type) => {
    calls.push(`${name}|${type}`);
    const key = `${name.toLowerCase()}|${type}`;
    if (reject.includes(name.toLowerCase())) throw new Error('network down');
    if (fail.includes(name.toLowerCase())) return { status: 2, answers: [] };
    // Does the name exist at all (any type)?
    const exists = Object.keys(zone).some((k) => k.startsWith(`${name.toLowerCase()}|`));
    const data = zone[key];
    if (!data) return { status: exists ? 0 : 3, answers: [] };
    return { status: 0, answers: data.map((d) => ({ type: TYPE[type], data: d })) };
  };
  resolver.calls = calls;
  return resolver;
};

export const txt = (s) => `"${s}"`;

/** A healthy Google Workspace domain: MX, SPF ~all, DMARC reject, DKIM at google. */
export const healthy = {
  'good.example|TXT': [txt('v=spf1 include:_spf.google.com ~all'), txt('google-site-verification=abc')],
  'good.example|MX': ['1 aspmx.l.google.com.', '5 alt1.aspmx.l.google.com.'],
  '_dmarc.good.example|TXT': [txt('v=DMARC1; p=reject; rua=mailto:dmarc@good.example')],
  'google._domainkey.good.example|TXT': [
    txt('v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA' + 'A'.repeat(330)),
  ],
  '_spf.google.com|TXT': [txt('v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all')],
  '_netblocks.google.com|TXT': [txt('v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ~all')],
  '_netblocks2.google.com|TXT': [txt('v=spf1 ip6:2001:4860:4000::/36 ~all')],
  '_netblocks3.google.com|TXT': [txt('v=spf1 ip4:172.217.0.0/19 ~all')],
};
