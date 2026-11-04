# email-auth-check

Check a domain's MX, SPF, DMARC and DKIM from public DNS, count the DNS lookups an SPF record costs, and build a valid DMARC record. A command-line tool and a library for Node.js, with no runtime dependencies.

It is the same engine behind the free tools at roimaxi.com:

- [Email setup checker](https://roimaxi.com/tools/email-setup-checker)
- [SPF lookup counter](https://roimaxi.com/tools/spf-lookup-counter)
- [DMARC record generator](https://roimaxi.com/tools/dmarc-record-generator)
- [Bank Email Readiness Index](https://roimaxi.com/research/bank-email-readiness-index), which graded bank domains with this code

The grading here is identical to the site's, so a domain gets the same grade on the command line as it does in the browser on the same day.

## Install

Node 18 or later.

```sh
npx email-auth-check example.com
```

or, to keep it around:

```sh
npm install -g email-auth-check
# or, as a library
npm install email-auth-check
```

## Command line

### Full report

```sh
email-auth-check example.com
```

Prints a grade A to F, then one section each for MX, SPF (with the estimated lookup count and the cost of each include), DMARC (the policy and where reports go) and DKIM (the common selectors at which a key was found). Each finding has a plain-words fix, and where a DNS value would help, the value to publish.

Exit code 0 for grades A to C, 1 for D, F or a domain that does not exist, 2 when a lookup failed and there is no grade.

### SPF lookup count

```sh
email-auth-check spf example.com
```

Prints the record, the tree of includes and redirects with what each costs, the void lookups, the heaviest includes, and the findings against RFC 7208: the limit of 10 DNS-querying terms, the limit of 2 void lookups, 10 MX hosts per `mx` term, loops, duplicates, syntax errors and the ending (`-all`, `~all`, `?all`, `+all` or none).

Exit code 1 when any finding is a fail.

### DMARC record

```sh
email-auth-check dmarc --policy reject --rua mailto:dmarc@example.com --domain example.com
```

Prints the host, type and value to publish. Options:

| Option | Tag | Notes |
| --- | --- | --- |
| `--policy none\|quarantine\|reject` | `p=` | Default `none` |
| `--sp none\|quarantine\|reject` | `sp=` | Left out when it equals the policy |
| `--rua a@b.com[,c@d.com]` | `rua=` | `mailto:` is optional |
| `--ruf a@b.com` | `ruf=` | |
| `--pct 0-100` | `pct=` | Left out at 100, and at `p=none` where it has no effect |
| `--adkim r\|s`, `--aspf r\|s` | `adkim=`, `aspf=` | Default `r` |
| `--fo 0\|1\|d\|s[:...]` | `fo=` | Only written when there is a `ruf` address |
| `--domain example.com` | | Sets the host name and lists any authorisation records a report address on another domain needs (RFC 7489 section 7.1) |

Tags at their default are left out, so the record says only what was chosen.

### Machine-readable output

Add `--json` to any command. `--no-colour` (or `NO_COLOR=1`) turns off colour.

## Library

ESM only.

```js
import {
  checkDomain,
  countSpfLookups,
  buildDmarcRecord,
  validateDmarc,
  parseDmarc,
  normalizeDomain,
  dohResolver,
} from 'email-auth-check';

const { domain } = normalizeDomain('https://www.example.com/');

const report = await checkDomain(domain);
report.grade; // 'A' | 'B' | 'C' | 'D' | 'F' | null
report.sections; // [{ key: 'mx' | 'spf' | 'dmarc' | 'dkim', state, records, notes, ... }]

const spf = await countSpfLookups(domain);
spf.lookups; // 7
spf.voids; // 0
spf.root; // the tree
spf.findings; // [{ state, text, fix? }]

const rec = buildDmarcRecord({ domain, policy: 'quarantine', rua: 'dmarc@example.com' });
rec.host; // '_dmarc.example.com'
rec.value; // 'v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com'

validateDmarc('v=DMARC1; p=reject'); // { usable, policy, tags, issues }
parseDmarc('v=DMARC1; p=reject; pct=50'); // { v: 'DMARC1', p: 'reject', pct: '50' }
```

### Resolvers

`checkDomain` and `countSpfLookups` take `{ resolver }`. The default is `dohResolver()`, which queries Cloudflare's DNS-over-HTTPS JSON API and falls back to Google's when Cloudflare fails or answers SERVFAIL. Answers are cached for the life of one resolver, so build one per check.

Any function with the shape `(name, type) => Promise<{ status, answers }>` works, where `status` is the DNS RCODE and `answers` is `[{ type, data }]` as the DoH JSON APIs return it. That is how the tests run without the network, and how you would plug in your own resolver, `node:dns`, or a cache.

```js
const resolver = dohResolver({ timeoutMs: 5000, fetch: myRateLimitedFetch });
await checkDomain('example.com', { resolver });
```

Lower-level pieces are exported too: `walkSpf`, `parseSpf`, `parseMx`, `parseDkim`, `rsaBits`, `txtData`, `orgDomain`, `gradeFrom`, `optionsFromRecord`, and the constants `DKIM_SELECTORS`, `SPF_LOOKUP_LIMIT`, `SPF_VOID_LIMIT`, `SPF_MX_HOST_LIMIT`. Types ship with the package.

## How grading works

Three signals are graded, SPF, DMARC and MX, each as pass, warn or fail. The grade is capped by the worst finding and never averaged:

| Grade | Meaning |
| --- | --- |
| A | No fails, no warnings |
| B | One warning |
| C | Two or more warnings |
| D | One fail |
| F | Two or more fails |

What each signal does:

- **SPF**: no record or `+all` fails; `?all` warns; `~all` and `-all` pass. Two or more records or a syntax error fail. No `all` at the end, an estimated lookup count over 10, or an include that publishes no SPF record, warn.
- **DMARC**: no record fails; `p=none` warns; `p=quarantine` and `p=reject` pass unless `pct` is below 100 or `sp=none`, which warn. A record with no valid `p=` warns when it has `rua=` (RFC 7489 then reads it as `p=none`) and fails otherwise. A subdomain with no record of its own is read from its parent's record, including `sp=`.
- **MX**: no MX, or a null MX (`0 .`), fails.
- **DKIM** is reported but never graded. Ten common selectors are tried (`google`, `selector1`, `selector2`, `default`, `k1`, `s1`, `s2`, `resend`, `mail`, `dkim`). A key that is not found may still exist, because selectors are chosen by the sender and DNS has no way to list them. A found RSA key under 1024 bits is flagged.

When any graded lookup fails, there is no grade rather than a guess.

### The SPF count

The full report's SPF section uses a quick estimate: each include, `a`, `mx`, `ptr`, `exists` and followed `redirect` costs one, recursively. `spf` and `countSpfLookups()` do the full walk: they also look up `a` and `mx` targets to find void lookups, count MX hosts, detect loops and duplicates, and report what each include costs. Both counts are the worst case, what a receiver spends when it has to evaluate every term. Macros are counted once and not followed.

## Limitations

- **Public DNS only.** Everything comes from the DNS records a domain publishes. Nothing is sent to the domain, no mail is sent, no mailbox placement is tested, and nothing is known about the sending reputation of the IPs behind the records.
- **One day's snapshot.** DNS changes. A result is what the resolver returned at the moment it was asked, and a cached answer at Cloudflare or Google can lag a change by its TTL.
- **DKIM is a lower bound.** Only the common selectors are tried.
- **The SPF count is an estimate.** Receivers differ in how they count; macros only resolve for a real message; a receiver stops at the first match, so mail listed early can pass a record that is over the limit.
- **Organisational domain is approximate.** The parent of a subdomain is taken as the last two labels, or three under a two-level suffix such as `co.uk`. It does not use the Public Suffix List.
- **Two third parties see the question.** Cloudflare (1.1.1.1) and, on fallback, Google Public DNS receive the names being looked up. Pass your own resolver if that matters.

## Privacy

The tool stores nothing and sends nothing anywhere except the DNS queries described above. There is no telemetry.

## Development

```sh
npm install
npm test   # builds, then runs node:test against a fake resolver; no network
```

## Licence

MIT. Copyright 2026 M Ventures LTD (ROI Maximizer).
