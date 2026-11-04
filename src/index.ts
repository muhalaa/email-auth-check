/**
 * email-auth-check: MX, SPF, DMARC and DKIM checks from public DNS, an SPF
 * lookup counter and a DMARC record builder. Zero dependencies, Node 18+.
 *
 * The same engine as the free tools at https://roimaxi.com/tools/.
 */

export {
  dohResolver,
  normalizeDomain,
  orgDomain,
  txtData,
  DOH_URL,
  type DnsResult,
  type DohOptions,
  type FetchLike,
  type RecordType,
  type Resolver,
} from './dns.js';

export {
  isSpf,
  parseSpf,
  SPF_LOOKUP_LIMIT,
  SPF_MX_HOST_LIMIT,
  SPF_VOID_LIMIT,
  type Qualifier,
  type SpfRecord,
  type SpfTerm,
} from './spfParse.js';

export {
  checkDomain,
  walkSpf,
  parseDmarc,
  isDmarc,
  parseMx,
  mxProvider,
  parseDkim,
  rsaBits,
  gradeFrom,
  worst,
  DKIM_SELECTORS,
  VERDICT,
  type CheckOptions,
  type Grade,
  type Mx,
  type Note,
  type Report,
  type Section,
  type State,
  type Walk,
} from './check.js';

export {
  countSpfLookups,
  type CountOptions,
  type Finding,
  type FindingState,
  type SpfNode,
  type SpfReport,
  type TermRow,
} from './spfCount.js';

export {
  buildDmarcRecord,
  validateDmarc,
  optionsFromRecord,
  splitAddresses,
  POLICIES,
  FO_OPTIONS,
  POLICY_PLAIN,
  type Align,
  type BuiltRecord,
  type DmarcOptions,
  type FoOption,
  type Issue,
  type IssueLevel,
  type Policy,
  type Validation,
} from './dmarc.js';
