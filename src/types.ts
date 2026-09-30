import type { ExitCode } from './util/errors.ts';

export type { ExitCode } from './util/errors.ts';

// contextual risk verdict
export type RiskLevel = 'Critical' | 'High' | 'Medium' | 'Low' | 'Noise';

// reachable from the project
export type Reachable = 'yes' | 'likely' | 'unlikely' | 'no' | 'unknown';

// from osv database_specific.severity
export type GhsaSeverity = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
export type SeverityLabel = GhsaSeverity | 'UNKNOWN';

// --fail-on threshold, lowercase
export type FailOn = 'critical' | 'high' | 'medium' | 'low' | 'noise' | 'never';

// ollama, claude (api key), codex cli, mock
export type ProviderName = 'ollama' | 'claude' | 'codex' | 'mock';

// how the provider was picked
export type ProviderSelection = 'flag' | 'config' | 'picker' | 'default';

// picker's view of each provider
export interface ProviderAvailability {
  provider: ProviderName;
  available: boolean;
  // e.g. "mistral:7b (local, private)"
  detail: string;
  // suggested model, if known
  model: string | null;
  // ollama only
  strength?: 'strong' | 'usable' | 'weak' | 'unknown';
  // reason plus fix
  fix?: string[];
}

// auto: ollama if OLLAMA_API_KEY, else docs
export type SearchMode = 'auto' | 'ollama' | 'docs' | 'brave' | 'off';
export type SearchBackendName = 'ollama' | 'docs' | 'brave';

// auto keeps model default, ours is off
export type ThinkMode = 'auto' | 'on' | 'off';

// live osv, sqlite cache or snapshot
export type VulnSourceMode = 'live' | 'cache' | 'snapshot';

export type LockfileKind = 'npm-shrinkwrap' | 'package-lock' | 'yarn' | 'pnpm';
export type UnsupportedLockfileKind = 'yarn' | 'pnpm' | 'bun';

// yarn-berry is yarn 2+ (yaml lockfile)
export type PackageManager = 'npm' | 'yarn' | 'yarn-berry' | 'pnpm';

// mixed: regex fallback per file
export type AnalysisMethod = 'ast' | 'regex' | 'mixed';

// unresolvable, like _[name] or require(x)
export interface DynamicAccess {
  path: string;
  line: number;
  text: string;
  reason: 'computed-member' | 'dynamic-require' | 'unparsed-file' | 'reassigned-binding';
}

// call via project wrappers
export interface IndirectPath {
  // outer call site
  path: string;
  line: number;
  // outermost first
  via: string[];
  member: string | null;
}

// call from a dependent in node_modules
export interface DependentUsage {
  dependent: string;
  version: string;
  // e.g. node_modules/query-string/index.js
  path: string;
  line: number;
  member: string | null;
  text: string;
}

// feeds rails and risk rubric
export type FileScope = 'source' | 'test' | 'config' | 'scripts';

export type ImportKind =
  | 'esm-default'
  | 'esm-namespace'
  | 'esm-named'
  | 'esm-side-effect'
  | 'cjs-require'
  | 'cjs-destructure'
  | 'cjs-member'
  | 'dynamic-import'
  | 're-export';

// internal: package-only
export type BlamedSymbolKind = 'exported' | 'internal';

export type DepType = 'dependencies' | 'devDependencies' | 'optionalDependencies' | 'peerDependencies';

// target version derived in code
export type RecommendationAction =
  | 'upgrade'
  | 'upgrade_major'
  | 'update_transitive'
  | 'override'
  | 'remove'
  | 'ignore'
  | 'monitor';

// one action per package
export type ActionKind = 'bump' | 'bump-major' | 'update-transitive' | 'override-transitive';

export type ToolName =
  | 'search_code'
  | 'get_usage'
  | 'get_changelog'
  | 'check_deps'
  | 'read_file'
  | 'get_advisory'
  | 'web_search'
  | 'fetch_page';

// recon, verdict, migration research
export type ToolStage = 'recon' | 'verdict' | 'migration';

export type InvestigationStage = 'recon' | 'verdict';

export type ApprovalChoice = 'approve' | 'reject' | 'accept-risk';
// no tty, nothing applied
export type ApprovalMode = 'interactive' | 'flag' | 'non-interactive';

// flag > env > file > user > default
export type ConfigSource = 'flag' | 'env' | 'file' | 'user' | 'default';

// live trace labels
export type TraceLabel = 'evidence gate' | 'cached' | 'adjusted' | 'forced';

export type SpecStyle = 'caret' | 'tilde' | 'exact' | 'other';

// only fields we read
export interface PackageJson {
  name?: string;
  version?: string;
  private?: boolean;
  type?: 'module' | 'commonjs';
  main?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  overrides?: Record<string, unknown>;
  workspaces?: string[] | { packages?: string[] };
  engines?: Record<string, string>;
  scripts?: Record<string, string>;
  [key: string]: unknown;
}

// npm-shrinkwrap.json beats package-lock.json
export interface DiscoverResult {
  // absolute
  root: string;
  packageJsonPath: string | null;
  lockfilePath: string | null;
  lockfileKind: LockfileKind | null;
  // unparseable (bun)
  unsupported: { kind: UnsupportedLockfileKind; file: string }[];
  // package.json only: offer scratch lockfile
  needsLockfile: boolean;
  // also from packageManager field
  packageManager?: PackageManager;
}

// packages[""] plus package.json
export interface RootPackage {
  name: string;
  version: string | null;
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
  optionalDependencies: Record<string, string>;
  peerDependencies: Record<string, string>;
  // workspace globs or paths
  workspaces: string[];
  engines: Record<string, string>;
  // "lodash" -> "node_modules/lodash"
  edges: Record<string, string>;
}

export interface PackageNode {
  // e.g. "node_modules/a/node_modules/b", root is ""
  key: string;
  // aliased target for npm aliases
  name: string;
  version: string;
  dev: boolean;
  optional: boolean;
  devOptional: boolean;
  peer: boolean;
  bundled: boolean;
  isDirect: boolean;
  // dependents, "" is root
  parents: string[];
  // incl. optional and peer
  requires: Record<string, string>;
  // unresolved optional/peer omitted
  edges: Record<string, string>;
  // foo in foo@npm:bar@1
  alias?: string;
  resolved?: string;
  integrity?: string;
  license?: string;
  engines?: Record<string, string>;
  deprecated?: string;
  hasInstallScript?: boolean;
}

export interface DependencyGraph {
  root: RootPackage;
  lockfileVersion: number;
  nodes: Map<string, PackageNode>;
  // one key per installed copy
  byName: Map<string, string[]>;
  // scanned as first-party
  workspaceKeys: string[];
  // default npm
  packageManager?: PackageManager;
}

export type OsvEvent = { introduced: string } | { fixed: string } | { last_affected: string } | { limit: string };

export interface OsvRange {
  type: 'SEMVER' | 'ECOSYSTEM' | 'GIT';
  repo?: string;
  events: OsvEvent[];
  database_specific?: Record<string, unknown>;
}

export interface OsvAffected {
  package?: { name: string; ecosystem: string; purl?: string };
  ranges?: OsvRange[];
  versions?: string[];
  ecosystem_specific?: Record<string, unknown>;
  database_specific?: Record<string, unknown>;
}

export interface OsvSeverity {
  type: string; // "CVSS_V3" | "CVSS_V4" | "CVSS_V2"
  score: string; // vector string
}

export interface OsvReference {
  type: string;
  url: string;
}

// GET /v1/vulns/{id}
export interface OsvRecord {
  schema_version?: string;
  id: string;
  modified: string;
  published?: string;
  withdrawn?: string;
  aliases?: string[];
  related?: string[];
  summary?: string;
  details?: string;
  severity?: OsvSeverity[];
  affected?: OsvAffected[];
  references?: OsvReference[];
  database_specific?: {
    severity?: string;
    cwe_ids?: string[];
    github_reviewed?: boolean;
    github_reviewed_at?: string;
    nvd_published_at?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
}

// abbreviated packument entry
export interface AbbreviatedVersion {
  name?: string;
  version: string;
  deprecated?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  engines?: Record<string, string>;
  dist?: { tarball: string; integrity?: string; shasum?: string };
  hasInstallScript?: boolean;
}

export interface AbbreviatedPackument {
  name: string;
  modified?: string;
  'dist-tags': Record<string, string>;
  versions: Record<string, AbbreviatedVersion>;
}

// has repository, packument doesn't
export interface VersionManifest {
  name: string;
  version: string;
  description?: string;
  repository?: string | { type?: string; url?: string; directory?: string };
  homepage?: string;
  bugs?: string | { url?: string };
  main?: string;
  type?: 'module' | 'commonjs';
  exports?: unknown;
  dependencies?: Record<string, string>;
  engines?: Record<string, string>;
  deprecated?: string;
  dist?: { tarball: string; integrity?: string; shasum?: string };
  [key: string]: unknown;
}

export interface RepositoryInfo {
  // normalised https url
  url: string;
  host: 'github' | 'gitlab' | 'other';
  owner: string | null;
  repo: string | null;
  // from repository.directory
  directory: string | null;
}

export interface ProjectFile {
  // posix, project-relative
  path: string;
  abs: string;
  size: number;
  ext: string;
  scope: FileScope;
}

export interface ImportSite {
  // posix, project-relative
  path: string;
  // 1-based
  line: number;
  // trimmed
  statement: string;
  // null for named or side-effect imports
  binding: string | null;
  kind: ImportKind;
  // imported -> local
  named?: Record<string, string>;
  // "template" in require('lodash/template')
  subpath?: string;
  scope: FileScope;
}

// stored in the case file
export interface UsageEvidence {
  package: string;
  // any scope
  imported: boolean;
  files: ImportSite[];
  // source > 0 means used in source
  scopes: Record<FileScope, number>;
  // e.g. { merge: 3, get: 2 }
  membersUsed: Record<string, number>;
  // e.g. minimist(argv)
  bindingCalls: number;
  scannedFiles: number;
  // hit file cap, may be incomplete
  truncated?: boolean;
  // absent means regex
  method?: AnalysisMethod;
  // gate treats as unknown, not uncalled
  dynamicAccess?: DynamicAccess[];
  // via project wrappers and re-exports
  indirectPaths?: IndirectPath[];
  // calls from dependents in node_modules
  dependentUsage?: DependentUsage[];
}

export interface SearchMatch {
  path: string;
  line: number;
  text: string;
  scope: FileScope;
  context?: { before: string[]; after: string[] };
}

// e.g. _.merge(...) or minimist(...)
export interface UsageMatch extends SearchMatch {
  binding: string;
  // null when the binding is called
  member: string | null;
}

// Phase 1 output

export interface BlamedSymbol {
  name: string;
  kind: BlamedSymbolKind;
  // heuristic that found it
  via: 'backticks' | 'member-access' | 'call' | 'default-callable' | 'summary';
}

export interface VulnSeverity {
  cvssVector?: string;
  cvssScore?: number;
  cvssVersion?: string;
  ghsa?: GhsaSeverity;
}

export interface RecommendedFix {
  version: string;
  majorBump: boolean;
  // skipped, deprecated on npm
  skippedDeprecated?: string[];
}

export interface VulnCase {
  // GHSA-, MAL- or other
  id: string;
  // cve ids and aliases
  aliases: string[];
  // merged ids sharing a CVE
  mergedIds: string[];
  package: string;
  installedVersion: string;
  summary: string;
  // advisory excerpt, full text in osvRecords
  detailsExcerpt: string;
  blamedSymbols: BlamedSymbol[];
  severity: VulnSeverity;
  cweIds: string[];
  // malware, not a vuln
  malware: boolean;
  // e.g. ">=4.0.0 <4.17.21"
  affectedRange: string;
  // used by verify
  ranges: OsvRange[];
  fixedVersions: string[];
  recommendedFix: RecommendedFix | null;
  isDirect: boolean;
  isDevOnly: boolean;
  // up to 3 root paths
  dependencyPaths: string[][];
  references: OsvReference[];
  published: string;
  modified: string;
}

export interface PackageRef {
  name: string;
  version: string;
}

export interface PackageCase {
  name: string;
  version: string;
  // lockfile keys at this version
  keys: string[];
  isDirect: boolean;
  isDevOnly: boolean;
  // set when direct
  depType: DepType | null;
  spec: string | null;
  dependencyPaths: string[][];
  dependents: PackageRef[];
  vulnIds: string[];
  worstSeverity: SeverityLabel;
  usage: UsageEvidence;
  // npm deprecation message
  deprecated: string | null;
  latestVersion: string | null;
}

export interface VulnSourceInfo {
  mode: VulnSourceMode;
  // oldest datum's fetch time
  fetchedAt: string;
  ageHours: number;
  // over 7 days old or partial
  warning?: string;
}

export interface CaseFileCounts {
  dependencies: number;
  direct: number;
  dev: number;
  vulnerablePackages: number;
  vulnerabilities: number;
  bySeverity: Record<SeverityLabel, number>;
}

export interface CaseFile {
  // CASE_FILE_VERSION
  version: number;
  project: { root: string; name: string; lockfile: string; lockfileVersion: number };
  scannedAt: string;
  vulnSource: VulnSourceInfo;
  counts: CaseFileCounts;
  packages: PackageCase[];
  vulnerabilities: VulnCase[];
  // so get_advisory skips the db
  osvRecords: Record<string, OsvRecord>;
}

// facts only, no risk opinion
export interface DossierModelOutput {
  inputSources: string[];
  callSiteNotes: string[];
  dependentsSummary: string;
  fixCost: string;
  openQuestions: string[];
}

export interface Dossier extends DossierModelOutput {
  package: string;
  version: string;
  toolCalls: ToolCallRecord[];
  steps: number;
  durationMs: number;
  // built deterministically after failure
  forced?: boolean;
}

// judgement fields only
export interface VerdictModelOutput {
  risk: RiskLevel;
  reachable: Reachable;
  confidence: number;
  reasoning: string;
  evidence: string[];
  recommendationAction: RecommendationAction;
}

export interface ToolCallRecord {
  stage: ToolStage;
  tool: string;
  args: Record<string, unknown>;
  // harness: gate or research code
  by: 'model' | 'harness';
  ok: boolean;
  // trace hint
  summary: string;
  cached: boolean;
  truncated: boolean;
  durationMs: number;
  step: number;
}

export interface Recommendation {
  action: RecommendationAction;
  // from recommendedFix, not the model
  targetVersion: string | null;
  majorBump: boolean;
  // this cve's own fix, when the package fix is higher
  fixedIn?: string;
  // from get_changelog
  breakingChanges?: string[];
  notes?: string;
}

export interface InvestigationMeta {
  provider: ProviderName;
  model: string;
  promptVersion: string;
  steps: number;
  toolCalls: ToolCallRecord[];
  durationMs: number;
  // fallback after two schema failures
  forced: boolean;
  // clamped by rails
  adjusted?: boolean;
  originalRisk?: RiskLevel;
  adjustReason?: string;
  // from verdict-cache.json
  cached?: boolean;
  // gate activity
  gate?: { fired: boolean; coached: boolean; harnessCalls: string[] };
  // model's prose analysis
  analysis?: string;
}

export interface Verdict {
  vulnId: string;
  package: string;
  installedVersion: string;
  risk: RiskLevel;
  reachable: Reachable;
  // 0..1
  confidence: number;
  reasoning: string;
  evidence: string[];
  recommendation: Recommendation;
  investigation: InvestigationMeta;
}

export interface Assessment {
  // ASSESSMENT_VERSION
  version: number;
  // sha256 of case file
  caseFileHash: string;
  createdAt: string;
  updatedAt: string;
  provider: ProviderName;
  model: string;
  promptVersion: string;
  // false while running or interrupted
  complete: boolean;
  dossiers: Dossier[];
  verdicts: Verdict[];
}

// json schema subset
export interface JsonSchema {
  type?: 'object' | 'array' | 'string' | 'number' | 'integer' | 'boolean' | 'null';
  description?: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: (string | number | boolean | null)[];
  const?: unknown;
  default?: unknown;
  examples?: unknown[];
  minimum?: number;
  maximum?: number;
  minLength?: number;
  maxLength?: number;
  minItems?: number;
  maxItems?: number;
  pattern?: string;
  additionalProperties?: boolean | JsonSchema;
  anyOf?: JsonSchema[];
  oneOf?: JsonSchema[];
}

// ollama /api/chat tool shape
export interface ToolSchema {
  type: 'function';
  function: { name: string; description: string; parameters: JsonSchema };
}

export interface ToolTruncation {
  // hard char cap for the model
  maxChars: number;
  defaultLines?: number;
  maxLines?: number;
  defaultResults?: number;
  maxResults?: number;
}

// sqlite web_cache or map in tests
export interface KeyValueCache {
  get<T = unknown>(namespace: string, key: string): T | undefined;
  set(namespace: string, key: string, value: unknown, ttlMs?: number): void;
  delete?(namespace: string, key: string): void;
}

// AuditLog, MemoryAudit, nullAudit
export interface AuditSink {
  log(event: AuditEvent): void;
}

// built once per run
export interface ToolContext {
  projectRoot: string;
  config: Config;
  caseFile: CaseFile | null;
  graph: DependencyGraph | null;
  cache: KeyValueCache | null;
  audit: AuditSink | null;
  signal?: AbortSignal;
  // fills a missing package arg
  focus?: { package: string; version: string; vulnId?: string };
}

export interface ToolResult {
  ok: boolean;
  // serialised by the registry
  data?: unknown;
  // raw text instead of json
  text?: string;
  // trace summary
  hint: string;
  // already truncated
  truncated?: boolean;
  // fixable error, e.g. bad regex
  error?: string;
  cached?: boolean;
}

export type ToolHandler<A> = (args: A, ctx: ToolContext) => Promise<ToolResult>;

export interface ToolDef<A = Record<string, unknown>> {
  name: ToolName;
  description: string;
  parameters: JsonSchema;
  // stages that expose it
  stages: ToolStage[];
  truncation: ToolTruncation;
  // applied after global aliases
  aliases?: Record<string, string>;
  // shown on malformed calls
  example: Record<string, unknown>;
  // e.g. "Checking if template() is called..."
  describe: (args: A) => string;
  // defaults to the handler hint
  summarize?: (result: ToolResult, args: A) => string;
  handler: ToolHandler<A>;
}

export type ToolExecutionStatus = 'ok' | 'error' | 'unknown-tool' | 'not-in-stage' | 'invalid-args';

// from ToolRegistry.execute
export interface ToolExecution {
  // as requested
  requested: string;
  // null when unknown
  tool: ToolName | null;
  stage: ToolStage;
  status: ToolExecutionStatus;
  ok: boolean;
  // normalised args
  args: Record<string, unknown>;
  rawArgs: unknown;
  // e.g. [["pkg", "package"]]
  renamedArgs: [string, string][];
  droppedArgs: string[];
  // filled by harness
  filledArgs: string[];
  // exact tool message
  content: string;
  // ToolDef.describe
  description: string;
  // ToolDef.summarize or hint
  hint: string;
  result: ToolResult | null;
  truncated: boolean;
  durationMs: number;
}

export type ChatRole = 'system' | 'user' | 'assistant' | 'tool';

// arguments always an object
export interface ToolCall {
  function: { name: string; arguments: Record<string, unknown>; index?: number };
  id?: string;
  // text: recovered from prose
  source?: 'native' | 'text';
}

// ollama wire format, snake_case
export interface ChatMessage {
  role: ChatRole;
  content: string;
  tool_calls?: ToolCall[];
  // role tool only
  tool_name?: string;
  // thinking output, not sent back
  thinking?: string;
}

export interface ChatOptions {
  temperature?: number;
  num_ctx?: number;
  seed?: number;
  num_predict?: number;
  top_p?: number;
  top_k?: number;
  stop?: string[];
}

// for mock matcher and debug log
export type ChatPurpose =
  | 'warmup'
  | 'recon'
  | 'dossier'
  | 'verdict-loop'
  | 'verdict'
  | 'migration'
  | 'brief'
  | 'codemod'
  | 'other';

export interface ChatRequest {
  // defaults to provider model
  model?: string;
  messages: ChatMessage[];
  tools?: ToolSchema[];
  // grammar-enforced output
  format?: 'json' | JsonSchema;
  // merged over defaults
  options?: ChatOptions;
  keepAlive?: string | number;
  think?: boolean;
  purpose?: ChatPurpose;
  // default llmMs (180 s)
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface ChatUsage {
  promptTokens?: number;
  completionTokens?: number;
  totalMs?: number;
  loadMs?: number;
  promptEvalMs?: number;
  evalMs?: number;
}

export interface ChatResponse {
  // tool_calls normalised
  message: ChatMessage;
  model: string;
  done: boolean;
  doneReason?: string;
  usage?: ChatUsage;
}

export interface ModelCheck {
  ok: boolean;
  // as requested
  model: string;
  installed: boolean;
  // null when unknown
  tools: boolean | null;
  // "mistral:latest" for "mistral"
  resolvedModel: string | null;
  message?: string;
  fix?: string[];
}

export interface ChangelogRelease {
  tag: string;
  name: string | null;
  publishedAt: string | null;
  url: string | null;
  body: string;
}

// behind get_changelog
export interface ChangelogInfo {
  package: string;
  fromVersion: string;
  toVersion: string;
  majorBump: boolean;
  source: 'github-releases' | 'changelog-file' | 'cache' | 'unavailable';
  repository: string | null;
  releases: ChangelogRelease[];
  // BREAKING, removed, dropped support
  breakingLines: string[];
  targetDeprecated: string | null;
  targetEnginesNode: string | null;
  // e.g. "unavailable offline"
  note?: string;
}

export interface WebSearchHit {
  title: string;
  url: string;
  snippet: string;
  backend: SearchBackendName;
}

export interface WebSearchResponse {
  query: string;
  backend: SearchBackendName | 'none';
  hits: WebSearchHit[];
  cached: boolean;
  note?: string;
}

// fetch_page text
export interface PageText {
  url: string;
  finalUrl: string;
  title: string | null;
  // keyword windows, about 3k chars
  text: string;
  totalChars: number;
  truncated: boolean;
  // likely js-rendered
  jsRendered: boolean;
  cached: boolean;
  fetchedAt: string;
}

export interface MigrationSource {
  url: string;
  kind: 'release-notes' | 'changelog' | 'migration-guide' | 'readme' | 'web' | 'issue';
  title: string | null;
  // when known
  version: string | null;
  cached: boolean;
  fetchedAt: string;
  // quotes verified against this
  text: string;
}

export interface MigrationQuery {
  query: string;
  backend: SearchBackendName | 'none';
  urls: string[];
  cached: boolean;
}

export interface MigrationBriefItem {
  change: string;
  appliesToProject: 'yes' | 'no' | 'unsure';
  // verbatim or verified is false
  evidenceQuote: string;
  evidenceUrl: string;
  oldApi: string;
  newApi: string;
  affectedFiles: string[];
  verified: boolean;
}

export interface MigrationBrief {
  package: string;
  from: string;
  to: string;
  items: MigrationBriefItem[];
  sources: MigrationSource[];
  queries: MigrationQuery[];
  // cache only (--offline)
  offline: boolean;
  model: string;
  createdAt: string;
}

// codemod search/replace edit
export interface CodeEdit {
  file: string;
  search: string;
  replace: string;
  why: string;
}

export interface FilePatch {
  // posix, project-relative
  file: string;
  edits: CodeEdit[];
  // from the diff package
  diff: string;
  beforeHash: string;
  newContent: string;
}

export interface RejectedEdit {
  file: string;
  edit: CodeEdit | null;
  reason: string;
}

export interface CodemodResult {
  package: string;
  model: string;
  patches: FilePatch[];
  rejected: RejectedEdit[];
  // fallback manual checklist
  manualChecklist: string[] | null;
}

export interface EnginesCheck {
  targetNode: string | null;
  projectNode: string | null;
  runningNode: string;
  // null when unknown
  compatible: boolean | null;
  message?: string;
}

// one bump can close several CVEs
export interface Action {
  // e.g. "bump-major:marked@4.0.10"
  id: string;
  kind: ActionKind;
  package: string;
  fromVersion: string;
  toVersion: string;
  vulnIds: string[];
  worstRisk: RiskLevel;
  majorBump: boolean;
  direct: { depType: DepType; spec: string; specStyle: SpecStyle } | null;
  // transitive: parent range check
  parents: { name: string; version: string; key: string; range: string; acceptsTarget: boolean }[];
  importedInSource: boolean;
  // research and codemod before the gate
  requiresMigration: boolean;
  engines: EnginesCheck | null;
  notes: string[];
  brief?: MigrationBrief;
  codemod?: CodemodResult;
}

export interface Identity {
  osUser: string;
  gitName: string | null;
  gitEmail: string | null;
}

export interface ApprovalRecord {
  actionId: string;
  package: string;
  decision: ApprovalChoice;
  mode: ApprovalMode;
  // bump, edits, or both atomically
  scope: 'bump' | 'codemod' | 'transaction';
  // per-file decisions
  files?: { file: string; approved: boolean }[];
  by: Identity;
  at: string;
  // reason or "reject all remaining"
  reason?: string;
  until?: string;
}

export interface BackupFile {
  // posix, project-relative
  path: string;
  sha256: string;
  size: number;
  mode: number;
}

// .patch-pilot/backup/<id>/manifest.json
export interface BackupManifest {
  id: string;
  createdAt: string;
  // absolute
  dir: string;
  projectRoot: string;
  files: BackupFile[];
  actionIds: string[];
}

export interface LockfileNodeChange {
  key: string;
  change: 'added' | 'removed' | 'changed';
  from?: string;
  to?: string;
}

export interface LockfileDiff {
  changes: LockfileNodeChange[];
  // target nodes plus subtree
  allowed: LockfileNodeChange[];
  // auto-aborts under --ci or no tty
  unexpected: LockfileNodeChange[];
}

export interface VerifyResult {
  vulnId: string;
  package: string;
  cleared: boolean;
  // all installed copies after change
  nodes: { key: string; version: string; affected: boolean }[];
}

export interface ApplyResult {
  actionId: string;
  ok: boolean;
  error?: string;
  before: string;
  after: string | null;
  command?: string[];
  filesChanged: { path: string; beforeHash: string; afterHash: string }[];
  lockfileDiff?: LockfileDiff;
  verify: VerifyResult[];
  rolledBack: boolean;
}

export interface RollbackResult {
  backupId: string;
  restored: string[];
  // hash matches neither side
  mismatched: string[];
  missing: string[];
  // node_modules not restored
  note: string;
}

export interface Phase3Result {
  exitCode: ExitCode;
  actions: Action[];
  approvals: ApprovalRecord[];
  results: ApplyResult[];
  reports: { md: string; json: string } | null;
}

// config ignore entry
export interface IgnoreEntry {
  // OSV id or CVE alias
  id: string;
  package?: string;
  reason: string;
  // "Name <email>"
  by: string;
  createdAt: string;
  // resurfaces after this date
  until?: string;
}

export interface ProjectConfigFile {
  provider?: ProviderName;
  model?: string;
  codemodModel?: string;
  ollamaHost?: string;
  numCtx?: number;
  maxSteps?: number;
  think?: ThinkMode;
  search?: SearchMode;
  failOn?: FailOn;
  // extra walker excludes
  exclude?: string[];
  ignore?: IgnoreEntry[];
}

// ~/.patch-pilot/config.json, holds secrets
export interface UserConfigFile {
  ollamaApiKey?: string;
  githubToken?: string;
  braveApiKey?: string;
  anthropicApiKey?: string;
  codexApiKey?: string;
  // remembered picker choice
  provider?: ProviderName;
  model?: string;
  codemodModel?: string;
  ollamaHost?: string;
  numCtx?: number;
  maxSteps?: number;
  think?: ThinkMode;
  search?: SearchMode;
  failOn?: FailOn;
}

export interface ConfigPaths {
  projectRoot: string;
  // <project>/.patch-pilot
  stateDir: string;
  // ~/.patch-pilot
  homeDir: string;
  // ~/.patch-pilot/config.json, may be missing
  userConfigFile: string;
  dbFile: string;
  trustedFile: string;
  // <project>/patch-pilot.config.json, may be missing
  configFile: string;
  caseFile: string;
  assessmentFile: string;
  verdictCacheFile: string;
  auditLog: string;
  reportMd: string;
  reportJson: string;
  backupDir: string;
  tmpDir: string;
  debugLog: string;
}

export interface ConfigTimeouts {
  osvMs: number;
  registryMs: number;
  llmMs: number;
  webMs: number;
  ollamaProbeMs: number;
}

export interface Config {
  // absolute, symlinks resolved
  projectRoot: string;
  provider: ProviderName;
  model: string;
  // null means use model
  codemodModel: string | null;
  // no trailing slash
  ollamaHost: string;
  ollamaApiKey: string | null;
  githubToken: string | null;
  braveApiKey: string | null;
  // env or user config only
  anthropicApiKey: string | null;
  // else codex chatgpt login
  codexApiKey: string | null;
  providerSelection: ProviderSelection;
  numCtx: number;
  // qwen3, gpt-oss
  think: ThinkMode;
  // tool calls per loop
  maxSteps: number;
  limit: number | null;
  // package names or vuln ids
  only: string[];
  maxCves: number | null;
  offline: boolean;
  dryRun: boolean;
  // --no-cache
  noCache: boolean;
  approveAll: boolean;
  approveCodemods: boolean;
  approve: string[];
  trust: boolean;
  json: boolean;
  verbose: boolean;
  quiet: boolean;
  seed: number;
  search: SearchMode;
  ci: boolean;
  failOn: FailOn;
  resume: boolean;
  // built-ins plus config exclude
  exclude: string[];
  ignore: IgnoreEntry[];
  // PATCHPILOT_DEBUG=1, logs to debug.log
  debug: boolean;
  color: boolean;
  // tty, no --ci or --json
  interactive: boolean;
  // --mock-script or PATCHPILOT_MOCK_SCRIPT
  mockScript: string | null;
  paths: ConfigPaths;
  timeouts: ConfigTimeouts;
  configFile: string | null;
  userConfigFile: string | null;
  // source of each value
  sources: Partial<Record<keyof Config, ConfigSource>>;
  // non-fatal, printed by cli
  warnings: string[];
}

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'skip' | 'info';

export type PreflightCheckId =
  | 'node'
  | 'npm'
  | 'ollama-binary'
  | 'ollama-server'
  | 'model'
  | 'tools'
  | 'codemod-model'
  | 'disk'
  | 'search-key'
  | 'git'
  | 'osv'
  | 'registry'
  | 'db';

export interface PreflightCheck {
  id: PreflightCheckId;
  label: string;
  status: CheckStatus;
  // e.g. "v24.14.1"
  detail: string;
  // fatal, exit 3
  hard: boolean;
  // one line each
  fix: string[];
  links: string[];
}

export interface InstalledModel {
  name: string;
  digest: string | null;
  sizeBytes: number | null;
  parameterSize: string | null;
  // null when unknown
  capabilities: string[] | null;
}

export interface OllamaProbe {
  host: string;
  binary: string | null;
  reachable: boolean;
  version: string | null;
  models: InstalledModel[];
  requestedModel: string;
  // exact, alias or fallback
  resolvedModel: string | null;
  // default missing, fell back
  fallback: boolean;
  toolsCapable: boolean | null;
  // with the "tools" capability
  toolModels: string[];
  // --codemod-model resolution
  codemodModel: string | null;
  codemodResolved: string | null;
  error: string | null;
}

export interface PreflightNeeds {
  // npm on PATH
  npm: boolean;
  // skipped for mock
  ollama: boolean;
  // for ~/.patch-pilot
  disk: boolean;
  // OLLAMA_API_KEY and git
  optional: boolean;
  // doctor extras
  extras: boolean;
}

export interface PreflightResult {
  // no hard failure
  ok: boolean;
  checks: PreflightCheck[];
  // null if ollama skipped
  ollama: OllamaProbe | null;
  node: { version: string };
  npm: { path: string | null; version: string | null };
  git: { path: string | null; version: string | null };
  durationMs: number;
}

export interface TrustEntry {
  // absolute, symlinks resolved
  path: string;
  // origin url at trust time
  remote: string | null;
  trustedAt: string;
  by: string;
  method: 'prompt' | 'flag' | 'command';
}

// ~/.patch-pilot/trusted.json
export interface TrustStore {
  version: 1;
  directories: Record<string, TrustEntry>;
}

type Stage = ToolStage;

export type AuditEvent =
  | { event: 'preflight'; ok: boolean; checks: { id: PreflightCheckId; status: CheckStatus; detail: string }[]; model: string | null; ollamaVersion: string | null }
  | { event: 'trust.granted'; dir: string; remote: string | null; method: TrustEntry['method']; by: Identity }
  | { event: 'state.reset'; removed: string[] }
  | { event: 'scan.start'; command: string; dir: string; version: string; provider: ProviderName; model: string; options: Record<string, unknown> }
  | { event: 'discover.lockfile'; lockfile: string | null; kind: LockfileKind | null; lockfileVersion: number | null; generated: boolean; unsupported: string[] }
  | { event: 'deps.parsed'; total: number; direct: number; dev: number; lockfileVersion: number }
  | { event: 'osv.query'; mode: VulnSourceMode; queried: number; vulnIds: number; hydrated: number; cacheHits: number; ageHours: number; warning?: string; durationMs: number }
  | { event: 'casefile.saved'; path: string; sha256: string; packages: number; vulnerabilities: number }
  | { event: 'investigate.start'; packages: number; vulnerabilities: number; provider: ProviderName; model: string; promptVersion: string; resume: boolean }
  | { event: 'tool.call'; stage: Stage; package: string; vulnId?: string; tool: string; args: Record<string, unknown>; by: 'model' | 'harness'; step: number }
  | { event: 'tool.result'; stage: Stage; package: string; vulnId?: string; tool: string; ok: boolean; summary: string; truncated: boolean; cached: boolean; durationMs: number }
  | { event: 'gate.evidence'; package: string; vulnId: string; missing: string[]; action: 'coached' | 'harness-ran' | 'satisfied'; tool?: string; args?: Record<string, unknown> }
  | { event: 'verdict'; vulnId: string; package: string; installedVersion: string; risk: RiskLevel; reachable: Reachable; confidence: number; action: RecommendationAction; forced: boolean; steps: number; durationMs: number; model: string }
  | { event: 'verdict.adjusted'; vulnId: string; package: string; originalRisk: RiskLevel; risk: RiskLevel; rule: string; reasked: boolean }
  | { event: 'verdict.cached'; vulnId: string; package: string; risk: RiskLevel; key: string }
  | { event: 'approval'; actionId: string; package: string; kind: ActionKind; decision: ApprovalChoice; mode: ApprovalMode; scope: ApprovalRecord['scope']; files?: { file: string; approved: boolean }[]; by: Identity; reason?: string }
  | { event: 'risk.accepted'; vulnId: string; package?: string; reason: string; until?: string; by: Identity; source: 'gate' | 'command' }
  | { event: 'patch.backup'; backupId: string; dir: string; files: { path: string; sha256: string }[] }
  | { event: 'patch.apply'; actionId: string; package: string; kind: ActionKind; before: string; after: string | null; command?: string[]; files: { path: string; beforeHash: string; afterHash: string }[]; ok: boolean; error?: string }
  | { event: 'lockfile.diff'; actionId: string; added: number; removed: number; changed: number; unexpected: string[]; decision: 'clean' | 'confirmed' | 'aborted' }
  | { event: 'migration.search'; package: string; backend: SearchBackendName | 'none'; query: string; urls: string[]; cached: boolean }
  | { event: 'migration.brief'; package: string; from: string; to: string; items: number; verified: number; sources: string[]; offline: boolean }
  | { event: 'codemod.proposed'; package: string; file: string; edits: number; rejected: number; model: string }
  | { event: 'codemod.applied'; package: string; file: string; beforeHash: string; afterHash: string; syntaxOk: boolean | null }
  | { event: 'verify.result'; vulnId: string; package: string; cleared: boolean; versions: string[] }
  | { event: 'rollback'; backupId: string; restored: string[]; mismatched: string[]; reason: string }
  | { event: 'report.written'; md: string; json: string }
  | { event: 'provider.selected'; provider: ProviderName; model: string; selection: ProviderSelection; cloud: boolean; options: { provider: ProviderName; available: boolean; detail: string }[] }
  | { event: 'delegated.run'; provider: ProviderName; package: string; command: string[]; exitCode: number | null; durationMs: number; toolCalls: number; verdicts: number; usage?: Record<string, number> }
  | { event: 'error'; phase?: string; message: string; code?: string; exitCode?: number };

export type AuditEventName = AuditEvent['event'];

// event plus timestamp and run id
export type AuditRecord = AuditEvent & { ts: string; run: string };
