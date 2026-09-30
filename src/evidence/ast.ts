// import and use evidence per file
import { createRequire } from 'node:module';
import path from 'node:path';
// ts 7 has no js api yet, parse with the ts 6 compat package
import type ts from '@typescript/typescript6';
import type { DynamicAccess, ImportKind } from '../types.ts';

// lazy

const TYPESCRIPT_API_PACKAGE = '@typescript/typescript6';
const requireModule = createRequire(import.meta.url);
let tsModule: typeof ts | null = null;
// SyntaxKind is a getter, cache it
let kinds: typeof ts.SyntaxKind | null = null;

export function typescript(): typeof ts {
  if (tsModule === null) tsModule = requireModule(TYPESCRIPT_API_PACKAGE) as typeof ts;
  return tsModule;
}

function syntaxKind(): typeof ts.SyntaxKind {
  if (kinds === null) kinds = typescript().SyntaxKind;
  return kinds;
}

// walks recurse, deeper goes to regex
export const MAX_NESTING = 1000;

// iterative, stops past limit
function nestingDepth(root: ts.Node, limit: number): number {
  const T = typescript();
  const stack: ts.Node[] = [root];
  const depths: number[] = [0];
  let max = 0;
  while (stack.length > 0) {
    const node = stack.pop() as ts.Node;
    const depth = depths.pop() as number;
    if (depth > max) {
      max = depth;
      if (max > limit) return max;
    }
    T.forEachChild(node, (child) => {
      stack.push(child);
      depths.push(depth + 1);
    });
  }
  return max;
}

export type ScriptLang = 'js' | 'jsx' | 'ts' | 'tsx';

// defaults to js
export function scriptLangOf(source: string): ScriptLang {
  let lang: ScriptLang = 'js';
  for (const m of source.matchAll(/<script\b([^>]*)>/gi)) {
    const attr = /\blang\s*=\s*["']?([a-z]+)/i.exec(m[1] ?? '');
    const value = (attr?.[1] ?? '').toLowerCase();
    if (value === 'tsx') return 'tsx';
    if (value === 'ts' || value === 'typescript') lang = 'ts';
    else if (value === 'jsx' && lang === 'js') lang = 'jsx';
  }
  return lang;
}

function scriptKind(relPath: string, lang: ScriptLang | undefined): ts.ScriptKind {
  const T = typescript();
  const ext = path.extname(relPath).toLowerCase();
  const byLang = (l: ScriptLang): ts.ScriptKind => (l === 'ts' ? T.ScriptKind.TS : l === 'tsx' ? T.ScriptKind.TSX : l === 'jsx' ? T.ScriptKind.JSX : T.ScriptKind.JS);
  switch (ext) {
    case '.ts':
    case '.mts':
    case '.cts':
      return T.ScriptKind.TS;
    case '.tsx':
      return T.ScriptKind.TSX;
    case '.jsx':
      return T.ScriptKind.JSX;
    case '.vue':
    case '.svelte':
      return byLang(lang ?? 'js');
    default:
      return T.ScriptKind.JS;
  }
}

export type ParseOutcome = { ok: true; model: FileModel } | { ok: false; line: number; message: string };

export interface Span {
  start: number;
  end: number;
}

// regex path's ImportSite vocabulary
export interface ModuleImport {
  specifier: string;
  kind: ImportKind;
  // import, require or export keyword
  at: number;
  span: Span;
  binding: string | null;
  named?: Record<string, string>;
  // require('./y').default
  viaDefault?: boolean;
}

export type RootSource = { kind: 'pkg'; pkg: string; subpath?: string } | { kind: 'file'; file: string };

// _.merge -> ['merge']
export interface ModuleUse {
  source: RootSource;
  // -1 for none
  record: number;
  // _, alias, require or (re-export)
  local: string;
  path: string[];
  call: boolean;
  at: number;
  // -1 at module level
  unit: number;
}

export interface DynamicHit {
  source: RootSource;
  reason: DynamicAccess['reason'];
  at: number;
  span: Span;
}

export interface PackageImport {
  record: number;
  import: ModuleImport;
  pkg: string;
  subpath?: string;
}

export interface PackageAnalysis {
  imports: PackageImport[];
  // re-exports add a pseudo-use per name
  uses: ModuleUse[];
  dynamic: DynamicHit[];
}

export type ExportTarget =
  | { kind: 'unit'; file: string; unit: number }
  | { kind: 'pkg'; pkg: string; path: string[] }
  | { kind: 'file'; file: string; path: string[] }
  | { kind: 'object'; props: Map<string, ExportTarget> };

export interface SummaryUnit {
  name: string;
  line: number;
  callees: number[];
}

// kept for every parsed file
export interface FileSummary {
  path: string;
  units: SummaryUnit[];
  pkgUses: { unit: number; pkg: string; member: string | null; line: number }[];
  fileUses: { unit: number; file: string; path: string[]; call: boolean; line: number; local: string }[];
  exports: Map<string, ExportTarget>;
  // export * from './x'
  stars: string[];
  // export * from 'lodash'
  pkgStars: string[];
}

export type SpecifierResolver = (specifier: string, fromPath: string) => string | null;

// syntax error falls back to regex
export function parseModule(script: string, relPath: string, lang?: ScriptLang): ParseOutcome {
  const T = typescript();
  let sf: ts.SourceFile;
  try {
    sf = T.createSourceFile(relPath, script, { languageVersion: T.ScriptTarget.Latest, jsDocParsingMode: T.JSDocParsingMode.ParseNone }, true, scriptKind(relPath, lang));
  } catch (err) {
    return { ok: false, line: 1, message: err instanceof Error ? err.message : String(err) };
  }
  const diagnostics = (sf as unknown as { parseDiagnostics?: readonly ts.DiagnosticWithLocation[] }).parseDiagnostics ?? [];
  const error = diagnostics.find((d) => d.category === T.DiagnosticCategory.Error);
  if (error) {
    const line = sf.getLineAndCharacterOfPosition(error.start ?? 0).line + 1;
    return { ok: false, line, message: T.flattenDiagnosticMessageText(error.messageText, ' ') };
  }
  if (nestingDepth(sf, MAX_NESTING) > MAX_NESTING) return { ok: false, line: 1, message: `nested more than ${MAX_NESTING} levels deep` };
  return { ok: true, model: new FileModel(relPath, script, sf) };
}

type DeclKind = 'var' | 'let' | 'const' | 'param' | 'function' | 'class' | 'import' | 'catch' | 'enum' | 'implicit';

interface Scope {
  kind: 'module' | 'function' | 'block';
  parent: Scope | null;
  vars: Map<string, Decl>;
}

interface Decl {
  id: number;
  name: string;
  kind: DeclKind;
  // VariableDeclaration, Parameter, ImportSpecifier...
  node: ts.Node;
  refs: ts.Identifier[];
  // assignments, updates, for-in/of heads
  writes: ts.Node[];
}

interface Binding {
  decls: Decl[];
  declOfName: Map<ts.Identifier, Decl>;
  refOf: Map<ts.Identifier, Decl>;
  // incl implicit globals
  unresolved: Map<string, ts.Identifier[]>;
}

function isFunctionUnitNode(node: ts.Node): node is ts.FunctionLikeDeclaration {
  const K = syntaxKind();
  switch (node.kind) {
    case K.FunctionDeclaration:
    case K.FunctionExpression:
    case K.ArrowFunction:
    case K.MethodDeclaration:
    case K.Constructor:
    case K.GetAccessor:
    case K.SetAccessor:
      return true;
    default:
      return false;
  }
}

// skipped by every walk
function isTypeLevel(node: ts.Node): boolean {
  const K = syntaxKind();
  const kind = node.kind;
  switch (kind) {
    case K.InterfaceDeclaration:
    case K.TypeAliasDeclaration:
    case K.TypeParameter:
      return true;
    case K.HeritageClause:
      return (node as ts.HeritageClause).token === K.ImplementsKeyword;
    case K.ImportDeclaration:
      return (node as ts.ImportDeclaration).importClause?.isTypeOnly === true;
    case K.ExportDeclaration:
      return (node as ts.ExportDeclaration).isTypeOnly;
    case K.ImportEqualsDeclaration:
      return (node as ts.ImportEqualsDeclaration).isTypeOnly;
    default:
      // extends Base<T> falls outside this
      return kind >= K.FirstTypeNode && kind <= K.LastTypeNode;
  }
}

function isAssignmentOperator(kind: ts.SyntaxKind): boolean {
  const K = syntaxKind();
  return kind >= K.FirstAssignment && kind <= K.LastAssignment;
}

// not a property, label or decl
function isReferencePosition(id: ts.Identifier): boolean {
  const K = syntaxKind();
  const p = id.parent;
  if (!p) return false;
  switch (p.kind) {
    case K.PropertyAccessExpression:
      return (p as ts.PropertyAccessExpression).expression === id;
    case K.PropertyAssignment:
      return (p as ts.PropertyAssignment).initializer === id;
    case K.ShorthandPropertyAssignment:
      return true;
    case K.VariableDeclaration:
    case K.Parameter:
    case K.BindingElement:
    case K.PropertyDeclaration:
    case K.PropertySignature:
    case K.EnumMember:
      return (p as ts.VariableDeclaration).initializer === id;
    case K.FunctionDeclaration:
    case K.FunctionExpression:
    case K.ClassDeclaration:
    case K.ClassExpression:
    case K.MethodDeclaration:
    case K.MethodSignature:
    case K.GetAccessor:
    case K.SetAccessor:
    case K.EnumDeclaration:
    case K.ModuleDeclaration:
    case K.InterfaceDeclaration:
    case K.TypeAliasDeclaration:
    case K.TypeParameter:
    case K.ImportClause:
    case K.NamespaceImport:
    case K.ImportSpecifier:
    case K.ImportEqualsDeclaration:
    case K.NamespaceExport:
    case K.NamespaceExportDeclaration:
    case K.LabeledStatement:
    case K.BreakStatement:
    case K.ContinueStatement:
    case K.JsxAttribute:
    case K.JsxClosingElement:
    case K.MetaProperty:
    case K.QualifiedName:
      return false;
    case K.ExportSpecifier: {
      const spec = p as ts.ExportSpecifier;
      const decl = spec.parent.parent;
      if (decl.moduleSpecifier || decl.isTypeOnly || spec.isTypeOnly) return false;
      return (spec.propertyName ?? spec.name) === id;
    }
    case K.JsxOpeningElement:
    case K.JsxSelfClosingElement:
      return (p as ts.JsxOpeningElement).tagName === id && !/^[a-z]/.test(id.text);
    default:
      return true;
  }
}

function assignmentPatternOwner(start: ts.Node): ts.Node | null {
  const T = typescript();
  let cur: ts.Node = start;
  for (;;) {
    const p = cur.parent;
    if (!p) return null;
    if (T.isObjectLiteralExpression(cur) || T.isArrayLiteralExpression(cur)) {
      if (T.isBinaryExpression(p) && p.left === cur && p.operatorToken.kind === syntaxKind().EqualsToken) return p;
      if ((T.isForOfStatement(p) || T.isForInStatement(p)) && p.initializer === cur) return p;
    }
    if (
      T.isObjectLiteralExpression(p) ||
      T.isArrayLiteralExpression(p) ||
      T.isPropertyAssignment(p) ||
      T.isShorthandPropertyAssignment(p) ||
      T.isSpreadElement(p) ||
      T.isSpreadAssignment(p) ||
      T.isParenthesizedExpression(p)
    ) {
      cur = p;
      continue;
    }
    if (T.isBinaryExpression(p) && p.left === cur && p.operatorToken.kind === syntaxKind().EqualsToken && !T.isObjectLiteralExpression(cur) && !T.isArrayLiteralExpression(cur)) {
      // [a = 1] = arr
      cur = p;
      continue;
    }
    return null;
  }
}

// assignment, update or for-in/of
function writeOf(id: ts.Identifier): ts.Node | null {
  const T = typescript();
  let n: ts.Node = id;
  let p = n.parent;
  while (p && (T.isParenthesizedExpression(p) || T.isNonNullExpression(p) || T.isAsExpression(p) || T.isSatisfiesExpression(p) || T.isTypeAssertionExpression(p))) {
    n = p;
    p = p.parent;
  }
  if (!p) return null;
  if (T.isBinaryExpression(p) && p.left === n && isAssignmentOperator(p.operatorToken.kind)) return p;
  if ((T.isPrefixUnaryExpression(p) || T.isPostfixUnaryExpression(p)) && (p.operator === syntaxKind().PlusPlusToken || p.operator === syntaxKind().MinusMinusToken)) return p;
  if ((T.isForInStatement(p) || T.isForOfStatement(p)) && p.initializer === n) return p;
  if (T.isShorthandPropertyAssignment(p) || (T.isPropertyAssignment(p) && p.initializer === n) || T.isArrayLiteralExpression(p) || T.isSpreadElement(p) || T.isSpreadAssignment(p)) {
    return assignmentPatternOwner(p.kind === syntaxKind().ShorthandPropertyAssignment || p.kind === syntaxKind().PropertyAssignment ? p.parent : p);
  }
  return null;
}

function bindFile(sf: ts.SourceFile): Binding {
  const T = typescript();
  const decls: Decl[] = [];
  const declOfName = new Map<ts.Identifier, Decl>();
  const refOf = new Map<ts.Identifier, Decl>();
  const unresolved = new Map<string, ts.Identifier[]>();
  const scopeOf = new Map<ts.Node, Scope>();
  const newScope = (kind: Scope['kind'], parent: Scope | null): Scope => ({ kind, parent, vars: new Map() });
  const moduleScope = newScope('module', null);
  scopeOf.set(sf, moduleScope);
  const functionScope = (s: Scope): Scope => {
    let c = s;
    while (c.kind === 'block' && c.parent) c = c.parent;
    return c;
  };
  const declare = (scope: Scope, nameNode: ts.Identifier, kind: DeclKind, node: ts.Node): void => {
    let d = scope.vars.get(nameNode.text);
    if (!d) {
      d = { id: decls.length, name: nameNode.text, kind, node, refs: [], writes: [] };
      decls.push(d);
      scope.vars.set(nameNode.text, d);
    }
    declOfName.set(nameNode, d);
  };
  const declarePattern = (scope: Scope, name: ts.BindingName, kind: DeclKind, node: ts.Node): void => {
    if (T.isIdentifier(name)) {
      declare(scope, name, kind, node);
      return;
    }
    for (const el of name.elements) if (T.isBindingElement(el)) declarePattern(scope, el.name, kind, el);
  };

  // pass 1: scopes and decls
  const declareIn = (node: ts.Node, scope: Scope): void => {
    if (isTypeLevel(node)) return;
    if (isFunctionUnitNode(node)) {
      if (T.isFunctionDeclaration(node) && node.name) declare(scope, node.name, 'function', node);
      const fnScope = newScope('function', scope);
      scopeOf.set(node, fnScope);
      if (T.isFunctionExpression(node) && node.name) declare(fnScope, node.name, 'function', node);
      for (const m of T.canHaveModifiers(node) ? (T.getModifiers(node) ?? []) : []) declareIn(m, scope);
      for (const d of T.canHaveDecorators(node) ? (T.getDecorators(node) ?? []) : []) declareIn(d, scope);
      if (node.name && T.isComputedPropertyName(node.name)) declareIn(node.name, scope);
      for (const p of node.parameters) {
        declarePattern(fnScope, p.name, 'param', p);
        T.forEachChild(p, (c) => declareIn(c, fnScope));
      }
      const body = node.body;
      if (body) {
        if (T.isBlock(body)) {
          scopeOf.set(body, fnScope);
          for (const st of body.statements) declareIn(st, fnScope);
        } else {
          declareIn(body, fnScope);
        }
      }
      return;
    }
    if (T.isClassDeclaration(node) || T.isClassExpression(node)) {
      let inner = scope;
      if (T.isClassDeclaration(node) && node.name) declare(scope, node.name, 'class', node);
      if (T.isClassExpression(node) && node.name) {
        inner = newScope('block', scope);
        scopeOf.set(node, inner);
        declare(inner, node.name, 'class', node);
      }
      T.forEachChild(node, (c) => declareIn(c, inner));
      return;
    }
    if (T.isVariableDeclarationList(node)) {
      const isVar = (node.flags & T.NodeFlags.BlockScoped) === 0;
      const kind: DeclKind = isVar ? 'var' : node.flags & T.NodeFlags.Const ? 'const' : 'let';
      const target = isVar ? functionScope(scope) : scope;
      for (const d of node.declarations) declarePattern(target, d.name, kind, d);
      T.forEachChild(node, (c) => declareIn(c, scope));
      return;
    }
    if (T.isBlock(node) || T.isCaseBlock(node) || T.isModuleBlock(node) || T.isClassStaticBlockDeclaration(node) || T.isForStatement(node) || T.isForInStatement(node) || T.isForOfStatement(node)) {
      const s = newScope('block', scope);
      scopeOf.set(node, s);
      T.forEachChild(node, (c) => declareIn(c, s));
      return;
    }
    if (T.isCatchClause(node)) {
      const s = newScope('block', scope);
      scopeOf.set(node, s);
      if (node.variableDeclaration) declarePattern(s, node.variableDeclaration.name, 'catch', node.variableDeclaration);
      T.forEachChild(node, (c) => declareIn(c, s));
      return;
    }
    if (T.isImportDeclaration(node)) {
      const clause = node.importClause;
      if (clause && !clause.isTypeOnly) {
        if (clause.name) declare(scope, clause.name, 'import', clause);
        const nb = clause.namedBindings;
        if (nb && T.isNamespaceImport(nb)) declare(scope, nb.name, 'import', nb);
        if (nb && T.isNamedImports(nb)) for (const el of nb.elements) if (!el.isTypeOnly) declare(scope, el.name, 'import', el);
      }
      return;
    }
    if (T.isImportEqualsDeclaration(node)) {
      if (!node.isTypeOnly) declare(scope, node.name, 'import', node);
      return;
    }
    if (T.isEnumDeclaration(node)) {
      declare(scope, node.name, 'enum', node);
      T.forEachChild(node, (c) => declareIn(c, scope));
      return;
    }
    if (T.isModuleDeclaration(node)) {
      if (T.isIdentifier(node.name)) declare(scope, node.name, 'var', node);
      if (node.body) declareIn(node.body, scope);
      return;
    }
    T.forEachChild(node, (c) => declareIn(c, scope));
  };
  for (const st of sf.statements) declareIn(st, moduleScope);

  // pass 2: refs and writes
  const lookup = (name: string, scope: Scope): Decl | null => {
    for (let s: Scope | null = scope; s; s = s.parent) {
      const d = s.vars.get(name);
      if (d) return d;
    }
    return null;
  };
  const visit = (node: ts.Node, scope: Scope): void => {
    if (isTypeLevel(node)) return;
    if (T.isIdentifier(node)) {
      if (!isReferencePosition(node)) return;
      const d = lookup(node.text, scope);
      if (d) {
        d.refs.push(node);
        refOf.set(node, d);
        const w = writeOf(node);
        if (w) d.writes.push(w);
      } else {
        const list = unresolved.get(node.text);
        if (list) list.push(node);
        else unresolved.set(node.text, [node]);
      }
      return;
    }
    if (T.isExpressionWithTypeArguments(node)) {
      visit(node.expression, scope);
      return;
    }
    if (isFunctionUnitNode(node)) {
      const inner = scopeOf.get(node) ?? scope;
      for (const m of T.canHaveModifiers(node) ? (T.getModifiers(node) ?? []) : []) visit(m, scope);
      for (const d of T.canHaveDecorators(node) ? (T.getDecorators(node) ?? []) : []) visit(d, scope);
      if (node.name && T.isComputedPropertyName(node.name)) visit(node.name, scope);
      for (const p of node.parameters) visit(p, inner);
      if (node.body) {
        if (T.isBlock(node.body)) for (const st of node.body.statements) visit(st, inner);
        else visit(node.body, inner);
      }
      return;
    }
    const s = scopeOf.get(node) ?? scope;
    T.forEachChild(node, (c) => visit(c, s));
  };
  for (const st of sf.statements) visit(st, moduleScope);

  // sloppy lib = require('x')
  for (const [name, ids] of unresolved) {
    if (!ids.some((id) => writeOf(id) !== null)) continue;
    const d: Decl = { id: decls.length, name, kind: 'implicit', node: ids[0] as ts.Node, refs: [], writes: [] };
    decls.push(d);
    for (const id of ids) {
      d.refs.push(id);
      refOf.set(id, d);
      const w = writeOf(id);
      if (w) d.writes.push(w);
    }
  }
  return { decls, declOfName, refOf, unresolved };
}

// parens, as, await, ?:, ||, ??
function climb(node: ts.Expression): ts.Expression {
  const T = typescript();
  const K = syntaxKind();
  let cur: ts.Expression = node;
  for (;;) {
    const p = cur.parent;
    if (!p) return cur;
    if (T.isParenthesizedExpression(p) || T.isNonNullExpression(p) || T.isAsExpression(p) || T.isSatisfiesExpression(p) || T.isTypeAssertionExpression(p) || T.isAwaitExpression(p)) {
      cur = p;
      continue;
    }
    if (T.isConditionalExpression(p) && (p.whenTrue === cur || p.whenFalse === cur)) {
      cur = p;
      continue;
    }
    if (T.isBinaryExpression(p)) {
      const op = p.operatorToken.kind;
      if (op === K.BarBarToken || op === K.QuestionQuestionToken || ((op === K.AmpersandAmpersandToken || op === K.CommaToken) && p.right === cur)) {
        cur = p;
        continue;
      }
    }
    return cur;
  }
}

// parens, !, as, <T>, satisfies
function unwrap(node: ts.Expression): ts.Expression {
  const T = typescript();
  let cur = node;
  while (T.isParenthesizedExpression(cur) || T.isNonNullExpression(cur) || T.isAsExpression(cur) || T.isSatisfiesExpression(cur) || T.isTypeAssertionExpression(cur)) cur = cur.expression;
  return cur;
}

// call, new, tag, decorator, JSX
function isInvoked(expr: ts.Expression): boolean {
  const T = typescript();
  const p = expr.parent;
  if (!p) return false;
  if ((T.isCallExpression(p) || T.isNewExpression(p)) && p.expression === expr) return true;
  if (T.isTaggedTemplateExpression(p) && p.tag === expr) return true;
  if ((T.isJsxOpeningElement(p) || T.isJsxSelfClosingElement(p)) && p.tagName === expr) return true;
  if (T.isDecorator(p) && p.expression === expr) return true;
  return false;
}

function propertyNameText(name: ts.PropertyName | ts.ModuleExportName | ts.BindingName | undefined): string | null {
  const T = typescript();
  if (!name) return null;
  if (T.isIdentifier(name) || T.isStringLiteral(name) || T.isNumericLiteral(name) || T.isNoSubstitutionTemplateLiteral(name)) return name.text;
  if (T.isComputedPropertyName(name)) {
    const e = unwrap(name.expression);
    if (T.isStringLiteral(e) || T.isNoSubstitutionTemplateLiteral(e)) return e.text;
  }
  return null;
}

function isModuleExports(node: ts.Node): boolean {
  const T = typescript();
  return T.isPropertyAccessExpression(node) && T.isIdentifier(node.expression) && node.expression.text === 'module' && node.name.text === 'exports';
}

const FUNCTION_METHODS = new Set(['call', 'apply', 'bind']);
const MAX_ALIAS_DEPTH = 3;

function subpathMember(subpath: string): string {
  const last = subpath.split('/').filter(Boolean).pop() ?? subpath;
  return last.replace(/\.[cm]?[jt]sx?$/i, '');
}

// longest name wins
export function matchPackageSpecifier(spec: string, packages: readonly string[]): { pkg: string; subpath?: string } | null {
  let best: { pkg: string; subpath?: string } | null = null;
  for (const pkg of packages) {
    if (spec === pkg) return { pkg };
    if (spec.startsWith(`${pkg}/`) && (!best || pkg.length > best.pkg.length)) {
      const subpath = spec.slice(pkg.length + 1);
      best = subpath ? { pkg, subpath } : { pkg };
    }
  }
  return best;
}

function sourceKey(s: RootSource): string {
  return s.kind === 'pkg' ? `p:${s.pkg}/${s.subpath ?? ''}` : `f:${s.file}`;
}

// src/lib/index.ts -> lib
export function moduleBaseName(relPath: string): string {
  const base = path.posix.basename(relPath).replace(/\.[^.]+$/, '');
  if (base === 'index') {
    const dir = path.posix.basename(path.posix.dirname(relPath));
    if (dir && dir !== '.') return dir;
  }
  return base.replace(/[^\w$]+([a-zA-Z0-9])/g, (_m, c: string) => c.toUpperCase()).replace(/[^\w$]/g, '') || 'module';
}

interface Root {
  source: RootSource;
  record: number;
  decl: Decl | null;
  expr: ts.Expression | null;
  local: string;
  path: string[];
  // member alias, .call/.apply call it
  fn: boolean;
  depth: number;
  // not reported as a reassignment
  createdBy: ts.Node | null;
}

interface RawUse {
  root: Root;
  path: string[];
  call: boolean;
  at: number;
  node: ts.Node;
}

interface RawDynamic {
  root: Root;
  reason: DynamicAccess['reason'];
  node: ts.Node;
}

interface Lhs {
  decl: Decl | null;
  name: string | null;
  pattern: ts.ObjectBindingPattern | ts.ObjectLiteralExpression | null;
  target: ts.Node;
  createdBy: ts.Node | null;
}

interface PatternElement {
  key: string;
  local: string;
  decl: Decl | null;
}

interface ImportInternal extends ModuleImport {
  node: ts.Node;
  bindingDecl: Decl | null;
  namedDecls: { imported: string; decl: Decl | null; local: string }[];
  rest: { decl: Decl | null; local: string } | null;
  // require('x').m() with no local
  direct: ts.Expression | null;
  // import('x').then((m) => ...)
  thenRoots: { decl: Decl | null; local: string; path: string[] }[];
  // x = require('y')
  createdBy: ts.Node | null;
}

interface UnitInfo {
  name: string;
  node: ts.Node;
  line: number;
}

export class FileModel {
  readonly path: string;
  readonly script: string;
  readonly sf: ts.SourceFile;
  private lineStarts: number[] | null = null;
  private bindingCache: Binding | null = null;
  private importCache: ImportInternal[] | null = null;
  private dynamicRequireCache: ts.CallExpression[] = [];
  private specifierNodes = new Set<ts.Node>();
  private stringCache: Set<string> | null = null;
  private unitCache: { units: UnitInfo[]; unitOfFn: Map<ts.Node, number>; unitByDecl: Map<Decl, number>; objectUnits: Map<Decl, Map<string, number>> } | null = null;
  private trackCache = new Map<string, { uses: RawUse[]; dynamic: RawDynamic[]; holders: Map<Decl, Root[]> }>();

  constructor(relPath: string, script: string, sf: ts.SourceFile) {
    this.path = relPath;
    this.script = script;
    this.sf = sf;
  }

  // 1-based
  lineOf(offset: number): number {
    if (this.lineStarts === null) {
      const starts = [0];
      for (let i = 0; i < this.script.length; i += 1) if (this.script.charCodeAt(i) === 10) starts.push(i + 1);
      this.lineStarts = starts;
    }
    const starts = this.lineStarts;
    let lo = 0;
    let hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if ((starts[mid] as number) <= offset) lo = mid;
      else hi = mid - 1;
    }
    return lo + 1;
  }

  // 1-based
  lineStart(line: number): number {
    this.lineOf(0);
    return (this.lineStarts as number[])[line - 1] ?? 0;
  }

  private get binding(): Binding {
    if (this.bindingCache === null) this.bindingCache = bindFile(this.sf);
    return this.bindingCache;
  }

  // static, require, dynamic, re-export
  get imports(): readonly ModuleImport[] {
    return this.internalImports();
  }

  private internalImports(): ImportInternal[] {
    if (this.importCache !== null) return this.importCache;
    const T = typescript();
    const out: ImportInternal[] = [];
    const visit = (node: ts.Node): void => {
      if (isTypeLevel(node)) return;
      if (T.isImportDeclaration(node)) {
        this.importDeclaration(node, out);
        return;
      }
      if (T.isExportDeclaration(node)) {
        if (node.moduleSpecifier) this.reexportDeclaration(node, out);
        return;
      }
      if (T.isImportEqualsDeclaration(node)) {
        this.importEquals(node, out);
        return;
      }
      if (T.isCallExpression(node)) {
        if (T.isIdentifier(node.expression) && node.expression.text === 'require' && node.arguments.length >= 1) this.requireCall(node, out);
        else if (node.expression.kind === syntaxKind().ImportKeyword && node.arguments.length >= 1) this.dynamicImport(node, out);
      }
      T.forEachChild(node, visit);
    };
    visit(this.sf);
    this.importCache = out;
    return out;
  }

  private staticString(expr: ts.Expression | undefined): string | null {
    const T = typescript();
    if (!expr) return null;
    const e = unwrap(expr);
    if (T.isStringLiteral(e) || T.isNoSubstitutionTemplateLiteral(e)) return e.text;
    if (T.isIdentifier(e)) {
      const d = this.binding.refOf.get(e);
      if (d && d.kind === 'const' && T.isVariableDeclaration(d.node) && T.isIdentifier(d.node.name) && d.node.initializer) {
        const init = unwrap(d.node.initializer);
        if (T.isStringLiteral(init) || T.isNoSubstitutionTemplateLiteral(init)) return init.text;
      }
    }
    return null;
  }

  // x = top, const { a } = top
  private lhsOf(top: ts.Expression): Lhs | null {
    const T = typescript();
    const p = top.parent;
    if (!p) return null;
    const b = this.binding;
    const fromName = (name: ts.BindingName, createdBy: ts.Node | null): Lhs => {
      if (T.isIdentifier(name)) return { decl: b.declOfName.get(name) ?? null, name: name.text, pattern: null, target: name, createdBy };
      if (T.isObjectBindingPattern(name)) return { decl: null, name: null, pattern: name, target: name, createdBy };
      return { decl: null, name: null, pattern: null, target: name, createdBy };
    };
    if ((T.isVariableDeclaration(p) || T.isParameter(p) || T.isBindingElement(p)) && p.initializer === top) return fromName(p.name, null);
    if (T.isBinaryExpression(p) && p.operatorToken.kind === syntaxKind().EqualsToken && p.right === top) {
      const left = unwrap(p.left);
      if (T.isIdentifier(left)) return { decl: b.refOf.get(left) ?? null, name: left.text, pattern: null, target: left, createdBy: p };
      if (T.isObjectLiteralExpression(left)) return { decl: null, name: null, pattern: left, target: left, createdBy: p };
      return { decl: null, name: null, pattern: null, target: left, createdBy: p };
    }
    if (T.isPropertyDeclaration(p) && p.initializer === top) return { decl: null, name: null, pattern: null, target: p.name, createdBy: null };
    return null;
  }

  private patternElements(pattern: ts.ObjectBindingPattern | ts.ObjectLiteralExpression): { elements: PatternElement[]; rest: { decl: Decl | null; local: string } | null } {
    const T = typescript();
    const b = this.binding;
    const elements: PatternElement[] = [];
    let rest: { decl: Decl | null; local: string } | null = null;
    if (T.isObjectBindingPattern(pattern)) {
      for (const el of pattern.elements) {
        if (el.dotDotDotToken) {
          if (T.isIdentifier(el.name)) rest = { decl: b.declOfName.get(el.name) ?? null, local: el.name.text };
          continue;
        }
        if (!T.isIdentifier(el.name)) continue;
        const key = el.propertyName ? propertyNameText(el.propertyName) : el.name.text;
        if (key === null) continue;
        elements.push({ key, local: el.name.text, decl: b.declOfName.get(el.name) ?? null });
      }
      return { elements, rest };
    }
    for (const prop of pattern.properties) {
      if (T.isShorthandPropertyAssignment(prop)) {
        elements.push({ key: prop.name.text, local: prop.name.text, decl: b.refOf.get(prop.name) ?? null });
      } else if (T.isPropertyAssignment(prop)) {
        const key = propertyNameText(prop.name);
        let target = unwrap(prop.initializer);
        if (T.isBinaryExpression(target) && target.operatorToken.kind === syntaxKind().EqualsToken) target = unwrap(target.left);
        if (key !== null && T.isIdentifier(target)) elements.push({ key, local: target.text, decl: b.refOf.get(target) ?? null });
      } else if (T.isSpreadAssignment(prop)) {
        const target = unwrap(prop.expression);
        if (T.isIdentifier(target)) rest = { decl: b.refOf.get(target) ?? null, local: target.text };
      }
    }
    return { elements, rest };
  }

  // module.exports, exports or exports.x
  private exportsTarget(node: ts.Node): { name: string | null } | null {
    const T = typescript();
    // unless the file declares its own
    const isExportsId = (n: ts.Node): boolean => {
      if (!T.isIdentifier(n) || n.text !== 'exports') return false;
      const d = this.binding.refOf.get(n);
      return !d || d.kind === 'implicit';
    };
    if (isModuleExports(node) || isExportsId(node)) return { name: null };
    if (T.isPropertyAccessExpression(node) || T.isElementAccessExpression(node)) {
      const base = node.expression;
      const name = T.isPropertyAccessExpression(node) ? node.name.text : this.staticString(node.argumentExpression);
      if (name !== null && (isModuleExports(base) || isExportsId(base))) return { name };
    }
    return null;
  }

  private baseImport(node: ts.Node, specifier: string, kind: ImportKind, at: number, span: Span): ImportInternal {
    return { specifier, kind, at, span, binding: null, node, bindingDecl: null, namedDecls: [], rest: null, direct: null, thenRoots: [], createdBy: null };
  }

  private importDeclaration(node: ts.ImportDeclaration, out: ImportInternal[]): void {
    const T = typescript();
    if (!T.isStringLiteral(node.moduleSpecifier)) return;
    this.specifierNodes.add(node.moduleSpecifier);
    const spec = node.moduleSpecifier.text;
    const at = node.getStart(this.sf);
    const span = { start: at, end: node.moduleSpecifier.end };
    const clause = node.importClause;
    if (!clause) {
      out.push(this.baseImport(node, spec, 'esm-side-effect', at, span));
      return;
    }
    if (clause.isTypeOnly) return;
    const b = this.binding;
    let defaultLocal: string | null = clause.name?.text ?? null;
    let defaultDecl: Decl | null = clause.name ? (b.declOfName.get(clause.name) ?? null) : null;
    const named: Record<string, string> = {};
    const namedDecls: ImportInternal['namedDecls'] = [];
    const nb = clause.namedBindings;
    if (nb && T.isNamedImports(nb)) {
      for (const el of nb.elements) {
        if (el.isTypeOnly) continue;
        const imported = el.propertyName ? el.propertyName.text : el.name.text;
        const local = el.name.text;
        if (imported === 'default') {
          if (!defaultLocal) {
            defaultLocal = local;
            defaultDecl = b.declOfName.get(el.name) ?? null;
          }
          continue;
        }
        named[imported] = local;
        namedDecls.push({ imported, decl: b.declOfName.get(el.name) ?? null, local });
      }
    }
    const ns = nb && T.isNamespaceImport(nb) ? nb.name : null;
    if (defaultLocal) {
      out.push({ ...this.baseImport(node, spec, 'esm-default', at, span), binding: defaultLocal, bindingDecl: defaultDecl, named, namedDecls });
    }
    if (ns) out.push({ ...this.baseImport(node, spec, 'esm-namespace', at, span), binding: ns.text, bindingDecl: b.declOfName.get(ns) ?? null });
    if (!defaultLocal && !ns && nb && T.isNamedImports(nb)) out.push({ ...this.baseImport(node, spec, 'esm-named', at, span), named, namedDecls });
  }

  private reexportDeclaration(node: ts.ExportDeclaration, out: ImportInternal[]): void {
    const T = typescript();
    if (node.isTypeOnly || !node.moduleSpecifier || !T.isStringLiteral(node.moduleSpecifier)) return;
    this.specifierNodes.add(node.moduleSpecifier);
    const at = node.getStart(this.sf);
    const base = this.baseImport(node, node.moduleSpecifier.text, 're-export', at, { start: at, end: node.moduleSpecifier.end });
    const clause = node.exportClause;
    if (!clause || T.isNamespaceExport(clause)) {
      out.push(base);
      return;
    }
    const named: Record<string, string> = {};
    for (const el of clause.elements) {
      if (el.isTypeOnly) continue;
      named[(el.propertyName ?? el.name).text] = el.name.text;
    }
    out.push({ ...base, named });
  }

  private importEquals(node: ts.ImportEqualsDeclaration, out: ImportInternal[]): void {
    const T = typescript();
    if (node.isTypeOnly || !T.isExternalModuleReference(node.moduleReference)) return;
    const ref = node.moduleReference;
    if (!T.isStringLiteral(ref.expression)) return;
    this.specifierNodes.add(ref.expression);
    const at = ref.getStart(this.sf);
    out.push({
      ...this.baseImport(node, ref.expression.text, 'cjs-require', at, { start: at, end: ref.end }),
      binding: node.name.text,
      bindingDecl: this.binding.declOfName.get(node.name) ?? null,
    });
  }

  private requireCall(call: ts.CallExpression, out: ImportInternal[]): void {
    const T = typescript();
    const arg = call.arguments[0] as ts.Expression;
    const spec = this.staticString(arg);
    if (spec === null) {
      this.dynamicRequireCache.push(call);
      return;
    }
    const argNode = unwrap(arg);
    if (T.isStringLiteral(argNode) || T.isNoSubstitutionTemplateLiteral(argNode)) this.specifierNodes.add(argNode);
    const at = call.expression.getStart(this.sf);
    const base = this.baseImport(call, spec, 'cjs-require', at, { start: at, end: call.end });
    const top = climb(call);
    const p = top.parent;
    let member: string | null = null;
    let memberNode: ts.Expression | null = null;
    if (p && T.isPropertyAccessExpression(p) && p.expression === top) {
      member = p.name.text;
      memberNode = p;
    } else if (p && T.isElementAccessExpression(p) && p.expression === top) {
      const key = this.staticString(p.argumentExpression);
      if (key !== null) {
        member = key;
        memberNode = p;
      }
    }
    if (member !== null && memberNode !== null) {
      const lhs = this.lhsOf(climb(memberNode));
      if (lhs && this.exportsTarget(lhs.target)) {
        out.push({ ...base, kind: 're-export', named: { [member]: member } });
        return;
      }
      if (lhs?.pattern) {
        const { elements, rest } = this.patternElements(lhs.pattern);
        out.push({
          ...base,
          kind: 'cjs-destructure',
          binding: rest?.local ?? null,
          rest,
          named: Object.fromEntries(elements.map((e) => [e.key, e.local])),
          namedDecls: elements.map((e) => ({ imported: e.key, decl: e.decl, local: e.local })),
          createdBy: lhs.createdBy,
        });
        return;
      }
      if (lhs?.name) {
        if (member === 'default') out.push({ ...base, binding: lhs.name, bindingDecl: lhs.decl, viaDefault: true, createdBy: lhs.createdBy });
        else out.push({ ...base, kind: 'cjs-member', named: { [member]: lhs.name }, namedDecls: [{ imported: member, decl: lhs.decl, local: lhs.name }], createdBy: lhs.createdBy });
        return;
      }
      out.push(member === 'default' ? { ...base, direct: call } : { ...base, kind: 'cjs-member', direct: call });
      return;
    }
    if (isInvoked(top)) {
      out.push({ ...base, direct: call });
      return;
    }
    const lhs = this.lhsOf(top);
    if (lhs && this.exportsTarget(lhs.target)) {
      out.push({ ...base, kind: 're-export' });
      return;
    }
    if (lhs?.pattern) {
      const { elements, rest } = this.patternElements(lhs.pattern);
      out.push({
        ...base,
        kind: 'cjs-destructure',
        binding: rest?.local ?? null,
        rest,
        named: Object.fromEntries(elements.map((e) => [e.key, e.local])),
        namedDecls: elements.map((e) => ({ imported: e.key, decl: e.decl, local: e.local })),
        createdBy: lhs.createdBy,
      });
      return;
    }
    if (lhs?.name) {
      out.push({ ...base, binding: lhs.name, bindingDecl: lhs.decl, createdBy: lhs.createdBy });
      return;
    }
    out.push({ ...base, direct: call });
  }

  private dynamicImport(call: ts.CallExpression, out: ImportInternal[]): void {
    const T = typescript();
    const arg = call.arguments[0] as ts.Expression;
    const spec = this.staticString(arg);
    if (spec === null) {
      this.dynamicRequireCache.push(call);
      return;
    }
    const argNode = unwrap(arg);
    if (T.isStringLiteral(argNode) || T.isNoSubstitutionTemplateLiteral(argNode)) this.specifierNodes.add(argNode);
    const at = call.getStart(this.sf);
    const base = this.baseImport(call, spec, 'dynamic-import', at, { start: at, end: call.end });
    const top = climb(call);
    const p = top.parent;
    const spanFrom = (lhs: Lhs): Span => {
      const target = lhs.target;
      const decl = target.parent;
      if (decl && T.isVariableDeclaration(decl) && T.isVariableDeclarationList(decl.parent) && decl.parent.declarations.length === 1) return { start: decl.parent.getStart(this.sf), end: call.end };
      return { start: target.getStart(this.sf), end: call.end };
    };
    // import('x').then((m) => m.merge())
    if (p && T.isPropertyAccessExpression(p) && p.expression === top && p.name.text === 'then' && p.parent && T.isCallExpression(p.parent) && p.parent.expression === p) {
      const cb = p.parent.arguments[0];
      const thenRoots: ImportInternal['thenRoots'] = [];
      if (cb && (T.isArrowFunction(cb) || T.isFunctionExpression(cb)) && cb.parameters[0]) {
        const name = cb.parameters[0].name;
        if (T.isIdentifier(name)) thenRoots.push({ decl: this.binding.declOfName.get(name) ?? null, local: name.text, path: [] });
        else if (T.isObjectBindingPattern(name)) for (const e of this.patternElements(name).elements) thenRoots.push({ decl: e.decl, local: e.local, path: [e.key] });
      }
      out.push({ ...base, thenRoots });
      return;
    }
    // (await import('x')).default
    if (p && (T.isPropertyAccessExpression(p) || T.isElementAccessExpression(p)) && p.expression === top) {
      const member = T.isPropertyAccessExpression(p) ? p.name.text : this.staticString(p.argumentExpression);
      if (member === 'default') {
        const lhs = this.lhsOf(climb(p));
        if (lhs?.name) {
          out.push({ ...base, span: spanFrom(lhs), binding: lhs.name, bindingDecl: lhs.decl, viaDefault: true, createdBy: lhs.createdBy });
          return;
        }
      }
      out.push({ ...base, direct: call });
      return;
    }
    const lhs = this.lhsOf(top);
    if (lhs?.name) {
      out.push({ ...base, span: spanFrom(lhs), binding: lhs.name, bindingDecl: lhs.decl, createdBy: lhs.createdBy });
      return;
    }
    if (lhs?.pattern) {
      const { elements } = this.patternElements(lhs.pattern);
      out.push({
        ...base,
        span: spanFrom(lhs),
        named: Object.fromEntries(elements.map((e) => [e.key, e.local])),
        namedDecls: elements.map((e) => ({ imported: e.key, decl: e.decl, local: e.local })),
        createdBy: lhs.createdBy,
      });
      return;
    }
    out.push({ ...base, direct: call });
  }

  private rootsOf(index: number, rec: ImportInternal, source: RootSource): Root[] {
    const roots: Root[] = [];
    const isFile = source.kind === 'file';
    const sub = source.kind === 'pkg' && source.subpath ? [subpathMember(source.subpath)] : [];
    const make = (decl: Decl | null, expr: ts.Expression | null, local: string, rootPath: string[]): Root => ({
      source,
      record: index,
      decl,
      expr,
      local,
      path: rootPath,
      fn: false,
      depth: 0,
      createdBy: rec.createdBy,
    });
    if (rec.kind === 're-export') return roots;
    if (rec.bindingDecl) {
      let rootPath = sub;
      if (isFile) rootPath = rec.kind === 'esm-default' || rec.viaDefault ? ['default'] : [];
      roots.push(make(rec.bindingDecl, null, rec.binding ?? '', rootPath));
    } else if (rec.rest) {
      roots.push(make(rec.rest.decl, null, rec.rest.local, isFile ? [] : sub));
    }
    for (const n of rec.namedDecls) roots.push(make(n.decl, null, n.local, [n.imported]));
    for (const t of rec.thenRoots) roots.push(make(t.decl, null, t.local, t.path));
    if (rec.direct) roots.push(make(null, rec.direct, rec.kind === 'dynamic-import' ? 'import' : 'require', isFile ? [] : sub));
    return roots.filter((r) => r.decl !== null || r.expr !== null);
  }

  private track(roots: readonly Root[]): { uses: RawUse[]; dynamic: RawDynamic[]; holders: Map<Decl, Root[]> } {
    const T = typescript();
    const uses: RawUse[] = [];
    const dynamic: RawDynamic[] = [];
    const holders = new Map<Decl, Root[]>();
    const queue: Root[] = [...roots];
    const seen = new Set<string>();
    const use = (root: Root, usePath: string[], call: boolean, at: ts.Node, node: ts.Node): void => {
      uses.push({ root, path: usePath, call, at: at.getStart(this.sf), node });
    };
    const alias = (lhs: Lhs, root: Root, aliasPath: string[], fn: boolean, at: ts.Node, node: ts.Node): void => {
      if (!lhs.decl || root.depth >= MAX_ALIAS_DEPTH) {
        if (aliasPath.length > 0 || fn) use(root, aliasPath, false, at, node);
        return;
      }
      queue.push({ ...root, decl: lhs.decl, expr: null, local: lhs.name ?? root.local, path: aliasPath, fn, depth: root.depth + 1, createdBy: lhs.createdBy });
    };
    const destructure = (pattern: ts.ObjectBindingPattern | ts.ObjectLiteralExpression, root: Root, basePath: string[], at: ts.Node, node: ts.Node): void => {
      if (root.depth >= MAX_ALIAS_DEPTH) {
        use(root, basePath, false, at, node);
        return;
      }
      const createdBy = T.isObjectLiteralExpression(pattern) ? (pattern.parent ?? null) : null;
      const { elements, rest } = this.patternElements(pattern);
      for (const e of elements) {
        if (!e.decl) continue;
        queue.push({ ...root, decl: e.decl, expr: null, local: e.local, path: [...basePath, e.key], fn: false, depth: root.depth + 1, createdBy });
      }
      if (rest?.decl) queue.push({ ...root, decl: rest.decl, expr: null, local: rest.local, path: basePath, fn: false, depth: root.depth + 1, createdBy });
    };
    // top.x, top['x'], computed or number
    const accessOn = (top: ts.Expression): { name: string; node: ts.Expression } | 'computed' | 'number' | null => {
      const p = top.parent;
      if (!p) return null;
      if (T.isPropertyAccessExpression(p) && p.expression === top) return T.isIdentifier(p.name) ? { name: p.name.text, node: p } : null;
      if (T.isElementAccessExpression(p) && p.expression === top) {
        const arg = unwrap(p.argumentExpression);
        if (T.isNumericLiteral(arg)) return 'number';
        const key = this.staticString(arg);
        return key !== null ? { name: key, node: p } : 'computed';
      }
      return null;
    };
    const member = (accessNode: ts.Expression, name: string, root: Root, basePath: string[], level: number, at: ts.Node): void => {
      const maxLevel = root.source.kind === 'file' ? 2 : 1;
      const functionLike = root.fn || (basePath.length > 0 && FUNCTION_METHODS.has(name));
      if (functionLike && FUNCTION_METHODS.has(name)) {
        const top = climb(accessNode);
        if (isInvoked(top)) {
          if (name === 'bind') {
            const callTop = climb(top.parent as ts.Expression);
            const lhs = this.lhsOf(callTop);
            if (lhs?.decl) alias(lhs, root, basePath, true, at, callTop);
            else use(root, basePath, false, at, accessNode);
          } else {
            use(root, basePath, true, at, accessNode);
          }
          return;
        }
      }
      if (root.fn) {
        use(root, basePath, false, at, accessNode);
        return;
      }
      const nextPath = [...basePath, name];
      const top = climb(accessNode);
      if (isInvoked(top)) {
        use(root, nextPath, true, at, accessNode);
        return;
      }
      const next = accessOn(top);
      if (next !== null && next !== 'computed' && next !== 'number') {
        if (FUNCTION_METHODS.has(next.name) && isInvoked(climb(next.node))) {
          if (next.name === 'bind') {
            const callTop = climb(climb(next.node).parent as ts.Expression);
            const lhs = this.lhsOf(callTop);
            if (lhs?.decl) alias(lhs, root, nextPath, true, at, callTop);
            else use(root, nextPath, false, at, accessNode);
          } else {
            use(root, nextPath, true, at, accessNode);
          }
          return;
        }
        if (level < maxLevel) {
          member(next.node, next.name, root, nextPath, level + 1, at);
          return;
        }
        use(root, nextPath, false, at, accessNode);
        return;
      }
      const lhs = this.lhsOf(top);
      if (lhs?.decl) {
        alias(lhs, root, nextPath, true, at, top);
        return;
      }
      if (lhs?.pattern && root.source.kind === 'file' && level < maxLevel) {
        destructure(lhs.pattern, root, nextPath, at, top);
        return;
      }
      use(root, nextPath, false, at, accessNode);
    };
    const classify = (ref: ts.Expression, root: Root): void => {
      const top = climb(ref);
      const access = accessOn(top);
      if (access === 'computed') {
        dynamic.push({ root, reason: 'computed-member', node: top.parent as ts.Node });
        return;
      }
      if (access === 'number') return;
      if (access) {
        member(access.node, access.name, root, root.path, 1, ref);
        return;
      }
      if (isInvoked(top) || (T.isIdentifier(ref) && ref.parent && (T.isJsxOpeningElement(ref.parent) || T.isJsxSelfClosingElement(ref.parent)) && ref.parent.tagName === ref)) {
        use(root, root.path, true, ref, top);
        return;
      }
      if (T.isIdentifier(ref) && writeOf(ref) !== null && climb(ref) === ref) return; // reported with the writes
      const lhs = this.lhsOf(top);
      if (lhs?.decl) {
        alias(lhs, root, root.path, root.fn, ref, top);
        return;
      }
      if (lhs?.pattern) {
        if (root.fn) use(root, root.path, false, ref, top);
        else destructure(lhs.pattern, root, root.path, ref, top);
        return;
      }
      // only if it holds a member or file value
      if (root.path.length > 0 || root.fn || root.source.kind === 'file') use(root, root.path, false, ref, top);
    };
    while (queue.length > 0) {
      const root = queue.shift() as Root;
      if (root.decl) {
        const key = `${root.decl.id}|${sourceKey(root.source)}|${root.path.join('.')}|${root.fn ? 1 : 0}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const list = holders.get(root.decl);
        if (list) list.push(root);
        else holders.set(root.decl, [root]);
        for (const ref of root.decl.refs) classify(ref, root);
        for (const w of root.decl.writes) {
          if (w === root.createdBy) continue;
          dynamic.push({ root, reason: 'reassigned-binding', node: w });
        }
      } else if (root.expr) {
        classify(root.expr, root);
      }
    }
    return { uses, dynamic, holders };
  }

  private trackFor(key: string, roots: readonly Root[]): { uses: RawUse[]; dynamic: RawDynamic[]; holders: Map<Decl, Root[]> } {
    const hit = this.trackCache.get(key);
    if (hit) return hit;
    const result = this.track(roots);
    this.trackCache.set(key, result);
    return result;
  }

  private unitName(fn: ts.FunctionLikeDeclaration): string | null {
    const T = typescript();
    if ((T.isFunctionDeclaration(fn) || T.isFunctionExpression(fn)) && fn.name) return fn.name.text;
    if (T.isFunctionDeclaration(fn)) {
      const mods = T.getModifiers(fn) ?? [];
      return mods.some((m) => m.kind === syntaxKind().DefaultKeyword) ? moduleBaseName(this.path) : null;
    }
    if (T.isMethodDeclaration(fn) || T.isGetAccessorDeclaration(fn) || T.isSetAccessorDeclaration(fn)) return propertyNameText(fn.name);
    if (T.isConstructorDeclaration(fn)) {
      const cls = fn.parent;
      return T.isClassDeclaration(cls) && cls.name ? cls.name.text : 'constructor';
    }
    const top = climb(fn as ts.Expression);
    const p = top.parent;
    if (!p) return null;
    if (T.isVariableDeclaration(p) && p.initializer === top && T.isIdentifier(p.name)) return p.name.text;
    if (T.isPropertyAssignment(p) && p.initializer === top) return propertyNameText(p.name);
    if (T.isPropertyDeclaration(p) && p.initializer === top) return propertyNameText(p.name);
    if (T.isBinaryExpression(p) && p.operatorToken.kind === syntaxKind().EqualsToken && p.right === top) {
      const left = unwrap(p.left);
      if (isModuleExports(left)) return moduleBaseName(this.path);
      if (T.isIdentifier(left)) return left.text;
      if (T.isPropertyAccessExpression(left)) return left.name.text === 'default' ? moduleBaseName(this.path) : left.name.text;
    }
    if (T.isExportAssignment(p)) return moduleBaseName(this.path);
    return null;
  }

  private get unitData(): NonNullable<FileModel['unitCache']> {
    if (this.unitCache !== null) return this.unitCache;
    const T = typescript();
    const b = this.binding;
    const units: UnitInfo[] = [];
    const unitOfFn = new Map<ts.Node, number>();
    const unitByDecl = new Map<Decl, number>();
    const objectUnits = new Map<Decl, Map<string, number>>();
    const visit = (node: ts.Node): void => {
      if (isTypeLevel(node)) return;
      if (isFunctionUnitNode(node)) {
        const name = this.unitName(node);
        if (name !== null) {
          const index = units.length;
          units.push({ name, node, line: this.lineOf(node.getStart(this.sf)) });
          unitOfFn.set(node, index);
          if (T.isFunctionDeclaration(node) && node.name) {
            const d = b.declOfName.get(node.name);
            if (d) unitByDecl.set(d, index);
          } else if (T.isFunctionExpression(node) || T.isArrowFunction(node)) {
            const top = climb(node);
            const p = top.parent;
            if (p && T.isVariableDeclaration(p) && p.initializer === top && T.isIdentifier(p.name)) {
              const d = b.declOfName.get(p.name);
              if (d) unitByDecl.set(d, index);
            } else if (p && T.isBinaryExpression(p) && p.right === top && T.isIdentifier(unwrap(p.left))) {
              const d = b.refOf.get(unwrap(p.left) as ts.Identifier);
              if (d) unitByDecl.set(d, index);
            }
          }
        }
      }
      T.forEachChild(node, visit);
    };
    visit(this.sf);
    // helpers.render() calls a unit
    for (const d of b.decls) {
      if (!T.isVariableDeclaration(d.node) || !d.node.initializer) continue;
      const init = unwrap(d.node.initializer);
      if (!T.isObjectLiteralExpression(init)) continue;
      const map = new Map<string, number>();
      for (const prop of init.properties) {
        const key = propertyNameText(prop.name);
        if (key === null) continue;
        const fnNode = T.isMethodDeclaration(prop) ? prop : T.isPropertyAssignment(prop) ? unwrap(prop.initializer) : null;
        const unit = fnNode ? unitOfFn.get(fnNode) : undefined;
        if (unit !== undefined) map.set(key, unit);
        else if (T.isShorthandPropertyAssignment(prop)) {
          const ref = b.refOf.get(prop.name);
          const u = ref ? unitByDecl.get(ref) : undefined;
          if (u !== undefined) map.set(key, u);
        }
      }
      if (map.size > 0) objectUnits.set(d, map);
    }
    this.unitCache = { units, unitOfFn, unitByDecl, objectUnits };
    return this.unitCache;
  }

  // skips anonymous fns
  unitAt(node: ts.Node): number {
    const { unitOfFn } = this.unitData;
    for (let cur: ts.Node | undefined = node.parent; cur; cur = cur.parent) {
      const u = unitOfFn.get(cur);
      if (u !== undefined) return u;
    }
    return -1;
  }

  packageImports(packages: readonly string[]): PackageImport[] {
    const out: PackageImport[] = [];
    this.internalImports().forEach((rec, index) => {
      const m = matchPackageSpecifier(rec.specifier, packages);
      if (!m) return;
      const entry: PackageImport = { record: index, import: rec, pkg: m.pkg };
      if (m.subpath) entry.subpath = m.subpath;
      out.push(entry);
    });
    return out;
  }

  private rootsForPackage(entries: readonly PackageImport[]): Root[] {
    const recs = this.internalImports();
    const roots: Root[] = [];
    for (const e of entries) {
      const source: RootSource = e.subpath ? { kind: 'pkg', pkg: e.pkg, subpath: e.subpath } : { kind: 'pkg', pkg: e.pkg };
      roots.push(...this.rootsOf(e.record, recs[e.record] as ImportInternal, source));
    }
    return roots;
  }

  private toUses(raw: readonly RawUse[]): ModuleUse[] {
    return raw.map((u) => ({ source: u.root.source, record: u.root.record, local: u.root.local, path: u.path, call: u.call, at: u.at, unit: this.unitAt(u.node) }));
  }

  private reexportUses(entries: readonly PackageImport[]): ModuleUse[] {
    const out: ModuleUse[] = [];
    for (const e of entries) {
      if (e.import.kind !== 're-export' || !e.import.named) continue;
      const at = this.lineStart(this.lineOf(e.import.at));
      const source: RootSource = { kind: 'pkg', pkg: e.pkg };
      for (const imported of Object.keys(e.import.named)) out.push({ source, record: e.record, local: '(re-export)', path: [imported], call: false, at, unit: -1 });
    }
    return out;
  }

  private stringLiterals(): Set<string> {
    if (this.stringCache !== null) return this.stringCache;
    const T = typescript();
    this.internalImports();
    const set = new Set<string>();
    const visit = (node: ts.Node): void => {
      if ((T.isStringLiteral(node) || T.isNoSubstitutionTemplateLiteral(node)) && !this.specifierNodes.has(node)) set.add(node.text);
      else if (T.isTemplateExpression(node)) {
        set.add(node.head.text);
        for (const s of node.templateSpans) set.add(s.literal.text);
      }
      T.forEachChild(node, visit);
    };
    visit(this.sf);
    this.stringCache = set;
    return set;
  }

  // require(expr) naming pkg via a string
  private dynamicRequiresFor(pkg: string): ts.CallExpression[] {
    this.internalImports();
    if (this.dynamicRequireCache.length === 0) return [];
    const strings = this.stringLiterals();
    const named = [...strings].some((s) => s === pkg || s.startsWith(`${pkg}/`) || s.endsWith(`/${pkg}`) || s.includes(`/${pkg}/`));
    if (!named) return [];
    return this.dynamicRequireCache.filter((call) => !this.looksRelative(call.arguments[0] as ts.Expression));
  }

  private looksRelative(expr: ts.Expression): boolean {
    const T = typescript();
    const e = unwrap(expr);
    const relText = (text: string): boolean => text.startsWith('.') || text.startsWith('/');
    if (T.isTemplateExpression(e)) {
      if (relText(e.head.text)) return true;
      const first = e.templateSpans[0]?.expression;
      const id = first ? unwrap(first) : null;
      return e.head.text === '' && id !== null && T.isIdentifier(id) && /^__(?:dirname|filename)$/.test(id.text);
    }
    if (T.isBinaryExpression(e) && e.operatorToken.kind === syntaxKind().PlusToken) {
      let left: ts.Expression = e;
      while (T.isBinaryExpression(left) && left.operatorToken.kind === syntaxKind().PlusToken) left = unwrap(left.left);
      if (T.isStringLiteral(left) || T.isNoSubstitutionTemplateLiteral(left)) return relText(left.text);
      if (T.isIdentifier(left)) return /^__(?:dirname|filename)$/.test(left.text);
      return false;
    }
    if (T.isCallExpression(e)) {
      const callee = unwrap(e.expression);
      const name = T.isPropertyAccessExpression(callee) ? callee.name.text : T.isIdentifier(callee) ? callee.text : '';
      return /^(?:join|resolve|fileURLToPath|relative)$/.test(name);
    }
    return false;
  }

  analyzePackage(pkg: string): PackageAnalysis {
    const entries = this.packageImports([pkg]);
    if (entries.length === 0) {
      const dyn = this.dynamicRequiresFor(pkg).map((call) => this.dynamicHit({ kind: 'pkg', pkg }, 'dynamic-require', call));
      return { imports: [], uses: [], dynamic: dyn };
    }
    const { uses, dynamic } = this.trackFor(`pkg:${pkg}`, this.rootsForPackage(entries));
    const all = [...this.toUses(uses), ...this.reexportUses(entries)].sort((a, b) => a.at - b.at);
    const dyn: DynamicHit[] = [
      ...dynamic.map((d) => this.dynamicHit(d.root.source, d.reason, d.node)),
      ...this.dynamicRequiresFor(pkg).map((call) => this.dynamicHit({ kind: 'pkg', pkg }, 'dynamic-require', call)),
    ];
    return { imports: entries, uses: dedupeUses(all), dynamic: dedupeDynamic(dyn) };
  }

  private dynamicHit(source: RootSource, reason: DynamicAccess['reason'], node: ts.Node): DynamicHit {
    const start = node.getStart(this.sf);
    return { source, reason, at: start, span: { start, end: node.end } };
  }

  // null if a site matches no record
  usesForSites(sites: readonly { line: number; kind: ImportKind; binding: string | null; named?: Record<string, string>; subpath?: string; statement?: string }[]): ModuleUse[] | null {
    const recs = this.internalImports();
    const chosen = new Map<number, { rec: ImportInternal; subpath?: string }>();
    for (const site of sites) {
      const candidates = recs
        .map((rec, index) => ({ rec, index }))
        .filter(({ rec }) => {
          if (this.lineOf(rec.at) !== site.line || rec.kind !== site.kind || (rec.binding ?? null) !== (site.binding ?? null)) return false;
          if (!sameNamed(rec.named, site.named)) return false;
          if (site.subpath) return rec.specifier.endsWith(`/${site.subpath}`);
          return true;
        });
      if (candidates.length === 0) return null;
      const pick = candidates.find(({ rec }) => (site.statement ?? '').includes(rec.specifier)) ?? candidates[0];
      if (!pick) return null;
      chosen.set(pick.index, { rec: pick.rec, ...(site.subpath ? { subpath: site.subpath } : {}) });
    }
    const entries: PackageImport[] = [...chosen.entries()].map(([record, { rec, subpath }]) => {
      const pkg = subpath ? rec.specifier.slice(0, rec.specifier.length - subpath.length - 1) : rec.specifier;
      return subpath ? { record, import: rec, pkg, subpath } : { record, import: rec, pkg };
    });
    const key = `sites:${[...chosen.keys()].sort((a, b) => a - b).join(',')}`;
    const { uses } = this.trackFor(key, this.rootsForPackage(entries));
    return dedupeUses([...this.toUses(uses), ...this.reexportUses(entries)].sort((a, b) => a.at - b.at));
  }

  summarize(packages: readonly string[], resolve: SpecifierResolver): FileSummary {
    const T = typescript();
    const recs = this.internalImports();
    const roots: Root[] = [];
    const recSource: (RootSource | null)[] = recs.map((rec) => {
      const m = matchPackageSpecifier(rec.specifier, packages);
      if (m) return m.subpath ? { kind: 'pkg', pkg: m.pkg, subpath: m.subpath } : { kind: 'pkg', pkg: m.pkg };
      const file = resolve(rec.specifier, this.path);
      return file && file !== this.path ? { kind: 'file', file } : null;
    });
    recs.forEach((rec, index) => {
      const source = recSource[index];
      if (source) roots.push(...this.rootsOf(index, rec, source));
    });
    const { uses, holders } = this.track(roots);
    const { units, unitOfFn, unitByDecl, objectUnits } = this.unitData;
    const b = this.binding;
    const pkgUses: FileSummary['pkgUses'] = [];
    const fileUses: FileSummary['fileUses'] = [];
    for (const u of uses) {
      const unit = this.unitAt(u.node);
      const line = this.lineOf(u.at);
      if (u.root.source.kind === 'pkg') pkgUses.push({ unit, pkg: u.root.source.pkg, member: u.path.length > 0 ? (u.path[u.path.length - 1] as string) : null, line });
      else fileUses.push({ unit, file: u.root.source.file, path: u.path, call: u.call, line, local: u.root.local });
    }

    const exportsMap = new Map<string, ExportTarget>();
    const stars: string[] = [];
    const pkgStars: string[] = [];
    const seenDecls = new Set<Decl>();
    const specTarget = (spec: string, targetPath: string[]): ExportTarget | null => {
      const m = matchPackageSpecifier(spec, packages);
      if (m) return { kind: 'pkg', pkg: m.pkg, path: m.subpath ? [subpathMember(m.subpath), ...targetPath] : targetPath };
      const file = resolve(spec, this.path);
      return file && file !== this.path ? { kind: 'file', file, path: targetPath } : null;
    };
    const originOf = (d: Decl): ExportTarget | null => {
      const held = holders.get(d)?.[0];
      if (held) return held.source.kind === 'pkg' ? { kind: 'pkg', pkg: held.source.pkg, path: held.path } : { kind: 'file', file: held.source.file, path: held.path };
      const u = unitByDecl.get(d);
      if (u !== undefined) return { kind: 'unit', file: this.path, unit: u };
      if (seenDecls.has(d)) return null;
      if (T.isVariableDeclaration(d.node) && T.isIdentifier(d.node.name) && d.node.initializer) {
        seenDecls.add(d);
        try {
          return valueOf(d.node.initializer);
        } finally {
          seenDecls.delete(d);
        }
      }
      return null;
    };
    const objectTarget = (obj: ts.ObjectLiteralExpression): ExportTarget => {
      const props = new Map<string, ExportTarget>();
      for (const prop of obj.properties) {
        if (T.isSpreadAssignment(prop)) continue;
        const key = propertyNameText(prop.name);
        if (key === null) continue;
        let target: ExportTarget | null = null;
        if (T.isPropertyAssignment(prop)) target = valueOf(prop.initializer);
        else if (T.isShorthandPropertyAssignment(prop)) {
          const d = b.refOf.get(prop.name);
          target = d ? originOf(d) : null;
        } else if (T.isMethodDeclaration(prop) || T.isGetAccessorDeclaration(prop)) {
          const u = unitOfFn.get(prop);
          target = u !== undefined ? { kind: 'unit', file: this.path, unit: u } : null;
        }
        if (target) props.set(key, target);
      }
      return { kind: 'object', props };
    };
    const extend = (base: ExportTarget, name: string): ExportTarget | null => {
      switch (base.kind) {
        case 'pkg':
          return { kind: 'pkg', pkg: base.pkg, path: [...base.path, name] };
        case 'file':
          return { kind: 'file', file: base.file, path: [...base.path, name] };
        case 'object':
          return base.props.get(name) ?? null;
        default:
          return base;
      }
    };
    const valueOf = (expr: ts.Expression): ExportTarget | null => {
      const e = unwrap(expr);
      if (T.isIdentifier(e)) {
        const d = b.refOf.get(e);
        return d ? originOf(d) : null;
      }
      if (T.isFunctionExpression(e) || T.isArrowFunction(e)) {
        const u = unitOfFn.get(e);
        return u !== undefined ? { kind: 'unit', file: this.path, unit: u } : null;
      }
      if (T.isObjectLiteralExpression(e)) return objectTarget(e);
      if (T.isPropertyAccessExpression(e) || T.isElementAccessExpression(e)) {
        const name = T.isPropertyAccessExpression(e) ? e.name.text : this.staticString(e.argumentExpression);
        if (name === null) return null;
        const base = valueOf(e.expression);
        return base ? extend(base, name) : null;
      }
      if (T.isCallExpression(e)) {
        if (T.isIdentifier(e.expression) && e.expression.text === 'require') {
          const spec = this.staticString(e.arguments[0]);
          return spec === null ? null : specTarget(spec, []);
        }
        if (e.expression.kind === syntaxKind().ImportKeyword) return null;
        const callee = unwrap(e.expression);
        if (T.isPropertyAccessExpression(callee) && callee.name.text === 'bind') return valueOf(callee.expression);
      }
      return null;
    };
    const setExport = (name: string, target: ExportTarget | null): void => {
      if (target && !exportsMap.has(name)) exportsMap.set(name, target);
    };
    const hasModifier = (node: ts.Node, kind: ts.SyntaxKind): boolean => T.canHaveModifiers(node) && (T.getModifiers(node) ?? []).some((m) => m.kind === kind);
    const moduleValue = (expr: ts.Expression): void => {
      const e = unwrap(expr);
      const v = valueOf(e);
      if (v) exportsMap.set('default', v);
      if (T.isObjectLiteralExpression(e) && v && v.kind === 'object') {
        for (const [k, t] of v.props) setExport(k, t);
        for (const prop of e.properties) {
          if (!T.isSpreadAssignment(prop)) continue;
          const s = valueOf(prop.expression);
          if (s?.kind === 'file' && s.path.length === 0) stars.push(s.file);
          if (s?.kind === 'pkg' && s.path.length === 0) pkgStars.push(s.pkg);
        }
      }
      if (v?.kind === 'file' && v.path.length === 0) stars.push(v.file);
      if (v?.kind === 'pkg' && v.path.length === 0) pkgStars.push(v.pkg);
    };
    for (const st of this.sf.statements) {
      if (T.isFunctionDeclaration(st) && hasModifier(st, syntaxKind().ExportKeyword)) {
        const u = unitOfFn.get(st);
        const name = hasModifier(st, syntaxKind().DefaultKeyword) ? 'default' : st.name?.text;
        if (name && u !== undefined) setExport(name, { kind: 'unit', file: this.path, unit: u });
      } else if (T.isVariableStatement(st) && hasModifier(st, syntaxKind().ExportKeyword)) {
        for (const decl of st.declarationList.declarations) {
          if (!T.isIdentifier(decl.name)) continue;
          const d = b.declOfName.get(decl.name);
          setExport(decl.name.text, d ? originOf(d) : null);
        }
      } else if (T.isExportDeclaration(st) && !st.isTypeOnly) {
        if (!st.moduleSpecifier) {
          if (st.exportClause && T.isNamedExports(st.exportClause)) {
            for (const el of st.exportClause.elements) {
              if (el.isTypeOnly) continue;
              const local = el.propertyName ?? el.name;
              const d = T.isIdentifier(local) ? b.refOf.get(local) : undefined;
              setExport(el.name.text, d ? originOf(d) : null);
            }
          }
        } else if (T.isStringLiteral(st.moduleSpecifier)) {
          const spec = st.moduleSpecifier.text;
          const clause = st.exportClause;
          if (!clause) {
            const t = specTarget(spec, []);
            if (t?.kind === 'file') stars.push(t.file);
            if (t?.kind === 'pkg' && t.path.length === 0) pkgStars.push(t.pkg);
          } else if (T.isNamespaceExport(clause)) {
            setExport(clause.name.text, specTarget(spec, []));
          } else {
            for (const el of clause.elements) {
              if (el.isTypeOnly) continue;
              const imported = (el.propertyName ?? el.name).text;
              const t = specTarget(spec, imported === 'default' && matchPackageSpecifier(spec, packages) ? [] : [imported]);
              setExport(el.name.text, t);
            }
          }
        }
      } else if (T.isExportAssignment(st)) {
        if (st.isExportEquals) moduleValue(st.expression);
        else {
          const v = valueOf(st.expression);
          if (v) exportsMap.set('default', v);
        }
      }
    }
    // module.exports = ..., exports.x = ...
    const visit = (node: ts.Node): void => {
      if (isTypeLevel(node)) return;
      if (T.isBinaryExpression(node) && node.operatorToken.kind === syntaxKind().EqualsToken) {
        const target = this.exportsTarget(unwrap(node.left));
        if (target) {
          let right = node.right;
          // module.exports = exports = x
          while (T.isBinaryExpression(unwrap(right)) && (unwrap(right) as ts.BinaryExpression).operatorToken.kind === syntaxKind().EqualsToken) right = (unwrap(right) as ts.BinaryExpression).right;
          if (target.name === null) moduleValue(right);
          else setExport(target.name === 'default' ? 'default' : target.name, valueOf(right));
        }
      }
      T.forEachChild(node, visit);
    };
    visit(this.sf);

    // calls, callbacks, this.m()
    const callees: Set<number>[] = units.map(() => new Set<number>());
    const exportedUnit = (name: string): number | undefined => {
      const t = exportsMap.get(name);
      return t?.kind === 'unit' ? t.unit : undefined;
    };
    const classOf = (node: ts.Node): ts.ClassLikeDeclaration | null => {
      for (let cur: ts.Node | undefined = node.parent; cur; cur = cur.parent) if (T.isClassDeclaration(cur) || T.isClassExpression(cur)) return cur;
      return null;
    };
    const classMethod = (cls: ts.ClassLikeDeclaration, name: string): number | undefined => {
      for (const m of cls.members) {
        if (propertyNameText(m.name) !== name) continue;
        if (T.isMethodDeclaration(m) || T.isGetAccessorDeclaration(m)) return unitOfFn.get(m);
        if (T.isPropertyDeclaration(m) && m.initializer) return unitOfFn.get(unwrap(m.initializer));
      }
      return undefined;
    };
    const edge = (from: ts.Node, to: number | undefined): void => {
      if (to === undefined) return;
      const u = this.unitAt(from);
      if (u >= 0 && u !== to) (callees[u] as Set<number>).add(to);
    };
    const visitRefs = (node: ts.Node): void => {
      if (isTypeLevel(node)) return;
      if (T.isIdentifier(node)) {
        const d = b.refOf.get(node);
        if (d) {
          const u = unitByDecl.get(d);
          if (u !== undefined) edge(node, u);
          const p = node.parent;
          if (p && T.isPropertyAccessExpression(p) && p.expression === node) {
            const map = objectUnits.get(d);
            if (map) edge(node, map.get(p.name.text));
          }
        }
        return;
      }
      if (T.isPropertyAccessExpression(node)) {
        const base = unwrap(node.expression);
        if (base.kind === syntaxKind().ThisKeyword) {
          const cls = classOf(node);
          if (cls) edge(node, classMethod(cls, node.name.text));
        } else if (this.exportsTarget(base)?.name === null) {
          edge(node, exportedUnit(node.name.text));
        }
      }
      T.forEachChild(node, visitRefs);
    };
    visitRefs(this.sf);

    return {
      path: this.path,
      units: units.map((u, i) => ({ name: u.name, line: u.line, callees: [...(callees[i] as Set<number>)] })),
      pkgUses,
      fileUses,
      exports: exportsMap,
      stars: [...new Set(stars)],
      pkgStars: [...new Set(pkgStars)],
    };
  }
}

function sameNamed(a: Record<string, string> | undefined, b: Record<string, string> | undefined): boolean {
  const ka = Object.keys(a ?? {}).sort();
  const kb = Object.keys(b ?? {}).sort();
  if (ka.length !== kb.length) return false;
  return ka.every((k, i) => k === kb[i] && (a ?? {})[k] === (b ?? {})[k]);
}

function dedupeUses(uses: readonly ModuleUse[]): ModuleUse[] {
  const seen = new Set<string>();
  return uses.filter((u) => {
    const key = `${u.at}|${u.local}|${u.path.join('.')}|${u.call ? 1 : 0}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function dedupeDynamic(hits: readonly DynamicHit[]): DynamicHit[] {
  const seen = new Set<string>();
  return hits
    .filter((h) => {
      const key = `${h.at}|${h.reason}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .sort((a, b) => a.at - b.at);
}

// null for the default callable
export function useMember(use: Pick<ModuleUse, 'path'>): string | null {
  return use.path.length > 0 ? (use.path[use.path.length - 1] as string) : null;
}
