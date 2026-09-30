import type { JsonSchema } from '../types.ts';

function typeOf(value: unknown): string {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  return typeof value;
}

function matchesType(value: unknown, type: NonNullable<JsonSchema['type']>): boolean {
  const actual = typeOf(value);
  if (type === 'number') return actual === 'number' || actual === 'integer';
  return actual === type;
}

// empty when valid
export function validateJson(value: unknown, schema: JsonSchema, at = '$'): string[] {
  const errors: string[] = [];
  if (schema.anyOf || schema.oneOf) {
    const options = schema.anyOf ?? schema.oneOf ?? [];
    if (!options.some((option) => validateJson(value, option, at).length === 0)) {
      errors.push(`${at}: does not match any allowed shape`);
    }
    return errors;
  }
  if (schema.const !== undefined && JSON.stringify(value) !== JSON.stringify(schema.const)) {
    errors.push(`${at}: must be ${JSON.stringify(schema.const)}`);
  }
  if (schema.type && !matchesType(value, schema.type)) {
    errors.push(`${at}: expected ${schema.type}, got ${typeOf(value)}`);
    return errors;
  }
  if (schema.enum && !schema.enum.some((option) => option === value)) {
    errors.push(`${at}: must be one of ${schema.enum.map((e) => JSON.stringify(e)).join(', ')}`);
  }
  if (typeof value === 'string') {
    if (schema.minLength !== undefined && value.length < schema.minLength) errors.push(`${at}: shorter than ${schema.minLength}`);
    if (schema.maxLength !== undefined && value.length > schema.maxLength) errors.push(`${at}: longer than ${schema.maxLength}`);
    if (schema.pattern !== undefined) {
      try {
        if (!new RegExp(schema.pattern, 'u').test(value)) errors.push(`${at}: does not match ${schema.pattern}`);
      } catch {
        // bad schema pattern, ignore
      }
    }
  }
  if (typeof value === 'number') {
    if (schema.minimum !== undefined && value < schema.minimum) errors.push(`${at}: below minimum ${schema.minimum}`);
    if (schema.maximum !== undefined && value > schema.maximum) errors.push(`${at}: above maximum ${schema.maximum}`);
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) errors.push(`${at}: needs at least ${schema.minItems} items`);
    if (schema.maxItems !== undefined && value.length > schema.maxItems) errors.push(`${at}: at most ${schema.maxItems} items`);
    if (schema.items) value.forEach((item, i) => errors.push(...validateJson(item, schema.items as JsonSchema, `${at}[${i}]`)));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    for (const key of schema.required ?? []) {
      if (!Object.hasOwn(obj, key) || obj[key] === undefined) errors.push(`${at}: missing required "${key}"`);
    }
    const props = schema.properties ?? {};
    for (const [key, v] of Object.entries(obj)) {
      const prop = Object.hasOwn(props, key) ? props[key] : undefined;
      if (prop) errors.push(...validateJson(v, prop, `${at}.${key}`));
      else if (schema.additionalProperties === false) errors.push(`${at}: unexpected property "${key}"`);
      else if (schema.additionalProperties && typeof schema.additionalProperties === 'object') {
        errors.push(...validateJson(v, schema.additionalProperties, `${at}.${key}`));
      }
    }
  }
  return errors;
}

export interface CoerceResult {
  value: Record<string, unknown>;
  // e.g. 'maxResults "40" -> 40'
  notes: string[];
}

function coerceScalar(value: unknown, schema: JsonSchema, key: string, notes: string[]): unknown {
  const type = schema.type;
  if (type === 'integer' || type === 'number') {
    let n = value;
    if (typeof value === 'string' && value.trim() !== '' && Number.isFinite(Number(value))) {
      n = Number(value);
      notes.push(`${key} "${value}" -> ${n}`);
    }
    if (typeof n === 'number' && Number.isFinite(n)) {
      if (type === 'integer' && !Number.isInteger(n)) n = Math.trunc(n);
      if (schema.minimum !== undefined && (n as number) < schema.minimum) {
        notes.push(`${key} ${n} raised to ${schema.minimum}`);
        n = schema.minimum;
      }
      if (schema.maximum !== undefined && (n as number) > schema.maximum) {
        notes.push(`${key} ${n} capped at ${schema.maximum}`);
        n = schema.maximum;
      }
    }
    return n;
  }
  if (type === 'string' && (typeof value === 'number' || typeof value === 'boolean')) {
    notes.push(`${key} ${String(value)} -> "${String(value)}"`);
    return String(value);
  }
  if (type === 'string' && Array.isArray(value) && value.every((v) => typeof v === 'string')) {
    notes.push(`${key} list joined`);
    return value.join(',');
  }
  if (type === 'boolean' && typeof value === 'string' && /^(true|false)$/i.test(value)) {
    return value.toLowerCase() === 'true';
  }
  return value;
}

// drop empty optionals, parse, clamp
export function coerceToSchema(args: Record<string, unknown>, schema: JsonSchema): CoerceResult {
  const notes: string[] = [];
  const out: Record<string, unknown> = {};
  const props = schema.properties ?? {};
  const required = new Set(schema.required ?? []);
  for (const [key, raw] of Object.entries(args)) {
    // skip proto
    if (key === '__proto__') continue;
    const prop = Object.hasOwn(props, key) ? props[key] : undefined;
    if (raw === null || raw === undefined || (raw === '' && !required.has(key))) {
      if (prop && !required.has(key)) continue;
    }
    out[key] = prop ? coerceScalar(raw, prop, key, notes) : raw;
  }
  return { value: out, notes };
}

// default, example, enum or minimal
export function synthesizeFromSchema(schema: JsonSchema): unknown {
  if (schema.const !== undefined) return schema.const;
  if (schema.default !== undefined) return schema.default;
  if (schema.examples && schema.examples.length > 0) return schema.examples[0];
  if (schema.enum && schema.enum.length > 0) return schema.enum[0];
  const option = schema.anyOf?.[0] ?? schema.oneOf?.[0];
  if (option) return synthesizeFromSchema(option);
  switch (schema.type) {
    case 'object': {
      const out: Record<string, unknown> = {};
      const props = schema.properties ?? {};
      const keys = schema.required ?? Object.keys(props);
      for (const key of keys) {
        const prop = props[key];
        out[key] = prop ? synthesizeFromSchema(prop) : null;
      }
      return out;
    }
    case 'array': {
      const count = schema.minItems ?? 0;
      return Array.from({ length: count }, () => (schema.items ? synthesizeFromSchema(schema.items) : null));
    }
    case 'string': {
      const base = 'mock';
      return schema.minLength && schema.minLength > base.length ? base.padEnd(schema.minLength, 'x') : base;
    }
    case 'integer': {
      if (schema.minimum !== undefined && schema.maximum !== undefined) return Math.ceil((schema.minimum + schema.maximum) / 2);
      return schema.minimum ?? 0;
    }
    case 'number': {
      if (schema.minimum !== undefined && schema.maximum !== undefined) return (schema.minimum + schema.maximum) / 2;
      return schema.minimum ?? 0;
    }
    case 'boolean':
      return false;
    case 'null':
      return null;
    default:
      return null;
  }
}

function typeLabel(schema: JsonSchema): string {
  if (schema.enum) return schema.enum.map((e) => JSON.stringify(e)).join('|');
  if (schema.type === 'array') return `${schema.items ? typeLabel(schema.items) : 'any'}[]`;
  return schema.type ?? 'any';
}

// get_usage(package: string, symbol?: string)
export function schemaSignature(name: string, schema: JsonSchema): string {
  const required = new Set(schema.required ?? []);
  const params = Object.entries(schema.properties ?? {}).map(
    ([key, prop]) => `${key}${required.has(key) ? '' : '?'}: ${typeLabel(prop)}`,
  );
  return `${name}(${params.join(', ')})`;
}
