/**
 * Minimal YAML reader for the subset GitHub Actions workflows actually use.
 *
 * Why not a dependency: Sentinel audits supply chains, so it ships with zero
 * runtime dependencies — the tool should not be the largest attack surface in
 * the room. This parser handles block mappings, block sequences, inline
 * scalars, inline flow sequences (`[a, b]`), quoted scalars, comments, and
 * block scalars (`|`, `>`), which covers workflow files.
 *
 * It is deliberately *not* a general YAML implementation: anchors, aliases,
 * multi-document streams, complex keys and flow mappings are unsupported. When
 * it cannot parse a file it says so (`parseError`) instead of guessing, and the
 * coverage report names the file. Never use it for security-relevant parsing of
 * attacker-controlled YAML.
 */

export type YamlValue = string | number | boolean | null | YamlValue[] | { [k: string]: YamlValue };

interface Line {
  indent: number;
  content: string;
  /** 1-based line number in the source. */
  number: number;
}

export class YamlParseError extends Error {}

function tokenize(src: string): Line[] {
  const out: Line[] = [];
  const rawLines = src.split(/\r?\n/);
  for (let i = 0; i < rawLines.length; i += 1) {
    const raw = rawLines[i] ?? '';
    if (raw.trim().length === 0) continue;
    const trimmedStart = raw.replace(/^\s*/, '');
    if (trimmedStart.startsWith('#')) continue;
    if (raw.includes('\t')) throw new YamlParseError(`tab indentation at line ${i + 1}`);
    out.push({ indent: raw.length - trimmedStart.length, content: stripComment(trimmedStart), number: i + 1 });
  }
  return out.filter((l) => l.content.trim().length > 0);
}

/** Remove a trailing `# comment`, respecting quotes. */
function stripComment(s: string): string {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < s.length; i += 1) {
    const ch = s[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble) {
      const prev = i > 0 ? s[i - 1] : ' ';
      if (prev === ' ' || i === 0) return s.slice(0, i).trimEnd();
    }
  }
  return s.trimEnd();
}

/** Mapping keys: strip quotes, never coerce to a boolean or number. */
function unquoteKey(raw: string): string {
  const s = raw.trim();
  if ((s.startsWith('"') && s.endsWith('"')) || (s.startsWith("'") && s.endsWith("'"))) {
    return s.slice(1, -1);
  }
  return s;
}

function parseScalar(raw: string): YamlValue {
  const s = raw.trim();
  if (s.length === 0) return null;
  if ((s.startsWith('"') && s.endsWith('"') && s.length > 1) || (s.startsWith("'") && s.endsWith("'") && s.length > 1)) {
    return s.slice(1, -1);
  }
  if (s.startsWith('[') && s.endsWith(']')) {
    const inner = s.slice(1, -1).trim();
    if (inner.length === 0) return [];
    return splitFlow(inner).map((part) => parseScalar(part));
  }
  if (s.startsWith('{') && s.endsWith('}')) {
    const inner = s.slice(1, -1).trim();
    const obj: Record<string, YamlValue> = {};
    if (inner.length === 0) return obj;
    for (const part of splitFlow(inner)) {
      const idx = part.indexOf(':');
      if (idx < 0) continue;
      obj[parseScalar(part.slice(0, idx)) as string] = parseScalar(part.slice(idx + 1));
    }
    return obj;
  }
  if (s === 'true' || s === 'True' || s === 'yes' || s === 'on') return true;
  if (s === 'false' || s === 'False' || s === 'no' || s === 'off') return false;
  if (s === 'null' || s === '~') return null;
  if (/^-?\d+$/.test(s)) return Number(s);
  if (/^-?\d*\.\d+$/.test(s)) return Number(s);
  return s;
}

function splitFlow(inner: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let cur = '';
  let inSingle = false;
  let inDouble = false;
  for (const ch of inner) {
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    if (!inSingle && !inDouble) {
      if (ch === '[' || ch === '{') depth += 1;
      else if (ch === ']' || ch === '}') depth -= 1;
      else if (ch === ',' && depth === 0) {
        parts.push(cur);
        cur = '';
        continue;
      }
    }
    cur += ch;
  }
  if (cur.trim().length > 0) parts.push(cur);
  return parts.map((p) => p.trim());
}

/** Index of the `:` that ends a mapping key, or -1. */
function keyColon(content: string): number {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < content.length; i += 1) {
    const ch = content[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === ':' && !inSingle && !inDouble) {
      const next = content[i + 1];
      if (next === undefined || next === ' ') return i;
    }
  }
  return -1;
}

export function parseYaml(src: string): YamlValue {
  const lines = tokenize(src);
  if (lines.length === 0) return null;
  const [value, consumed] = parseBlock(lines, 0, lines[0]!.indent);
  if (consumed < lines.length) {
    // trailing content at a shallower indent than the first line — malformed
    throw new YamlParseError(`unexpected content at line ${lines[consumed]!.number}`);
  }
  return value;
}

function parseBlock(lines: Line[], start: number, indent: number): [YamlValue, number] {
  const first = lines[start];
  if (!first) return [null, start];
  if (first.content.startsWith('- ') || first.content === '-') {
    return parseSequence(lines, start, indent);
  }
  return parseMapping(lines, start, indent);
}

function parseSequence(lines: Line[], start: number, indent: number): [YamlValue[], number] {
  const items: YamlValue[] = [];
  let i = start;
  while (i < lines.length) {
    const line = lines[i]!;
    if (line.indent < indent) break;
    if (line.indent > indent || !(line.content.startsWith('- ') || line.content === '-')) break;
    const rest = line.content === '-' ? '' : line.content.slice(2).trim();
    if (rest.length === 0) {
      const next = lines[i + 1];
      if (next && next.indent > indent) {
        const [val, consumed] = parseBlock(lines, i + 1, next.indent);
        items.push(val);
        i = consumed;
      } else {
        items.push(null);
        i += 1;
      }
      continue;
    }
    const colon = keyColon(rest);
    if (colon >= 0) {
      // inline mapping start inside a sequence item: `- name: x`
      const virtualIndent = indent + 2;
      const synthetic: Line[] = [{ indent: virtualIndent, content: rest, number: line.number }];
      let j = i + 1;
      while (j < lines.length && lines[j]!.indent >= virtualIndent) {
        synthetic.push(lines[j]!);
        j += 1;
      }
      const [val] = parseMapping(synthetic, 0, virtualIndent);
      items.push(val);
      i = j;
      continue;
    }
    items.push(parseScalar(rest));
    i += 1;
  }
  return [items, i];
}

function parseMapping(lines: Line[], start: number, indent: number): [Record<string, YamlValue>, number] {
  const obj: Record<string, YamlValue> = {};
  let i = start;
  while (i < lines.length) {
    const line = lines[i]!;
    if (line.indent < indent) break;
    if (line.indent > indent) throw new YamlParseError(`unexpected indent at line ${line.number}`);
    if (line.content.startsWith('- ')) break;
    const colon = keyColon(line.content);
    if (colon < 0) throw new YamlParseError(`expected 'key:' at line ${line.number}`);
    // Keys are read as plain strings. YAML 1.1 coerces bare `on`/`off`/`yes`
    // to booleans, which would turn a workflow's `on:` trigger block into a
    // property named `true` — a bug that silently empties the trigger list.
    const key = unquoteKey(line.content.slice(0, colon));
    const rest = line.content.slice(colon + 1).trim();
    if (rest === '|' || rest === '>' || rest === '|-' || rest === '>-' || rest === '|+' || rest === '>+') {
      const folded = rest.startsWith('>');
      const blockLines: string[] = [];
      let j = i + 1;
      while (j < lines.length && lines[j]!.indent > indent) {
        blockLines.push(lines[j]!.content);
        j += 1;
      }
      obj[key] = blockLines.join(folded ? ' ' : '\n');
      i = j;
      continue;
    }
    if (rest.length > 0) {
      obj[key] = parseScalar(rest);
      i += 1;
      continue;
    }
    const next = lines[i + 1];
    if (next && next.indent > indent) {
      const [val, consumed] = parseBlock(lines, i + 1, next.indent);
      obj[key] = val;
      i = consumed;
      continue;
    }
    if (next && next.indent === indent && (next.content.startsWith('- ') || next.content === '-')) {
      const [val, consumed] = parseSequence(lines, i + 1, indent);
      obj[key] = val;
      i = consumed;
      continue;
    }
    obj[key] = null;
    i += 1;
  }
  return [obj, i];
}

/** Convenience: `parseYaml` that returns null instead of throwing. */
export function tryParseYaml(src: string): { value: YamlValue; error?: string } {
  try {
    return { value: parseYaml(src) };
  } catch (err) {
    return { value: null, error: err instanceof Error ? err.message : String(err) };
  }
}
