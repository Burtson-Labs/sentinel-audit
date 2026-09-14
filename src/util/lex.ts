/**
 * Lexical pre-pass for JS/TS source.
 *
 * Rules run against a *masked* copy of the source in which comments and string
 * / template / regex literal bodies are replaced by spaces of the same length.
 * Offsets therefore stay valid against the original text, but a rule can no
 * longer match inside a comment or a string — which is where a large share of
 * grep-style static-analysis false positives come from ("we found `eval(` —
 * it was in a code sample in a docblock").
 *
 * This is not a parser. It is honest about that: `maskSource` gives a rule
 * "this token is real code", not "this token is an AST node of kind X".
 */

export interface MaskedSource {
  /** Same length as the input; comments/strings blanked to spaces. */
  code: string;
  /** Same length as the input; only string literal bodies kept, rest spaces. */
  strings: string;
  /**
   * Same length as the input; **comments only** blanked.
   *
   * This is the right search space for rules about *values* — URLs, env var
   * names, attribute literals — which live inside string literals but must not
   * match inside a comment. Matching raw source instead is how a scanner ends up
   * reporting a URL that appears in a sentence explaining why that URL is
   * wrong.
   */
  codeAndStrings: string;
  /**
   * Same length as the input; comments blanked, and every string literal whose
   * body reads as a *sentence* blanked with them.
   *
   * This is the search space for rules about values. A value — a URL, an
   * algorithm name, a storage key, a shell command — is a short literal. A
   * literal that is a sentence is prose that happens to live in a string: an
   * error message, a help text, a rule description. The constructs a scanner
   * hunts for appear in prose exactly when the prose is *about* them
   * (`createHash("md5") becomes createHash("sha256")`), which is how a
   * security tool ends up reporting its own rule definitions, and how a CLI's
   * help text becomes a finding. Template interpolations inside a prose
   * literal stay visible: they are code.
   */
  codeAndValues: string;
  /** 0-based offsets of lines, for fast line lookup. */
  lineStarts: number[];
}

type Mode = 'code' | 'line-comment' | 'block-comment' | 'single' | 'double' | 'template' | 'regex';

const SPACE = ' ';

export function maskSource(src: string): MaskedSource {
  const n = src.length;
  const code = new Array<string>(n);
  const strings = new Array<string>(n);
  // `both` starts as a copy of the source; the comment branches blank it.
  const both = new Array<string>(n);
  for (let i = 0; i < n; i += 1) both[i] = src[i]!;
  const lineStarts: number[] = [0];
  // [start, end) of every string/template literal body, for the prose pass.
  const literalSpans: Array<[number, number]> = [];
  let literalStart = -1;

  let mode: Mode = 'code';
  let templateDepth = 0;
  // stack for `${ }` inside templates
  const templateStack: number[] = [];

  for (let i = 0; i < n; i += 1) {
    const ch = src[i]!;
    const next = i + 1 < n ? src[i + 1]! : '';
    if (ch === '\n') lineStarts.push(i + 1);

    const keepNewline = ch === '\n';

    switch (mode) {
      case 'code': {
        if (ch === '/' && next === '/') {
          mode = 'line-comment';
          code[i] = SPACE;
          strings[i] = SPACE;
          both[i] = SPACE;
          continue;
        }
        if (ch === '/' && next === '*') {
          mode = 'block-comment';
          code[i] = SPACE;
          strings[i] = SPACE;
          both[i] = SPACE;
          continue;
        }
        if (ch === "'") {
          mode = 'single';
          literalStart = i + 1;
          code[i] = ch; // keep the quote so rules can see a literal was here
          strings[i] = SPACE;
          continue;
        }
        if (ch === '"') {
          mode = 'double';
          literalStart = i + 1;
          code[i] = ch;
          strings[i] = SPACE;
          continue;
        }
        if (ch === '`') {
          mode = 'template';
          literalStart = i + 1;
          templateDepth = 0;
          code[i] = ch;
          strings[i] = SPACE;
          continue;
        }
        if (ch === '/' && isRegexStart(src, i)) {
          mode = 'regex';
          code[i] = ch;
          strings[i] = SPACE;
          both[i] = SPACE;
          continue;
        }
        code[i] = ch;
        strings[i] = SPACE;
        continue;
      }
      case 'line-comment': {
        code[i] = keepNewline ? '\n' : SPACE;
        strings[i] = keepNewline ? '\n' : SPACE;
        both[i] = keepNewline ? '\n' : SPACE;
        if (keepNewline) mode = 'code';
        continue;
      }
      case 'block-comment': {
        code[i] = keepNewline ? '\n' : SPACE;
        strings[i] = keepNewline ? '\n' : SPACE;
        both[i] = keepNewline ? '\n' : SPACE;
        if (ch === '*' && next === '/') {
          code[i + 1] = SPACE;
          strings[i + 1] = SPACE;
          both[i + 1] = SPACE;
          i += 1;
          mode = 'code';
        }
        continue;
      }
      case 'single':
      case 'double': {
        const quote = mode === 'single' ? "'" : '"';
        if (ch === '\\') {
          code[i] = SPACE;
          strings[i] = SPACE;
          if (i + 1 < n) {
            code[i + 1] = src[i + 1] === '\n' ? '\n' : SPACE;
            strings[i + 1] = src[i + 1] === '\n' ? '\n' : src[i + 1]!;
            i += 1;
          }
          continue;
        }
        if (ch === quote) {
          literalSpans.push([literalStart, i]);
          code[i] = ch;
          strings[i] = SPACE;
          mode = 'code';
          continue;
        }
        code[i] = keepNewline ? '\n' : SPACE;
        strings[i] = keepNewline ? '\n' : ch;
        continue;
      }
      case 'template': {
        if (ch === '\\') {
          code[i] = SPACE;
          strings[i] = SPACE;
          if (i + 1 < n) {
            code[i + 1] = src[i + 1] === '\n' ? '\n' : SPACE;
            strings[i + 1] = src[i + 1] === '\n' ? '\n' : src[i + 1]!;
            i += 1;
          }
          continue;
        }
        if (ch === '$' && next === '{') {
          // interpolation is real code
          templateStack.push(templateDepth);
          code[i] = SPACE;
          code[i + 1] = SPACE;
          strings[i] = SPACE;
          strings[i + 1] = SPACE;
          i += 1;
          const end = findInterpolationEnd(src, i + 1);
          for (let j = i + 1; j < end && j < n; j += 1) {
            code[j] = src[j]!;
            strings[j] = src[j] === '\n' ? '\n' : SPACE;
            if (src[j] === '\n') lineStarts.push(j + 1);
          }
          if (end < n) {
            code[end] = SPACE;
            strings[end] = SPACE;
          }
          i = end;
          continue;
        }
        if (ch === '`') {
          literalSpans.push([literalStart, i]);
          code[i] = ch;
          strings[i] = SPACE;
          mode = 'code';
          continue;
        }
        code[i] = keepNewline ? '\n' : SPACE;
        strings[i] = keepNewline ? '\n' : ch;
        continue;
      }
      case 'regex': {
        // A regex literal's body is a *pattern*, not a value. Rules that look
        // for values (URLs, env names, algorithm names) must not see it — a
        // static-analysis tool's own rule definitions are full of the very
        // constructs it hunts for, and without this the tool reports itself.
        if (ch === '\\') {
          code[i] = SPACE;
          strings[i] = SPACE;
          both[i] = SPACE;
          if (i + 1 < n) {
            code[i + 1] = SPACE;
            strings[i + 1] = SPACE;
            both[i + 1] = SPACE;
            i += 1;
          }
          continue;
        }
        if (ch === '/' || keepNewline) {
          code[i] = keepNewline ? '\n' : ch;
          strings[i] = keepNewline ? '\n' : SPACE;
          both[i] = keepNewline ? '\n' : ch;
          mode = 'code';
          continue;
        }
        code[i] = SPACE;
        strings[i] = ch;
        both[i] = SPACE;
        continue;
      }
    }
  }

  if (literalStart >= 0 && (mode === 'single' || mode === 'double' || mode === 'template')) {
    literalSpans.push([literalStart, n]); // unterminated literal runs to EOF
  }

  // Prose pass: blank the body of every literal that reads as a sentence.
  // Only positions the `strings` view owns are touched, so template
  // interpolations (real code) survive inside a prose template.
  const values = both.slice();
  for (const [start, end] of literalSpans) {
    if (end - start < PROSE_MIN_CHARS) continue;
    let body = '';
    for (let k = start; k < end; k += 1) body += strings[k] === '\n' ? ' ' : strings[k]!;
    if (!looksLikeProse(body)) continue;
    for (let k = start; k < end; k += 1) {
      if (strings[k] !== SPACE && strings[k] !== '\n') values[k] = SPACE;
    }
  }

  // de-duplicate / sort lineStarts (template interpolation can push twice)
  const uniqueStarts = Array.from(new Set(lineStarts)).sort((a, b) => a - b);
  return {
    code: code.join(''),
    strings: strings.join(''),
    codeAndStrings: both.join(''),
    codeAndValues: values.join(''),
    lineStarts: uniqueStarts,
  };
}

const PROSE_MIN_CHARS = 40;
const PROSE_MIN_TOKENS = 5;
/**
 * A token that means "this string may be executed, queried or dereferenced,
 * not read": a flag, a URL, a path, a variable, a shell operator, or a bare
 * symbol the way SQL and expressions carry them (`= ? AND`).
 */
const OPERATIONAL_TOKEN = /^--?[A-Za-z]|:\/\/|^[.~]?\/[\w.-]|^\$|^[&|;]{1,2}$|^[=?*+<>{}()[\]]+$/;
/** A plain word, with the punctuation a sentence hangs on it. */
const WORD_TOKEN = /^[A-Za-z][A-Za-z'\u2019-]*[,.;:!?)]*$/;

/**
 * Does this literal body read as a sentence rather than a value?
 *
 * Deliberately conservative in the direction of reporting: the body must be
 * long enough and word-dense enough to be prose, and a single token that looks
 * like a flag, path, URL, variable or shell operator vetoes the verdict, because
 * a string that can be executed is a value however chatty it is.
 */
export function looksLikeProse(body: string): boolean {
  const trimmed = body.trim();
  if (trimmed.length < PROSE_MIN_CHARS) return false;
  const tokens = trimmed.split(/\s+/);
  if (tokens.length < PROSE_MIN_TOKENS) return false;
  if (tokens.some((t) => OPERATIONAL_TOKEN.test(t))) return false;
  const words = tokens.filter((t) => WORD_TOKEN.test(t)).length;
  return words / tokens.length >= 0.6;
}

function findInterpolationEnd(src: string, from: number): number {
  let depth = 1;
  for (let i = from; i < src.length; i += 1) {
    const ch = src[i];
    if (ch === '{') depth += 1;
    else if (ch === '}') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return src.length;
}

/** Heuristic: is the `/` at `i` the start of a regex literal rather than division? */
function isRegexStart(src: string, i: number): boolean {
  for (let j = i - 1; j >= 0; j -= 1) {
    const ch = src[j]!;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r') continue;
    if ('([{,;:=!&|?+*~^%<>'.includes(ch)) return true;
    if (/[A-Za-z0-9_$)\]]/.test(ch)) {
      // could be `return /re/` or `typeof /re/`
      const before = src.slice(Math.max(0, j - 10), j + 1);
      return /\b(return|typeof|case|in|of|delete|void|new|do|else|yield|await)$/.test(before);
    }
    return false;
  }
  return true;
}

export function lineNumberFor(masked: MaskedSource, offset: number): number {
  const { lineStarts } = masked;
  let lo = 0;
  let hi = lineStarts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (lineStarts[mid]! <= offset) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/**
 * All matches of `re` against the masked code, with line numbers and the
 * *original* source text for the matched line.
 */
export function matchCode(
  src: string,
  masked: MaskedSource,
  re: RegExp,
): Array<{ index: number; line: number; match: RegExpExecArray; lineText: string }> {
  const out: Array<{ index: number; line: number; match: RegExpExecArray; lineText: string }> = [];
  const flags = re.flags.includes('g') ? re.flags : `${re.flags}g`;
  const rx = new RegExp(re.source, flags);
  let m: RegExpExecArray | null;
  while ((m = rx.exec(masked.code)) !== null) {
    const line = lineNumberFor(masked, m.index);
    out.push({ index: m.index, line, match: m, lineText: sourceLine(src, line) });
    if (m.index === rx.lastIndex) rx.lastIndex += 1;
  }
  return out;
}

export function sourceLine(src: string, line: number): string {
  let start = 0;
  let current = 1;
  while (current < line && start < src.length) {
    const nl = src.indexOf('\n', start);
    if (nl === -1) break;
    start = nl + 1;
    current += 1;
  }
  const end = src.indexOf('\n', start);
  return src.slice(start, end === -1 ? src.length : end);
}

/**
 * Returns the masked code window that follows `offset` up to `chars`, useful
 * for "is there an auth check near this route registration" style questions.
 */
export function windowAfter(masked: MaskedSource, offset: number, chars = 400): string {
  return masked.code.slice(offset, offset + chars);
}
