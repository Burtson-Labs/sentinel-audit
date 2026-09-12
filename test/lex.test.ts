import { describe, it, expect } from 'vitest';
import { maskSource, matchCode, lineNumberFor, sourceLine } from '../src/util/lex.js';

describe('maskSource', () => {
  it('preserves offsets so line numbers stay correct', () => {
    const src = 'const a = 1;\n// comment\nconst b = "str";\n';
    const m = maskSource(src);
    expect(m.code).toHaveLength(src.length);
    expect(m.strings).toHaveLength(src.length);
    expect(m.codeAndStrings).toHaveLength(src.length);
  });

  it('blanks line comments in the code view', () => {
    const src = 'const x = 1; // eval(danger)\n';
    const m = maskSource(src);
    expect(m.code).not.toContain('eval');
  });

  it('blanks block comments across lines', () => {
    const src = 'a;\n/* eval(1)\n   innerHTML = x */\nb;\n';
    const m = maskSource(src);
    expect(m.code).not.toContain('eval');
    expect(m.code).not.toContain('innerHTML');
    expect(m.code).toContain('a;');
    expect(m.code).toContain('b;');
  });

  it('blanks string literal bodies but keeps the quotes in place', () => {
    const src = `const s = 'eval(1)';\n`;
    const m = maskSource(src);
    expect(m.code).not.toContain('eval');
    // quotes stay at their original offsets so a rule can tell a literal was here
    expect(m.code[10]).toBe("'");
    expect(m.code[18]).toBe("'");
    expect(m.strings).toContain('eval(1)');
  });

  it('keeps template interpolations as real code', () => {
    const src = 'const s = `prefix ${eval(payload)} suffix`;\n';
    const m = maskSource(src);
    expect(m.code).toContain('eval(payload)');
    expect(m.code).not.toContain('prefix');
  });

  it('handles escaped quotes inside strings', () => {
    const src = `const s = 'it\\'s eval(1) here'; const real = 2;\n`;
    const m = maskSource(src);
    expect(m.code).not.toContain('eval');
    expect(m.code).toContain('const real = 2;');
  });

  it('does not treat division as a regex literal', () => {
    const src = 'const ratio = a / b; const other = c / d; eval(1);\n';
    const m = maskSource(src);
    expect(m.code).toContain('eval(1)');
  });

  it('blanks regex literal bodies', () => {
    const src = 'const re = /innerHTML=/g; const after = 1;\n';
    const m = maskSource(src);
    expect(m.code).not.toContain('innerHTML=');
    expect(m.code).toContain('const after = 1;');
  });

  describe('codeAndStrings', () => {
    it('keeps string contents', () => {
      const src = `const url = 'http://example.org/x';\n`;
      const m = maskSource(src);
      expect(m.codeAndStrings).toContain('http://example.org/x');
    });

    it('removes comment contents — the false-positive class it exists for', () => {
      const src = '// note: http://bad.example used to be here\nconst ok = 1;\n';
      const m = maskSource(src);
      expect(m.codeAndStrings).not.toContain('http://bad.example');
      expect(m.codeAndStrings).toContain('const ok = 1;');
    });

    it('removes block-comment contents', () => {
      const src = '/* see http://docs.example.org/guide */\nconst ok = 1;\n';
      const m = maskSource(src);
      expect(m.codeAndStrings).not.toContain('docs.example.org');
    });
  });
});

describe('matchCode', () => {
  it('reports 1-based line numbers and the original line text', () => {
    const src = 'line1;\nline2;\nconst target = eval(x);\n';
    const m = maskSource(src);
    const hits = matchCode(src, m, /eval\s*\(/g);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.line).toBe(3);
    expect(hits[0]!.lineText).toBe('const target = eval(x);');
  });

  it('finds every occurrence, not just the first', () => {
    const src = 'eval(1); eval(2);\neval(3);\n';
    const hits = matchCode(src, maskSource(src), /eval\s*\(/g);
    expect(hits).toHaveLength(3);
  });

  it('works with a non-global regex', () => {
    const src = 'eval(1); eval(2);\n';
    const hits = matchCode(src, maskSource(src), /eval\s*\(/);
    expect(hits).toHaveLength(2);
  });
});

describe('lineNumberFor / sourceLine', () => {
  it('maps offsets to lines', () => {
    const src = 'aaa\nbbb\nccc\n';
    const m = maskSource(src);
    expect(lineNumberFor(m, 0)).toBe(1);
    expect(lineNumberFor(m, 4)).toBe(2);
    expect(lineNumberFor(m, 9)).toBe(3);
  });

  it('reads a line back by number', () => {
    const src = 'aaa\nbbb\nccc';
    expect(sourceLine(src, 2)).toBe('bbb');
    expect(sourceLine(src, 3)).toBe('ccc');
  });
});

describe('regex literals are patterns, not values', () => {
  it('blanks a regex body in every view rules consult', () => {
    const src = 'const RE = /rejectUnauthorized\\s*:\\s*false/;\nconst after = 1;\n';
    const m = maskSource(src);
    // A static-analysis tool's own rule definitions contain the constructs it
    // hunts for. Without this, the tool reports itself.
    expect(m.code).not.toContain('rejectUnauthorized');
    expect(m.codeAndStrings).not.toContain('rejectUnauthorized');
    expect(m.codeAndStrings).toContain('const after = 1;');
  });

  it('still sees a value in a real string literal', () => {
    const src = `const cfg = { rejectUnauthorized: false };\n`;
    const m = maskSource(src);
    expect(m.codeAndStrings).toContain('rejectUnauthorized: false');
  });
});
