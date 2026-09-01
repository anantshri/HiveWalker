'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const RV = loadSrc({ only: /30-pdf/ });
const { makePdf, sanitise, fileNameFor } = RV.ui.pdf;
const { reportPdfModel } = RV.ui.viewModel;

function modelOf(lines) { return { lines, replacedChars: 0 }; }

test('sanitise: typographic chars map to ASCII, exotic become ? (counted)', () => {
  const s = sanitise('smart ‘quote’ – dash … ellipsis CAFÉ café 日本');
  // Accented Latin (É é) is inside WinAnsi and passes through; CJK is not.
  assert.strictEqual(s.text, "smart 'quote' - dash ... ellipsis CAFÉ café ??");
  assert.strictEqual(s.replaced, 2); // the two CJK chars
});

test('sanitise: PDF string syntax is escaped', () => {
  // (indirect: escapePdf is internal; verify via a generated stream)
  const bytes = makePdf(modelOf([{ text: 'paren ( ) and \\\\ backslash', style: 'body' }]));
  const s = Buffer.from(bytes).toString('latin1');
  assert.ok(s.includes('paren \\( \\) and \\\\\\\\ backslash'), 'parens/backslash escaped in stream');
});

test('makePdf: header, EOF, catalog/pages, fonts, xref offsets all valid', () => {
  const bytes = makePdf(modelOf([{ text: 'hello report', style: 'body' }]));
  const s = Buffer.from(bytes).toString('latin1');
  assert.ok(s.startsWith('%PDF-1.4'), 'PDF header');
  assert.ok(s.trimEnd().endsWith('%%EOF'), 'EOF marker');
  assert.ok(/\/Type \/Catalog \/Pages 2 0 R/.test(s), 'catalog');
  assert.ok(/\/Count 1/.test(s), 'pages count');
  assert.ok(s.includes('/BaseFont /Courier') && s.includes('/BaseFont /Helvetica'), 'base-14 fonts');
  assert.ok(s.includes('/WinAnsiEncoding'), 'winansi encoding');
  // xref integrity: startxref → 'xref', every offset → 'N 0 obj'
  const xrefStart = parseInt(s.match(/startxref\n(\d+)/)[1], 10);
  assert.strictEqual(s.slice(xrefStart, xrefStart + 4), 'xref');
  const offs = [...s.matchAll(/^(\d{10}) 00000 n /gm)].map((m) => parseInt(m[1], 10));
  assert.ok(offs.length >= 6, 'object count');
  for (const o of offs) assert.match(s.slice(o, o + 12), /^\d+ 0 obj/, `offset ${o} → obj decl`);
});

test('makePdf: line styles map to the right fonts and appear in the stream', () => {
  const bytes = makePdf(modelOf([
    { text: 'A Title', style: 'title' },
    { text: 'some meta', style: 'meta' },
    { text: 'SECTION', style: 'section' },
    { text: 'plain body', style: 'body' },
    { text: 'a note', style: 'note' },
  ]));
  const s = Buffer.from(bytes).toString('latin1');
  assert.ok(/\/F3 13 Tf[^\n]*A Title/.test(s), 'title → Helvetica-Bold 13');
  assert.ok(/\/F1 9 Tf[^\n]*plain body/.test(s), 'body → Courier 9');
  assert.ok(s.includes('SECTION') && s.includes('a note'));
});

test('makePdf: long input paginates with correct page footers', () => {
  const lines = [];
  for (let i = 0; i < 200; i++) lines.push({ text: 'line ' + i, style: 'body' });
  const bytes = makePdf(modelOf(lines));
  const s = Buffer.from(bytes).toString('latin1');
  const pages = (s.match(/\/Type \/Page[^s]/g) || []).length;
  assert.ok(pages >= 3, `expected 3+ pages, got ${pages}`);
  assert.strictEqual((s.match(/page \d+ of /g) || []).length, pages, 'footer per page');
  assert.ok(s.includes(`page 1 of ${pages}`) && s.includes(`page ${pages} of ${pages}`));
  assert.ok(s.includes('line 199'), 'last line present');
});

test('makePdf: body lines wrap at the printable width instead of overflowing', () => {
  const long = 'X'.repeat(300);
  const bytes = makePdf(modelOf([{ text: long, style: 'body' }]));
  const s = Buffer.from(bytes).toString('latin1');
  // Courier 9pt at 515pt usable width → 95 chars per line max.
  const shown = [...s.matchAll(/\(((?:X|\\.)+)\) Tj/g)].map((m) => m[1]);
  assert.ok(shown.every((t) => t.length <= 95), 'no line exceeds printable width');
  assert.strictEqual(shown.join('').length, 300, 'no characters lost');
});

test('makePdf: replaced-characters note appears in the footer when needed', () => {
  const bytes = makePdf({ lines: [{ text: '日本', style: 'body' }], replacedChars: 2 });
  const s = Buffer.from(bytes).toString('latin1');
  assert.match(s, /2 unprintable character/);
});

test('makePdf: empty model still yields a valid single-page PDF', () => {
  const bytes = makePdf(modelOf([]));
  const s = Buffer.from(bytes).toString('latin1');
  assert.ok(s.startsWith('%PDF-1.4') && s.trimEnd().endsWith('%%EOF'));
  assert.ok(/\/Count 1/.test(s));
});

test('reportPdfModel: structured result flattens with styles in order', () => {
  const result = {
    plugin: 'demo', shortDescr: 'Demo', hiveTypes: ['system'], category: 'config',
    mitre: 'T1082', version: '20240101', ranAt: new Date(), error: null,
    sections: [{
      title: 'Sec', blocks: [
        { kind: 'text', lines: ['t1'] },
        { kind: 'kv', pairs: [['k', 'v']] },
        { kind: 'note', text: 'note!' },
        { kind: 'table', columns: ['a', 'b'], rows: [['1', '2']] },
      ],
    }],
  };
  const m = reportPdfModel([result, { ...result, plugin: 'two', error: { name: 'E', message: 'boom' }, sections: [] }]);
  const texts = m.lines.map((l) => l.text);
  assert.ok(texts.includes('demo v.20240101'));
  assert.ok(texts.includes('MITRE: T1082 (config)'));
  assert.ok(texts.includes('Sec'));
  assert.ok(texts.some((t) => t.includes('t1')));
  assert.ok(texts.some((t) => t.includes('k') && t.includes('v')));
  assert.ok(texts.includes('note!'));
  assert.ok(texts.some((t) => t.includes('a | b')));
  assert.ok(texts.some((t) => t.includes('ERROR: E: boom')), 'error result represented');
  // styles present
  const styles = new Set(m.lines.map((l) => l.style));
  for (const st of ['title', 'meta', 'section', 'body', 'note']) assert.ok(styles.has(st), st);
});

test('fileNameFor: slug-safe, timestamped', () => {
  const name = fileNameFor('All 5 Plugins!!', new Date(Date.UTC(2026, 8, 1, 10, 5)));
  assert.strictEqual(name, 'hivewalker-report-all-5-plugins-20260901-1005.pdf');
});
