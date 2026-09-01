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

// Parse the objects of a generated PDF into {num → body} for graph checks.
function objectsOf(s) {
  const objs = new Map();
  for (const m of s.matchAll(/^(\d+) 0 obj\n([\s\S]*?)\nendobj$/gm)) {
    objs.set(parseInt(m[1], 10), m[2]);
  }
  return objs;
}

test('makePdf: reference graph resolves — Kids are Pages, /Contents is a stream, /Annots is a Link', () => {
  const bytes = makePdf(modelOf([
    { text: 'first page', style: 'body' },
    ...Array.from({ length: 120 }, (_, i) => ({ text: 'filler ' + i, style: 'body' })),
  ]));
  const s = Buffer.from(bytes).toString('latin1');
  const objs = objectsOf(s);
  const ref = (body, key) => {
    const m = body.match({ Pages: /\/Pages (\d+) 0 R/, Parent: /\/Parent (\d+) 0 R/, Contents: /\/Contents (\d+) 0 R/, P: /\/P (\d+) 0 R/ }[key]);
    return m ? parseInt(m[1], 10) : null;
  };

  const catalog = [...objs.values()].find((b) => b.includes('/Type /Catalog'));
  const pagesRoot = ref(catalog, 'Pages');
  const pagesTree = objs.get(pagesRoot);
  const kids = [...pagesTree.matchAll(/(\d+) 0 R/g)].map((m) => parseInt(m[1], 10));
  const count = parseInt(pagesTree.match(/\/Count (\d+)/)[1], 10);
  assert.ok(kids.length >= 2, 'multi-page document');
  assert.strictEqual(kids.length, count, 'Kids length matches /Count');

  for (const kid of kids) {
    const page = objs.get(kid);
    assert.ok(page && page.startsWith('<<'), `kid ${kid} exists`);
    // '/Type /Page ' with the trailing space — must not match '/Type /Pages'.
    assert.ok(page.includes('/Type /Page '), `page ${kid} is a Page object, not a content stream or annot`);
    assert.strictEqual(ref(page, 'Parent'), pagesRoot, `page ${kid} parent is the pages tree`);

    const content = ref(page, 'Contents');
    const contentBody = objs.get(content);
    assert.ok(contentBody, `page ${kid} /Contents ${content} resolves`);
    assert.ok(contentBody.startsWith(`<< /Length`), `page ${kid} /Contents ${content} is a stream object`);
    assert.ok(contentBody.includes('\nstream\n'), `page ${kid} /Contents ${content} carries a stream`);

    const annotNums = [...page.matchAll(/\/Annots \[([^\]]*)\]/g)].flatMap((m) =>
      [...m[1].matchAll(/(\d+) 0 R/g)].map((r) => parseInt(r[1], 10)));
    for (const a of annotNums) {
      const annot = objs.get(a);
      assert.ok(annot && annot.includes('/Type /Annot') && annot.includes('/Subtype /Link'),
        `page ${kid} /Annots ${a} is a Link annotation`);
      assert.strictEqual(ref(annot, 'P'), kid, `annot ${a} /P points back at its page ${kid}`);
    }
  }

  // No object may be its own /Contents or /Annots target (the off-by-one signature).
  for (const [num, body] of objs) {
    assert.notStrictEqual(ref(body, 'Contents'), num, `obj ${num} /Contents must not self-reference`);
    assert.notStrictEqual(ref(body, 'Annots'), num, `obj ${num} /Annots must not self-reference`);
  }
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

test('makePdf: every page footer carries a clickable link back to the site', () => {
  const bytes = makePdf(modelOf([{ text: 'line', style: 'body' }]));
  const s = Buffer.from(bytes).toString('latin1');
  const pages = (s.match(/\/Type \/Page[^s]/g) || []).length;
  const links = (s.match(/\/Subtype \/Link/g) || []).length;
  assert.strictEqual(links, pages, 'one link annotation per page');
  assert.ok(s.includes('/URI (https://anantshri.github.io/HiveWalker/)'));
  // Each link's /Rect sits over the footer URL line (y between FOOTER_Y-12 and FOOTER_Y-7).
  assert.match(s, /\/Subtype \/Link \/Rect \[40 12 [\d.]+ 17\]/);
  // The visible URL text is drawn in the footer of every page.
  assert.strictEqual((s.match(/https:\/\/anantshri\.github\.io\/HiveWalker\//g) || []).length, pages * 2);
});

test('makePdf: cover page shows hive info; report starts on page 2', () => {
  const coverRows = [['Embedded file name', 'SYSTEM'], ['Format version', '1.5'], ['Checksum valid', 'yes']];
  const bytes = makePdf(
    modelOf([{ text: 'REPORT BODY LINE', style: 'body' }]),
    { coverRows, coverTitle: 'HiveWalker Forensic Report', generatedText: '2026-09-01 10:00:00 UTC' },
  );
  const s = Buffer.from(bytes).toString('latin1');
  const pages = (s.match(/\/Type \/Page[^s]/g) || []).length;
  assert.strictEqual(pages, 2, 'cover + one content page');
  // First content stream is the cover: title + generated + info rows, no body.
  const first = s.slice(s.indexOf('stream') + 7, s.indexOf('endstream'));
  assert.ok(first.includes('HiveWalker Forensic Report'));
  assert.ok(first.includes('2026-09-01 10:00:00 UTC'));
  assert.ok(first.includes('Embedded file name') && first.includes('SYSTEM'));
  assert.ok(first.includes('Checksum valid'));
  assert.ok(!first.includes('REPORT BODY LINE'), 'report body not on the cover');
  // Second content stream has the report body.
  const second = s.slice(s.indexOf('stream', s.indexOf('endstream')) + 7);
  assert.ok(second.includes('REPORT BODY LINE'));
});

test('makePdf: cover overflow keeps the cover to a single page', () => {
  const manyRows = Array.from({ length: 80 }, (_, i) => ['Row ' + i, 'value ' + i]);
  const bytes = makePdf(modelOf([{ text: 'body', style: 'body' }]), { coverRows: manyRows });
  const s = Buffer.from(bytes).toString('latin1');
  const pages = (s.match(/\/Type \/Page[^s]/g) || []).length;
  assert.strictEqual(pages, 2, 'long cover rows are truncated, not paginated');
  assert.ok(s.includes('body'), 'report body still present');
});
