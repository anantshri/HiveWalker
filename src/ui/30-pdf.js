// rv.ui.pdf — a minimal, dependency-free PDF writer for report export.
// Supports what text reports need: Base-14 fonts (no embedding), text showing
// with per-line style, automatic pagination, and a running footer. Output is a
// complete PDF 1.4 byte stream (catalog, pages, page objects, content
// streams, xref table with exact byte offsets, trailer).
//
// Character set: WinAnsi (Latin-1-ish). Codepoints outside it are replaced
// with '?' and reported back so the UI can note the substitution.
(function (RV) {
  'use strict';

  // A4 portrait in points.
  const PAGE_W = 595.28;
  const PAGE_H = 841.89;
  const MARGIN = 40;
  const BODY_SIZE = 9;
  const BODY_LINE = 12;     // leading for body text
  const TOP_SIZE = 13;
  const TOP_LINE = 18;
  const FOOTER_SIZE = 7.5;
  const FOOTER_Y = 24;

  // Base-14: monospace body (keeps table columns aligned), sans for headers.
  const FONTS = {
    body: { ref: 'F1', base: 'Courier', size: BODY_SIZE, line: BODY_LINE },
    note: { ref: 'F1', base: 'Courier', size: BODY_SIZE, line: BODY_LINE },
    section: { ref: 'F2', base: 'Helvetica', size: 10.5, line: 15 },
    meta: { ref: 'F2', base: 'Helvetica', size: BODY_SIZE + 1, line: BODY_LINE },
    title: { ref: 'F3', base: 'Helvetica-Bold', size: TOP_SIZE, line: TOP_LINE },
  };

  // Unicode → ASCII normalisations for the common typographic characters
  // (everything else outside Latin-1 becomes '?').
  const ASCII_MAP = {
    '‘': "'", '’': "'", '“': '"', '”': '"',
    '–': '-', '—': '--', '…': '...', ' ': ' ',
    '→': '->', '·': '*', '•': '*',
  };

  /**
   * Sanitise one string for WinAnsi output. Returns {text, replaced} where
   * replaced counts codepoints that could not be represented.
   */
  function sanitise(str) {
    let out = '';
    let replaced = 0;
    for (const ch of String(str)) {
      const mapped = ASCII_MAP[ch];
      if (mapped !== undefined) { out += mapped; continue; }
      const cp = ch.codePointAt(0);
      if (cp >= 32 && cp <= 255) out += ch;
      else if (ch === '\t') out += '    ';
      else if (ch === '\u0000') out += '?', replaced++;
      else { out += '?'; replaced++; }
    }
    return { text: out, replaced };
  }

  /** Escape PDF string syntax (backslash, parens). */
  function escapePdf(str) {
    return str.replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');
  }

  // Courier metrics: fixed 600/1000 em → char width = 0.6 * size.
  const charW = (size) => 0.6 * size;

  /** Hard-wrap a sanitised line to the printable width (Courier only). */
  function wrapCourier(text, size) {
    const maxChars = Math.floor((PAGE_W - 2 * MARGIN) / charW(size));
    if (maxChars < 8) return [text];
    const out = [];
    let cur = '';
    for (const ch of text) {
      if (ch === '\n' || cur.length >= maxChars) { out.push(cur); cur = ch === '\n' ? '' : ch; }
      else cur += ch;
    }
    out.push(cur);
    return out;
  }

  /**
   * Build the PDF byte string for a styled-line model
   * ({lines:[{text, style}], ...} — see viewModel.reportPdfModel).
   * @returns {Uint8Array}
   */
  function makePdf(model, opts) {
    const o = opts || {};
    const footerBase = o.footerBase || 'HiveWalker report';
    const lines = (model && model.lines) || [];

    // --- lay out pages -------------------------------------------------------
    const usableTop = PAGE_H - MARGIN;
    const pages = [];
    let page = [];
    let y = usableTop;
    let replacedTotal = model.replacedChars || 0;

    const newPage = () => { pages.push(page); page = []; y = usableTop; };
    const place = (text, style) => {
      const f = FONTS[style] || FONTS.body;
      const wrapped = f.ref === 'F1' ? wrapCourier(text, f.size) : [text];
      for (const w of wrapped) {
        if (y < MARGIN + FOOTER_Y + f.line) newPage();
        page.push({ text: w, font: f.ref, size: f.size, y });
        y -= f.line;
      }
    };

    for (const l of lines) {
      if (l.style === 'title' && page.length > 0) y -= 6; // extra gap before a new result title
      place(l.text, l.style);
    }
    if (page.length > 0 || pages.length === 0) pages.push(page);

    // --- content streams -----------------------------------------------------
    const total = pages.length;
    const contents = pages.map((plines, i) => {
      const footer = `${footerBase} - page ${i + 1} of ${total}` +
        (replacedTotal > 0 ? ` - ${replacedTotal} unprintable character(s) shown as ?` : '');
      let s = 'BT\n';
      for (const L of plines) {
        s += `/${L.font} ${L.size} Tf 1 0 0 1 ${MARGIN} ${L.y.toFixed(2)} Tm (${escapePdf(L.text)}) Tj\n`;
      }
      s += `/F2 ${FOOTER_SIZE} Tf 1 0 0 1 ${MARGIN} ${FOOTER_Y} Tm (${escapePdf(footer)}) Tj\n`;
      s += 'ET';
      return s;
    });

    // --- assemble objects ----------------------------------------------------
    // Object numbering: 1 catalog, 2 pages, 3.. fonts, then page + content pairs.
    const objects = [];
    const pageObjNums = [];
    const nPages = pages.length;
    const FONT_objs = [
      '<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>',
      '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
      '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>',
    ];
    const firstPageObj = 3 + FONT_objs.length;
    for (let i = 0; i < nPages; i++) pageObjNums.push(firstPageObj + i * 2);

    objects.push(`<< /Type /Catalog /Pages 2 0 R >>`);
    objects.push(`<< /Type /Pages /Kids [${pageObjNums.map((n) => `${n} 0 R`).join(' ')}] /Count ${nPages} >>`);
    objects.push(...FONT_objs);
    pages.forEach((_, i) => {
      const contentNum = firstPageObj + i * 2 + 1;
      objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
        `/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents ${contentNum} 0 R >>`);
      objects.push(`<< /Length ${contents[i].length} >>\nstream\n${contents[i]}\nendstream`);
    });

    // --- serialise with xref -------------------------------------------------
    let pdf = '%PDF-1.4\n%\xE2\xE3\xCF\xD3\n';
    const offsets = [];
    objects.forEach((body, i) => {
      offsets.push(pdf.length);
      pdf += `${i + 1} 0 obj\n${body}\nendobj\n`;
    });
    const xrefStart = pdf.length;
    const n = objects.length + 1;
    pdf += `xref\n0 ${n}\n0000000000 65535 f \n`;
    for (const off of offsets) pdf += `${String(off).padStart(10, '0')} 00000 n \n`;
    pdf += `trailer\n<< /Size ${n} /Root 1 0 R >>\nstartxref\n${xrefStart}\n%%EOF\n`;

    // Latin-1 byte string → Uint8Array.
    const bytes = new Uint8Array(pdf.length);
    for (let i = 0; i < pdf.length; i++) bytes[i] = pdf.charCodeAt(i) & 0xff;
    return bytes;
  }

  /** Timestamped filename fragment: hivewalker-report-<slug>-<yyyymmdd-hhmm>. */
  function fileNameFor(slug, date) {
    const d = date || new Date();
    const p = (x, w) => String(x).padStart(w || 2, '0');
    const stamp = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}-${p(d.getUTCHours())}${p(d.getUTCMinutes())}`;
    const safe = String(slug).toLowerCase().replace(/[^a-z0-9._-]+/g, '-').replace(/^-+|-+$/g, '') || 'report';
    return `hivewalker-report-${safe}-${stamp}.pdf`;
  }

  /**
   * Render the displayed result(s) to a PDF and trigger a download.
   * Pure local: Blob + object URL, revoked immediately after the click.
   */
  function downloadReportPdf(results, slug) {
    const hive = RV.ui.app.state.hive;
    const footerBase = `HiveWalker - ${hive && hive.meta && hive.meta.fileName ? hive.meta.fileName : 'registry hive'} - generated ${RV.plugins.helpers.formatDate(new Date())}`;
    const model = RV.ui.viewModel.reportPdfModel(results);
    const bytes = makePdf(model, { footerBase });
    const blob = new Blob([bytes], { type: 'application/pdf' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileNameFor(slug, new Date());
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    return { bytes, name: a.download, replaced: model.replacedChars };
  }

  RV.ui.pdf = { makePdf, sanitise, fileNameFor, downloadReportPdf };
})(window.RV);
