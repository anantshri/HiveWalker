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
  const SITE_URL = 'https://anantshri.github.io/HiveWalker/';

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
   * A cover page (title + hive info) is rendered first when `opts.coverRows`
   * is provided ([[label, value], …] — from viewModel.hiveMeta).
   * Every page's footer links back to the HiveWalker site.
   * @returns {Uint8Array}
   */
  function makePdf(model, opts) {
    const o = opts || {};
    const footerBase = o.footerBase || 'HiveWalker report';
    const coverRows = Array.isArray(o.coverRows) && o.coverRows.length > 0 ? o.coverRows : null;
    const coverTitle = o.coverTitle || 'HiveWalker Forensic Report';
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

    // Cover page: centred title + generation stamp, then the hive-info table,
    // all on one page (report content starts on the next page).
    if (coverRows) {
      const centre = (text, style, atY) => {
        const f = FONTS[style] || FONTS.body;
        const w = text.length * (f.ref === 'F1' ? charW(f.size) : f.size * 0.5);
        const x = Math.max(MARGIN, (PAGE_W - w) / 2);
        page.push({ text, font: f.ref, size: f.size, y: atY, x });
      };
      centre(coverTitle, 'title', usableTop - 150);
      centre(`Generated ${o.generatedText || ''}`.trim(), 'meta', usableTop - 176);
      // Hive info rows as a label/value block below the title.
      let cy = usableTop - 220;
      for (const [k, v] of coverRows) {
        if (cy < MARGIN + 60) break; // keep the cover to one page
        page.push({ text: String(k), font: 'F2', size: 9.5, y: cy, x: MARGIN + 40 });
        page.push({ text: String(v), font: 'F1', size: 9, y: cy, x: MARGIN + 190 });
        cy -= 16;
      }
      newPage();
    }

    for (const l of lines) {
      if (l.style === 'title' && page.length > 0) y -= 6; // extra gap before a new result title
      place(l.text, l.style);
    }
    if (page.length > 0 || pages.length === 0) pages.push(page);

    // --- content streams -----------------------------------------------------
    // Footer on every page: running text + a highlighted, clickable link back
    // to the HiveWalker site (link annotation rect covers just the URL part).
    const total = pages.length;
    let linkObjNums = [];
    const contents = pages.map((plines, i) => {
      const running = `${footerBase} - page ${i + 1} of ${total}` +
        (replacedTotal > 0 ? ` - ${replacedTotal} unprintable character(s) shown as ?` : '');
      let s = 'BT\n';
      for (const L of plines) {
        const x = L.x == null ? MARGIN : L.x;
        s += `/${L.font} ${L.size} Tf 1 0 0 1 ${x.toFixed(2)} ${L.y.toFixed(2)} Tm (${escapePdf(L.text)}) Tj\n`;
      }
      s += `/F2 ${FOOTER_SIZE} Tf 1 0 0 1 ${MARGIN} ${FOOTER_Y} Tm (${escapePdf(running)}) Tj\n`;
      s += `0 0 0 rg /F2 ${FOOTER_SIZE} Tf 1 0 0 1 ${MARGIN} ${FOOTER_Y - 9} Tm ` +
        `(${escapePdf(SITE_URL)}) Tj\n`;
      s += 'ET\n0.13 0.39 0.72 RG 0.5 w\n' + // accent-blue, thin
        `${MARGIN} ${FOOTER_Y - 10.5} m ${MARGIN + SITE_URL.length * FOOTER_SIZE * 0.5} ${FOOTER_Y - 10.5} l S`;
      return s;
    });

    // --- assemble objects ----------------------------------------------------
    // Numbering: 1 catalog, 2 pages, 3-5 fonts, then per page: content, page.
    // (Page objects reference their content + link annotation, so content and
    // annotation objects must be numbered before the page that cites them.)
    const objects = [];
    const nPages = pages.length;
    const FONT_objs = [
      '<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>',
      '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>',
      '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>',
    ];
    const firstPageObj = 3 + FONT_objs.length;
    const pageObjNums = [];
    for (let i = 0; i < nPages; i++) pageObjNums.push(firstPageObj + i * 3);

    objects.push(`<< /Type /Catalog /Pages 2 0 R >>`);
    objects.push(`<< /Type /Pages /Kids [${pageObjNums.map((n) => `${n} 0 R`).join(' ')}] /Count ${nPages} >>`);
    objects.push(...FONT_objs);
    pages.forEach((_, i) => {
      const contentNum = firstPageObj + i * 3 + 1;
      const linkNum = firstPageObj + i * 3 + 2;
      const pageNum = firstPageObj + i * 3;
      objects.push(`<< /Length ${contents[i].length} >>\nstream\n${contents[i]}\nendstream`);
      // Clickable link annotation over the footer URL.
      objects.push(`<< /Type /Annot /Subtype /Link /Rect [${MARGIN} ${FOOTER_Y - 12} ` +
        `${MARGIN + SITE_URL.length * FOOTER_SIZE * 0.5} ${FOOTER_Y - 7}] /Border [0 0 0] ` +
        `/A << /S /URI /URI (${SITE_URL}) >> /P ${pageNum} 0 R >>`);
      objects.push(`<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
        `/Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> ` +
        `/Contents ${contentNum} 0 R /Annots [${linkNum} 0 R] >>`);
    });
    linkObjNums = pageObjNums; // (kept for potential future use/debugging)

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
   * Page 1 is a cover (hive info from viewModel.hiveMeta); report content
   * starts on page 2. Every page footer links back to the HiveWalker site.
   * Pure local: Blob + object URL, revoked after the click.
   */
  function downloadReportPdf(results, slug) {
    const hive = RV.ui.app.state.hive;
    const meta = hive ? RV.ui.viewModel.hiveMeta(hive) : null;
    const generatedText = RV.plugins.helpers.formatDate(new Date());
    const footerBase = `HiveWalker - ${meta && meta.title ? meta.title : 'registry hive'}`;
    const model = RV.ui.viewModel.reportPdfModel(results);
    const bytes = makePdf(model, {
      footerBase,
      coverRows: meta ? meta.rows : null,
      coverTitle: 'HiveWalker Forensic Report',
      generatedText,
    });
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
