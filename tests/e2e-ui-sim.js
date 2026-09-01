'use strict';
// E2E simulation of the new UI features (not a node:test file — run directly).
const { makeDom, findIn } = require('./helpers/dom-stub');
makeDom();

const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const RV = loadSrc();

(async () => {
  const buf = new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SYSTEM' }).build((r) => {
    r.key('Software').key('Microsoft').value('Ver', 1, '1.0');
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('MountedDevices');
    r.key('ControlSet001', {}, (cs) => cs.key('Control', {}, (c) => c.key('ComputerName', {}, (cn) =>
      cn.key('ComputerName', {}, (x) => x.value('ComputerName', 1, 'HOST-A')))));
  }).toBuffer();

  // 0) empty state: no resizer handle before any load
  const panes0 = document.getElementById('panes');
  RV.ui.resizer.init(panes0, 'tree-pane', 'values-pane');
  console.log('0. no handle in empty state:', !panes0.children.some((c) => c.id === 'pane-resizer'));

  await RV.ui.app.loadFile(buf);
  const app = RV.ui.app.state;
  console.log('loaded:', !!app.hive, '| selected:', app.selectedKey.path);

  // 1) click-to-open
  const treePane = document.getElementById('tree-pane');
  const swRow = treePane.querySelectorAll('.tree-row').find((r) => r.dataset.path.endsWith('Software'));
  swRow.dispatch('click');
  console.log('1. click-to-open expanded:', swRow.dataset.expanded === 'true');
  const msRow = treePane.querySelectorAll('.tree-row').find((r) => r.dataset.path.endsWith('Microsoft'));
  console.log('   child visible after click:', !!msRow);

  // 2) resizer appears only after load (app.showPanes initialises it)
  const panes = document.getElementById('panes');
  console.log('2. resizer present after load:', panes.children.some((c) => c.id === 'pane-resizer'));

  // 3) path bar
  RV.ui.app.navigateTo(app.hive.getSubkey('Software\\Microsoft'));
  const pane = document.getElementById('values-pane');
  const bar = pane.children[0];
  const crumbs = bar.querySelector('.path-crumbs');
  console.log('3. path bar:', bar.className === 'path-bar',
    '| crumbs:', crumbs.children.map((c) => c.textContent).join(''));

  // 4) keyboard nav
  RV.ui.tree.init();
  treePane.dispatch('keydown', { key: 'ArrowDown' });
  console.log('4. ArrowDown selected:', app.selectedKey.path);

  // 5) meta panel close (ensurePane attaches to document.body, not byId)
  RV.ui.hivemeta.toggle();
  const metaPane = findIn(document.body, 'meta-pane');
  console.log('5. meta open (hidden=false):', metaPane.hidden === false);
  const closeBtn = metaPane.children.find((c) => c.className === 'panel-close');
  closeBtn.dispatch('click');
  console.log('   closed via ✕ (hidden=true):', metaPane.hidden === true);

  // 6) Reports tab: switch, filter, run a plugin, run-all, export PDF
  RV.ui.app.setTab('reports');
  const reportsTab = document.getElementById('reports-tab');
  console.log('6. reports tab active:', RV.ui.app.currentTab() === 'reports',
    '| workspace rendered:', reportsTab.querySelectorAll('.report-plugin-btn').length > 0);
  const filter = reportsTab.querySelector('#report-filter');
  filter.value = 'compname';
  filter.dispatch('input');
  console.log('   filter narrowed:', reportsTab.querySelectorAll('.report-plugin-btn').length < 150);
  filter.value = '';
  filter.dispatch('input');
  const compBtn = reportsTab.querySelectorAll('.report-plugin-btn')
    .find((b) => b.querySelector('.report-plugin-name').textContent === 'compname');
  compBtn.dispatch('click');
  const output = reportsTab.querySelector('#report-output');
  console.log('   ran a plugin, output rendered:', output.children.length > 0);
  reportsTab.querySelector('.report-run-all').dispatch('click');
  console.log('   run-all rendered results:', output.children.length > 0);
  reportsTab.querySelector('.report-export-pdf').dispatch('click');
  const dl = globalThis.__downloads[globalThis.__downloads.length - 1];
  console.log('   PDF exported:', !!dl && dl.name.startsWith('hivewalker-report-'),
    '| valid:', dl && dl.bytes.toString('latin1').startsWith('%PDF-1.4'));

  // 7) back to viewer — state preserved
  RV.ui.app.setTab('viewer');
  console.log('7. back to viewer:', RV.ui.app.currentTab() === 'viewer',
    '| selection preserved:', app.selectedKey.path);
})().catch((e) => { console.error('FAIL:', e); process.exit(1); });
