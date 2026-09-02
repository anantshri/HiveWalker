// Issue #6 infosec/DFIR plugins: firewallrules, svcunquoted, winrm,
// appcompatlayers, officetrust, officemru, comhijack, pcaexec, execsummary.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const { ftBytes } = require('./helpers/ft-bytes');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime, helpers, session } = RV.plugins;
const textOf = (name, hive, opts) => RV.ui.viewModel.reportText(runtime.run(name, hive, opts));

// -- builders ---------------------------------------------------------------

function sysHive(build) {
  return RV.reg.openHive(new HiveBuilder({ fileName: 'SYSTEM' }).build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('ControlSet001', {}, (cs) => { if (build) build(cs); });
  }).toBuffer());
}
function swHive(build) {
  return RV.reg.openHive(new HiveBuilder({ fileName: 'SOFTWARE' }).build((r) => { if (build) build(r); }).toBuffer());
}
function ntHive(build) {
  return RV.reg.openHive(new HiveBuilder({ fileName: 'NTUSER.DAT' }).build((r) => { if (build) build(r); }).toBuffer());
}
/** Descend/create a `A\B\C` chain from a KeySpec, returning the leaf spec. */
function deep(node, path) {
  for (const part of path.split('\\')) node = node.key(part);
  return node;
}
/** REG_SZ FILETIME-hex token for Office MRU [T…]. */
function ftHex(date) {
  const ft = (BigInt(date.getTime()) + 11644473600000n) * 10000n;
  return ft.toString(16).padStart(16, '0');
}

// ---------------------------------------------------------------------------
// firewallrules

test('firewallrules: decodes rules, flags inbound-allow + writable path, profile OFF', () => {
  const hive = sysHive((cs) => {
    const fp = deep(cs, 'Services\\SharedAccess\\Parameters\\FirewallPolicy');
    fp.key('PublicProfile').value('EnableFirewall', 4, 0);
    const fr = fp.key('FirewallRules');
    fr.value('{rule-a}', 1, 'v2.31|Action=Allow|Active=TRUE|Dir=In|Protocol=6|LPort=4444|App=C:\\Users\\Public\\bd.exe|Name=Backdoor|');
    fr.value('{rule-b}', 1, 'v2.31|Action=Allow|Active=TRUE|Dir=Out|Protocol=17|LPort=443|App=C:\\Windows\\System32\\legit.exe|Name=DNS out|');
    fr.value('{rule-c}', 1, 'v2.31|Action=Block|Active=FALSE|Dir=In|Protocol=1|Name=ICMP block|');
  });
  const t = textOf('firewallrules', hive);
  assert.ok(t.includes('ICMPv4') && t.includes('ICMP block'), 'icmp rule decoded (proto map + no-app)');
  assert.ok(t.includes('OFF (at-risk)'), 'public profile off flagged');
  assert.ok(t.includes('Backdoor') && t.includes('4444') && t.includes('TCP'), 'rule decoded');
  assert.ok(t.includes('inbound-allow') && t.includes('writable-path'), 'risky rule noted');
  assert.ok(t.includes('DNS out') && t.includes('UDP'), 'benign rule shown');
  assert.ok(t.includes('T1686'), 'mitre note (v19 renumber of former T1562.004)');
});

test('firewallrules: degrades cleanly when the FirewallRules key is absent', () => {
  assert.ok(textOf('firewallrules', sysHive()).includes('FirewallRules key not found'));
});

// ---------------------------------------------------------------------------
// svcunquoted

test('svcunquoted: flags unquoted-with-space and writable-path binaries, passes clean ones', () => {
  const hive = sysHive((cs) => {
    const svcs = cs.key('Services');
    svcs.key('vulnsvc').value('ImagePath', 1, 'C:\\Program Files\\Bad Co\\svc.exe').value('Start', 4, 2);
    svcs.key('writsvc').value('ImagePath', 1, '"C:\\Users\\Public\\tool.exe"').value('Start', 4, 3);
    svcs.key('cleansvc').value('ImagePath', 1, 'C:\\Windows\\System32\\svchost.exe -k netsvcs').value('Start', 4, 2);
    svcs.key('driversvc').value('ImagePath', 1, '\\SystemRoot\\System32\\drivers\\x.sys');
  });
  const t = textOf('svcunquoted', hive);
  assert.ok(t.includes('vulnsvc') && t.includes('unquoted path w/ space'), 'unquoted flagged');
  assert.ok(t.includes('writsvc') && t.includes('binary in writable path'), 'writable flagged');
  assert.ok(!t.includes('cleansvc'), 'system svchost not flagged');
  assert.ok(!t.includes('driversvc'), 'driver \\SystemRoot form not flagged');
  assert.ok(t.includes('T1574.009'));
});

test('svcunquoted: reports none for a clean service set', () => {
  const hive = sysHive((cs) => cs.key('Services').key('ok').value('ImagePath', 1, 'C:\\Windows\\a.exe'));
  assert.ok(textOf('svcunquoted', hive).includes('No unquoted-path or writable-binary services'));
});

// ---------------------------------------------------------------------------
// winrm (cross-hive: SYSTEM service state + SOFTWARE policy)

test('winrm: merges SYSTEM service start with SOFTWARE weak-auth settings via session', () => {
  session.clear();
  const sys = sysHive((cs) => cs.key('Services').key('WinRM').value('Start', 4, 2));
  const sw = swHive((r) => {
    const winrm = deep(r, 'Software\\Policies\\Microsoft\\Windows\\WinRM');
    winrm.key('Service').value('AllowUnencrypted', 4, 1).value('AllowBasic', 4, 1)
      .value('AllowAutoConfig', 4, 1).value('IPv4Filter', 1, '192.168.0.0/24');
    winrm.key('Client').value('TrustedHosts', 1, '*');
  });
  session.attach(sys, 'SYSTEM');
  const t = textOf('winrm', sw, { session });
  assert.ok(t.includes('Automatic'), 'service start decoded from SYSTEM via session');
  assert.ok(t.includes('at-risk (unencrypted)') && t.includes('at-risk (Basic auth)'), 'weak auth flagged');
  assert.ok(t.includes('listener auto-configured') && t.includes('scoped'), 'auto-config + scoped filter verdicts');
  assert.ok(t.includes('trusts any host'), 'TrustedHosts=* flagged');
  assert.ok(t.includes('T1021.006'));
  session.clear();
});

test('winrm: notes missing SYSTEM when only SOFTWARE is present', () => {
  session.clear();
  const sw = swHive((r) => deep(r, 'Software\\Policies\\Microsoft\\Windows\\WinRM\\Service').value('AllowBasic', 4, 0));
  const t = textOf('winrm', sw, { session });
  assert.ok(t.includes('SYSTEM hive not attached'), 'missing-system note');
});

// ---------------------------------------------------------------------------
// appcompatlayers

test('appcompatlayers: flags RUNASADMIN elevation and writable path', () => {
  const hive = ntHive((r) => {
    const layers = deep(r, 'Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers');
    layers.value('C:\\Users\\bob\\AppData\\Local\\Temp\\evil.exe', 1, '~ RUNASADMIN HIGHDPIAWARE');
    layers.value('C:\\Program Files\\App\\app.exe', 1, 'WIN7RTM HIGHDPIAWARE');
  });
  const t = textOf('appcompatlayers', hive);
  assert.ok(t.includes('evil.exe') && t.includes('ELEVATION') && t.includes('writable-path'), 'elevated writable flagged');
  assert.ok(t.includes('app.exe') && t.includes('WIN7RTM'), 'benign shim listed');
  assert.ok(t.includes('T1546.011'));
});

test('appcompatlayers: none present → clean message', () => {
  assert.ok(textOf('appcompatlayers', ntHive()).includes('No AppCompatFlags\\Layers entries'));
});

// ---------------------------------------------------------------------------
// officetrust

test('officetrust: decodes macro-enabled documents with trust time', () => {
  const when = new Date(Date.UTC(2026, 7, 15, 9, 30, 0));
  const macro = Buffer.concat([ftBytes(when), (() => { const b = Buffer.alloc(4); b.writeUInt32LE(0x7fffffff); return b; })()]);
  const edit = Buffer.concat([ftBytes(when), (() => { const b = Buffer.alloc(4); b.writeUInt32LE(0x00000001); return b; })()]);
  const hive = ntHive((r) => {
    const tr = deep(r, 'Software\\Microsoft\\Office\\16.0\\Word\\Security\\Trusted Documents\\TrustRecords');
    tr.value('%USERPROFILE%/Downloads/invoice.docm', 3, macro);
    tr.value('C:/reports/report.xlsx', 3, edit);
  });
  const t = textOf('officetrust', hive);
  assert.ok(t.includes('invoice.docm') && t.includes('MACROS/CONTENT ENABLED'), 'macro doc flagged');
  assert.ok(t.includes('report.xlsx') && t.includes('editing only'), 'editing-only doc shown');
  assert.ok(t.includes('2026-08-15'), 'trust time rendered');
  assert.ok(t.includes('T1204.002'));
});

test('officetrust: none present → clean message', () => {
  assert.ok(textOf('officetrust', ntHive()).includes('No Office Trusted Documents'));
});

// ---------------------------------------------------------------------------
// officemru

test('officemru: parses File MRU path + last-opened time, skips Max Display', () => {
  const when = new Date(Date.UTC(2026, 4, 20, 12, 0, 0));
  const hive = ntHive((r) => {
    const mru = deep(r, 'Software\\Microsoft\\Office\\16.0\\Word\\File MRU');
    mru.value('Max Display', 4, 25);
    mru.value('Item 1', 1, `[F00000000][T${ftHex(when)}][O00000000]*C:\\Users\\bob\\Documents\\secret.docx`);
  });
  const t = textOf('officemru', hive);
  assert.ok(t.includes('secret.docx'), 'document path parsed');
  assert.ok(t.includes('2026-05-20'), 'last-opened time parsed');
  assert.ok(!t.includes('Max Display'), 'Max Display skipped');
});

test('officemru: none present → clean message', () => {
  assert.ok(textOf('officemru', ntHive()).includes('No Office MRU entries'));
});

// ---------------------------------------------------------------------------
// comhijack

test('comhijack: flags a user-hive InprocServer32 pointing at a writable path + TreatAs', () => {
  const hive = ntHive((r) => {
    const clsid = deep(r, 'Software\\Classes\\CLSID');
    clsid.key('{aaaa-bbbb}').key('InprocServer32')
      .value('', 1, 'C:\\Users\\bob\\AppData\\Roaming\\evil.dll').value('ThreadingModel', 1, 'Apartment');
    clsid.key('{cccc-dddd}').key('TreatAs').value('', 1, '{9999-0000}');
  });
  const t = textOf('comhijack', hive);
  assert.ok(t.includes('{aaaa-bbbb}') && t.includes('evil.dll'), 'server listed');
  assert.ok(t.includes('writable-path (hijack?)') && t.includes('Apartment'), 'hijack flagged with threading');
  assert.ok(t.includes('TreatAs') && t.includes('redirect'), 'TreatAs redirect shown');
  assert.ok(t.includes('T1546.015'));
});

test('comhijack: empty user classes → benign note', () => {
  assert.ok(textOf('comhijack', ntHive()).includes('No COM servers defined'));
});

// ---------------------------------------------------------------------------
// pcaexec

test('pcaexec: lists executables from Store and Persisted', () => {
  const hive = ntHive((r) => {
    const ca = deep(r, 'Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant');
    ca.key('Store').value('C:\\Users\\bob\\Desktop\\tool.exe', 3, Buffer.alloc(8));
    ca.key('Persisted').value('C:\\Temp\\x.exe', 4, 1);
  });
  const t = textOf('pcaexec', hive);
  assert.ok(t.includes('tool.exe') && t.includes('Store'), 'store entry');
  assert.ok(t.includes('x.exe') && t.includes('Persisted'), 'persisted entry');
  assert.ok(t.includes('T1059'));
});

test('pcaexec: none present → clean message', () => {
  assert.ok(textOf('pcaexec', ntHive()).includes('No Compatibility Assistant'));
});

// ---------------------------------------------------------------------------
// execsummary (meta / cross-hive)

function uaHive(exe, count, date) {
  return ntHive((r) => {
    const ua = deep(r, 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{GUID}\\Count');
    const data = Buffer.alloc(16);
    data.writeUInt32LE(count, 4);
    ftBytes(date).copy(data, 8);
    ua.value(helpers.rot13(exe), 3, data);
  });
}
function bamHive(exe, date) {
  return sysHive((cs) => {
    deep(cs, 'Services\\bam\\State\\UserSettings\\S-1-5-21-1-2-3-1001').value(exe, 3, ftBytes(date));
  });
}

test('execsummary: merges UserAssist + BAM into one time-sorted timeline', () => {
  session.clear();
  const nt = uaHive('C:\\Windows\\notepad.exe', 7, new Date(Date.UTC(2026, 0, 2, 8, 0, 0)));
  const sys = bamHive('C:\\Tools\\poc.exe', new Date(Date.UTC(2026, 0, 3, 8, 0, 0)));
  session.attach(nt, 'NTUSER.DAT');
  session.attach(sys, 'SYSTEM');
  const t = textOf('execsummary', nt, { session });
  assert.ok(t.includes('notepad.exe') && t.includes('UserAssist'), 'userassist merged');
  assert.ok(t.includes('poc.exe') && t.includes('BAM/DAM'), 'bam merged');
  assert.ok(t.includes('Sources merged'), 'source summary printed');
  // Newest first: the 2026-01-03 BAM event precedes the 2026-01-02 UA event.
  assert.ok(t.indexOf('2026-01-03') < t.indexOf('2026-01-02'), 'sorted newest-first');
  assert.ok(t.includes('Correlate before concluding'), 'semantics caveat');
  session.clear();
});

test('execsummary: no session, no artifacts → guidance message', () => {
  session.clear();
  assert.ok(textOf('execsummary', sysHive()).includes('No execution artifacts found'));
});

// ---------------------------------------------------------------------------
// registration sanity

test('all nine issue-#6 plugins are registered with mitre + category', () => {
  for (const n of ['firewallrules', 'svcunquoted', 'winrm', 'appcompatlayers',
    'officetrust', 'officemru', 'comhijack', 'pcaexec', 'execsummary']) {
    const p = runtime.get(n);
    assert.ok(p, `${n} registered`);
    assert.ok(p.mitre && p.category && p.shortDescr, `${n} has metadata`);
  }
});
