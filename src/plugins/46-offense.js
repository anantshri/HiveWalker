// rv.plugins — offense-oriented audits: a consolidated autostart sweep
// (`autostarts`, MITRE-tagged per source, StartupApproved correlation) and a
// defense-posture audit (`defposture`). Inspired by the persistence/defense-
// evasion key sets in Splunk STRT's published registry detections and
// HackTricks' interesting-keys page (key lists are public configuration
// facts, not derived from RegRipper).
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;

  // ---------------------------------------------------------------------------
  // autostarts — declarative sweep table. `{label, hives, path, ccs?, values?
  // (null = all values + subkey defaults), mitre}`.
  const AUTOSTART_SOURCES = [
    { label: 'Run (HKLM)', hives: ['software', 'ntuser'], path: 'Microsoft\\Windows\\CurrentVersion\\Run', mitre: 'T1547.001' },
    { label: 'RunOnce (HKLM)', hives: ['software', 'ntuser'], path: 'Microsoft\\Windows\\CurrentVersion\\RunOnce', mitre: 'T1547.001' },
    { label: 'Run (Wow6432Node)', hives: ['software', 'ntuser'], path: 'WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run', mitre: 'T1547.001' },
    { label: 'RunOnce (Wow6432Node)', hives: ['software', 'ntuser'], path: 'WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce', mitre: 'T1547.001' },
    { label: 'Run (Policies)', hives: ['software', 'ntuser'], path: 'Software\\Policies\\Microsoft\\Windows\\System\\Run' , mitre: 'T1547.001' },
    { label: 'RunOnceEx\\Setup', hives: ['software'], path: 'Microsoft\\Windows\\CurrentVersion\\RunOnceEx', subkeys: true, mitre: 'T1547.001' },
    { label: 'RunServices', hives: ['software', 'ntuser'], path: 'Microsoft\\Windows\\CurrentVersion\\RunServices', mitre: 'T1547.001' },
    { label: 'Winlogon: Shell', hives: ['software'], path: 'Microsoft\\Windows NT\\CurrentVersion\\Winlogon', values: ['Shell'], mitre: 'T1547.002' },
    { label: 'Winlogon: Userinit', hives: ['software'], path: 'Microsoft\\Windows NT\\CurrentVersion\\Winlogon', values: ['Userinit'], mitre: 'T1547.002' },
    { label: 'Winlogon: System/VmApplet/Taskman/AppSetup/GinaDLL', hives: ['software'], path: 'Microsoft\\Windows NT\\CurrentVersion\\Winlogon', values: ['System', 'VmApplet', 'Taskman', 'AppSetup', 'GinaDLL'], mitre: 'T1547.002' },
    { label: 'LSA: Security Packages', hives: ['system'], ccs: true, path: '\\Control\\Lsa', values: ['Security Packages'], mitre: 'T1547.005' },
    { label: 'LSA: Notification Packages', hives: ['system'], ccs: true, path: '\\Control\\Lsa', values: ['Notification Packages'], mitre: 'T1556' },
    { label: 'AppInit_DLLs', hives: ['software'], path: 'Microsoft\\Windows NT\\CurrentVersion\\Windows', values: ['AppInit_DLLs', 'LoadAppInit_DLLs'], mitre: 'T1546.010' },
    { label: 'IFEO: Debugger', hives: ['software', 'ntuser'], path: 'Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options', ifeo: true, values: ['Debugger'], mitre: 'T1546.012' },
    { label: 'SilentProcessExit', hives: ['software'], path: 'Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit', ifeo: true, values: ['MonitorProcess', 'ReportingMode'], mitre: 'T1546.012' },
    { label: 'Active Setup StubPath', hives: ['software', 'ntuser'], path: 'Microsoft\\Active Setup\\Installed Components', subkeys: 'StubPath', mitre: 'T1547.002' },
    { label: 'Netsh helpers', hives: ['software'], path: 'Microsoft\\Netsh', values: null, mitre: 'T1546.007' },
    { label: 'Time Providers', hives: ['system'], ccs: true, path: '\\Services\\W32Time\\TimeProviders', subkeys: 'DllName', mitre: 'T1547.003' },
    { label: 'Print Monitors', hives: ['system'], ccs: true, path: '\\Control\\Print\\Monitors', subkeys: 'Driver', mitre: 'T1547.002' },
    { label: 'BootExecute', hives: ['system'], ccs: true, path: '\\Control\\Session Manager', values: ['BootExecute', 'SetupExecute'], mitre: 'T1547.002' },
    { label: 'ShellServiceObjectDelayLoad', hives: ['software', 'ntuser'], path: 'Software\\Microsoft\\Windows\\CurrentVersion\\ShellServiceObjectDelayLoad', values: null, mitre: 'T1547.001' },
  ];

  /**
   * StartupApproved binary: 16-byte records (u32 flags, u32 unknown, 8-byte
   * last-run FILETIME on Win8+); the low byte of the flags enables (2/6) or
   * disables (3/…) the entry. Public format fact.
   */
  function decodeStartupApproved(raw) {
    if (!raw || raw.length < 8) return null;
    const flag = raw[0];
    let state = 'unknown';
    if (flag === 0x02 || flag === 0x06) state = 'enabled';
    else if (flag === 0x03 || (flag & 0x01)) state = 'disabled';
    let lastRun = null;
    if (raw.length >= 16) lastRun = H.filetimeFromBinary(raw, 8);
    return { state, lastRun };
  }

  function startupApprovedMap(hive) {
    const map = new Map(); // lowercase value name → {state, lastRun}
    // SOFTWARE hives are often mounted with or without the leading Software\
    // component depending on acquisition — probe both spellings.
    const bases = ['Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved',
      'Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved'];
    for (const base of bases) {
      for (const leaf of ['Run', 'Run32', 'StartupFolder']) {
        const k = H.subkey(hive, base + '\\' + leaf);
        if (!k) continue;
        for (const v of k.getValues()) {
          const d = decodeStartupApproved(v.getRawData());
          if (d) map.set(v.name.toLowerCase(), d);
        }
      }
    }
    return map;
  }

  R.register({
    name: 'autostarts',
    hives: ['software', 'ntuser', 'system'],
    category: 'persistence',
    mitre: 'T1547',
    version: '20260901',
    shortDescr: 'Consolidated autostart sweep across Run keys, Winlogon, LSA, IFEO, Active Setup and more',
    run(hive, ctx) {
      ctx.section('Autostart Extensibility Points');
      const { name: ccs } = H.getControlSet(hive);
      const approved = startupApprovedMap(hive);
      const rows = [];

      for (const src of AUTOSTART_SOURCES) {
        let path = src.path;
        if (src.ccs) path = (ccs || 'ControlSet001') + path;

        if (src.ifeo) {
          // Sweep every IFEO child subkey for the named values.
          const ifeo = H.subkey(hive, path);
          if (!ifeo) continue;
          for (const target of ifeo.getSubkeys()) {
            for (const vn of (src.values || [])) {
              const val = H.getValueString(target, vn, '');
              if (val) rows.push([src.label + ' — ' + target.name, target.path, vn, val, src.mitre]);
            }
          }
          continue;
        }

        const key = H.subkey(hive, path);
        if (!key) continue;

        if (src.subkeys === true) {
          // RunOnceEx-style: each subkey's values are commands.
          for (const sk of key.getSubkeys()) {
            for (const v of sk.getValues()) {
              rows.push([src.label + ' — ' + sk.name, sk.path, v.name, String(v.getData().value), src.mitre]);
            }
          }
        } else if (typeof src.subkeys === 'string') {
          // e.g. Time Providers / Print Monitors: read one named value per subkey.
          for (const sk of key.getSubkeys()) {
            const val = H.getValueString(sk, src.subkeys, '');
            if (val) rows.push([src.label + ' — ' + sk.name, sk.path, src.subkeys, val, src.mitre]);
          }
        } else if (Array.isArray(src.values)) {
          for (const vn of src.values) {
            const val = H.getValueString(key, vn, '');
            if (val) rows.push([src.label, path, vn, val, src.mitre]);
          }
        } else {
          // All values.
          for (const v of key.getValues()) {
            const data = String(v.getData().value);
            if (!data) continue;
            rows.push([src.label, path, v.name, data, src.mitre]);
          }
        }
      }

      if (rows.length === 0) {
        ctx.rptMsg('No autostart entries found in this hive.');
        return;
      }
      const t = ctx.table(['Source', 'Key', 'Name', 'Data', 'MITRE', 'StartupApproved']);
      for (const [label, path, name, data, mitre] of rows.slice(0, H.MAX_PLUGIN_ROWS)) {
        const ap = approved.get(String(name).toLowerCase());
        let state = 'not tracked';
        if (ap) {
          state = ap.state;
          if (ap.lastRun) state += ` (last run ${H.formatDate(ap.lastRun)})`;
        }
        t.row([label, path, name, data, mitre, state]);
      }
      if (rows.length > H.MAX_PLUGIN_ROWS) ctx.note(`Truncated to ${H.MAX_PLUGIN_ROWS} of ${rows.length} entries.`);
      if (approved.size > 0) {
        ctx.note('StartupApproved decodes 12-byte enable/disable records for Run-key entries; "disabled" entries are tampering signals (malware disabling legit AV/updators).');
      }
    },
  });

  // ---------------------------------------------------------------------------
  // defposture — defense-configuration audit with verdicts.

  const DEFPROBE = (area, path, value, judge) => ({ area, path, value, judge });
  const v = (verdict) => verdict; // readability

  const DEF_PROBES = [
    // Defender (both config + Policies locations)
    DEFPROBE('Defender', 'Software\\Microsoft\\Windows Defender', 'DisableAntiSpyware', (x) => (x === 1 ? v('at-risk') : v('OK'))),
    DEFPROBE('Defender', 'Software\\Microsoft\\Windows Defender', 'DisableAntiVirus', (x) => (x === 1 ? v('at-risk') : v('OK'))),
    DEFPROBE('Defender', 'Software\\Policies\\Microsoft\\Windows Defender', 'DisableAntiSpyware', (x) => (x === 1 ? v('at-risk') : v('OK'))),
    DEFPROBE('Defender', 'Software\\Microsoft\\Windows Defender\\Real-Time Protection', 'DisableRealtimeMonitoring', (x) => (x === 1 ? v('at-risk') : v('OK'))),
    DEFPROBE('Defender', 'Software\\Microsoft\\Windows Defender\\Real-Time Protection', 'DisableBehaviorMonitoring', (x) => (x === 1 ? v('at-risk') : v('OK'))),
    DEFPROBE('Defender', 'Software\\Microsoft\\Windows Defender\\Real-Time Protection', 'DisableIOAVProtection', (x) => (x === 1 ? v('at-risk') : v('OK'))),
    DEFPROBE('Defender', 'Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection', 'DisableRealtimeMonitoring', (x) => (x === 1 ? v('at-risk') : v('OK'))),
    // UAC
    DEFPROBE('UAC', 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'EnableLUA', (x) => (x === 0 ? v('at-risk') : x === 1 ? v('hardened') : v('OK'))),
    DEFPROBE('UAC', 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'ConsentPromptBehaviorAdmin', (x) => (x === 0 ? v('at-risk (no prompt)') : x === 5 ? v('OK (default)') : v('OK'))),
    DEFPROBE('UAC', 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'EnableInstallerDetection', (x) => (x === 0 ? v('at-risk') : v('OK'))),
    DEFPROBE('UAC', 'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', 'FilterAdministratorToken', (x) => (x === 1 ? v('hardened') : v('OK'))),
    // Credential theft
    DEFPROBE('WDigest', 'ccs:Control\\SecurityProviders\\WDigest', 'UseLogonCredential', (x) => (x === 1 ? v('at-risk (cleartext passwords in LSASS)') : v('OK'))),
    DEFPROBE('LSA', 'ccs:Control\\Lsa', 'RunAsPPL', (x) => (x === 1 ? v('hardened') : v('OK'))),
    DEFPROBE('LSA', 'ccs:Control\\Lsa', 'LsaCfgFlags', (x) => (x === 1 ? v('hardened (Credential Guard)') : v('OK'))),
    // PowerShell
    DEFPROBE('PowerShell', 'Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging', 'EnableModuleLogging', (x) => (x === 1 ? v('hardened') : v('OK'))),
    DEFPROBE('PowerShell', 'Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging', 'EnableScriptBlockLogging', (x) => (x === 1 ? v('hardened') : v('OK'))),
    DEFPROBE('PowerShell', 'Software\\Policies\\Microsoft\\Windows\\PowerShell\\ExecutionPolicy', 'ExecutionPolicy', (x) => (/unrestricted|bypass/i.test(String(x)) ? v('at-risk') : v('OK'))),
    // SmartScreen / misc
    DEFPROBE('SmartScreen', 'Software\\Policies\\Microsoft\\Windows\\System', 'EnableSmartScreen', (x) => (x === 0 ? v('at-risk') : v('OK'))),
    DEFPROBE('RDP', 'ccs:Control\\Terminal Server', 'fDenyTSConnections', (x) => (x === 0 ? v('RDP enabled (review exposure)') : v('OK (RDP off)'))),
    DEFPROBE('CrashControl', 'ccs:Control\\CrashControl', 'CrashDumpEnabled', (x) => (x === 0 ? v('at-risk (crash dumps disabled — anti-forensics signal)') : v('OK'))),
  ];

  const DEFENDER_EXCLUSION_KEYS = [
    'Software\\Microsoft\\Windows Defender\\Exclusions\\Paths',
    'Software\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Paths',
    'Software\\Microsoft\\Windows Defender\\Exclusions\\Process',
    'Software\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Process',
    'Software\\Microsoft\\Windows Defender\\Exclusions\\Extension',
    'Software\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Extension',
    'Software\\Microsoft\\Windows Defender\\Exclusions\\Ip',
    'Software\\Policies\\Microsoft\\Windows Defender\\Exclusions\\Ip',
  ];

  const USER_LOCKOUT_KEYS = [
    'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System:DisableRegistryTools',
    'Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System:DisableTaskMgr',
    'Software\\Policies\\Microsoft\\Windows\\System:DisableCMD',
  ];

  R.register({
    name: 'defposture',
    hives: ['software', 'system'],
    category: 'defense evasion (audit)',
    mitre: 'T1685',
    version: '20260901',
    shortDescr: 'Defense posture audit: Defender/UAC/WDigest/PowerShell/SmartScreen settings with verdicts',
    run(hive, ctx) {
      ctx.section('Defense Posture');
      const { name: ccs } = H.getControlSet(hive);
      const counts = { hardened: 0, OK: 0, 'at-risk': 0 };

      const t = ctx.table(['Area', 'Setting', 'Value', 'Verdict']);
      const bump = (verdict) => {
        if (String(verdict).startsWith('at-risk')) counts['at-risk']++;
        else if (String(verdict).startsWith('hardened')) counts.hardened++;
        else counts.OK++;
      };

      for (const probe of DEF_PROBES) {
        const path = probe.path.startsWith('ccs:')
          ? (ccs || 'ControlSet001') + '\\' + probe.path.slice(4)
          : probe.path;
        const key = H.subkey(hive, path);
        if (!key) continue;
        const raw = H.getValueData(key, probe.value, undefined);
        if (raw === undefined || raw == null) continue;
        const verdict = probe.judge(raw);
        bump(verdict);
        t.row([probe.area, probe.value, String(raw), verdict]);
      }

      // Defender exclusions — each entry is its own finding.
      let exclusions = 0;
      for (const p of DEFENDER_EXCLUSION_KEYS) {
        const key = H.subkey(hive, p);
        if (!key) continue;
        for (const val of key.getValues()) {
          const verdict = 'at-risk (exclusion)';
          counts['at-risk']++;
          t.row(['Defender', 'Exclusion: ' + p.split('\\').pop(), val.name, verdict]);
          exclusions++;
        }
      }

      // Response-tool lockouts (DisableTaskMgr etc.).
      for (const spec of USER_LOCKOUT_KEYS) {
        const [path, name] = spec.split(':');
        const key = H.subkey(hive, path);
        if (!key) continue;
        const raw = H.getValueDword(key, name, null);
        if (raw === 1) {
          counts['at-risk']++;
          t.row(['Tool lockout', name, '1', 'at-risk (incident-response tool disabled)']);
        }
      }

      // MiniNt key presence — registry-namespace virtualization evasion.
      if (H.subkey(hive, 'Software\\Microsoft\\Windows NT\\CurrentVersion\\MiniNt') != null) {
        counts['at-risk']++;
        t.row(['Event log', 'MiniNt key', 'present', 'at-risk (Security event log virtualized/hidden — T1112)']);
      }

      ctx.note(`Verdict totals: ${counts.hardened} hardened, ${counts.OK} OK, ${counts['at-risk']} AT-RISK` +
        (exclusions ? ` (${exclusions} Defender exclusion${exclusions > 1 ? 's' : ''})` : '') + '.');
      ctx.note('Run with both SOFTWARE and SYSTEM attached for full coverage (WDigest/RDP/CrashControl live in SYSTEM).');
    },
  });
})(window.RV);
