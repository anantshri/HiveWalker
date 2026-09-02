// rv.plugins — infosec audit plugins that decode/synthesise rather than dump:
//   firewallrules  — decode Windows Firewall rule strings, flag risky allows
//   svcunquoted    — unquoted service ImagePath privilege-escalation candidates
//   winrm          — WinRM / PSRemoting exposure and weak-auth settings
// All pure-registry (SYSTEM/SOFTWARE), no backend. Key layouts are public
// configuration facts (MSDN / netsh advfirewall / WinRM GPO docs), not derived
// from RegRipper. Proposed in issue #6 (infosec/DFIR use-case plugins).
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;

  // User-writable / staging locations — an executable here referenced by a
  // service, firewall allow or COM server is a classic tampering signal.
  const WRITABLE_RE = /\\users\\|\\appdata\\|\\temp\\|\\tmp\\|\\programdata\\|\\public\\|\\downloads\\|\\windows\\temp\\|\\perflogs\\/i;

  /** Resolve a hive of the requested type: the current hive if it matches,
   *  else a session-attached hive of that type, else null. */
  function pick(hive, ctx, type) {
    if (H.guessHiveType(hive).has(type)) return hive;
    const e = ctx.session && ctx.session.byType(type);
    return e ? e.hive : null;
  }

  // ---------------------------------------------------------------------------
  // firewallrules — decode SharedAccess FirewallRules value strings.

  const PROTO = { 1: 'ICMPv4', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 58: 'ICMPv6' };
  const FW_BASE = '\\Services\\SharedAccess\\Parameters\\FirewallPolicy';

  /** Split a `|Key=Value|…` rule string into a lowercase-keyed object. */
  function parseRule(str) {
    const f = {};
    for (const part of String(str).split('|')) {
      const eq = part.indexOf('=');
      if (eq > 0) f[part.slice(0, eq).toLowerCase()] = part.slice(eq + 1);
    }
    return f;
  }

  R.register({
    name: 'firewallrules',
    hives: ['system'],
    category: 'defense evasion (audit)',
    mitre: 'T1686',
    version: '20260902',
    shortDescr: 'Decode Windows Firewall rules; flag inbound-allow and rules pointing at writable paths',
    run(hive, ctx) {
      ctx.section('Windows Firewall');
      const { name: ccs } = H.getControlSet(hive);
      const base = (ccs || 'ControlSet001') + FW_BASE;

      // Per-profile on/off + default actions.
      const prof = ctx.table(['Profile', 'Firewall', 'Default Inbound', 'Default Outbound']);
      for (const p of ['Domain', 'Standard', 'Public']) {
        const k = H.subkey(hive, base + '\\' + p + 'Profile');
        if (!k) continue;
        const en = H.getValueDword(k, 'EnableFirewall', null);
        const din = H.getValueDword(k, 'DefaultInboundAction', null);
        const dout = H.getValueDword(k, 'DefaultOutboundAction', null);
        prof.row([
          p, en === 0 ? 'OFF (at-risk)' : en === 1 ? 'on' : '(unset)',
          din === 1 ? 'Block' : din === 0 ? 'Allow' : '(default)',
          dout === 1 ? 'Block' : dout === 0 ? 'Allow' : '(default)',
        ]);
      }

      const rulesKey = H.subkey(hive, base + '\\FirewallRules');
      if (!rulesKey) { ctx.rptMsg('FirewallRules key not found under ' + base + '.'); return; }

      ctx.section('Firewall Rules');
      const t = ctx.table(['Action', 'Dir', 'Proto', 'Port', 'Application', 'Name', 'Active', 'Note']);
      let risky = 0;
      let total = 0;
      for (const v of rulesKey.getValues()) {
        if (t.count() >= H.MAX_PLUGIN_ROWS) break;
        const f = parseRule(String(v.getData().value));
        total++;
        const dir = /^out$/i.test(f.dir) ? 'Out' : /^in$/i.test(f.dir) ? 'In' : (f.dir || '?');
        const action = /allow/i.test(f.action) ? 'Allow' : /block/i.test(f.action) ? 'Block' : (f.action || '?');
        const proto = f.protocol != null && PROTO[Number(f.protocol)] ? PROTO[Number(f.protocol)] : (f.protocol || 'any');
        const port = f.lport || f.rport || 'any';
        const app = f.app || '(any)';
        const notes = [];
        if (action === 'Allow' && dir === 'In') notes.push('inbound-allow');
        if (f.app && WRITABLE_RE.test(f.app)) notes.push('writable-path');
        if (notes.length) risky++;
        t.row([action, dir, proto, port, app, f.name || v.name, /^true$/i.test(f.active) ? 'yes' : 'no', notes.join(', ')]);
      }
      ctx.note(`${total} rule(s); ${risky} flagged (inbound-allow or app in a user-writable path).`);
      ctx.note('Attacker-authored allow rules (esp. inbound to a binary under \\Users, \\Temp or \\ProgramData) enable C2/lateral movement — MITRE T1686.');
    },
  });

  // ---------------------------------------------------------------------------
  // svcunquoted — unquoted ImagePath with a space is a hijack primitive: an
  // attacker who can write C:\Program.exe (or an earlier path segment) gets it
  // executed as the service account (T1574.009).

  /** True when a service ImagePath is the classic unquoted-with-space form. */
  function isUnquotedVulnerable(imagePath) {
    const p = String(imagePath).trim();
    if (!p || p.startsWith('"')) return false;
    if (!/^[a-z]:\\/i.test(p)) return false; // driver \SystemRoot\… forms aren't the classic case
    // Isolate the executable portion (up to and incl. the first .exe); a space
    // anywhere in that portion means Windows can be steered to a shorter path.
    const m = /^(.*?\.exe)\b/i.exec(p);
    const exePart = m ? m[1] : p.split(/\s/)[0];
    return /\s/.test(exePart);
  }

  R.register({
    name: 'svcunquoted',
    hives: ['system'],
    category: 'privilege escalation (audit)',
    mitre: 'T1574.009',
    version: '20260902',
    shortDescr: 'Services with unquoted ImagePath containing spaces, or binaries in writable paths (privesc)',
    run(hive, ctx) {
      ctx.section('Unquoted / Writable-Path Service Binaries');
      const { name: ccs } = H.getControlSet(hive);
      const services = H.subkey(hive, (ccs || 'ControlSet001') + '\\Services');
      if (!services) { ctx.rptMsg('Services key not found.'); return; }

      const t = ctx.table(['Service', 'Start', 'ImagePath', 'Finding']);
      const START = { 0: 'boot', 1: 'system', 2: 'auto', 3: 'manual', 4: 'disabled' };
      let findings = 0;
      for (const s of services.getSubkeys()) {
        if (t.count() >= H.MAX_PLUGIN_ROWS) break;
        const img = H.getValueString(s, 'ImagePath', '');
        if (!img) continue;
        const flags = [];
        if (isUnquotedVulnerable(img)) flags.push('unquoted path w/ space');
        if (WRITABLE_RE.test(img)) flags.push('binary in writable path');
        if (!flags.length) continue;
        const start = H.getValueDword(s, 'Start', null);
        t.row([s.name, START[start] || (start == null ? '?' : String(start)), img, flags.join('; ')]);
        findings++;
      }
      if (findings === 0) { ctx.rptMsg('No unquoted-path or writable-binary services found.'); return; }
      ctx.note(`${findings} service(s) flagged. Unquoted paths need a writable intermediate directory to exploit (T1574.009); binaries under \\Users/\\ProgramData/\\Temp are direct replace-and-restart targets (T1543.003).`);
    },
  });

  // ---------------------------------------------------------------------------
  // winrm — remote-management exposure. Service start state lives in SYSTEM;
  // the weak-auth toggles live in SOFTWARE policy keys. Runs from either hive
  // and pulls the other from the session when attached.

  const WINRM_PROBES = [
    { scope: 'Service', name: 'AllowAutoConfig', path: 'Software\\Policies\\Microsoft\\Windows\\WinRM\\Service', judge: (x) => (x === 1 ? 'listener auto-configured' : 'OK') },
    { scope: 'Service', name: 'AllowBasic', path: 'Software\\Policies\\Microsoft\\Windows\\WinRM\\Service', judge: (x) => (x === 1 ? 'at-risk (Basic auth)' : 'OK') },
    { scope: 'Service', name: 'AllowUnencrypted', path: 'Software\\Policies\\Microsoft\\Windows\\WinRM\\Service', judge: (x) => (x === 1 ? 'at-risk (unencrypted)' : 'OK') },
    { scope: 'Service', name: 'IPv4Filter', path: 'Software\\Policies\\Microsoft\\Windows\\WinRM\\Service', judge: (x) => (String(x) === '*' ? 'at-risk (any source IP)' : 'scoped') },
    { scope: 'Client', name: 'AllowBasic', path: 'Software\\Policies\\Microsoft\\Windows\\WinRM\\Client', judge: (x) => (x === 1 ? 'at-risk (Basic auth)' : 'OK') },
    { scope: 'Client', name: 'AllowUnencrypted', path: 'Software\\Policies\\Microsoft\\Windows\\WinRM\\Client', judge: (x) => (x === 1 ? 'at-risk (unencrypted)' : 'OK') },
    { scope: 'Client', name: 'TrustedHosts', path: 'Software\\Policies\\Microsoft\\Windows\\WinRM\\Client', judge: (x) => (String(x) === '*' ? 'at-risk (trusts any host)' : 'scoped') },
  ];
  const SVC_START = { 2: 'Automatic (remoting likely enabled)', 3: 'Manual', 4: 'Disabled' };

  R.register({
    name: 'winrm',
    hives: ['software', 'system'],
    category: 'lateral movement (audit)',
    mitre: 'T1021.006',
    version: '20260902',
    shortDescr: 'WinRM / PSRemoting service state and weak-auth (Basic/Unencrypted/TrustedHosts=*) settings',
    run(hive, ctx) {
      ctx.section('WinRM / PSRemoting');
      const sys = pick(hive, ctx, 'system');
      const sw = pick(hive, ctx, 'software');

      if (sys) {
        const { name: ccs } = H.getControlSet(sys);
        const svc = H.subkey(sys, (ccs || 'ControlSet001') + '\\Services\\WinRM');
        if (svc) {
          const start = H.getValueDword(svc, 'Start', null);
          ctx.kv('WinRM service Start', start == null ? '(unset)' : (SVC_START[start] || String(start)));
        } else ctx.kv('WinRM service', 'not present in SYSTEM');
      } else {
        ctx.note('SYSTEM hive not attached — service start state unavailable (attach SYSTEM for full coverage).');
      }

      if (!sw) { ctx.note('SOFTWARE hive not attached — WinRM policy settings unavailable.'); return; }
      const t = ctx.table(['Scope', 'Setting', 'Value', 'Verdict']);
      let atrisk = 0;
      for (const p of WINRM_PROBES) {
        const key = H.subkey(sw, p.path);
        if (!key) continue;
        const raw = H.getValueData(key, p.name, undefined);
        if (raw === undefined || raw == null) continue;
        const verdict = p.judge(raw);
        if (String(verdict).startsWith('at-risk')) atrisk++;
        t.row([p.scope, p.name, String(raw), verdict]);
      }
      ctx.note(atrisk > 0
        ? `${atrisk} weak WinRM setting(s) — Basic/Unencrypted auth or TrustedHosts=* widen the remote-exec attack surface (T1021.006).`
        : 'No weak WinRM auth settings found in the attached SOFTWARE hive.');
    },
  });
})(window.RV);
