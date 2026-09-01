// rv.plugins — SAM-hive plugin. Reduced port of RegRipper's samparse: lists
// local accounts by username (from the Names subkeys, whose LastWrite is the
// account-creation time) and their RIDs (from the numeric user subkeys). Full
// F/V binary-structure decoding (logon counts, ACB flags) is deferred.
(function (RV) {
  'use strict';

  const R = RV.plugins.runtime;
  const H = RV.plugins.helpers;

  R.register({
    name: 'samparse',
    hives: ['sam'],
    category: 'user activity',
    mitre: 'T1136.001',
    version: '20200825',
    shortDescr: 'Parse SAM file for user account info (reduced)',
    run(hive, ctx) {
      const users = H.subkey(hive, 'SAM\\Domains\\Account\\Users');
      ctx.section('User Information');
      if (!users) { ctx.rptMsg('SAM\\Domains\\Account\\Users not found.'); return; }

      // Names\<username> — each subkey name is a local account name; its
      // LastWrite time is the account-creation date.
      const names = users.getSubkey('Names');
      if (names) {
        const t = ctx.table(['Username', 'Account Created']);
        for (const n of names.getSubkeys()) t.row([n.name, H.formatDate(n.lastWriteDate)]);
      } else {
        ctx.rptMsg('Names subkey not found.');
      }

      // Numeric RID subkeys (e.g. 000001F4 → 500). Skip the Names container.
      ctx.section('RIDs');
      const t = ctx.table(['RID (hex)', 'RID (dec)', 'LastWrite']);
      for (const u of users.getSubkeys()) {
        if (!/^[0-9a-f]{8}$/i.test(u.name)) continue;
        t.row([u.name, String(parseInt(u.name, 16)), H.formatDate(u.lastWriteDate)]);
      }
    },
  });
})(window.RV);
