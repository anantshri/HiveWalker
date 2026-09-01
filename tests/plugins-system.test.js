'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { loadSrc } = require('./helpers/load-src');
const { HiveBuilder } = require('./helpers/hive-builder');
const { ftBytes } = require('./helpers/ft-bytes');

// Load through the view-model layer so tests can assert on reportText() too.
const RV = loadSrc({ only: /20-view-model/ });
const { runtime } = RV.plugins;

const SHUTDOWN = new Date('2023-06-15T10:00:00Z');
const USB_INSTALL = new Date('2023-01-02T03:04:05Z');

// A 24-byte MountedDevices volume value: 8 pad bytes then a 16-byte GUID.
const volume24 = Buffer.concat([
  Buffer.alloc(8),
  Buffer.from([0x78, 0x56, 0x34, 0x12, 0xbc, 0x9a, 0xf0, 0xde, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]),
]);
const deviceStr = Buffer.from('\\Device\\HarddiskVolume2\\padding-to-exceed-eighty-bytes-xx', 'utf16le');

const hive = RV.reg.openHive(new HiveBuilder({ fileName: '\\??\\C:\\Windows\\System32\\config\\SYSTEM' }).build((r) => {
  r.key('Select', {}, (s) => s.value('Current', 4, 1));
  r.key('MountedDevices', {}, (md) => {
    md.value('\\DosDevices\\C:', 3, Buffer.from([0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 0]));
    md.value('\\??\\Volume{guid}', 3, volume24);
    md.value('\\DosDevices\\D:', 3, deviceStr);
  });
  r.key('ControlSet001', {}, (cs) => {
    cs.key('Control', {}, (c) => {
      c.key('ComputerName', {}, (cn) => {
        cn.key('ComputerName', {}, (x) => x.value('ComputerName', 1, 'WIN-TEST'));
        cn.key('ActiveComputerName', {}, (x) => x.value('ComputerName', 1, 'WIN-ACTIVE'));
      });
      c.key('TimeZoneInformation', {}, (tz) => {
        tz.value('Bias', 4, 300);
        tz.value('ActiveTimeBias', 4, 240);
        tz.value('StandardName', 1, 'Eastern Standard Time');
        tz.value('DaylightName', 1, 'Eastern Daylight Time');
        tz.value('TimeZoneKeyName', 1, 'Eastern Standard Time');
      });
      c.key('Windows', {}, (w) => w.value('ShutdownTime', 3, ftBytes(SHUTDOWN)));
    });
    cs.key('Services', {}, (svc) => {
      svc.key('Svc1', {}, (k) => {
        k.value('Type', 4, 0x10);
        k.value('Start', 4, 2);
        k.value('ImagePath', 1, 'C:\\svc1.exe');
        k.value('DisplayName', 1, 'Service One');
        k.value('ObjectName', 1, 'LocalSystem');
      });
      svc.key('Tcpip', {}, (tcp) => tcp.key('Parameters', {}, (pr) => {
        pr.value('Hostname', 1, 'win-test');
        pr.value('Domain', 1, 'corp.example');
        pr.key('Interfaces', {}, (ifs) => ifs.key('{iface-guid}', {}, (i) => {
          i.value('DhcpIPAddress', 1, '10.0.0.5');
          i.value('DhcpDomain', 1, 'dhcp.example');
        }));
      }));
    });
    cs.key('Enum', {}, (e) => e.key('USBStor', {}, (us) => us.key('Disk&Ven_X', {}, (dev) => dev.key('12345&0', {}, (inst) => {
      inst.value('FriendlyName', 1, 'My USB Drive');
      inst.value('Mfg', 1, 'ACME');
      inst.key('Properties', {}, (p) => p.key('{83da6326-97a6-4088-9453-a1923f573b29}', {}, (g) => g.key('0064', {}, (sk) => sk.value('', 3, ftBytes(USB_INSTALL)))));
    }))));
  });
}).toBuffer());

const text = (name) => RV.ui.viewModel.reportText(runtime.run(name, hive));

test('compname: ComputerName + hostname + domain', () => {
  const t = text('compname');
  assert.match(t, /WIN-TEST/);
  assert.match(t, /WIN-ACTIVE/);
  assert.match(t, /win-test/);
  assert.match(t, /corp\.example/);
});

test('timezone: names and bias in hours', () => {
  const t = text('timezone');
  assert.match(t, /Eastern Standard Time/);
  assert.match(t, /Bias\s+300 \(5 hours\)/);
  assert.match(t, /ActiveTimeBias\s+240 \(4 hours\)/);
});

test('shutdown: decodes binary FILETIME', () => {
  assert.match(text('shutdown'), /ShutdownTime\s+2023-06-15 10:00:00 UTC/);
});

test('services: decodes type/start and lists fields', () => {
  const t = text('services');
  assert.match(t, /Svc1/);
  assert.match(t, /Own_Process/);
  assert.match(t, /Auto Start/);
  assert.match(t, /C:\\svc1\.exe/);
});

test('usbstor: friendly name + property timestamp', () => {
  const t = text('usbstor');
  assert.match(t, /My USB Drive/);
  assert.match(t, /First Install\s+2023-01-02 03:04:05 UTC/);
});

test('ips: reports DHCP address + domain', () => {
  const t = text('ips');
  assert.match(t, /10\.0\.0\.5/);
  assert.match(t, /dhcp\.example/);
});

test('mountdev: drive signature, volume GUID, device', () => {
  const t = text('mountdev');
  assert.match(t, /44 33 22 11/);
  assert.match(t, /Volume GUID: \{/);
  assert.match(t, /HarddiskVolume2/);
});

test('missing key: plugin reports gracefully, no error', () => {
  const empty = RV.reg.openHive(new HiveBuilder().build((r) => r.key('Nothing')).toBuffer());
  const res = runtime.run('compname', empty);
  assert.strictEqual(res.error, null);
  assert.match(RV.ui.viewModel.reportText(res), /not found/);
});
