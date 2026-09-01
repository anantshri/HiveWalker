// rv.plugins — auto-imported RegRipper "simple" plugin descriptors.
// Generated from RegRipper 4.0 plugins that follow regular key/value/subkey
// read patterns (no bespoke binary decoding, no user intervention). Each entry
// is data consumed by RV.plugins.simple (see 32-simple.js). Bespoke plugins
// live in 40-43; binary-decoder plugins are a separate follow-up.
// RegRipper is by H. Carvey (keydet89) — https://github.com/keydet89/RegRipper4.0
// (RR 3.0: MIT; RR 4.0: personal/academic use only — see NOTICE.md)
(function (RV) {
  'use strict';
  RV.plugins.simple.registerAll([
  {
    "name": "allow_upgrade",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1601",
    "version": "2023075",
    "shortDescr": "Check for AllowUpgradesWithUnsupportedTPMOrCPU value",
    "mode": "named",
    "paths": [
      "Setup\\MoSetup"
    ],
    "names": [
      "AllowUpgradesWithUnsupportedTPMOrCPU"
    ]
  },
  {
    "name": "allowedenum",
    "hives": [
      "ntuser",
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1564.001",
    "version": "20200813",
    "shortDescr": "Extracts AllowedEnumeration values to determine hidden special folders",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AllowedEnumeration",
      "Microsoft\\Windows\\CurrentVersion\\Explorer\\AllowedEnumeration"
    ]
  },
  {
    "name": "amsienable",
    "hives": [
      "ntuser"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20210217",
    "shortDescr": "Gets user's AMSIEnable value",
    "mode": "named",
    "paths": [
      "Software\\Microsoft\\Windows Script\\Settings"
    ],
    "names": [
      "AmsiEnable"
    ]
  },
  {
    "name": "appassoc",
    "hives": [
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1546.001",
    "version": "20200813",
    "shortDescr": "Gets contents of user's ApplicationAssociationToasts key",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\ApplicationAssociationToasts"
    ]
  },
  {
    "name": "appcertdlls",
    "hives": [
      "system"
    ],
    "category": "privilege escalation",
    "mitre": "T1546.009",
    "version": "20200813",
    "shortDescr": "Get entries from AppCertDlls key",
    "mode": "values",
    "paths": [
      "Control\\Session Manager\\AppCertDlls"
    ],
    "ccs": true
  },
  {
    "name": "appkeys",
    "hives": [
      "ntuser",
      "software"
    ],
    "category": "persistence",
    "mitre": "",
    "version": "20200813",
    "shortDescr": "Extracts AppKeys entries.",
    "mode": "subkeys",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\AppKey",
      "Microsoft\\Windows\\CurrentVersion\\Explorer\\AppKey"
    ],
    "subkeyNames": [
      "ShellExecute",
      "Association"
    ]
  },
  {
    "name": "appmodel",
    "hives": [
      "software"
    ],
    "category": "privilege escalation",
    "mitre": "T1548.002",
    "version": "20230703",
    "shortDescr": "Gets AppModelUnlock values",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\AppModelUnlock"
    ],
    "names": [
      "AllowAllTrustedApps",
      "AllowDevelopmentWithoutDevLicense"
    ]
  },
  {
    "name": "apppaths",
    "hives": [
      "ntuser",
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200813",
    "shortDescr": "Gets content of App Paths subkeys",
    "mode": "subkeys",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\App Paths",
      "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths",
      "Software\\Microsoft\\Windows\\CurrentVersion\\App Paths",
      "Wow6432Node\\Software\\Microsoft\\Windows\\CurrentVersion\\App Paths"
    ],
    "subkeyNames": [
      ""
    ]
  },
  {
    "name": "appsetup",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "T1546",
    "version": "20200909",
    "shortDescr": "Get autolaunch entries for when user connects to Terminal Server",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\WinLogon"
    ],
    "names": [
      "AppSetup"
    ]
  },
  {
    "name": "assoc",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "T1546.001",
    "version": "20220829",
    "shortDescr": "Get shell\\open\\command settings for various file types",
    "mode": "named",
    "paths": [
      "Classes\\exefile\\shell\\open\\command",
      "Classes\\evtfile\\shell\\open\\command",
      "Classes\\evtxfile\\shell\\open\\command",
      "Classes\\inifile\\shell\\open\\command",
      "Classes\\Excel.CSV\\shell\\open\\command",
      "Classes\\WSFFile\\shell\\open\\command"
    ],
    "names": [
      ""
    ]
  },
  {
    "name": "attachmgr",
    "hives": [
      "ntuser"
    ],
    "category": "defense evasion",
    "mitre": "T1553.005",
    "version": "20220926",
    "shortDescr": "Checks user's keys that manage the Attachment Manager functionality",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Associations",
      "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Attachments"
    ]
  },
  {
    "name": "auth",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200816",
    "shortDescr": "Gets Authentication info",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI"
    ],
    "names": [
      "LastLoggedOnSAMUser",
      "LastLoggedOnUser",
      "LastLoggedOnDisplayName",
      "LastLoggedOnUserSID"
    ]
  },
  {
    "name": "autoadminlogon",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "T1078.003",
    "version": "20220829",
    "shortDescr": "Get autoadminlogon settings",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\WinLogon"
    ],
    "names": [
      "AutoAdminLogon",
      "DefaultPassword"
    ]
  },
  {
    "name": "autodialdll",
    "hives": [
      "system"
    ],
    "category": "persistence",
    "mitre": "T1546",
    "version": "20221026",
    "shortDescr": "Get AutodialDLL DLL",
    "mode": "named",
    "paths": [
      "Services\\WinSock2\\Parameters"
    ],
    "ccs": true,
    "names": [
      "AutodialDLL"
    ]
  },
  {
    "name": "automount",
    "hives": [
      "system"
    ],
    "category": "initial access",
    "mitre": "T1091",
    "version": "20221010",
    "shortDescr": "Get automount Settings",
    "mode": "named",
    "paths": [
      "Services\\mountmgr"
    ],
    "ccs": true,
    "names": [
      "NoAutoMount"
    ]
  },
  {
    "name": "backuprestore",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20201012",
    "shortDescr": "Gets the contents of the FilesNotToSnapshot, KeysNotToRestore, and FilesNotToBackup keys",
    "mode": "values",
    "paths": [
      "Control\\BackupRestore\\FilesNotToSnapshot",
      "Control\\BackupRestore\\FilesNotToBackup",
      "Control\\BackupRestore\\KeysNotToRestore"
    ],
    "ccs": true
  },
  {
    "name": "bitbucket",
    "hives": [
      "ntuser"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20221129",
    "shortDescr": "Gets user's BitBucket settings",
    "mode": "subkeys",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\BitBucket\\Volume"
    ],
    "subkeyNames": [
      "MaxCapacity",
      "NukeOnDelete"
    ]
  },
  {
    "name": "calibrator",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "T1548.002",
    "version": "20200904",
    "shortDescr": "Checks DisplayCalibrator value (possible bypass assoc with LockBit ransomware)",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\ICM\\Calibration"
    ],
    "names": [
      "DisplayCalibrator"
    ]
  },
  {
    "name": "certpadding",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1562",
    "version": "20220110",
    "shortDescr": "Check EnableCertPaddingCheck value",
    "mode": "named",
    "paths": [
      "Microsoft\\Cryptography\\WintrustConfig",
      "Wow6432Node\\Microsoft\\Cryptography\\WintrustConfig"
    ],
    "names": [
      "EnableCertPaddingCheck"
    ]
  },
  {
    "name": "cmdproc",
    "hives": [
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1546",
    "version": "20200904",
    "shortDescr": "Autostart - get Command Processor\\AutoRun value from NTUSER.DAT hive",
    "mode": "named",
    "paths": [
      "Software\\Microsoft\\Command Processor"
    ],
    "names": [
      "AutoRun"
    ]
  },
  {
    "name": "codepage",
    "hives": [
      "system"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200904",
    "shortDescr": "Checks codepage value",
    "mode": "named",
    "paths": [
      "Control\\Nls\\CodePage"
    ],
    "ccs": true,
    "names": [
      "ACP"
    ]
  },
  {
    "name": "compdesc",
    "hives": [
      "ntuser"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200904",
    "shortDescr": "Gets contents of user's ComputerDescriptions key",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComputerDescriptions"
    ]
  },
  {
    "name": "cred",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1112",
    "version": "20200730",
    "shortDescr": "Checks for UseLogonCredential value",
    "mode": "named",
    "paths": [
      "Control\\SecurityProviders\\WDigest"
    ],
    "ccs": true,
    "names": [
      "UseLogonCredential"
    ]
  },
  {
    "name": "dafupnp",
    "hives": [
      "system"
    ],
    "category": "devices",
    "mitre": "",
    "version": "20200904",
    "shortDescr": "Parses data from networked media streaming devices",
    "mode": "subkeys",
    "paths": [
      "Enum\\SWD\\DAFUPnPProvider"
    ],
    "ccs": true,
    "subkeyNames": [
      "DeviceDesc",
      "CompatibleIDs",
      "HardwareID",
      "LocationInformation",
      "Mfg",
      "FriendlyName"
    ]
  },
  {
    "name": "databasepath",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1564",
    "version": "20201021",
    "shortDescr": "Get DataBasePath value from System hive",
    "mode": "named",
    "paths": [
      "Services\\Tcpip\\Parameters"
    ],
    "ccs": true,
    "names": [
      "DataBasePath"
    ]
  },
  {
    "name": "datatracing",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "T1546",
    "version": "20201018",
    "shortDescr": "Checks for MS SQL data tracing DLL",
    "mode": "named",
    "paths": [
      "Microsoft\\BidInterface\\Loader",
      "Wow6432Node\\Microsoft\\BidInterface\\Loader"
    ],
    "names": [
      ":Path"
    ]
  },
  {
    "name": "dcom",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200904",
    "shortDescr": "Check DCOM Ports",
    "mode": "named",
    "paths": [
      "Microsoft\\Rpc\\Internet"
    ],
    "names": [
      "Ports",
      "PortsInternetAvailable",
      "UseInternetPorts"
    ]
  },
  {
    "name": "ddo",
    "hives": [
      "ntuser"
    ],
    "category": "devices",
    "mitre": "",
    "version": "20200904",
    "shortDescr": "Gets user's DeviceDisplayObjects key contents",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\Windows NT\\CurrentVersion\\DeviceDisplayObjects"
    ]
  },
  {
    "name": "defrag",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1027",
    "version": "20201130",
    "shortDescr": "Get Defrag LastRun value",
    "mode": "named",
    "paths": [
      "Control\\Session Manager\\Configuration Manager\\Defrag"
    ],
    "ccs": true,
    "names": [
      "LastRun"
    ]
  },
  {
    "name": "diagnostics",
    "hives": [
      "software"
    ],
    "category": "execution",
    "mitre": "T1203",
    "version": "20220531",
    "shortDescr": "Get ScriptedDiagnostics settings",
    "mode": "named",
    "paths": [
      "Policies\\Microsoft\\Windows\\ScriptedDiagnostics"
    ],
    "names": [
      "EnableDiagnostics",
      "ValidateTrust"
    ]
  },
  {
    "name": "disable445",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20220921",
    "shortDescr": "Determine if SMB over NetBIOS is disabled",
    "mode": "named",
    "paths": [
      "Services\\NetBT\\Parameters"
    ],
    "ccs": true,
    "names": [
      "SMBDeviceEnabled"
    ]
  },
  {
    "name": "disableonedrive",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20220614",
    "shortDescr": "Check DisableFileSyncNGSC value",
    "mode": "named",
    "paths": [
      "Policies\\Microsoft\\Windows\\OneDrive"
    ],
    "names": [
      "DisableFileSyncNGSC"
    ]
  },
  {
    "name": "disableproxy",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20211025",
    "shortDescr": "Get disableproxy settings",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Internet Settings",
      "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"
    ],
    "names": [
      "DisableProxyAuthenticationSchemes"
    ]
  },
  {
    "name": "disableremotescm",
    "hives": [
      "system"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200831",
    "shortDescr": "Gets DisableRemoteScmEndpoints value from System hive",
    "mode": "named",
    "paths": [
      "Control"
    ],
    "ccs": true,
    "names": [
      "DisableRemoteScmEndpoints"
    ]
  },
  {
    "name": "disablesr",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20200911",
    "shortDescr": "Gets the value that turns System Restore either on or off",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\SystemRestore"
    ],
    "names": [
      "DisableSR"
    ]
  },
  {
    "name": "dllsearch",
    "hives": [
      "system"
    ],
    "category": "persistence",
    "mitre": "T1574.001",
    "version": "20210705",
    "shortDescr": "Check values that impact DLL Search Order loading",
    "mode": "named",
    "paths": [
      "Control\\Session Manager"
    ],
    "ccs": true,
    "names": [
      "CWDIllegalInDllSearch",
      "SafeDLLSearchMode"
    ]
  },
  {
    "name": "dnsclient",
    "hives": [
      "software"
    ],
    "category": "",
    "mitre": "",
    "version": "202010504",
    "shortDescr": "Check if LLMNR/NBT-NS is disabled",
    "mode": "named",
    "paths": [
      "Software\\Policies\\Microsoft\\Windows NT\\DNSClient"
    ],
    "names": [
      "EnableMulticast"
    ]
  },
  {
    "name": "driverinstall",
    "hives": [
      "software"
    ],
    "category": "",
    "mitre": "",
    "version": "20221024",
    "shortDescr": "Check driverinstall settings",
    "mode": "values",
    "paths": [
      "Policies\\Microsoft\\Windows\\DriverInstall\\Restrictions\\AllowUserDeviceClasses"
    ]
  },
  {
    "name": "duo",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20220927",
    "shortDescr": "Get DUO config",
    "mode": "values",
    "paths": [
      "Duo Security\\DuoCredProv",
      "Policies\\Duo Security\\DuoCredProv"
    ]
  },
  {
    "name": "enablelinkedconn",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1112",
    "version": "20220707",
    "shortDescr": "Gets EnableLinkedConnections value",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    ],
    "names": [
      "EnableLinkedConnections"
    ]
  },
  {
    "name": "eventsasp",
    "hives": [
      "software"
    ],
    "category": "user execution",
    "mitre": "T1204.001",
    "version": "20230217",
    "shortDescr": "",
    "mode": "named",
    "paths": [
      "Policies\\Microsoft\\EventViewer",
      "Microsoft\\Windows NT\\CurrentVersion\\Event Viewer"
    ],
    "names": [
      "MicrosoftEventVwrDisableLinks",
      "MicrosoftRedirectionURL",
      "MicrosoftRedirectionProgram",
      "MicrosoftRedirectionProgramCommandLineParameters",
      "ConfirmURL"
    ]
  },
  {
    "name": "eventtranscript",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20210927",
    "shortDescr": "Get EventTranscript.db settings",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection",
      "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection",
      "Policies\\Microsoft\\Windows\\DataCollection"
    ],
    "names": [
      "AllowTelemetry",
      "MaxTelemetryAllowed"
    ]
  },
  {
    "name": "execpolicy",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200911",
    "shortDescr": "Gets PowerShell Execution Policy",
    "mode": "named",
    "paths": [
      "Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.Powershell"
    ],
    "names": [
      "ExecutionPolicy"
    ]
  },
  {
    "name": "feature_block",
    "hives": [
      "software"
    ],
    "category": "lateral movement",
    "mitre": "T1210",
    "version": "20230724",
    "shortDescr": "Get FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION key values",
    "mode": "values",
    "paths": [
      "Software\\Policies\\Microsoft\\Internet Explorer\\Main\\FeatureControl\\FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION"
    ]
  },
  {
    "name": "fsdepends",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1553.005",
    "version": "20220809",
    "shortDescr": "Get VHD[X] Settings",
    "mode": "named",
    "paths": [
      "Services\\FsDepends\\Parameters"
    ],
    "ccs": true,
    "names": [
      "VirtualDiskExpandOnMount",
      "VirtualDiskMaxTreeDepth",
      "VirtualDiskNoLocalMount"
    ]
  },
  {
    "name": "guestauth",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1112",
    "version": "20201105",
    "shortDescr": "Gets AllowInsecureGuestAuth value",
    "mode": "named",
    "paths": [
      "Services\\LanmanWorkstation\\Parameters"
    ],
    "ccs": true,
    "names": [
      "AllowInsecureGuestAuth"
    ]
  },
  {
    "name": "hello",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20210315",
    "shortDescr": "Check to see if \"Require Windows Hello Sign-in\" is enabled.",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\PasswordLess\\Device"
    ],
    "names": [
      "DevicePasswordLessBuildVersion"
    ]
  },
  {
    "name": "identities",
    "hives": [
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1078",
    "version": "20200911",
    "shortDescr": "Extracts values from Identities key; NTUSER.DAT",
    "mode": "values",
    "paths": [
      "Identities"
    ]
  },
  {
    "name": "imagefile",
    "hives": [
      "software",
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1546.012",
    "version": "20200730",
    "shortDescr": "Checks Image File Execution Options subkeys values",
    "mode": "subkeys",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
      "Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
      "Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
      "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
    ]
  },
  {
    "name": "improviders",
    "hives": [
      "ntuser"
    ],
    "category": "user activity",
    "mitre": "",
    "version": "20201015",
    "shortDescr": "Get IM providers from NTUSER.DAT",
    "mode": "subkeys",
    "paths": [
      "Software\\IM Providers"
    ],
    "subkeyNames": [
      "DefaultIMApp",
      "UpAndRunning",
      "ProcessID"
    ]
  },
  {
    "name": "injectdll64",
    "hives": [
      "ntuser",
      "software"
    ],
    "category": "malware",
    "mitre": "",
    "version": "20200911",
    "shortDescr": "Retrieve values set to weaken Chrome security",
    "mode": "values",
    "paths": [
      "Software\\Policies\\Google\\Chrome",
      "Policies\\Google\\Chrome"
    ]
  },
  {
    "name": "inprocserver",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "T1546",
    "version": "20201005",
    "shortDescr": "Checks CLSID InProcServer32 values for indications of malware",
    "mode": "subkeys",
    "paths": [
      "Classes\\CLSID",
      "Classes\\Wow6432Node\\CLSID",
      "CLSID",
      "Wow6432Node\\CLSID"
    ]
  },
  {
    "name": "installelevated",
    "hives": [
      "software",
      "ntuser"
    ],
    "category": "privilege escalation",
    "mitre": "T1546.016",
    "version": "20230703",
    "shortDescr": "Check AlwaysInstallElevated value",
    "mode": "named",
    "paths": [
      "Policies\\Microsoft\\Windows\\Installer",
      "Software\\Policies\\Microsoft\\Windows\\Installer"
    ],
    "names": [
      "AlwaysInstallElevated"
    ]
  },
  {
    "name": "installerlogging",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20230213",
    "shortDescr": "Determines product/MSI install logging",
    "mode": "named",
    "paths": [
      "Policies\\Microsoft\\Windows\\Installer"
    ],
    "names": [
      "logging"
    ]
  },
  {
    "name": "kdc",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1562",
    "version": "20210312",
    "shortDescr": "Get values related to ",
    "mode": "named",
    "paths": [
      "Services\\Kdc"
    ],
    "ccs": true,
    "names": [
      "NonForwardableDelegation",
      "PerformTicketSignature"
    ]
  },
  {
    "name": "lastloggedon",
    "hives": [
      "software"
    ],
    "category": "user activity",
    "mitre": "T1078",
    "version": "20201007",
    "shortDescr": "Gets LastLoggedOn* values from LogonUI key",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI"
    ],
    "names": [
      "LastLoggedOnUser",
      "LastLoggedOnSAMUser",
      "LastLoggedOnUserSID"
    ]
  },
  {
    "name": "licenses",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20201005",
    "shortDescr": "Get contents of HKLM/Software/Licenses key",
    "mode": "values",
    "paths": [
      "Licenses"
    ]
  },
  {
    "name": "listsoft",
    "hives": [
      "ntuser"
    ],
    "category": "config",
    "mitre": "",
    "version": "20201005",
    "shortDescr": "Lists contents of user's Software key",
    "mode": "subkeys",
    "paths": [
      "Software"
    ]
  },
  {
    "name": "load",
    "hives": [
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1547.001",
    "version": "20200921",
    "shortDescr": "Gets load and run values from user hive",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
    ]
  },
  {
    "name": "localdumps",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20220419",
    "shortDescr": "Get WER LocalDumps settings",
    "mode": "subkeys",
    "paths": [
      "Microsoft\\Windows\\Windows Error Reporting\\LocalDumps"
    ],
    "subkeyNames": [
      "DumpFolder"
    ]
  },
  {
    "name": "lsa",
    "hives": [
      "system"
    ],
    "category": "credential access",
    "mitre": "T1003.001",
    "version": "20220302",
    "shortDescr": "Lists specific contents of LSA key",
    "mode": "named",
    "paths": [
      "Control\\LSA"
    ],
    "ccs": true,
    "names": [
      "RunAsPPL",
      "DisableRestrictedAdmin",
      "LsaCfgFlags",
      "LimitBlankPasswordUse"
    ]
  },
  {
    "name": "lsass_auditlevel",
    "hives": [
      "software"
    ],
    "category": "credential access",
    "mitre": "T1003.001",
    "version": "20220119",
    "shortDescr": "Check AuditLevel value for LSASS",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\LSASS\\.exe"
    ],
    "names": [
      "AuditLevel"
    ]
  },
  {
    "name": "lxss",
    "hives": [
      "ntuser"
    ],
    "category": "defense evasion",
    "mitre": "T1564.006",
    "version": "20200927",
    "shortDescr": "Gets WSL config.",
    "mode": "subkeys",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Lxss"
    ],
    "subkeyNames": [
      "DefaultDistribution",
      "DistributionName",
      "KernelCommandLine"
    ]
  },
  {
    "name": "maint",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20210326",
    "shortDescr": "Check for MaintenanceDisabled value",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\Schedule\\Maintenance"
    ],
    "names": [
      "MaintenanceDisabled"
    ]
  },
  {
    "name": "mpnotify",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "T1546",
    "version": "20230702",
    "shortDescr": "Get WinLogon mpnotify setting",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\WinLogon"
    ],
    "names": [
      "mpnotify"
    ]
  },
  {
    "name": "muicache",
    "hives": [
      "ntuser",
      "usrclass"
    ],
    "category": "program execution",
    "mitre": "T1059",
    "version": "20221121",
    "shortDescr": "Gets EXEs from user's MUICache key",
    "mode": "values",
    "paths": [
      "Local Settings\\Software\\Microsoft\\Windows\\Shell\\MUICache",
      "Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache"
    ]
  },
  {
    "name": "nation",
    "hives": [
      "ntuser"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200921",
    "shortDescr": "Gets region information from HKCU",
    "mode": "named",
    "paths": [
      "Control Panel\\International\\Geo"
    ],
    "names": [
      "Nation"
    ]
  },
  {
    "name": "netsh",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "T1546.007",
    "version": "20200813",
    "shortDescr": "Gets list of NetSH helper DLLs",
    "mode": "values",
    "paths": [
      "Microsoft\\Netsh"
    ]
  },
  {
    "name": "networkprotection",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20221114",
    "shortDescr": "Get Windows Defender NetworkProtection settings",
    "mode": "named",
    "paths": [
      "Policies\\Microsoft\\Windows Defender\\Policy Manager",
      "Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\NetworkProtection"
    ],
    "names": [
      "EnableNetworkProtection"
    ]
  },
  {
    "name": "ntds",
    "hives": [
      "system"
    ],
    "category": "persistence",
    "mitre": "T1547.008",
    "version": "20200921",
    "shortDescr": "Parse Services NTDS key for specific persistence values",
    "mode": "named",
    "paths": [
      "Services\\NTDS"
    ],
    "ccs": true,
    "names": [
      "LsaDbExtPt",
      "DirectoryServiceExtPt"
    ]
  },
  {
    "name": "osversion",
    "hives": [
      "ntuser"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200921",
    "shortDescr": "Checks for OSVersion value",
    "mode": "named",
    "paths": [
      "Software\\Microsoft"
    ],
    "names": [
      "OSVersion"
    ]
  },
  {
    "name": "pagefile",
    "hives": [
      "system"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200921",
    "shortDescr": "Get info on pagefile(s)",
    "mode": "named",
    "paths": [
      "Control\\Session Manager\\Memory Management"
    ],
    "ccs": true,
    "names": [
      "PagingFiles",
      "ExistingPageFiles",
      "ClearPageFileAtShutdown"
    ]
  },
  {
    "name": "pending",
    "hives": [
      "system"
    ],
    "category": "persistence",
    "mitre": "T1547",
    "version": "20230510",
    "shortDescr": "Gets contents of PendingFileRenameOperations value",
    "mode": "named",
    "paths": [
      "Control\\Session Manager"
    ],
    "ccs": true,
    "names": [
      "PendingFileRenameOperations"
    ]
  },
  {
    "name": "pendinggpos",
    "hives": [
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1547",
    "version": "20200922",
    "shortDescr": "Gets contents of user's PendingGPOs key",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\IEAK\\GroupPolicy\\PendingGPOs"
    ]
  },
  {
    "name": "perf",
    "hives": [
      "system"
    ],
    "category": "privilege escalation",
    "mitre": "T1543.003",
    "version": "20201130",
    "shortDescr": "Get EnablePeriodicBackup value",
    "mode": "named",
    "paths": [
      "Services\\RpcEptMapper\\Performance",
      "Services\\Dnscache\\Performance"
    ],
    "ccs": true,
    "names": [
      "Library",
      "Open",
      "Collect",
      "Close"
    ]
  },
  {
    "name": "persistconn",
    "hives": [
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1547.015",
    "version": "20230109",
    "shortDescr": "Gets Persistent Connections values",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\Windows NT\\CurrentVersion\\Network\\Persistent Connections"
    ]
  },
  {
    "name": "pointandprint",
    "hives": [
      "software"
    ],
    "category": "privilege escalation",
    "mitre": "T1068",
    "version": "20210705",
    "shortDescr": "Check Point & Print restrition values",
    "mode": "named",
    "paths": [
      "Policies\\Microsoft\\Windows NT\\Printers\\PointAndPrint"
    ],
    "names": [
      "NoWarningNoElevationOnInstall",
      "NoWarningNoElevationOnUpdate",
      "NoElevationOnInstall"
    ]
  },
  {
    "name": "portproxy",
    "hives": [
      "system"
    ],
    "category": "config",
    "mitre": "T1572",
    "version": "20200929",
    "shortDescr": "Check port proxy settings, set via netsh",
    "mode": "values",
    "paths": [
      "services\\PortProxy\\v4tov4\\tcp"
    ],
    "ccs": true
  },
  {
    "name": "ports",
    "hives": [
      "software"
    ],
    "category": "privilege escalation",
    "mitre": "T1068",
    "version": "20210309",
    "shortDescr": "Check port assignments",
    "mode": "values",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\Ports"
    ]
  },
  {
    "name": "prefetch",
    "hives": [
      "system"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200922",
    "shortDescr": "Gets the the Prefetch Parameters",
    "mode": "named",
    "paths": [
      "Control\\Session Manager\\Memory Management\\PrefetchParameters"
    ],
    "ccs": true,
    "names": [
      "EnablePrefetcher"
    ]
  },
  {
    "name": "printmon",
    "hives": [
      "system"
    ],
    "category": "persistence",
    "mitre": "T1546",
    "version": "20200922",
    "shortDescr": "Lists installed Print Monitors",
    "mode": "subkeys",
    "paths": [
      "Control\\Print\\Monitors"
    ],
    "ccs": true,
    "subkeyNames": [
      "Driver"
    ]
  },
  {
    "name": "processor_architecture",
    "hives": [
      "system"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200922",
    "shortDescr": "Get from the processor architecture System hive",
    "mode": "named",
    "paths": [
      "Control\\Session Manager\\Environment"
    ],
    "ccs": true,
    "names": [
      "PROCESSOR_ARCHITECTURE",
      "PROCESSOR_IDENTIFIER",
      "PROCESSOR_REVISION"
    ]
  },
  {
    "name": "putty",
    "hives": [
      "ntuser"
    ],
    "category": "lateral movement",
    "mitre": "T1021",
    "version": "20200924",
    "shortDescr": "Extracts the saved SshHostKeys for PuTTY.",
    "mode": "values",
    "paths": [
      "Software\\SimonTatham\\PuTTY\\SshHostKeys"
    ]
  },
  {
    "name": "railrunonce",
    "hives": [
      "system"
    ],
    "category": "persistence",
    "mitre": "T1547.001",
    "version": "20201020",
    "shortDescr": "Checks RemoteApp shell persistence",
    "mode": "values",
    "paths": [
      "Control\\Terminal Server\\RailRunonce"
    ],
    "ccs": true
  },
  {
    "name": "rdplockout",
    "hives": [
      "system"
    ],
    "category": "initial access",
    "mitre": "T1133",
    "version": "20220809",
    "shortDescr": "Queries System hive for RDP Lockout Settings",
    "mode": "named",
    "paths": [
      "Services\\RemoteAccess\\Parameters\\AccountLockout"
    ],
    "ccs": true,
    "names": [
      "MaxDenials",
      "ResetTime (mins)"
    ]
  },
  {
    "name": "rdpport",
    "hives": [
      "system"
    ],
    "category": "initial access",
    "mitre": "T1133",
    "version": "20220809",
    "shortDescr": "Queries System hive for RDP Port",
    "mode": "named",
    "paths": [
      "Control\\Terminal Server\\WinStations\\RDP-Tcp"
    ],
    "ccs": true,
    "names": [
      "PortNumber"
    ]
  },
  {
    "name": "regback",
    "hives": [
      "system"
    ],
    "category": "config",
    "mitre": "",
    "version": "20201130",
    "shortDescr": "Get EnablePeriodicBackup value",
    "mode": "named",
    "paths": [
      "Control\\Session Manager\\Configuration Manager"
    ],
    "ccs": true,
    "names": [
      "EnablePeriodicBackup"
    ]
  },
  {
    "name": "registerspooler",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20210705",
    "shortDescr": "Look for BlackLivesMatter key assoc. w/ REvil ransomware",
    "mode": "named",
    "paths": [
      "Policies\\Microsoft\\Windows NT\\Printers"
    ],
    "names": [
      "RegisterSpoolerRemoteRpcEndPoint"
    ]
  },
  {
    "name": "remoteuac",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1562",
    "version": "20220101",
    "shortDescr": "Get setting for remote UAC",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Policies\\System"
    ],
    "names": [
      "LocalAccountTokenFilterPolicy"
    ]
  },
  {
    "name": "restartmanager",
    "hives": [
      "ntuser"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20210111",
    "shortDescr": "Gets RestartManager\\Session0000 values",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\RestartManager\\Session0000"
    ]
  },
  {
    "name": "run_yara",
    "hives": [
      "software",
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1547.001",
    "version": "20230811",
    "shortDescr": "Get autostart key contents from Software hive",
    "mode": "values",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Run",
      "Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "Microsoft\\Windows\\CurrentVersion\\RunServices",
      "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
      "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
      "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
      "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
      "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
      "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
      "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce",
      "Software\\Microsoft\\Windows NT\\CurrentVersion\\Terminal Server\\Install",
      "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
      "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"
    ]
  },
  {
    "name": "screensaver",
    "hives": [
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1546.002",
    "version": "20220427",
    "shortDescr": "Gets user's screensaver settings",
    "mode": "values",
    "paths": [
      "Control Panel\\Desktop"
    ]
  },
  {
    "name": "screenshotindex",
    "hives": [
      "ntuser"
    ],
    "category": "collection",
    "mitre": "T1074.001",
    "version": "20230713",
    "shortDescr": "Checks user's ScreenshotIndex value",
    "mode": "named",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
    ],
    "names": [
      "ScreenshotIndex"
    ]
  },
  {
    "name": "searchscopes",
    "hives": [
      "ntuser"
    ],
    "category": "user activity",
    "mitre": "",
    "version": "20201005",
    "shortDescr": "Gets contents of user's SearchScopes key",
    "mode": "subkeys",
    "paths": [
      "Software\\Microsoft\\Internet Explorer\\SearchScopes"
    ],
    "subkeyNames": [
      "DefaultScope",
      "DisplayName"
    ]
  },
  {
    "name": "secctr",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20201005",
    "shortDescr": "Get data from Security Center key",
    "mode": "values",
    "paths": [
      "Microsoft\\Security Center"
    ]
  },
  {
    "name": "securityproviders",
    "hives": [
      "system"
    ],
    "category": "persistence",
    "mitre": "T1547.005",
    "version": "20201005",
    "shortDescr": "Gets SecurityProvider value from System hive",
    "mode": "named",
    "paths": [
      "Control\\SecurityProviders"
    ],
    "ccs": true,
    "names": [
      "SecurityProviders"
    ]
  },
  {
    "name": "shadow",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1112",
    "version": "20210425",
    "shortDescr": "Shadow value allows for eavesdropping on RDP connections",
    "mode": "named",
    "paths": [
      "Policies\\Microsoft\\Windows NT\\Terminal Services"
    ],
    "names": [
      "Shadow"
    ]
  },
  {
    "name": "shc",
    "hives": [
      "ntuser"
    ],
    "category": "config",
    "mitre": "",
    "version": "20201005",
    "shortDescr": "Gets SHC entries from user hive",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\UFH\\SHC"
    ]
  },
  {
    "name": "shellfolders",
    "hives": [
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1547.001",
    "version": "20201005",
    "shortDescr": "Gets user's shell folders values",
    "mode": "named",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders"
    ],
    "names": [
      "Startup"
    ]
  },
  {
    "name": "shelloverlay",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "T1546.015",
    "version": "20201007",
    "shortDescr": "Gets ShellIconOverlayIdentifiers values",
    "mode": "subkeys",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Explorer\\ShellIconOverlayIdentifiers"
    ]
  },
  {
    "name": "smartscreen",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20221108",
    "shortDescr": "Check Windows Defender SmartScreen settings",
    "mode": "named",
    "paths": [
      "Policies\\Microsoft\\Windows\\System",
      "Microsoft\\Windows\\CurrentVersion\\Explorer"
    ],
    "names": [
      "EnableSmartScreen",
      "ShellSmartScreenLevel",
      "SmartScreenEnabled"
    ]
  },
  {
    "name": "smb",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1562",
    "version": "20220101",
    "shortDescr": "Get SMB server settings (v1, v2, v3)",
    "mode": "named",
    "paths": [
      "Services\\LanmanServer\\Parameters"
    ],
    "ccs": true,
    "names": [
      "SMB1",
      "SMB2"
    ]
  },
  {
    "name": "sourcerouting",
    "hives": [
      "system"
    ],
    "category": "execution",
    "mitre": "T1203",
    "version": "20210212",
    "shortDescr": "Get Source Routing setting",
    "mode": "named",
    "paths": [
      "Services\\Tcpip\\Parameters"
    ],
    "ccs": true,
    "names": [
      "DisableIPSourceRouting"
    ]
  },
  {
    "name": "speech",
    "hives": [
      "ntuser"
    ],
    "category": "program execution",
    "mitre": "T1059",
    "version": "20201005",
    "shortDescr": "Get values from user's Speech key",
    "mode": "named",
    "paths": [
      "Software\\Microsoft\\Speech",
      "CurrentUserLexicon\\{C9E37C15-DF92-4727-85D6-72E5EEB6995A}\\Files"
    ],
    "names": [
      "Datafile",
      "DefaultTokenId"
    ]
  },
  {
    "name": "spooler",
    "hives": [
      "system"
    ],
    "category": "privilege escalation",
    "mitre": "T1547.012",
    "version": "20230715",
    "shortDescr": "Check Spooler service RequiredPrivileges value",
    "mode": "named",
    "paths": [
      "Services\\Spooler"
    ],
    "ccs": true,
    "names": [
      "RequiredPrivileges"
    ]
  },
  {
    "name": "spp_clients",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20201005",
    "shortDescr": "Determines volumes monitored by VSS",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows NT\\CurrentVersion\\SPP\\Clients"
    ],
    "names": [
      "{09F7EDC5-294E-4180-AF6A-FB0E6A0E9513}"
    ]
  },
  {
    "name": "staginginfo",
    "hives": [
      "ntuser"
    ],
    "category": "collection",
    "mitre": "T1074.001",
    "version": "20210407",
    "shortDescr": "Get info regarding CD burning",
    "mode": "subkeys",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\CD Burning\\StagingInfo"
    ],
    "subkeyNames": [
      "StagingPath",
      "Active",
      "DriveNumber"
    ]
  },
  {
    "name": "storagesense",
    "hives": [
      "software",
      "ntuser"
    ],
    "category": "persistence",
    "mitre": "T1547",
    "version": "20201230",
    "shortDescr": "Get StorageSense values",
    "mode": "values",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters\\StoragePolicy",
      "Microsoft\\Windows\\CurrentVersion\\StorageSense\\Parameters",
      "Policies\\Microsoft\\Windows\\StorageSense"
    ]
  },
  {
    "name": "sysinternals",
    "hives": [
      "ntuser"
    ],
    "category": "program execution",
    "mitre": "T1204",
    "version": "20220824",
    "shortDescr": "Checks for SysInternals apps keys",
    "mode": "subkeys",
    "paths": [
      "Software\\SysInternals"
    ],
    "subkeyNames": [
      "EulaAccepted"
    ]
  },
  {
    "name": "teamviewer",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "",
    "version": "20211025",
    "shortDescr": "Get Teamviewer Always_Online setting",
    "mode": "named",
    "paths": [
      "TeamViewer",
      "Wow6432Node\\TeamViewer"
    ],
    "names": [
      "Always_Online"
    ]
  },
  {
    "name": "termserv",
    "hives": [
      "system",
      "software"
    ],
    "category": "persistence",
    "mitre": "T1133",
    "version": "20220908",
    "shortDescr": "Gets Terminal Server settings from System and Software hives",
    "mode": "values",
    "paths": [
      "Policies\\Microsoft\\Windows NT\\Terminal Services",
      "Control\\Terminal Server",
      "Wds\\rdpwd",
      "WinStations\\RDP-Tcp"
    ],
    "ccs": true
  },
  {
    "name": "tgt",
    "hives": [
      "system"
    ],
    "category": "credential access",
    "mitre": "T1558.003",
    "version": "20201116",
    "shortDescr": "Lists allowtgtsessionkey value data",
    "mode": "named",
    "paths": [
      "Control\\LSA\\Kerberos\\Parameters"
    ],
    "ccs": true,
    "names": [
      "allowtgtsessionkey"
    ]
  },
  {
    "name": "thumbnail_cleanup",
    "hives": [
      "software"
    ],
    "category": "collection",
    "mitre": "T1005",
    "version": "20210315",
    "shortDescr": "Get Thumbnail Cache Autorun value",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\Thumbnail Cache",
      "Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VolumeCaches\\Thumbnail Cache"
    ],
    "names": [
      "Autorun"
    ]
  },
  {
    "name": "timeproviders",
    "hives": [
      "system"
    ],
    "category": "program execution",
    "mitre": "T1547.003",
    "version": "20200813",
    "shortDescr": "Check time providers for hijacking",
    "mode": "named",
    "paths": [
      "Services\\W32Time\\TimeProviders"
    ],
    "ccs": true,
    "names": [
      "DllName"
    ]
  },
  {
    "name": "tracing",
    "hives": [
      "software"
    ],
    "category": "program execution",
    "mitre": "",
    "version": "20200924",
    "shortDescr": "Gets list of apps that can be traced",
    "mode": "subkeys",
    "paths": [
      "Microsoft\\Tracing",
      "Wow6432Node\\Microsoft\\Tracing"
    ]
  },
  {
    "name": "trailersupport",
    "hives": [
      "system"
    ],
    "category": "config",
    "mitre": "",
    "version": "20220111",
    "shortDescr": "Check EnableTrailerSupport value (CVE-2022-21907)",
    "mode": "named",
    "paths": [
      "Services\\HTTP\\Parameters"
    ],
    "ccs": true,
    "names": [
      "EnableTrailerSupport"
    ]
  },
  {
    "name": "tsutilities",
    "hives": [
      "system"
    ],
    "category": "persistence",
    "mitre": "T1547",
    "version": "20200806",
    "shortDescr": "Checks TermServ Utilities",
    "mode": "subkeys",
    "paths": [
      "Control\\Terminal Server\\Utilities"
    ],
    "ccs": true
  },
  {
    "name": "ua_wiper",
    "hives": [
      "ntuser"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20220301",
    "shortDescr": "Settings associated with wiper found in the Ukraine",
    "mode": "named",
    "paths": [
      "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced"
    ],
    "names": [
      "ShowCompColor",
      "ShowInfoTip"
    ]
  },
  {
    "name": "uac",
    "hives": [
      "software"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20220826",
    "shortDescr": "Get Select User Account Control (UAC) Values from HKLMSOFTWAREMicrosoftWindowsCurrentVersionPoliciesSystem",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\policies\\system"
    ],
    "names": [
      "EnableLUA",
      "EnableVirtualization",
      "FilterAdministratorToken",
      "ConsentPromptBehaviorAdmin",
      "ConsentPromptBehaviorUser"
    ]
  },
  {
    "name": "updates",
    "hives": [
      "software"
    ],
    "category": "",
    "mitre": "",
    "version": "20170715",
    "shortDescr": "Gets updates/hotfixes from Software hive",
    "mode": "subkeys",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages"
    ]
  },
  {
    "name": "userextendedproperties",
    "hives": [
      "ntuser"
    ],
    "category": "identity",
    "mitre": "",
    "version": "20220509",
    "shortDescr": "Gets MS Live ID and account name mapping",
    "mode": "subkeys",
    "paths": [
      "Software\\Microsoft\\IdentityCRL\\UserExtendedProperties"
    ],
    "subkeyNames": [
      "cid"
    ]
  },
  {
    "name": "usn",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1562",
    "version": "20220101",
    "shortDescr": "Get USN change journal settings on Windows Server",
    "mode": "named",
    "paths": [
      "Services\\SrmSvc\\Settings"
    ],
    "ccs": true,
    "names": [
      "SkipUSNCreationForSystem",
      "SkipUSNCreationForVolumes"
    ]
  },
  {
    "name": "utilities",
    "hives": [
      "system"
    ],
    "category": "persistence",
    "mitre": "T1546",
    "version": "20221231",
    "shortDescr": "Get TS Utilities subkey values",
    "mode": "subkeys",
    "paths": [
      "Control\\Terminal Server\\Utilities"
    ],
    "ccs": true
  },
  {
    "name": "volinfocache",
    "hives": [
      "software"
    ],
    "category": "devices",
    "mitre": "",
    "version": "20200916",
    "shortDescr": "Gets VolumeInfoCache from Windows Search key",
    "mode": "subkeys",
    "paths": [
      "Microsoft\\Windows Search\\VolumeInfoCache"
    ],
    "subkeyNames": [
      "DriveType",
      "VolumeLabel"
    ]
  },
  {
    "name": "wbem",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200916",
    "shortDescr": "Get some contents from WBEM key",
    "mode": "values",
    "paths": [
      "Microsoft\\WBEM\\WDM",
      "Microsoft\\WBEM\\CIMOM"
    ]
  },
  {
    "name": "wdfilter",
    "hives": [
      "system"
    ],
    "category": "defense evasion",
    "mitre": "T1562.001",
    "version": "20201229",
    "shortDescr": "Get WDFilter Altitude value",
    "mode": "named",
    "paths": [
      "Services\\WdFilter\\Instances\\WdFilter Instance"
    ],
    "ccs": true,
    "names": [
      "Altitude"
    ]
  },
  {
    "name": "winevt",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "",
    "version": "20201012",
    "shortDescr": "Gets Enabled values for WINEVT Channels",
    "mode": "subkeys",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\WINEVT\\Channels"
    ],
    "subkeyNames": [
      "Enabled"
    ]
  },
  {
    "name": "winrar",
    "hives": [
      "ntuser"
    ],
    "category": "data staged",
    "mitre": "T1074.001",
    "version": "20200916",
    "shortDescr": "Get WinRARArcHistory entries",
    "mode": "values",
    "paths": [
      "Software\\WinRAR\\ArcHistory"
    ]
  },
  {
    "name": "winscp",
    "hives": [
      "ntuser"
    ],
    "category": "lateral movement",
    "mitre": "T1021",
    "version": "20200916",
    "shortDescr": "Gets user's WinSCP 2 data",
    "mode": "values",
    "paths": [
      "Software\\Martin Prikryl\\WinSCP 2",
      "Configuration\\CDCache",
      "Configuration\\History\\RemoteTarget"
    ]
  },
  {
    "name": "wow64",
    "hives": [
      "software"
    ],
    "category": "persistence",
    "mitre": "T1546",
    "version": "20200916",
    "shortDescr": "Gets contents of WOW64x86 key",
    "mode": "values",
    "paths": [
      "Microsoft\\WOW64\\x86",
      "Microsoft\\WOW64\\arm"
    ]
  },
  {
    "name": "wpbt",
    "hives": [
      "system"
    ],
    "category": "persistence",
    "mitre": "T1542.001",
    "version": "20220718",
    "shortDescr": "Get Windows Platform Binary Table Settings",
    "mode": "named",
    "paths": [
      "Control\\Session Manager"
    ],
    "ccs": true,
    "names": [
      "DisableWpbtExecution"
    ]
  },
  {
    "name": "wtg",
    "hives": [
      "system"
    ],
    "category": "config",
    "mitre": "",
    "version": "20200909",
    "shortDescr": "Check for Windows To Go setting",
    "mode": "named",
    "paths": [
      "Control"
    ],
    "ccs": true,
    "names": [
      "PortableOperatingSystem"
    ]
  },
  {
    "name": "xbox",
    "hives": [
      "software"
    ],
    "category": "config",
    "mitre": "T1546",
    "version": "20200909",
    "shortDescr": "Check for existence of TreatDeviceAsXbox value",
    "mode": "named",
    "paths": [
      "Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\TestHooks",
      "Microsoft\\Windows\\CurrentVersion\\Diagnostics\\DiagTrack\\TestHooks\\Volatile"
    ],
    "names": [
      "TreatDeviceAsXbox"
    ]
  }
]);
})(window.RV);
