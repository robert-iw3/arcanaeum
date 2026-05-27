### Registry Security Feature Tampering

Catches registry modifications that disable security features like Windows Defender, often part of ClickFix attacks where users are told to “fix” security issues by disabling protection.

T1562.001 - Disable or Modify Tools

TA0005 - Defense Evasion

```sql
event.type in:anycase ('Registry Value Create', 'Registry Value Modified') and(registry.keyPath contains:anycase 'DisableRealtimeMonitoring' or  registry.keyPath contains:anycase 'DisableBehaviorMonitoring' or  registry.keyPath contains:anycase 'DisableAntiSpyware' or  registry.keyPath contains:anycase 'DisableAntiVirus' or  registry.keyPath contains:anycase 'TamperProtection' or registry.keyPath contains:anycase 'DisableIOAVProtection') andsrc.process.name in:anycase ('reg.exe', 'powershell.exe', 'cmd.exe') and src.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe')
```