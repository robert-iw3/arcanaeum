### Suspicious MSI Execution from Browser

Catches MSI installer execution from browsers with silent installation flags, often used in FileFix attacks to install malware without user interaction.

T1218.007 - Msiexec

T1566.001 - Spearphishing Attachment

T1566.002 - Spearphishing Link

TA0005 - Defense Evasion

TA0001 - Initial Access

```sql
src.process.name = 'msiexec.exe' and src.process.parent.name in:anycase ('chrome.exe', 'firefox.exe', 'msedge.exe', 'iexplore.exe') and(src.process.cmdline contains:anycase '/q' or src.process.cmdline contains:anycase '/quiet' or src.process.cmdline contains:anycase '/passive') and src.process.cmdline contains:anycase 'Downloads'
```