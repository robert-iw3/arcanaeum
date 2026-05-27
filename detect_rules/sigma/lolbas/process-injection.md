### Process Injection T1055

    state-sponsored cyber actors have been observed: Injecting into the rundll32.exe process to hide usage of Mimikatz, as well as injecting into a running legitimate explorer.exe process for lateral movement

Sigma:

```yaml
title: HackTool - Mimikatz Execution
id: a642964e-bead-4bed-8910-1bb4d63e3b4d
status: test
description: Detection well-known mimikatz command line arguments
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - https://tools.thehacker.recipes/mimikatz/modules
author: Teymur Kheirkhabarov, oscd.community, David ANDRE (additional keywords), Tim Shelton
date: 2019-10-22
modified: 2023-02-21
tags:
    - attack.credential-access
    - attack.t1003.001
    - attack.t1003.002
    - attack.t1003.004
    - attack.t1003.005
    - attack.t1003.006
logsource:
    category: process_creation
    product: windows
detection:
    selection_tools_name:
        CommandLine|contains:
            - 'DumpCreds'
            - 'mimikatz'
    selection_function_names: # To cover functions from modules that are not in module_names
        CommandLine|contains:
            - '::aadcookie' # misc module
            - '::detours' # misc module
            - '::memssp' # misc module
            - '::mflt' # misc module
            - '::ncroutemon' # misc module
            - '::ngcsign' # misc module
            - '::printnightmare' # misc module
            - '::skeleton' # misc module
            - '::preshutdown'  # service module
            - '::mstsc'  # ts module
            - '::multirdp'  # ts module
    selection_module_names:
        CommandLine|contains:
            - 'rpc::'
            - 'token::'
            - 'crypto::'
            - 'dpapi::'
            - 'sekurlsa::'
            - 'kerberos::'
            - 'lsadump::'
            - 'privilege::'
            - 'process::'
            - 'vault::'
    condition: 1 of selection_*
falsepositives:
    - Unlikely
level: high

```

MDE
```sql
DeviceProcessEvents | where ((ProcessCommandLine contains @'DumpCreds' or ProcessCommandLine contains @'mimikatz') or (ProcessCommandLine contains @'::aadcookie' or ProcessCommandLine contains @'::detours' or ProcessCommandLine contains @'::memssp' or ProcessCommandLine contains @'::mflt' or ProcessCommandLine contains @'::ncroutemon' or ProcessCommandLine contains @'::ngcsign' or ProcessCommandLine contains @'::printnightmare' or ProcessCommandLine contains @'::skeleton' or ProcessCommandLine contains @'::preshutdown' or ProcessCommandLine contains @'::mstsc' or ProcessCommandLine contains @'::multirdp') or (ProcessCommandLine contains @'rpc::' or ProcessCommandLine contains @'token::' or ProcessCommandLine contains @'crypto::' or ProcessCommandLine contains @'dpapi::' or ProcessCommandLine contains @'sekurlsa::' or ProcessCommandLine contains @'kerberos::' or ProcessCommandLine contains @'lsadump::' or ProcessCommandLine contains @'privilege::' or ProcessCommandLine contains @'process::' or ProcessCommandLine contains @'vault::'))
```
