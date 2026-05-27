### Port Proxy T1090

The actor has used the following commands to enable port forwarding [T1090] on the host: “cmd.exe /c “netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress= connectport=8443 protocol=tcp""

```sh
“cmd.exe /c netsh interface portproxy add v4tov4 listenport=50100 listenaddress=0.0.0.0 connectport=1433 connectaddress="
```

### sigma rule

```yaml
title: Portproxy add command
id: 9efc7314-5c90-4c7b-9131-ef311b7f45a9
status: experimental
description: APT use portproxy commands to enable port forwarding on a host.
references:
    - https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-144a
author: _sim...
date:
tags:
    - attack.command_and_control #TA0011
    - attack.t1090
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\cmd.exe'
        - OriginalFileName: 'cmd.exe'
    selection_cli:
        CommandLine|contains|all:
            - 'netsh '
            - 'interface '
            - 'portproxy '
        CommandLine|contains:
            - 'add '
            - 'listenport '
            - 'connetaddress= '
            - 'connectport=1433'
    condition: all of selection_*
falsepositives:
    - Administrative activity
level: high
```

MDE:
```sql
DeviceProcessEvents | where ((FolderPath endswith @'\cmd.exe' or InitiatingProcessVersionInfoOriginalFileName =~ @'cmd.exe' or ProcessVersionInfoOriginalFileName =~ @'cmd.exe') and (ProcessCommandLine contains @'netsh ‘ and ProcessCommandLine contains @'interface ‘ and ProcessCommandLine contains @'portproxy ‘ and (ProcessCommandLine contains @'add ‘ or ProcessCommandLine contains @'listenport ‘ or ProcessCommandLine contains @'connetaddress= ‘ or ProcessCommandLine contains @'connectport=1433')))
```


    Where is replaced with an IPv4 address internal to the network, omitting the < >'s. Netsh is a built-in Windows command line scripting utility that can display or modify the network settings of a host, including the Windows Firewall. The portproxy add command is used to create a host:port proxy that will forward incoming connections on the provided listenaddress and listenport to the connectaddress and connectport. Administrative privileges are required to execute the portproxy command. Each portproxy command above will create a registry key…

```pwsh
HKLM\SYSTEM\CurrentControlSet\Services\PortProxy\v4tov4\tcp\
```

    Defenders should look for the presence of keys in this path and investigate any anomalous entries. Note: Using port proxies is not common for legitimate system administration since they can constitute a backdoor into the network that bypasses firewall policies. Administrators should limit port proxy usage within environments and only enable them for the period of time in which they are required. Defenders should also use unusual IP addresses and ports in the command lines or registry entries to identify other hosts that are potentially included in actor actions. All hosts on the network should be examined for new and unusual firewall and port forwarding rules, as well as IP addresses and ports specified by the actor. If network traffic or logging is available, defenders should attempt to identify what traffic was forwarded though the port proxies to aid in the hunt operation. As previously mentioned, identifying the associated user account that made the networking changes can also aid in the hunt operation. Firewall rule additions and changes can be viewed in Windows Event Viewer by navigating to: Applications and Service Logs | Microsoft | Windows | Windows Firewall With Advanced Security | Firewall. In addition to host-level changes, defenders should review perimeter firewall configurations for unauthorized changes and/or entries that may permit external connections to internal hosts. The actor is known to target perimeter devices in their operations. Firewall logs should be reviewed for any connections to systems on the ports listed in any portproxy commands discovered.
