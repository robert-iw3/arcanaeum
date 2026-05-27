### Lazarus Group's Evolving RAT Arsenal Targeting DeFi
---

The Lazarus Group, a North Korean state-sponsored threat actor, continues to target the financial and cryptocurrency sectors with sophisticated social engineering and an evolving set of remote access Trojans (RATs), including the newly detailed ThemeForestRAT and the advanced RemotePE. This group demonstrates persistent and adaptive tactics, employing multiple RATs in a single attack chain to maintain access and escalate privileges.

The article introduces ThemeForestRAT, a previously undocumented RAT used by Lazarus for at least six years, and RemotePE, a more advanced RAT deployed in later stages of an attack, highlighting the group's continuous development of its malware arsenal and its strategic use of different RATs for various attack phases. The group has also been observed using a sophisticated web-based administrative platform for centralized management of compromised systems and exfiltrated data, indicating an increased level of operational sophistication in their campaigns.

### Actionable Threat Data
---

Initial Access and Persistence:

Lazarus Group utilizes social engineering, often impersonating employees on platforms like Telegram and using fake meeting websites (e.g., calendly[.]live, picktime[.]live, oncehub[.]co).

Persistence is achieved through phantom DLL loading, specifically by placing TSVIPSrv.dll in %SystemRoot%\System32\ and modifying the SessionEnv service to auto-start and gain elevated privileges (SeDebugPrivilege, SeLoadDriverPrivilege).

The group has also been observed using wlbsctrl.dll with the IKEEXT service for phantom DLL loading.

Malware Deployment and Characteristics:

PerfhLoader, a custom loader, decrypts and loads payloads (e.g., perfh011.dat) using a rolling XOR key and Manual-DLL-Loader.

PondRAT communicates with C2 servers over HTTP(S), using XOR and Base64 encoding for messages, with a hardcoded XOR key (774C71664D5D25775478607E74555462773E525E18237947355228337F433A3B).

ThemeForestRAT uses RC4 encryption with the key 201A192D838F4853E300 for its configuration file (netraid.inf on Windows, /var/crash/cups on Linux, /private/etc/imap on macOS).

ThemeForestRAT communicates over HTTP(S) with C2 servers, using filenames prefixed with ThemeForest_ for commands and Thumb_ for responses.

RemotePE, a more advanced RAT, is delivered by DPAPILoader and RemotePELoader, with RemotePELoader check-in requests using a User-Agent of Microsoft-Delivery-Optimization/10.0.

Discovery and Lateral Movement Tools:

The actor deploys custom tools like Screenshotter, Keylogger, and Chromium browser dumpers, as well as public tools such as Mimikatz, Proxy Mini, and frpc (Fast Reverse Proxy client version 0.32.1).

Observed file paths for keylogger output include %TEMP%\tmpntl.dat (Windows) and /private/etc/xmem (macOS).

The group uses a unique file deletion technique for temporary files (e.g., TLT prefix) by overwriting contents with random bytes and renaming the file 27 times with sequential letters and then random uppercase letters.

### Combined Analysis Search
---
```sql
`#--------------------------------------------------------------------------------
# 1. IOC Search - Hashes
# This section searches for known malicious file hashes associated with the Lazarus tools.
# This is a high-fidelity search based on specific indicators.
#--------------------------------------------------------------------------------`
| tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Processes where (nodename = "All_Data") (Processes.process_hash IN (
    "24d5dd3006c63d0f46fb33cbc1f576325d4e7e03e3201ff4a3c1ffa604f1b74a", "4715e5522fc91a423a5fcad397b571c5654dc0c4202459fdca06841eba1ae9b3",
    "8c3c8f24dc0c1d165f14e5a622a1817af4336904a3aabeedee3095098192d91f", "f4d8e1a687e7f7336162d3caed9b25d9d3e6cfe75c89495f75a92ca87025374b",
    "85045d9898d28c9cdc4ed0ca5d76eceb457d741c5ca84bb753dde1bea980b516", "5e40d106977017b1ed235419b1e59ff090e1f43ac57da1bb5d80d66ae53b1df8",
    "c66ba5c68ba12eaf045ed415dfa72ec5d7174970e91b45fda9ebb32e0a37784a", "ff32bc1c756d560d8a9815db458f438d63b1dcb7e9930ef5b8639a55fa7762c9",
c"c4c18fefb61ec5b3c69c31beaa07a4918e0b0184cb43447f672f62134eb402b", "6510d460395ca3643133817b40d9df4fa0d9dbe8e60b514fdc2d4e26b567dfbd",
    "973f7939ea03fd2c9663dafc21bb968f56ed1b9a56b0284acf73c3ee141c053c", "f0321c93c93fa162855f8ea4356628eef7f528449204f42fbfa002955a0ba528",
    "4f6ae0110cf652264293df571d66955f7109e3424a070423b5e50edc3eb43874", "aa4a2d1215f864481994234f13ab485b95150161b4566c180419d93dda7ac039",
    "159471e1abc9adf6733af9d24781fbf27a776b81d182901c2e04e28f3fe2e6f3", "7a05188ab0129b0b4f38e2e7599c5c52149ce0131140db33feb251d926428d68",
    "37f5afb9ed3761e73feb95daceb7a1fdbb13c8b5fc1a2ba22e0ef7994c7920ef", "59a651dfce580d28d17b2f716878a8eff8d20152b364cf873111451a55b7224d",
c"3c8f5cc608e3a4a755fe1a2b099154153fb7a88e581f3b122777da399e698cca", "d998de6e40637188ccbb8ab4a27a1e76f392cb23df5a6a242ab9df8ee4ab3936",
    "e4ce73b4dbbd360a17f482abcae2d479bc95ea546d67ec257785fa51872b2e3f", "1a051e4a3b62cd2d4f175fb443f5172da0b40af27c5d1ffae21fde13536dd3e1",
    "9dddf5a1d32e3ba7cc27f1006a843bfd4bc34fa8a149bcc522f27bda8e95db14", "2c164237de4d5904a66c71843529e37cea5418cdcbc993278329806d97a336a5"
)) by Processes.dest, Processes.user, Processes.process_name, Processes.process, Processes.process_hash
| `drop_dm_object_name(Processes)`
| eval detection_name="Known Lazarus Group File Hash", detection_type="IOC"

`#--------------------------------------------------------------------------------
# 2. IOC Search - Network
# This section searches for network traffic to known malicious domains and IPs.
#--------------------------------------------------------------------------------`
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Network_Traffic where (nodename = "All_Data") (Network_Traffic.dest_ip IN (
        "144.172.74.120", "192.52.166.253"
    ) OR Network_Traffic.dest_name IN (
        "calendly.live", "picktime.live", "oncehub.co", "go.oncehub.co", "dpkgrepo.com", "pypilibrary.com",
        "pypistorage.com", "keondigital.com", "arcashop.org", "jdkgradle.com", "latamics.org", "lmaxtrd.com",
        "paxosfuture.com", "www.plexisco.com", "ftxstock.com", "www.natefi.org", "nansenpro.com", "aes-secure.net",
        "azureglobalaccelerator.com", "azuredeploypackages.net"
    )) by Network_Traffic.src, Network_Traffic.dest, Network_Traffic.dest_ip, Network_Traffic.dest_name, Network_Traffic.user
    | `drop_dm_object_name(Network_Traffic)`
    | eval detection_name="Known Lazarus Group C2/Infrastructure", detection_type="IOC"
]

`#--------------------------------------------------------------------------------
# 3. TTP Search - File System Artifacts
# This section searches for suspicious file paths and names used by Lazarus tools.
#--------------------------------------------------------------------------------`
| append [
    | tstats `summariesonly` count min(_time) as firstTime max(_time) as lastTime from datamodel=Endpoint.Filesystem where (nodename = "All_Data") (Filesystem.file_name IN (
        "netraid.inf", "perfh011.dat", "hsu.dat", "pfu.dat", "fpc.dat", "fp.exe", "tsvipsrv.dll",
        "wlbsctrl.dll", "adepfx.exe", "hd.exe", "msnprt.exe", "cmui.exe"
    ) OR Filesystem.file_path IN (
        "*\\tmpntl.dat", "*\\TMP01.dat", "/var/crash/cups", "/private/etc/imap", "/private/etc/krb5d.conf",
        "/etc/apdl.cf", "*\\system32\\apdl.cf", "/tmp/xweb_log.md", "*\\IconCache.log", "/private/etc/pdpaste",
        "/private/etc/xmem", "/private/etc/tls3", "*\\Microsoft\\Software\\Cache"
    ) OR (Filesystem.file_name="TLT*.tmp")) by Filesystem.dest, Filesystem.user, Filesystem.file_path, Filesystem.file_name
    | `drop_dm_object_name(Filesystem)`
    | eval detection_name="Lazarus Group File Artifact", detection_type="TTP"
]

`#--------------------------------------------------------------------------------
# 4. TTP Search - Phantom DLL Loading Persistence
# Looks for the command used to set the SessionEnv service to start automatically,
# a known persistence technique for this actor.
#--------------------------------------------------------------------------------`
| append [
    | search (index=* sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1) (process_name="sc.exe" AND process_command_line IN ("*config sessionenv start= auto*", "*config ikeext start= auto*"))
    | stats count min(_time) as firstTime max(_time) as lastTime by host, user, process_name, process_command_line
    | eval detection_name="Lazarus Phantom DLL Loading Persistence", detection_type="TTP"
    `# FP Note: Legitimate administrative activity could involve configuring services.
    # Correlate with other suspicious activity from the same host.`
]

`#--------------------------------------------------------------------------------
# 5. TTP Search - ThemeForestRAT C2 Pattern
# Looks for the unique URI patterns used by ThemeForestRAT.
#--------------------------------------------------------------------------------`
| append [
    | search (index=* sourcetype=stream:http OR sourcetype=pan:traffic) (url="*ThemeForest_*" OR url="*Thumb_*")
    | stats count min(_time) as firstTime max(_time) as lastTime values(url) as urls by src, dest, http_user_agent
    | eval detection_name="ThemeForestRAT C2 URI Pattern", detection_type="TTP"
]

`#--------------------------------------------------------------------------------
# 6. TTP Search - RemotePE Loader User-Agent
# Looks for the specific User-Agent used by RemotePELoader when contacting C2s.
#--------------------------------------------------------------------------------`
| append [
    | search (index=* sourcetype=stream:http OR sourcetype=pan:traffic) http_user_agent="Microsoft-Delivery-Optimization/10.0" dest IN ("aes-secure.net", "azureglobalaccelerator.com")
    | stats count min(_time) as firstTime max(_time) as lastTime values(url) as urls by src, dest, http_user_agent
    | eval detection_name="RemotePE Loader C2 User-Agent", detection_type="TTP"
    `# FP Note: While specific, it's possible other tools could adopt this User-Agent.
    # The combination with the destination domains makes this higher fidelity.`
]

`#--------------------------------------------------------------------------------
# Final Formatting
#--------------------------------------------------------------------------------`
| rename dest as endpoint, src as source
| eval firstTime=strftime(firstTime, "%Y-%m-%d %H:%M:%S"), lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
| table firstTime, lastTime, detection_name, detection_type, endpoint, source, user, process_name, process_command_line, process_hash, file_path, file_name, dest_ip, dest_name, http_user_agent, urls, count
```