### Raspberry Robin Threat Intelligence Report
---

Raspberry Robin, also known as Roshtyak, is an advanced and continuously evolving malware downloader active since 2021, primarily spreading via infected USB devices but now also through web downloads and Windows Script Files. It acts as an initial access broker for various criminal groups, including those linked to Russia, and is notable for its sophisticated obfuscation, anti-analysis techniques, and rapid adoption of new exploits.

Recent developments in Raspberry Robin include a shift in network encryption from AES-CTR to ChaCha-20, the integration of a new local privilege escalation exploit (CVE-2024-38196), and the use of dynamically corrected, intentionally corrupted TOR onion domains to complicate IOC extraction. Additionally, the malware has expanded its initial access vectors beyond USB drives to include Windows Script Files (.wsf) and archive files (.7z, .rar) distributed via web downloads and platforms like Discord.

### Actionable Threat Data
---

Monitor for `cmd.exe` executing randomly named files with unusual extensions (e.g., `.usb`, `.ico`, `.lnk`, `.bin`, `.sv`, `.lo`) from removable drives, often with additional whitespace in the command line.

Detect `msiexec.exe` making outbound network connections to download and execute packages, especially when the command line contains mixed-case syntax and suspicious URLs.

Look for the creation or modification of registry keys associated with persistence, particularly the `RunOnce` key, followed by the termination of `runonce.exe`.

Monitor for attempts to exploit CVE-2024-38196 or other recent local privilege escalation vulnerabilities, potentially involving injection into legitimate processes like `cleanmgr.exe`.

Identify network traffic to TOR onion domains, especially those that might appear intentionally corrupted or are rapidly rotated using fast flux techniques.

### Cmd.exe from Removable Drive
---
```sql
-- This search queries the Endpoint data model for process creation events.
-- It is designed to be CIM compliant and should work with any EDR or logging source
-- that populates the Endpoint.Processes data model.
from datamodel=Endpoint.Processes

-- Filter for process creation events where the parent process is cmd.exe.
| where Processes.parent_process_name = "cmd.exe"

-- Extract the file extension from the process name.
| eval file_ext = lower(mvindex(split(Processes.process_name, "."), -1))

-- Filter for specific file extensions associated with Raspberry Robin and
-- for processes launched from a non-system drive (e.g., D:, E:).
-- This regex may need to be tuned to exclude legitimate network drives or other fixed partitions.
| where file_ext IN ("usb", "ico", "lnk", "bin", "sv", "lo")
  AND match(Processes.process_path, "(?i)^[d-z]:\\\\")

-- Aggregate results to create a single alert per host and process.
| stats count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as cmdline by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name, Processes.process_path

-- Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### Msiexec.exe Outbound Connection
---
```sql
from datamodel=Endpoint.Processes

-- Filter for msiexec.exe process execution.
| where Processes.process_name = "msiexec.exe"

-- Filter for command lines indicating remote package installation.
-- Looks for /i or /q switches followed by http:// or https://.
| where match(Processes.process, "(?i)\s(/i|/q)\s.*https?:\/\/")

-- Potential for False Positives: Legitimate software deployment tools (e.g., SCCM, Intune)
-- may use msiexec.exe to install applications from network locations or the internet.
-- Consider filtering by parent process name or excluding known software distribution servers/domains.
-- The following line can be uncommented to filter for mixed-case syntax, a common obfuscation technique.
-- | where match(Processes.process, "(?=.*[a-z])(?=.*[A-Z])")

-- Aggregate results to create a single alert per host and command line.
| stats count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process by Processes.dest, Processes.user, Processes.parent_process, Processes.process_name

-- Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### RunOnce Key Persistence
---
```sql
-- Filter for RunOnce registry key modifications or runonce.exe process terminations.
| where (nodename="Registry" AND match(Registry.registry_path, "(?i)Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce")) OR (nodename="Processes" AND Processes.process_name="runonce.exe" AND Processes.action="stopped")

-- Group events by host in 5-minute intervals to find correlated activity.
| bucket _time span=5m
| stats dc(nodename) as distinct_nodetypes,
        values(Registry.registry_path) as registry_path,
        values(Registry.registry_value_name) as registry_value_name,
        values(Registry.registry_value_data) as command,
        min(_time) as firstTime,
        max(_time) as lastTime
        by dest, user

-- Filter for instances where both a registry and process event occurred for the same host.
-- Legitimate installers may use RunOnce keys, but the combination with the process termination is suspicious.
-- Investigate the command written to the registry key for malicious indicators.
| where distinct_nodetypes > 1

-- Format timestamps for readability.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### Suspicious Child Process of Cleanmgr.exe
---
```sql
from datamodel=Endpoint.Processes

-- Filter for events where the parent process is cleanmgr.exe.
| where Processes.parent_process_name = "cleanmgr.exe"

-- Potential for False Positives: While extremely rare, custom administration scripts might
-- use cleanmgr.exe in unusual ways. Review the context of any alerts.
-- The list of suspicious child processes can be expanded if needed.
| stats count min(_time) as firstTime max(_time) as lastTime values(Processes.process) as process by Processes.dest, Processes.user, Processes.parent_process_name, Processes.process_name

-- Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### TOR Onion Domain Traffic
---
```sql
from datamodel=Network_Traffic.All_Traffic

-- Filter for traffic where the destination hostname ends in .onion.
| where like(All_Traffic.dest, "%.onion")

-- Potential for False Positives: This detection will trigger on any TOR traffic,
-- including legitimate use of the TOR Browser for privacy.
-- Investigate the source host and user to determine if this is authorized or expected behavior.
-- Correlate with other alerts to identify malicious activity.

-- Aggregate results to create a single alert per source/destination pair.
| stats count min(_time) as firstTime max(_time) as lastTime by All_Traffic.src, All_Traffic.dest, All_Traffic.user

-- Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### Raspberry Robin DLL Hashes
---
```sql
from datamodel=Endpoint.Filesystem

-- Filter for known Raspberry Robin SHA256 hashes.
| where Filesystem.file_hash IN ("5b0476043da365be5325260f1f0811ea81c018a8acc9cee4cd46cb7348c06fc6", "05c6f53118d363ee80989ef37cad85ee1c35b0e22d5dcebd8a6d6a396a94cb65")

-- Aggregate results to create a single alert per host and file.
| stats count min(_time) as firstTime max(_time) as lastTime by Filesystem.dest, Filesystem.file_name, Filesystem.file_path, Filesystem.file_hash, Filesystem.user

-- Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```

### Raspberry Robin C2 .onion Domain Traffic
---
```sql
from datamodel=Network_Traffic.All_Traffic

-- Strip the port from the destination to match against the domain only.
| eval dest_host = replace(All_Traffic.dest, ":\\d+$", "")

-- Filter for known Raspberry Robin C2 domains embedded in the query.
| where dest_host IN (
    "ves2owzq3uqyikb4zoeumzr4uxpi3twmy5qa5fdc4g7btpc43x5ahxyd.onion",
    "df643p7juf4hhz3nqy4lychm2xslc645bozk3egqhsj46k6xqoy4xvad.onion",
    "d7qiqd6srhy4poo2q6vbn7bx4b2wl7nrclswfqprmldzuarbfz3rglid.onion",
    "yo2a27uulrkraxfdwfcx7zokonpsux5qlufqsu7ial45uitm5v2seyyd.onion",
    "oqki6m6qejavp7c5smafqa34locotxqbeh4scltzrhucgafykzzbh6ad.onion",
    "c5empmuptwtgmehonawb6pzd4ifupervyqduqpop2m3idsgbcwdtrdad.onion",
    "jsfnao46dnqos2avnrcvwlotr6xzqbp6uxfvl4mnkh6uyg6fch4bciqd.onion",
    "el4ccbgrbeyqdc4vn74tdtfstksdmwj66qdi7e77vucafwvvm7ozvgad.onion",
    "g7w5uxhxw5mp5jmshvevd273qvkph2if5xnvrjemthe6ok5q5dtek4ad.onion",
    "cunm2jbjumfxl6tfrtzkmpk7h722oxxqqfaw2iinkalt7ijf77ch27qd.onion",
    "r4gihskhiti437bonklmq24d6dl6swuw7zg5iseehjcepd3abbyyqsid.onion",
    "mh3ibr5n4abi3fr3rlaar7wr3p2ptjrcon3jcp6tuqxscxfii4pegkid.onion",
    "x76mtemtxl5fucgccu2nz4morfmpwwe44xp3ovkgsguzsntlh7ukn4id.onion",
    "xzxdiwnw354odly55y7twfrimzys5574eaw57ttetyyo4up5ww6v25ad.onion",
    "ipatoez4ldch3vabmz6lcawxtoogkmg5alxvwdm7fwzng7flvlz47ryd.onion",
    "wlfeie2rk6utw3y5aykjisr3yj6c7hme43st2weo4jmtok6zxw33hyad.onion",
    "fio6wjjlq4pihqf6qhefaqnkkfonkgbiu4uw3jvzhcuysejme4oxwyd.onion",
    "bpe2vrpvh5ri7odgbqxhr6mjaxe3zvekcexzdwpaiorq3xcbttrxywid.onion",
    "42lidqllkggf7tsgymwk4jzfmawdinwav5vkii3l3wsqcrk4k5ncrrad.onion",
    "vvftwyeaxr3f32t3etseadhvfx42ylza5g5gpg3zqp3e46tie2w34iyd.onion",
    "3c6vus267hplojma4d3qckohjgxnhattb2vkkwcm6anilylzqkzdakad.onion",
    "ztnjv2hf4gxl7x7f27qhhfxehdd4cd6cdfwjw6u7njmqxjgllzm6kgid.onion",
    "okindaw6oogkyrdjghbqdcmbcrxersox5yphfod2uy363g5go72tx7qd.onion",
    "uxfjrthzy6c6a7d2zqk47x4ltjm6hmftbroghxk4vfjva6mftpsmkbyd.onion",
    "3gqcnr6wlxmv3dunl6rb4mcosa7ttedzbgya42burisj4qoeudl77nad.onion",
    "kykggujjvvag7p4nmptsfuyqrqtqiqqun3pimsuupecmpoez2gph4vqd.onion",
    "d4fsxtbvffjubsxmhczl6mt2wqukyao23vzi2dd7nahpcrwrhvkualid.onion",
    "s54ui6ju3aa5w3anmo3lgwn53hm7us3lj5venw3eqyogoel6e6uv7fad.onion",
    "3rp2g7y5jyalwmihkagfvwdh3fjvbecor3vz4j6vwaxdnmi6onf2hrid.onion",
    "ag2qts4t6fy6x475c5xuknlwdugdoy33oueejdv5lkfavah73g6mvlyd.onion",
    "qtnf675tghndtnnrosx2lsrvktbq7iw3noetckags2fb2ci7cujzxfyd.onion",
    "4l4abrrv5j7662dioqthd5fz5u4oxbpfradwt3ntliw2gfnikgers6qd.onion",
    "glhdxhgiqrboqrgw2dmwutpocyilxxuahxc6v3lfpfxhihahw4tjfeid.onion",
    "csn3i3femv6dx362p4qesombr3e7gm5skcxkuqrymuaxeqqwmnrnvxyd.onion",
    "knvocjqt6znfp4lba3j237i5kjnxgmk6niqk72w3wb22bfif6i7wufad.onion",
    "yuuexutjzjmul7wldcecq6mpr2v5dyblw5n77elnoikttxfk3y54gnad.onion",
    "ysbbw6ghpxos5jzcmdjydrrl3clqdvwfygejrktre4bixr3zo63vk7yd.onion",
    "xwm5hhm4oalqhe4u67dfsqovxygkxox4bleir4isyqpncskamxa7bead.onion",
    "gutayapi55tb5dmjhlmlwk3owg4aqy5fbyw7uk4skoagzv3le4ge6kad.onion",
    "iz3iltwsdsaiqptqxba52bvwouzwoi56fw7vqbiw3znjo2jmifxmiuqd.onion",
    "ia5ynzyztblk7vde74szyhy6a7f57dqg6jvysnrm34fv2aivlcornzqd.onion",
    "j3w64lohpdl2fynduq7tey7v5kc5nfieblmi5g2znuadn75lkrgdi3yd.onion",
    "4x34ze2b5l7fh5b4miyvkg44ohajj2pb7hcewt3jt3wlccfbezejrgyd.onion",
    "sgk5c76pgs7a3qfhzvmey2ecnunsfdbykgjxvunnbpnn3ixlu7a5eqyd.onion",
    "ztgk5ebmxcq3onksgg3guxpe4abz4cktcfa5lgubcgyde3ojkbvyjnad.onion",
    "5lqerrumqsknnphthjiwg45uas7xcer65am4vs7z4zheshmx6hxyh2yd.onion",
    "5oiwshn53yari5pza6ca3rxctq47e4azf6wzsvyidmt3j55d5lf7rvyd.onion",
    "7jfv34s2axfur4euvzqzzowyqksby7hyt3sizuxvucxoc6ma46qjooqd.onion",
    "soraykkm25es2phzeszxpinfhcbqgyn7i4tznb4atvks3gnsynm7avad.onion",
    "tfjhxbhmr3vrmjrhc543npj4nk64jksodoclyjuqfn5aflmi44f657id.onion",
    "7ray5zki7gjzms3bzbivwtcacyt4raaz6bixzmmgu6ljy5pjfpebowqd.onion",
    "z5qg6hpu7sxjyws2fqxei2peywu2tttq6lxs5ybxesgffqmjpedyeuyd.onion",
    "werbjkqsmcugdcbdn5yvriyy6q4m2qfk3mg7cf6sujzandkwlsnlucid.onion",
    "aqumyf4ecfgbxgcnrels2qd2cq5obbnwr4zr37cqw3tg7v5o6kuhqqyd.onion",
    "wmdlzzdfkxikxrlw42rf75ug62semr3h6soc6tyoom3bb75zi7hjbrid.onion",
    "6g6z6zsz7xc2ywqunbzzc4u2uv7yakc5aiaqbojbajmfioj3dfkzbnqd.onion",
    "ne2vesxuik5dkz4vynmfped6rjfsjehmkajhkcpcjr5m3c3hc5bx5oad.onion",
    "7gb5jc3mr32qqyae2s3o5r4fpima2cqpuogpbcmwk7wyvwmqxpr4wdid.onion",
    "daorqgcuse6jzt7r22si2q4t7rjz622vxd5xhq4v4rzcyukltnqg3pyd.onion"
)

-- Potential for False Positives: This detection is based on a static list of IOCs.
-- While highly specific, there is a chance of FPs if a domain is re-purposed after being
-- sinkholed or taken over. The primary risk is the list becoming outdated.

-- Aggregate results to create a single alert per source and destination.
| stats count min(_time) as firstTime max(_time) as lastTime by All_Traffic.src, All_Traffic.dest, All_Traffic.user

-- Convert epoch timestamps to human-readable format.
| `security_content_ctime(firstTime)`
| `security_content_ctime(lastTime)`
```