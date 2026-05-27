### NetExec RDP Behaviour detected

This rule detects suspicious use of the Windows clipboard utility (clip.exe) or the "| clip" command pattern during RDP sessions. This behaviour is commonly associated with automated command execution and data exfiltration techniques, such as those used by NetExec. Legitimate use of clip.exe in remote sessions is rare, so these events may indicate lateral movement or post-exploitation activity via RDP.

https://github.com/Pennyw0rth/NetExec/pull/676/commits/f17f091d6b99be917ea7afca85d679b80cab7d49

https://github.com/Adamkadaban/NetExec/blob/rdp-exec/nxc/protocols/rdp.py#L412

T1021.001 - Remote Desktop Protocol

TA0002 - Execution

TA0008 - Lateral Movement

```sql
((src.process.cmdline contains:anycase ("| clip & exit","clip; exit")) OR (tgt.process.cmdline contains:anycase ("| clip & exit","clip; exit"))) OR (src.process.name contains:anycase ("clip.exe") AND src.parent.process.name contains:anycase ("powershell.exe","pwsh.exe","cmd.exe"))
```