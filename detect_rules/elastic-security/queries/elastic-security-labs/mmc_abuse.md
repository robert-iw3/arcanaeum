<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

## GrimResource -  Microsoft Management Console for initial access and evasion

After Microsoft disabled office macros by default for internet-sourced documents, other infection vectors like JavaScript, MSI files, LNK objects, and ISOs have surged in popularity. However, these other techniques are scrutinized by defenders and have a high likelihood of detection. Mature attackers seek to leverage new and undisclosed infection vectors to gain access while evading defenses. A recent example involved DPRK actors using a new command execution technique in MSC files.

Elastic researchers have uncovered a new infection technique also leveraging MSC files, which we refer to as GrimResource. It allows attackers to gain full code execution in the context of mmc.exe after a user clicks on a specially crafted MSC file. A sample leveraging GrimResource was first uploaded to VirusTotal on June 6th.

## Suspicious Execution via Microsoft Common Console

This detection was established prior to our discovery of this new execution technique. It was originally designed to identify a different method (which requires the user to click on the Taskpad after opening the MSC file) that exploits the same MSC file type to execute commands through the Console Taskpads command line attribute:

```sql
process where event.action == "start" and
 process.parent.executable : "?:\\Windows\\System32\\mmc.exe" and  process.parent.args : "*.msc" and
 not process.parent.args : ("?:\\Windows\\System32\\*.msc", "?:\\Windows\\SysWOW64\\*.msc", "?:\\Program files\\*.msc", "?:\\Program Files (x86)\\*.msc") and
 not process.executable :
              ("?:\\Windows\\System32\\mmc.exe",
               "?:\\Windows\\System32\\wermgr.exe",
               "?:\\Windows\\System32\\WerFault.exe",
               "?:\\Windows\\SysWOW64\\mmc.exe",
               "?:\\Program Files\\*.exe",
               "?:\\Program Files (x86)\\*.exe",
               "?:\\Windows\\System32\\spool\\drivers\\x64\\3\\*.EXE",
               "?:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe")
```

## .NET COM object created in non-standard Windows Script Interpreter

The sample is using the DotNetToJScript technique, which triggers another detection looking for RWX memory allocation from .NET on behalf of a Windows Script Host (WSH) script engine (Jscript or Vbscript):

The following EQL rule will detect execution via the .NET loader:

```sql
api where
  not process.name : ("cscript.exe", "wscript.exe") and
  process.code_signature.trusted == true and
  process.code_signature.subject_name : "Microsoft*" and
  process.Ext.api.name == "VirtualAlloc" and
  process.Ext.api.parameters.allocation_type == "RESERVE" and
  process.Ext.api.parameters.protection == "RWX" and
  process.thread.Ext.call_stack_summary : (
    /* .NET is allocating executable memory on behalf of a WSH script engine
     * Note - this covers both .NET 2 and .NET 4 framework variants */
    "*|mscoree.dll|combase.dll|jscript.dll|*",
    "*|mscoree.dll|combase.dll|vbscript.dll|*",
    "*|mscoree.dll|combase.dll|jscript9.dll|*",
    "*|mscoree.dll|combase.dll|chakra.dll|*"
)
```

## Script Execution via MMC Console File

The two previous detections were triggered by specific implementation choices to weaponize the GrimResource method (DotNetToJS and spawning a child process). These detections can be bypassed by using more OPSEC-safe alternatives.

Other behaviors that might initially seem suspicious — such as mmc.exe loading jscript.dll, vbscript.dll, and msxml3.dll — can be clarified compared to benign data. We can see that, except for vbscript.dll, these WSH engines are typically loaded by mmc.exe:

The following EQL rule will detect the execution of a script from the MMC console:

```sql
sequence by process.entity_id with maxspan=1m
 [process where event.action == "start" and
  process.executable : "?:\\Windows\\System32\\mmc.exe" and process.args : "*.msc"]
 [file where event.action == "open" and file.path : "?:\\Windows\\System32\\apds.dll"]
```

## Windows Script Execution via MMC Console File

Another detection and forensic artifact is the creation of a temporary HTML file in the INetCache folder, named redirect[*] as a result of the APDS XSS redirection:

The following EQL correlation can be used to detect this behavior while also capturing the msc file path:

```sql
sequence by process.entity_id with maxspan=1m
 [process where event.action == "start" and
  process.executable : "?:\\Windows\\System32\\mmc.exe" and process.args : "*.msc"]
 [file where event.action in ("creation", "overwrite") and
  process.executable :  "?:\\Windows\\System32\\mmc.exe" and file.name : "redirect[?]" and
  file.path : "?:\\Users\\*\\AppData\\Local\\Microsoft\\Windows\\INetCache\\IE\\*\\redirect[?]"]
```

## Conclusion

Attackers have developed a new technique to execute arbitrary code in Microsoft Management Console using crafted MSC files. Elastic's existing out of the box coverage shows our defense-in-depth approach is effective even against novel threats like this. Defenders should leverage our detection guidance to protect themselves and their customers from this technique before it proliferates into commodity threat groups.