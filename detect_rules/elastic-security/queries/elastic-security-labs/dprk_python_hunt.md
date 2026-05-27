<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

## DPRK's Python- fueled intrusions into secured networks

Few threat actors have garnered as much attention and notoriety in the shadowy world of state-sponsored cyber operations as the Democratic People's Republic of Korea (DPRK). DPRK-affiliated threat groups have consistently demonstrated their use of social engineering tactics coupled with tactical capabilities. At the forefront of their arsenal lies an unexpected weapon: Python.

This versatile programming language, prized for its accessibility and power, has become the tool for DPRK operatives seeking initial access to target systems. These threat actors have successfully penetrated some of the world's most secure networks through a potent combination of meticulously crafted social engineering schemes and elegantly disguised Python code.

This publication will examine the DPRK's use of social engineering and Python-based lures for initial access. Building on research published by the Reversing Labs team for the campaign they call VMConnect, we'll explore a very recent real-world example, dissect the code, and examine what makes these attacks so effective. By understanding these techniques, we aim to shed light on the evolving landscape of state-sponsored cyber threats and equip defenders with the knowledge to combat them.

Key takeaways

    The sophistication of DPRK's social engineering tactics often involves long-term persona development and targeted narratives.

    The use of Python for its ease of obfuscation, extensive library support, and ability to blend with legitimate system activities.

    These lures evidence the ongoing evolution of DPRK's techniques, which highlights the need for continuous vigilance and adaptation in cyber defense strategies.

    The Python script from this campaign includes modules that allow for the execution of system commands and to write and execute local files

## [Detection] Python Subprocess Shell Tempfile Execution and Remote Network Connection

```sql
sequence by process.parent.entity_id with maxspan=3s
[process where event.type == "start" and event.action == "exec" and process.parent.name : "python*"
 and process.name : ("sh", "zsh", "bash") and process.args == "-c" and process.args : "python*"]
[network where event.type == "start"]
```

## [Hunt] Python Executable File Creation in Temporary Directory

```sql
file where event.type == "modification" and file.Ext.header_bytes : ("cffaedfe*", "cafebabe*")
 and (process.name : "python*" or Effective_process.name : "python*") and file.path : ("/private/tmp/*", "/tmp/*")
```

## [Hunt] Interactive Shell Execution via Python

```sql
process where host.os.type == "macos" and event.type == "start" and event.action == "exec"
and process.parent.name : "python*" and process.name : ("sh", "zsh", "bash")
 and process.args == "-i" and process.args_count == 2
```

## [Hunt] Suspicious Python Child Process Execution

```sql
process where event.type == "start" and event.action == "exec" and process.parent.name : "python*"
 and process.name : ("screencapture", "security", "csrutil", "dscl", "mdfind", "nscurl", "sqlite3", "tclsh", "xattr")
```