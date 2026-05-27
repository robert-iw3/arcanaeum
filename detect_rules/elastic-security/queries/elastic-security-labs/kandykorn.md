<p align="center">
  <img src="https://www.elastic.co/security-labs/grid.svg" />
</p>

## Elastic catches DPRK passing out KANDYKORN


    Threat actors lured blockchain engineers with a Python application to gain initial access to the environment

    This intrusion involved multiple complex stages that each employed deliberate defense evasion techniques

    The intrusion set was observed on a macOS system where an adversary attempted to load binaries into memory, which is atypical of macOS intrusions

## Hunting queries

The events for EQL are provided with the Elastic Agent using the Elastic Defend integration. Hunting queries could return high signals or false positives. These queries are used to identify potentially suspicious behavior, but an investigation is required to validate the findings.
EQL queries

Using the Timeline section of the Security Solution in Kibana under the “Correlation" tab, you can use the below EQL queries to hunt for similar behaviors.

The following EQL query can be used to identify when a hidden executable creates and then immediately deletes a file within a temporary directory:

```sql
sequence by process.entity_id, file.path with maxspan=30s
  [file where event.action == "modification" and process.name : ".*" and
   file.path : ("/private/tmp/*", "/tmp/*", "/var/tmp/*")]
  [file where event.action == "deletion" and process.name : ".*" and
   file.path : ("/private/tmp/*", "/tmp/*", "/var/tmp/*")]
```

The following EQL query can be used to identify when a hidden file makes an outbound network connection followed by the immediate download of an executable file:

```sql
sequence by process.entity_id with maxspan=30s
[network where event.type == "start" and process.name : ".*"]
[file where event.action != "deletion" and file.Ext.header_bytes : ("cffaedfe*", "cafebabe*")]
```

The following EQL query can be used to identify when a macOS application binary gets renamed to a hidden file name within the same directory:

```sql
file where event.action == "rename" and file.name : ".*" and
 file.path : "/Applications/*/Contents/MacOS/*" and
 file.Ext.original.path : "/Applications/*/Contents/MacOS/*" and
 not startswith~(file.Ext.original.path,Effective_process.executable)
```

The following EQL query can be used to identify when an IP address is supplied as an argument to a hidden executable:

```sql
sequence by process.entity_id with maxspan=30s
[process where event.type == "start" and event.action == "exec" and process.name : ".*" and process.args regex~ "[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}"]
[network where event.type == "start"]
```

The following EQL query can be used to identify the rename or modification of a hidden executable file within the /Users/Shared directory or the execution of a hidden unsigned or untrusted process in the /Users/Shared directory:

```sql
any where
 (
  (event.category : "file" and event.action != "deletion" and file.Ext.header_bytes : ("cffaedfe*", "cafebabe*") and
   file.path : "/Users/Shared/*" and file.name : ".*" ) or
  (event.category : "process" and event.action == "exec" and process.executable : "/Users/Shared/*" and
   (process.code_signature.trusted == false or process.code_signature.exists == false) and process.name : ".*")
 )
```

The following EQL query can be used to identify when a URL is supplied as an argument to a python script via the command line:

```sql
sequence by process.entity_id with maxspan=30s
[process where event.type == "start" and event.action == "exec" and
 process.args : "python*" and process.args : ("/Users/*", "/tmp/*", "/var/tmp/*", "/private/tmp/*") and process.args : "http*" and
 process.args_count &lt;= 3 and
 not process.name : ("curl", "wget")]
[network where event.type == "start"]
```

The following EQL query can be used to identify the attempt of in memory Mach-O loading specifically by looking for the predictable temporary file creation of "NSCreateObjectFileImageFromMemory-*":

```sql
file where event.type != "deletion" and
file.name : "NSCreateObjectFileImageFromMemory-*"
```

The following EQL query can be used to identify the attempt of in memory Mach-O loading by looking for the load of the "NSCreateObjectFileImageFromMemory-*" file or a load with no dylib name provided:

```sql
any where ((event.action == "load" and not dll.path : "?*") or
  (event.action == "load" and dll.name : "NSCreateObjectFileImageFromMemory*"))
```