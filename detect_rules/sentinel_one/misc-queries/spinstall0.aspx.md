### spinstall0.aspx execution traces

This rule detects the execution of 'csc.exe' (C# compiler) when it attempts to create or interact with a file named 'App_Web_spinstall0.aspx'. This specific file name is often associated with web shell activity or malicious code compilation on web servers, particularly in the context of .NET applications. The rule aims to identify potential malicious compilation and execution of web-based backdoors or implants.

S0348 - Cardinal RAT

T1059.003 - Windows Command Shell

T1059 - Command and Scripting Interpreter

TA0002 - Execution

```sql
dataSource.name = 'SentinelOne' and endpoint.os = "windows" and event.type = "Process Creation" andsrc.process.name contains "csc.exe" and tgt.file.path contains "App_Web_spinstall0.aspx"
```

### SharePoint spinstall0 File Creation

This rule detects the creation of specific files named 'spinstall0' within the SharePoint Web Server Extensions template layouts directory. This activity could indicate an attempt to install or modify SharePoint components, potentially for malicious purposes or unauthorized changes.

T1213.002 - Sharepoint

T1119 - Automated Collection

TA0009 - Collection

```sql
event.category = 'file' && event.type = 'File Creation' && (tgt.file.path matches '\\\\microsoft shared\\\\Web Server Extensions\\\\15\\\\TEMPLATE\\\\LAYOUTS\\\\spinstall0' || tgt.file.path matches '\\\\microsoft shared\\\\Web Server Extensions\\\\16\\\\TEMPLATE\\\\LAYOUTS\\\\spinstall0')
```

