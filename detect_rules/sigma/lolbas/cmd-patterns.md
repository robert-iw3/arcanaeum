### cmd line patterns

Certain patterns in commands (with asterisks for wildcards) can be used to identify potentially malicious commands:

```pwsh
D:\{REDACTED}\xcopy C:\windows\temp\hp d:\{REDACTED}

Get-EventLog security -instanceid 4624

ldifde.exe -f c:\windows\temp\cisco_up.txt -p subtree

makecab ..\backup\210829–020000.zip ..\webapps\adssp\html\Lock.lic

move “\\\c$\users\public\Appfile\registry\SYSTEM" ..\backup\210829–020000.zip

netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=9999 connectaddress={REDACTED} connectport=8443 protocol=tcp

netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport=9999

Rar.exe a –{REDACTED} c:\Windows\temp\DMBC2C61.tmp

start-process -filepath c:\windows\temp\.bat — windowstyle hidden 1

Note: The batch file in question (.bat) could use any name, and no discernable pattern has been determined at this time.

wmic process call create “cmd.exe /c mkdir C:\users\public\Appfile & ntdsutil \"ac i ntds\" ifm \"create full C:\users\public\Appfile\" q q

wmic process call create “cmd.exe /c mkdir C:\Windows\Temp\tmp & ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\tmp\"

wmic process call create “cmd.exe /c ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\Pro"

wmic process call create “ntdsutil \"ac i ntds\" ifm \"create full C:\Windows\Temp\"

cmd.exe /C dir /S \\* >> *

cmd.exe /Q /c * 1> \\127.0.0.1\ADMIN$\__*.*>&1

powershell start-process -filepath c:\windows\temp\*.exe — windowstyle hidden
```

