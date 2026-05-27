### Impacket

The actor regularly employs the use of Impacket's wmiexec, which redirects output to a file within the victim host's ADMIN$ share (C:\Windows\) containing an epoch timestamp in its name. The following is an example of the “dir" command being executed by wmiexec.py

```pwsh
cmd.exe /Q /c dir 1> \\127.0.0.1\ADMIN$\__1684956600.123456 2>&1
```

Note: Discovery of an entry similar to the example above in the Windows Event Log and/or a file with a name in a similar format may be evidence of malicious activity and should be investigated further. In the event that only a filename is discovered, the epoch timestamp within the filename reflects the time of execution by default and can be used to help scope threat hunting activities.

