### Lumma Stealer: Detecting the delivery techniques and capabilities of a prolific infostealer.

Threat Intel Source:

https://www.microsoft.com/en-us/security/blog/2025/05/21/lumma-stealer-breaking-down-the-delivery-techniques-and-capabilities-of-a-prolific-infostealer/

##

```sql
| from datamodel:Endpoint.Registry
| where Registry.RegistryPath LIKE "%\\CurrentVersion\\Explorer\\RunMRU%"
| where Registry.Process.ProcessName="explorer.exe"
| where Registry.Action="set"
| where
    Registry.RegistryValueData LIKE "%✅%" OR
    (
        (Registry.RegistryValueData LIKE "*powershell*" OR Registry.RegistryValueData LIKE "*mshta*" OR Registry.RegistryValueData LIKE "*curl*" OR Registry.RegistryValueData LIKE "*msiexec*" OR Registry.RegistryValueData LIKE "*^*") AND
        Registry.RegistryValueData REGEX "[\u0400-\u04FF\u0370-\u03FF\u0590-\u05FF\u0600-\u06FF\u0E00-\u0E7F\u2C80-\u2CFF\u13A0-\u13FF\u0530-\u058F\u10A0-\u10FF\u0900-\u097F]"
    ) OR
    (
        Registry.RegistryValueData LIKE "*mshta*" AND
        Registry.RegistryValueName!="MRUList" AND
        NOT (Registry.RegistryValueData="mshta.exe\\1" OR Registry.RegistryValueData="mshta\\1")
    ) OR
    (
        (Registry.RegistryValueData LIKE "*bitsadmin*" OR Registry.RegistryValueData LIKE "*forfiles*" OR Registry.RegistryValueData LIKE "*ProxyCommand=*") AND
        Registry.RegistryValueName!="MRUList"
    ) OR
    (
        (Registry.RegistryValueData LIKE "cmd%" OR Registry.RegistryValueData LIKE "powershell%") AND
        (
            Registry.RegistryValueData LIKE "*-W Hidden *" OR Registry.RegistryValueData LIKE "*-eC *" OR Registry.RegistryValueData LIKE "*curl*" OR Registry.RegistryValueData LIKE "*E:jscript*" OR Registry.RegistryValueData LIKE "*ssh*" OR Registry.RegistryValueData LIKE "*Invoke-Expression*" OR
            Registry.RegistryValueData LIKE "*UtcNow*" OR Registry.RegistryValueData LIKE "*Floor*" OR Registry.RegistryValueData LIKE "*DownloadString*" OR Registry.RegistryValueData LIKE "*DownloadFile*" OR Registry.RegistryValueData LIKE "*FromBase64String*" OR
            Registry.RegistryValueData LIKE "*System.IO.Compression*" OR Registry.RegistryValueData LIKE "*System.IO.MemoryStream*" OR Registry.RegistryValueData LIKE "*iex*" OR Registry.RegistryValueData LIKE "*Invoke-WebRequest*" OR
            Registry.RegistryValueData LIKE "*iwr*" OR Registry.RegistryValueData LIKE "*Get-ADDomainController*" OR Registry.RegistryValueData LIKE "*-w h*" OR Registry.RegistryValueData LIKE "*-X POST*" OR
            Registry.RegistryValueData LIKE "*Invoke-RestMethod*" OR Registry.RegistryValueData LIKE "*-NoP -W*" OR Registry.RegistryValueData LIKE "*.InVOKe*" OR Registry.RegistryValueData LIKE "*-useb*" OR Registry.RegistryValueData LIKE "*irm *" OR Registry.RegistryValueData LIKE "*^*" OR
            Registry.RegistryValueData LIKE "*[char]*" OR Registry.RegistryValueData LIKE "*[scriptblock]*" OR Registry.RegistryValueData LIKE "*-UserAgent*" OR Registry.RegistryValueData LIKE "*UseBasicParsing*" OR Registry.RegistryValueData LIKE "*.Content*" OR
            Registry.RegistryValueData REGEX "[-/–][Ee^]{1,2}[NnCcOoDdEeMmAa^]*\\s[A-Za-z0-9+/=]{15,}"
        )
    )
```