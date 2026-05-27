import "pe"
import "elf"

rule TOOL_V2Ray_Framework_FireAnt
{
    meta:
        description = "Detects the V2Ray framework binary, a tool used for creating encrypted network proxies. Threat actors like Fire Ant (UNC3886) have been observed deploying V2Ray, often named 'update.exe', for command and control (C2) tunneling."
        author = "Rob Weber"
        date = "2025-07-25"
        version = 1
        reference = "https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/"
        tags = "FILE, TOOL, C2, PROXY, V2RAY, FIRE_ANT, UNC3886"
        mitre_attack = "T1572"
        malware_family = "V2Ray"
        malware_type = "Proxy Tool"

    strings:
        // Unique Go package paths found in compiled V2Ray binaries
        $path1 = "v2ray.com/core/app/proxyman" ascii
        $path2 = "v2ray.com/core/transport/internet" ascii
        $path3 = "v2ray.com/core/proxy/vmess" ascii // VMess protocol mentioned in the Fire Ant report

        // A more generic but still characteristic string from the tool's description
        $desc = "V2Ray is a platform for building proxies" ascii

    condition:
        // Check for either a Windows PE or Linux ELF executable, as V2Ray is cross-platform
        (pe.is_pe or elf.is_elf)
        // Scope to a reasonable file size for a Go binary to avoid scanning very large files
        and filesize < 50MB
        // Require at least two of the specific package paths for high confidence,
        // or the descriptive string as an alternative for different builds.
        and (2 of ($path*) or $desc)
}
