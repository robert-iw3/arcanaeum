import "pe"

rule SUSP_AutoIt_Dropper_DarkCloud_TTP
{
    meta:
        description = "Detects AutoIt-compiled executables exhibiting behaviors associated with the DarkCloud Stealer dropper. This rule identifies files containing specific embedded resource names or a combination of suspicious API calls used for in-memory shellcode execution."
        date = "2025-07-24"
        version = 1
        reference = "https://unit42.paloaltonetworks.com/darkcloud-stealer-and-obfuscated-autoit-scripting/"
        tags = "CRIME, INFOSTEALER, DARKCLOUD, AUTOIT, DROPPER, FILE, TTP"
        mitre_attack = "T1140, T1204"
        malware_family = "DarkCloud"
        malware_type = "Dropper"

    strings:
        // Magic bytes for a compiled AutoIt v3 script, often found in the resource section.
        $autoit_magic = { 41 55 33 21 45 41 30 36 } // "AU3!EA06"

        // Specific filenames embedded in the dropper via FileInstall()
        $embedded_files1 = "iodization" wide ascii
        $embedded_files2 = "plainstones" wide ascii

        // APIs used to change memory permissions and execute shellcode
        $api_vp = "VirtualProtect" ascii
        $api_cw = "CallWindowProc" ascii

    condition:
        // The file must be a Windows Portable Executable.
        pe.is_pe
        and filesize < 5MB
        // It must contain the AutoIt compiled script magic bytes.
        and $autoit_magic
        and
        (
            // High-confidence match for specific DarkCloud campaign artifacts.
            1 of ($embedded_files*)
            or
            // Broader TTP-based detection for in-memory execution.
            // This combination may flag other legitimate or malicious AutoIt scripts.
            ($api_vp and $api_cw)
        )
}
