rule WEBSHELL_PHP_F5_Uploader_FireAnt
{
    meta:
        description = "Detects a specific PHP webshell observed being deployed to F5 BIG-IP load balancers by the Fire Ant threat actor (UNC3886). The actor exploits CVE-2022-1388 to drop this file uploader webshell, typically at '/usr/local/www/xui/common/css/css.php'."
        author = "Rob Weber"
        date = "2025-07-25"
        version = 1
        reference = "https://www.sygnia.co/blog/fire-ant-a-deep-dive-into-hypervisor-level-espionage/"
        tags = "FILE, WEBSHELL, APT, FIRE_ANT, UNC3886, F5"
        mitre_attack = "T1190, T1505.003"
        malware_family = "Fire Ant"
        malware_type = "Webshell"

    strings:
        // Specific strings from the simple file uploader webshell code
        $s1 = "if ($_FILES[\"file\"][\"error\"] > 0)" ascii
        $s2 = "move_uploaded_file($_FILES[\"file\"][\"tmp_name\"], \"/tmp/\" . $_FILES[\"file\"][\"name\"]);" ascii
        $s3 = "echo \" . \" . \"/tmp/\" . $_FILES[\"file\"][\"name\"];" ascii

    condition:
        // This is a very small PHP file.
        filesize < 1KB
        // Require all the specific code artifacts to ensure high fidelity and avoid matching other simple uploaders.
        and all of them
}
