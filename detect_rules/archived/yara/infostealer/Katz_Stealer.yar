import "hash"

rule MAL_KatzStealer_Hashes_v1
{
    meta:
        description = "Detects known samples of the Katz Stealer infostealer based on their SHA1 file hashes."
        date = "2025-07-23"
        version = 1
        reference = "https://www.sentinelone.com/blog/katz-stealer-powerful-maas-on-the-prowl-for-credentials-and-crypto-assets/"
        hash = "0076795b220fa48c92b57994b015119aae8242ca"
        hash = "0c1f2ee0328e0ed7e4ec84ef452bffa1749f5602"
        hash = "17ce22264551bd32959790c4c2f57bec8304e2ce"
        hash = "1976a1a05a6a47ac33eb1cfc4e5a0eb11863f6eb"
        hash = "1b6b072df8f69a47fd481fa9be850c0063fd5b93"
        hash = "1d5ef46357eb2298b1c3c4faccbaafa729137613"
        hash = "1ee406eb68ab92bad77cf53df50c4ce6963e75fd"
        hash = "26e089bed61c0d89e5078f387bd55dd5895d4fc0"
        hash = "29daa866c85fc1e302c40a73bc2a0772aa285295"
        hash = "2f2ced67e87101f4d1275456f0861209809492fc"
        hash = "3cf4f3ababa912e0e6bb71ab5abb43681d8e7ecc"
        hash = "47ea1c41f79f775f0631191ee72852c1bfb61a7e"
        hash = "4e69cb16a3768733d94bb1b5d8f1556d0bddd09b"
        hash = "4eeda02db01cdf83948a83235c82e801522efa54"
        hash = "5179dbf5e9fd708f6e6df8b4913f21c3b78d5529"
        hash = "5492947d2b85a57f40201cd7d1351c3d4b92ae88"
        hash = "571b3681f7564236b7527d5b6fe14117f9d4de6d"
        hash = "5de014856702b9f1570944e8562ce283f7cd0a64"
        hash = "6351b5505dc671d143d5970eb08050d2f7344149"
        hash = "680984e43b76aa7a58ed9b617efe6afcb1f04bb7"
        hash = "6d88a5f0021278c2c3a56c177f39f4a31f286032"
        hash = "76bb7ffe523f594308ecd482db4f32047905c461"
        hash = "80f1b8b27833db614d3f7c2a389aceb033b8ce80"
        hash = "82dc7c0ca39f114c333caae9a6931a2a1c487ee5"
        hash = "8c2422ebab77a0de81d2e46e1326d8912b099018"
        hash = "9becb041aedc7c6aafeb412b4b91788e1df65b38"
        hash = "9c60a2b4764b7b5e3a6c7f20036490a539996d8a"
        hash = "a0717a486b4e037871c4657cf353cd298f13601f"
        hash = "b3d574dfb561f5439930e2a6d10917f3aa58c341"
        hash = "b40e56439d4dcdc238b8254adbd8862c73ca34bc"
        hash = "b61f92613dc911609b781e83c5baadc7e289dbc"
        hash = "b744179d3304d1e977e680502d201b7df49cb188"
        hash = "bbf2a5fdb039366b3f9eca603bf08ae92c43c0ef"
        hash = "cc800e4977d76c38656f3f60c5ed5f02df6a2f7b"
        hash = "ce19aa5eb7fce50dd94b5f740d162f8d9b057fde"
        hash = "da5ed6b939f51370709f66cbf0d8201ec8cd58b0"
        hash = "dffc1167399631ed779b5698d0ac2d9ea74af6c8"
        hash = "dffddd2fb7b139d2066284c5e0d16909f9188dc2"
        hash = "e26d65d8c25b0be7379e4322f6ebcadecbb02286"
        hash = "e78f942ca088c4965fcc5c8011cf6f9ee5c2a130"
        hash = "fb4792306f2cf514e56bc86485920b8134954433"
        tags = "CRIME, INFOSTEALER, KATZ_STEALER, FILE"
        mitre_attack = "T1555, T1056, T1105"
        malware_family = "Katz Stealer"
        malware_type = "Infostealer"

    condition:
        // Match if the file's SHA1 hash is in the known list of Katz Stealer samples.
        hash.sha1(0, filesize) == "0076795b220fa48c92b57994b015119aae8242ca" or
        hash.sha1(0, filesize) == "0c1f2ee0328e0ed7e4ec84ef452bffa1749f5602" or
        hash.sha1(0, filesize) == "17ce22264551bd32959790c4c2f57bec8304e2ce" or
        hash.sha1(0, filesize) == "1976a1a05a6a47ac33eb1cfc4e5a0eb11863f6eb" or
        hash.sha1(0, filesize) == "1b6b072df8f69a47fd481fa9be850c0063fd5b93" or
        hash.sha1(0, filesize) == "1d5ef46357eb2298b1c3c4faccbaafa729137613" or
        hash.sha1(0, filesize) == "1ee406eb68ab92bad77cf53df50c4ce6963e75fd" or
        hash.sha1(0, filesize) == "26e089bed61c0d89e5078f387bd55dd5895d4fc0" or
        hash.sha1(0, filesize) == "29daa866c85fc1e302c40a73bc2a0772aa285295" or
        hash.sha1(0, filesize) == "2f2ced67e87101f4d1275456f0861209809492fc" or
        hash.sha1(0, filesize) == "3cf4f3ababa912e0e6bb71ab5abb43681d8e7ecc" or
        hash.sha1(0, filesize) == "47ea1c41f79f775f0631191ee72852c1bfb61a7e" or
        hash.sha1(0, filesize) == "4e69cb16a3768733d94bb1b5d8f1556d0bddd09b" or
        hash.sha1(0, filesize) == "4eeda02db01cdf83948a83235c82e801522efa54" or
        hash.sha1(0, filesize) == "5179dbf5e9fd708f6e6df8b4913f21c3b78d5529" or
        hash.sha1(0, filesize) == "5492947d2b85a57f40201cd7d1351c3d4b92ae88" or
        hash.sha1(0, filesize) == "571b3681f7564236b7527d5b6fe14117f9d4de6d" or
        hash.sha1(0, filesize) == "5de014856702b9f1570944e8562ce283f7cd0a64" or
        hash.sha1(0, filesize) == "6351b5505dc671d143d5970eb08050d2f7344149" or
        hash.sha1(0, filesize) == "680984e43b76aa7a58ed9b617efe6afcb1f04bb7" or
        hash.sha1(0, filesize) == "6d88a5f0021278c2c3a56c177f39f4a31f286032" or
        hash.sha1(0, filesize) == "76bb7ffe523f594308ecd482db4f32047905c461" or
        hash.sha1(0, filesize) == "80f1b8b27833db614d3f7c2a389aceb033b8ce80" or
        hash.sha1(0, filesize) == "82dc7c0ca39f114c333caae9a6931a2a1c487ee5" or
        hash.sha1(0, filesize) == "8c2422ebab77a0de81d2e46e1326d8912b099018" or
        hash.sha1(0, filesize) == "9becb041aedc7c6aafeb412b4b91788e1df65b38" or
        hash.sha1(0, filesize) == "9c60a2b4764b7b5e3a6c7f20036490a539996d8a" or
        hash.sha1(0, filesize) == "a0717a486b4e037871c4657cf353cd298f13601f" or
        hash.sha1(0, filesize) == "b3d574dfb561f5439930e2a6d10917f3aa58c341" or
        hash.sha1(0, filesize) == "b40e56439d4dcdc238b8254adbd8862c73ca34bc" or
        hash.sha1(0, filesize) == "b61f92613dc911609b781e83c5baadc7e289dbc" or
        hash.sha1(0, filesize) == "b744179d3304d1e977e680502d201b7df49cb188" or
        hash.sha1(0, filesize) == "bbf2a5fdb039366b3f9eca603bf08ae92c43c0ef" or
        hash.sha1(0, filesize) == "cc800e4977d76c38656f3f60c5ed5f02df6a2f7b" or
        hash.sha1(0, filesize) == "ce19aa5eb7fce50dd94b5f740d162f8d9b057fde" or
        hash.sha1(0, filesize) == "da5ed6b939f51370709f66cbf0d8201ec8cd58b0" or
        hash.sha1(0, filesize) == "dffc1167399631ed779b5698d0ac2d9ea74af6c8" or
        hash.sha1(0, filesize) == "dffddd2fb7b139d2066284c5e0d16909f9188dc2" or
        hash.sha1(0, filesize) == "e26d65d8c25b0be7379e4322f6ebcadecbb02286" or
        hash.sha1(0, filesize) == "e78f942ca088c4965fcc5c8011cf6f9ee5c2a130" or
        hash.sha1(0, filesize) == "fb4792306f2cf514e56bc86485920b8134954433"
}