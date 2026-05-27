rule GIFTEDCROOK_FileStealer {
meta:
        description = "Rule to detect GIFTEDCROOK_FileStealer"
        last_modified = "2025-06-18"
        version = "1.4"
        sha256 = "a6dd44c4b7a9785525e7f487c064995dc5f33522dad8252d8637f6a6deef3013"
        sha256 = "ff1be55fb5bb3b37d2e54adfbe7f4fbba4caa049fad665c8619cf0666090748a"
        sha256 = "d7a66fd37e282d4722d53d31f7ba8ecdabc2e5f6910ba15290393d9a2f371997"
        sha256 = "b9d508d12d2b758091fb596fa8b8b4a1c638b7b8c11e08a1058d49673f93147d"
        sha256 = "2930ad9be3fec3ede8f49cecd33505132200d9c0ce67221d0b786739f42db18a"
        reference = "https://arcticwolf.com/resources/blog/giftedcrook-strategic-pivot-from-browser-stealer-to-data-exfiltration-platform/"

strings:
        $a1 = "MEZXB4whdffiufw2" ascii wide
        $a2 = "QKDBFY43DCMIEDX" ascii wide
        $a3 = "%s_delete.bat" ascii wide
        $a4 = "ALPQX418BERX91D" ascii wide
        $a5 = "Fi-cook.sqlite" ascii wide

        $code1 = {8B 4C 24 64 48 8B 44 24 38 89 4C 24 30 8B 4C 24 68 89
                  4C 24 34 48 B9 00 40 32 7C C9 0B 00 00}  // Check file condition
        $code2 = {41 2A C0 49 FF C0 32 04 3A 34 ?? 88 01 4D 3B C3 72 DF} // Decryption Algo
        $code3 = {40 53 48 83 EC 30 48 8B 05 0F B8 0B 00 48 33 C4 48 89
                  44 24 28 48 83 64 24 20 00 4C 8D 05 EA 08 0B 00 48 8B
                  DA 48 8B D1 48 8D 4C 24 20 E8 E2 79 07 00 48 8B 4C 24
                  20 48 8D 15 D2 08 0B 00 4C 8B C3 E8 C6 EE FF FF 48 8B
                  4C 24 20 E8 C0 7B 07 00 48 8B 4C 24 28 48 33 CC E8 1F
                  D6 06 00 48 83 C4 30 5B C3}
        $code4 = {48 89 5C 24 18 56 57 41 56 48 83 EC 40 48 8B 05 0C B5
                  0B 00 48 33 C4 48 89 44 24 38 0F 10 05 0D 06 0B 00 0F
                  B7 05 16 06 0B 00 4C 8B F2 48 8D 54 24 20 66 89 44 24
                  30 0F 11 44 24 20 E8 57 E2 06 00 48 8B F0 48 83 C9 FF
                  48 8D 44 24 20 48 FF C1 80 3C 08 00 75 F7 48 03 F1 48
                  8D 15 E4 05 0B 00 48 8B CE E8 30 E2 06 00 48}
        $code5 = {48 8B C4 48 89 58 08 48 89 68 10 48 89 70 18 48 89 78
                  20 41 56 48 83 EC 30 33 ED 48 8B F9 48 85 C9 0F 84 60
                  01 00 00 66 39 29 0F 84 57 01 00 00 B9 90 04 00 00 E8
                  C2 39 07 00 48 8B D8 48 85 C0 0F 84 4B 01 00 00 49 83
                  CE FF 48 89 A8 88 04 00 00 45 33 C9 4C 89 B0 80 04 00
                  00 45 33 C0 48 89 A8 78 04 00 00 33 D2 48 8B CF FF 15
                  78 F1 08 00 8B C8 48 03 C9 8B F0 48 83 C1 10 49 0F 42
                  CE E8 78 39 07 00 48 89 83 88 04 00 00 48 85 C0 0F 84
                  B7 00 00 00 45 33 C9 4C 8B C0 8B D6 48 8B CF FF 15 43
                  F1 08 00 85 C0 0F 84 9E 00 00 00 8B C8 8D 7D 02 48 8B
                  83 88 04 00 00 48 8D 14 48 66 83 7A FE 2F 74 16 66 83
                  7A FE 3A 74 0F 8D 45 5C 66 39 42 FE 74 06 66 89 02 48
                  03 D7 C7 02 2A 00 00 00 48 8D B3 28 02 00 00 48 8B 8B
                  88 04 00 00 4C 8B C6 89 6C 24 28 45 33 C9 33 D2 48 89
                  6C 24 20 FF 15 FB EE 08 00 48 89 83 80 04 00 00 49 3B
                  C6 75 62 89 AB 78 04 00 00 C7 83 7C 04 00 00 01 00 00
                  00 FF 15 19 EF 08 00 83 F8 03 74 18 83 F8 05 74 0E 3D
                  0B 01 00 00 75 0C BF 14 00 00 00 EB 05 BF 0D 00 00 00
                  8B CF E8 5D 2B 07 00 48 8B 8B 80 04 00 00 49 3B CE 74}
        $code6 = {0F 28 05 ?? C0 0A 00 0F 29 85 20 04 00 00 F2 0F 10 05
                  ?? C0 0A 00 0F 29 8D 10 04 00 00 0F 28 0D ?? C0 0A 00}
condition:
uint16(0) == 0x5A4D and filesize < 1MB and ((3 of ($a*)) or (any of ($code*)))
}