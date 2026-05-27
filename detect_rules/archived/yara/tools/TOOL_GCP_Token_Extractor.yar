import "pe"

rule TOOL_GCP_Token_Extractor_v1
{
    meta:
        description = "Detects tools designed to extract Google Workspace or GCP refresh tokens and credentials from local Windows systems by targeting Chrome's data stores or GCPW LSA secrets."
        author = "RW"
        date = "2025-08-20"
        version = 1
        tags = "TOOL, GCP, GOOGLE_WORKSPACE, CREDENTIAL_ACCESS, TOKEN_THEFT, FILE"
        mitre_attack = "T1555.003, T1528"
        malware_family = "GCPW_Token_Extractor"

    strings:
        // --- Target Locations (Chrome Profile & Registry) ---
        $loc_chrome_path = "AppData\\Local\\Google\\Chrome\\User Data" ascii wide
        $loc_web_data_db = "Web Data" ascii wide // Chrome SQLite DB for tokens
        $loc_local_state_file = "Local State" ascii wide // Chrome file with encryption key
        $loc_token_table = "token_service" ascii wide // SQLite table with tokens
        $loc_reg_path = "SOFTWARE\\Google\\Accounts" ascii wide // Registry path for tokens

        // --- Google API Endpoints ---
        $api_oauth = "googleapis.com/oauth2/v4/token" ascii
        $api_password_recovery = "devicepasswordescrowforwindows-pa.googleapis.com/v1/getprivatekey" ascii

        // --- OAuth & Crypto Parameters ---
        // These strings can be common in other legitimate OAuth clients, so they are combined with more specific indicators.
        $param_refresh_token = "refresh_token" ascii wide
        $param_client_id = "client_id" ascii wide
        $param_client_secret = "client_secret" ascii wide
        $param_os_crypt = "os_crypt" ascii wide // Key in Local State JSON
        $param_encrypted_key = "encrypted_key" ascii wide // Key in Local State JSON
        $param_unprotect_api = "CryptUnprotectData" ascii // Windows API for decryption

        // --- LSA Secret for GCPW ---
        $lsa_gcpw_secret = "Chrome-GCPW-" ascii wide

    condition:
        // Target PE files under 5MB
        pe.is_pe and filesize < 5MB and
        (
            // Scenario 1: Chrome/Registry Token Theft from browser data
            (
                2 of ($loc_*) and
                $api_oauth and
                3 of ($param_*)
            )
            or
            // Scenario 2: GCPW LSA Secret Password Recovery
            (
                $lsa_gcpw_secret and $api_password_recovery
            )
        )
}
