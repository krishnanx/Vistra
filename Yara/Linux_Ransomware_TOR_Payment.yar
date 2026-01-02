rule Linux_Ransomware_TOR_Payment_Fixed{
    meta:
        description = "TOR_based ransomware payment infrastructure"
        confidence = "high"
        severity = 90
        layer = "static"
        os = "linux"
        action = "delete"
    strings:
        // Indicators for a TOR darknet address
        $tor_onion = ".onion" ascii nocase
        $tor_http  = "http://" ascii nocase
        
        // Indicators related to payment and decryption
        $key_pay   = "payment" ascii nocase
        $key_dec   = "decrypt" ascii nocase
        
        // Additional common ransomware strings
        $key_btc   = "bitcoin" ascii wide nocase
        $key_wallet= "wallet" ascii wide nocase

    condition:
        3 of them
}