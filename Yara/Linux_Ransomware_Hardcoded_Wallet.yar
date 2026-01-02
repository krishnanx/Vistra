rule Linux_Ransomware_Hardcoded_Wallet
{
    meta:
        description = "Hardcoded cryptocurrency wallet in Linux binary"
        confidence = "medium"
        severity = 70
        layer = "static"
        os = "linux"
        action = "quarantine"

    strings:
        $btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $monero = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/

    condition:
        any of them
}
