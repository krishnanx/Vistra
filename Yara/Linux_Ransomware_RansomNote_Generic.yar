rule Linux_Ransomware_RansomNote_Generic
{
    meta:
        description = "Generic Linux ransomware ransom note"
        confidence = "high"
        severity = 95
        layer = "static"
        os = "linux"
        action = "delete"

    strings:
        $note1 = "Your files have been encrypted"
        $note2 = "All your data is locked"
        $btc   = "bitcoin"
        $pay   = "Send payment to"
        $tor   = ".onion"

    condition:
        3 of them
}
