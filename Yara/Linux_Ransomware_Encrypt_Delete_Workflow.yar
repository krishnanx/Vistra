rule Linux_Ransomware_Encrypt_Delete_Workflow
{
    meta:
        description = "Encrypt + delete original file pattern"
        severity = 85
        layer = "static"
        os = "linux"
        action = "quarantine"

    strings:
        $crypto1 = "EVP_EncryptInit" nocase
        $crypto2 = "AES_encrypt" nocase
        $file1   = "unlink(" ascii
        $file2   = "rename(" ascii
        $loop    = "readdir(" ascii

    condition:
        2 of them
}
