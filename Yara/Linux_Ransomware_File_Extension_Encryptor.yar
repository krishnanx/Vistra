rule Linux_Ransomware_File_Extension_Encryptor
{
    meta:
        description = "Detects Linux ransomware extension renaming behavior"
        confidence = "high"
        severity = 85
        layer = "static"
        os = "linux"
        action = "quarantine"

    strings:
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $ext3 = ".crypt"
        $rename = "rename("
        $readdir = "readdir"

    condition:
        3 of them
}
