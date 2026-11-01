rule Suspicious_Process_Injection_APIs : injection
{
    meta:
        description = "Imports commonly used together for remote process injection"
        severity = "high"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
    condition:
        all of them
}

rule Suspicious_Downloader_Strings : downloader
{
    meta:
        description = "Download-and-execute string pattern"
        severity = "medium"
    strings:
        $a = "URLDownloadToFile"
        $b = "ShellExecute"
        $c = "WinExec"
    condition:
        2 of them
}

rule Ransom_Note_Indicators : ransomware
{
    meta:
        description = "Common ransom-note phrasing"
        severity = "high"
    strings:
        $a = "your files have been encrypted"
        $b = "bitcoin"
        $c = "decrypt"
    condition:
        2 of them
}

rule EICAR_Test_File : test
{
    meta:
        description = "EICAR anti-malware test string (harmless)"
        severity = "info"
    strings:
        $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        all of them
}
