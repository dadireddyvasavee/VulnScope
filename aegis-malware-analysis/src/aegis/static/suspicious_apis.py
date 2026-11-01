"""Windows API imports commonly abused by malware, grouped by behavior category.
Presence alone is NOT proof of maliciousness - many benign programs import these."""

SUSPICIOUS_APIS: dict[str, set[str]] = {
    "process_injection": {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                          "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "ResumeThread"},
    "anti_analysis": {"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
                      "GetTickCount", "OutputDebugStringA"},
    "persistence": {"RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
                    "CreateServiceA", "CreateServiceW"},
    "keylogging": {"SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"},
    "networking": {"InternetOpenA", "InternetOpenUrlA", "URLDownloadToFileA", "URLDownloadToFileW",
                   "WSAStartup", "connect", "HttpSendRequestA"},
    "crypto": {"CryptEncrypt", "CryptAcquireContextA", "CryptGenKey", "BCryptEncrypt"},
    "dynamic_loading": {"LoadLibraryA", "LoadLibraryW", "GetProcAddress"},
    "execution": {"WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"},
}


def classify_imports(imports: list[str]) -> dict[str, list[str]]:
    names = set(imports)
    return {cat: sorted(names & apis) for cat, apis in SUSPICIOUS_APIS.items() if names & apis}
