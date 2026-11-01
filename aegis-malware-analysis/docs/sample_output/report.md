# AEGIS Analysis Report
**SHA-256:** `c0be15d83247498e82b93256df59de9331d3c19e999f8096cee78df2ab65978a`  
**Size:** 1536 bytes  
**Verdict:** CRITICAL (score 0.9494)

## Risk components
- yara: 0.900
- behavior: 0.999

## YARA matches
- Suspicious_Process_Injection_APIs (high): Imports commonly used together for remote process injection

## Suspicious imports
- process_injection: CreateRemoteThread, VirtualAllocEx, WriteProcessMemory
- anti_analysis: IsDebuggerPresent
- persistence: RegSetValueExA
- dynamic_loading: GetProcAddress, LoadLibraryA

## Structural anomalies
- high_entropy_section:.text
- rwx_section:.text

## Behavior signals
- lolbin_execution: 2 event(s)
- shadow_copy_deletion: 1 event(s)
- encoded_powershell: 1 event(s)
- registry_persistence: 1 event(s)
- encrypted_extension_writes: 1 event(s)
- network_activity: 1 event(s)

## IOCs
- urls: http://update-check.example-c2.net/gate.php
- domains: gate.php, update-check.example-c2.net
