# T1059.001 — Command and Scripting Interpreter: PowerShell

🚧 Work in progress 🚧

**Tactic:** Execution
**ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
**Status:** ✅ Detected

 
## Summary
 
PowerShell is one of the most heavily abused execution mechanisms in real intrusions.
Attackers use it for download cradles, in-memory execution, and obfuscated commands to
evade detection. This detection identifies PowerShell launched with the flags and patterns
that distinguish malicious use from benign administration.

## Emulation

Simulated with Atomic Red Team, using the assumed-breach model where tests run directly on the victim endpoint.

​`
Import-Module .\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
`

`
Invoke-AtomicTest T1059.001 -GetPrereqs
`

`
Invoke-AtomicTest T1059.001
`

Cleanup after testing to return the host to a known-good state:

​`
Invoke-AtomicTest T1059.001 -Cleanup
​`

## Telemetry source
 
- **Sysmon Event ID 1** (Process Create), collected via Azure Monitor Agent into the
  Log Analytics `Event` table.
- Sysmon configured with the SwiftOnSecurity baseline config.

## Detection logic (via KQL)
 
Written against the **Sysmon-via-AMA schema** (`Event` table), where event detail lives in
the `EventData` XML field, so the query string-matches on `EventData` rather than using the
clean named columns of the Defender Advanced Hunting schema:
 
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where EventData has "powershell"
| where EventData has_any ("-enc", "-EncodedCommand", "FromBase64String",
                           "DownloadString", "IEX", "hidden", "-nop", "-NoProfile")
| project TimeGenerated, Computer, RenderedDescription
| sort by TimeGenerated desc
```

## Sentinel analytics rule
 
| Setting | Value |
|---|---|
| Rule type | Scheduled query |
| Run frequency | Every 5 minutes |
| Lookback | Last 5 minutes |
| Alert threshold | Results > 0 |
| Entity mapping | Host → HostName = `Computer` |
| Incident creation | Enabled |
| MITRE mapping | Execution / T1059.001 |

## Validation

To-Do..

