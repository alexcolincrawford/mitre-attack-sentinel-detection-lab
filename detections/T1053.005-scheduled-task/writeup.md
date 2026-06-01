# T1053.005 — Scheduled Task/Job: Scheduled Task

**Tactic:** Persistence (also Execution, Privilege Escalation)  
**ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/)  
**Status:** ✅ Detected

## Summary

Scheduled tasks are a heavily used persistence mechanism. An attacker who registers a task gains execution on a trigger they control (at logon, at startup, on a schedule), often surviving reboots and sometimes running as SYSTEM.

Tasks can be created in several ways (`schtasks.exe`, PowerShell cmdlets, or WMI/CIM API), so this detection covers all common creation methods rather than assuming one tool.

## Emulation

Simulated with Atomic Red Team, using the assumed-breach model where tests run directly on the victim endpoint. From the Atomic Red Team install directory, in an elevated PowerShell session:

```powershell
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
Invoke-AtomicTest T1053.005 -GetPrereqs
Invoke-AtomicTest T1053.005
```

Cleanup after testing is important, as these tests register real scheduled tasks:

```powershell
Invoke-AtomicTest T1053.005 -Cleanup
```

## Telemetry source

- **Sysmon Event ID 1** (Process Create), collected via Azure Monitor Agent into the Log Analytics `Event` table.
- Sysmon configured with the SwiftOnSecurity baseline config.

**Why Sysmon EID 1?** Task creation is observable as the process that performs it. EID 1 captures the full command line, which distinguishes the creation method and intent.

An alternative would be Windows Security Event ID 4698 (Scheduled Task Created), but Sysmon EID 1 was chosen because it provides richer process command-line context.

## Detection logic

Written against the Sysmon-via-AMA schema (`Event` table), string-matching the `EventData` field. The detection matches task creation across all three common methods:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where (EventData has "schtasks.exe" and EventData has "/create")
   or EventData has_any ("Register-ScheduledTask", "New-ScheduledTask", "RegisterByXml")
| project TimeGenerated, Computer, RenderedDescription
| sort by TimeGenerated desc
```

A `schtasks.exe`-only rule is a common blind spot: scheduled tasks can also be created via PowerShell (`Register-ScheduledTask` / `New-ScheduledTask`) or the WMI/CIM API (`Invoke-CimMethod ... RegisterByXml`), neither of which launches `schtasks.exe`. Attackers may use these alternate APIs to avoid spawning `schtasks.exe` and bypass detections that rely solely on command-line monitoring of that utility.

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
| MITRE mapping | Persistence / T1053.005 |

Suppression is enabled, carrying forward the tuning lesson from the T1547.001 detection: a 1-hour lookback absorbs ingestion latency, while suppression stops the same events from raising duplicate incidents across consecutive runs.

## Validation

The rule fired and raised a single incident attributed to `CLIENT01.lab.local`, grouping task creation across all three methods.


![T1053.005 Scheduled Task Creation incident raised on CLIENT01, alongside the other lab detections](https://github.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/raw/main/detections/T1053.005-scheduled-task/screenshots/incidentforscheduledtaskcreation.png)

Notable captured activity:

- **`schtasks.exe /create`**: Creates a scheduled task from the command line, configured to run at logon, startup, or a specific time.
- **Credentials in command line**: A task created using `/RU` and `/RP`, where the account password is supplied directly on the command line.
- **UAC bypass (`EventViewerBypass` / `CompMgmtBypass`)**: A technique combining a scheduled task running with highest privileges and a registry modification to execute a process with elevated rights.
- **Encoded payload (`ATOMIC-T1053.005`)**: A task that launches an encoded PowerShell command, obscuring the underlying command.
- **PowerShell creation**: Tasks created via PowerShell cmdlets such as `New-ScheduledTaskAction` and `Register-ScheduledTask` instead of `schtasks.exe`.
- **WMI/CIM creation**: Tasks created through WMI/CIM methods, typically by registering an XML task definition using `Invoke-CimMethod`.

Captured Sysmon EID 1 record showing scheduled task creation via PowerShell and WMI/CIM RegisterByXml, demonstrating coverage beyond schtasks.exe.

![WMI/CIM entries](https://github.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/blob/main/detections/T1053.005-scheduled-task/screenshots/t1053.005-registerbyxml-record.png)


## False-positive considerations

Scheduled task creation is routine; software installers, updaters, and administrators create tasks legitimately, so this rule will fire on benign activity in a real environment. It can be tuned by:

- Allow-listing known-good task names and expected administrative task creation to reduce false positives from legitimate software and routine system administration.
- Prioritising higher-risk characteristics such as tasks running as SYSTEM, encoded or bypass-related PowerShell activity, and credentials supplied on the command line.
- Correlating with the creating user/context (interactive admin vs automated installer).

## Detection lifecycle covered

Emulate (Atomic Red Team) → confirm telemetry (Sysmon EID 1) → detect across three creation methods (KQL analytics rule) → raise incident (Sentinel/Defender) → suppression to prevent duplicate incidents → false-positive analysis → document (this writeup).
