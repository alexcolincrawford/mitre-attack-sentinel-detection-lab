# T1053.005 — Scheduled Task/Job: Scheduled Task

**Tactic:** Persistence (also Execution, Privilege Escalation)
**ATT&CK:** [T1053.005](https://attack.mitre.org/techniques/T1053/005/)
**Status:** ✅ Detected

## Summary

Scheduled tasks are a heavily used persistence mechanism. An attacker who registers a task
gains execution on a trigger they control (at logon, at startup, on a schedule), often
surviving reboots and sometimes running as SYSTEM. Tasks can be created several ways
(`schtasks.exe`, PowerShell cmdlets, or more advanced methods involving the WMI/CIM API), so
this detection covers all the common creation methods rather than assuming one tool.

## Emulation

Simulated with Atomic Red Team, using the assumed-breach model where tests run directly on
the victim endpoint. From the Atomic Red Team install directory, in an elevated PowerShell
session:

```powershell
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
Invoke-AtomicTest T1053.005 -GetPrereqs
Invoke-AtomicTest T1053.005
```

Cleanup after testing. Important here, as these tests register real scheduled tasks:

```powershell
Invoke-AtomicTest T1053.005 -Cleanup
```

## Telemetry source

- **Sysmon Event ID 1** (Process Create), collected via Azure Monitor Agent into the
  Log Analytics `Event` table.
- Sysmon configured with the SwiftOnSecurity baseline config.

**Why Sysmon EID 1?** Task creation is observable as the process that performs it. EID 1
captures the full command line of each, which is what distinguishes the creation method and
intent.

An alternative telemetry source would be Windows Security Event ID 4698 (Scheduled Task Created), but Sysmon EID 1 was chosen because it provides richer process command-line context.

## Detection logic (via KQL)

Written against the Sysmon-via-AMA schema (`Event` table), string-matching the `EventData`
XML field. The detection matches task *creation* across all three common methods:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where (EventData has "schtasks.exe" and EventData has "/create")
   or EventData has_any ("Register-ScheduledTask", "New-ScheduledTask", "RegisterByXml")
| project TimeGenerated, Computer, RenderedDescription
| sort by TimeGenerated desc
```

A `schtasks.exe`-only rule is a common blind spot: scheduled tasks can also be created via
PowerShell (`Register-ScheduledTask` / `New-ScheduledTask`) or the WMI/CIM API
(`Invoke-CimMethod ... RegisterByXml`), neither of which launches `schtasks.exe`. Attackers may use these alternate APIs because they avoid spawning schtasks.exe, 
bypassing detections that rely solely on command-line monitoring of that utility.

## Sentinel analytics rule

| Setting | Value |
|---|---|
| Rule type | Scheduled query |
| Run frequency | Every 5 minutes |
| Lookback | Last 1 hour |
| Alert threshold | Results > 0 |
| Suppression | On - stop for 1 hour after an alert |
| Entity mapping | Host → HostName = `Computer` |
| Incident creation | Enabled |
| MITRE mapping | Persistence / T1053.005 |

Suppression is enabled, carrying forward the tuning lesson from the
[T1547.001 detection](https://github.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/blob/main/detections/T1547.001-registry-run-key-persistence/writeup.md):
a 1-hour lookback absorbs ingestion latency, while suppression stops the same events raising
duplicate incidents across consecutive runs.

## Validation

The rule fired and raised a single incident attributed to `CLIENT01.lab.local`, grouping task
creation across all three methods.

[![T1053.005 Scheduled Task Creation incident raised on CLIENT01, alongside the other lab detections](https://github.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/raw/main/detections/T1053.005-scheduled-task/screenshots/incidentforscheduledtaskcreation.png)](/alexcolincrawford/mitre-attack-sentinel-detection-lab/blob/main/detections/T1053.005-scheduled-task/screenshots/incidentforscheduledtaskcreation.png)

Notable captured activity:

- **`schtasks.exe /create`** : Creates a scheduled task from the command line. The task can be configured to run at logon, system startup, or at a specific time.

- **Credentials in command line** : A scheduled task created using `/RU` and `/RP`, where the account password is supplied directly on the command line.

- **UAC bypass (`EventViewerBypass` / `CompMgmtBypass`)** : A technique that combines a scheduled task running with the highest privileges and a registry modification to execute a process with elevated rights.

- **Encoded payload (`ATOMIC-T1053.005`)** : A scheduled task that launches an encoded PowerShell command, making the underlying command more difficult to read at first glance.

- **PowerShell creation** : Scheduled tasks created through PowerShell cmdlets such as `New-ScheduledTaskAction` and `Register-ScheduledTask` instead of `schtasks.exe`.

- **WMI/CIM creation** : Scheduled tasks created through WMI/CIM methods, typically by registering an XML task definition using `Invoke-CimMethod`.

The PowerShell and WMI/CIM entries are the key result because they demonstrate coverage beyond the traditional schtasks.exe utility. This validates that the detection remains effective when tasks are registered through alternate Windows management interfaces.

[![Captured Sysmon EID 1 record on CLIENT01: a scheduled task created via the WMI/CIM RegisterByXml method through powershell.exe](https://github.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/raw/main/detections/T1053.005-scheduled-task/screenshots/t1053.005-registerbyxml-record.png)](/alexcolincrawford/mitre-attack-sentinel-detection-lab/blob/main/detections/T1053.005-scheduled-task/screenshots/t1053.005-registerbyxml-record.png)

## False-positive considerations

Scheduled task creation is routine, as software installers, updaters, and administrators
create tasks legitimately, so this rule will fire on benign activity in a real environment. It
would be tuned by:

- Allow-listing known-good task names, and expected administrative task creation to reduce false positives from legitimate software and routine system administration.
- Prioritising higher-risk characteristics such as tasks running as SYSTEM, encoded or bypass-related PowerShell activity, and credentials supplied on the command line
- Correlating with the creating user/context (interactive admin vs automated installer)

## Detection lifecycle covered

Emulate (Atomic Red Team) → confirm telemetry (Sysmon EID 1) → detect across three creation
methods (KQL analytics rule) → raise incident (Sentinel/Defender) → suppression to prevent
duplicate incidents → document (this writeup) and false-positive analysis.
