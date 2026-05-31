# T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys
 
**Tactic:** Persistence
**ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/)
**Status:** ✅ Detected

## Summary
 
The `Run` and `RunOnce` registry keys cause programs to execute automatically when a user
logs on, making them one of the most common persistence mechanisms in real intrusions. An
attacker who writes a malicious command into these keys gains execution on every logon. This
detection identifies writes to the `CurrentVersion\Run` / `RunOnce` keys, a classic
autostart persistence location.

## Scope
 
T1547.001 is an umbrella technique covering many autostart locations. This detection
deliberately targets the `Run`/`RunOnce` registry keys, as it's the most common variant. In a
production environment, full coverage of this technique would be layered across multiple
focused detections rather than one broad rule.

## Emulation
 
Simulated with Atomic Red Team, using the assumed-breach model where tests run directly on
the victim endpoint. From the Atomic Red Team install directory, in an elevated PowerShell
session:
 
```powershell
Import-Module C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1 -Force
Invoke-AtomicTest T1547.001 -GetPrereqs
Invoke-AtomicTest T1547.001
```

Cleanup after testing - important here, as these tests plant real persistence (registry
keys, startup-folder files, Winlogon entries):
 
```powershell
Invoke-AtomicTest T1547.001 -Cleanup
```

> Note: T1547.001 contains 20 atomic tests spanning many persistence locations. This detection targets the
> Run/RunOnce registry keys specifically.
 
## Telemetry source
 
- **Sysmon Event ID 13** (Registry value set), collected via Azure Monitor Agent into the
  Log Analytics `Event` table.
- Sysmon configured with the SwiftOnSecurity baseline config.

**Why Sysmon EID 13?** Persistence via Run keys is a *registry* operation, not a process
event, so the relevant telemetry is registry value modification (EID 13), not process
creation (EID 1). The SwiftOnSecurity Sysmon config already flags these events with its own
`RuleName: T1060,RunKey` tag, confirming Run-key writes are a monitored persistence signal.

## Detection logic (via KQL)
 
Written against the Sysmon-via-AMA schema (`Event` table), string-matching the `EventData`
XML field. The detection matches registry value-set events targeting the
`CurrentVersion\Run` / `RunOnce` keys:
 
```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 13
| where EventData has @"\CurrentVersion\Run"
| project TimeGenerated, Computer, RenderedDescription
| sort by TimeGenerated desc
```
 
`has @"\CurrentVersion\Run"` matches both `...\CurrentVersion\Run` and
`...\CurrentVersion\RunOnce` (RunOnce contains the same substring), covering both autostart
key variants in one filter.

## Sentinel analytics rule
 
| Setting | Value |
|---|---|
| Rule type | Scheduled query |
| Run frequency | Every 5 minutes |
| Lookback | Last 1 hour |
| Alert threshold | Results > 0 |
| Suppression | On — stop for 1 hour after an alert |
| Entity mapping | Host → HostName = `Computer` |
| Incident creation | Enabled |
| MITRE mapping | Persistence / T1547.001 |

**On suppression:** this rule has suppression enabled (stop for 1 hour after firing), a
refinement over the earlier [T1059.003 detection](../T1059.003%20Windows%20Command%20Shell/writeup.md),
which had a 1-hour lookback but no suppression and consequently re-detected the same events
across multiple runs: generating ~15 duplicate incidents from a single test. Enabling
suppression here produced a single clean incident from the same kind of repeated activity. This shows lookback and suppression must be tuned together: a long lookback absorbs ingestion latency, while suppression prevents duplicate incidents and alert fatigue.

## Validation

The rule fired and raised a single incident attributed to `CLIENT01.lab.local`, grouping the captured Run-key writes. The detected activity included three registry persistence entries:

- `...\CurrentVersion\Run\calc` → `calc.exe`
- `...\CurrentVersion\Run\Atomic Red Team` → `AtomicRedTeam.exe` (written via `reg.exe`)
- `...\CurrentVersion\Run\socks5_powershell` → `powershell.exe -windowstyle hidden -ExecutionPolicy Bypass`

The third entry is the standout because the command itself carries two evasion red flags:

- `-windowstyle hidden`: runs with no visible window, so the user never sees PowerShell launch (stealth)
- `-ExecutionPolicy Bypass`: ignores PowerShell's policy that normally restricts script execution

Set to run from a Run key, this command would re-execute on every logon.

![T1547.001-sock5-incident](screenshots/10.%20T1547.001%20-%20sock5-incident.png)

 
## False-positive considerations
 
Run-key writes are not inherently malicious, as legitimate software (installers, updaters)
registers autostart entries the same way. In testing, this project produced only the emulated
entries, but in production this rule would be tuned by:


- Allow-listing known-good software publishers / signed binaries
- Baselining expected autostart entries and alerting on deviations.
- Prioritising entries with suspicious traits (hidden windows, encoded/bypass PowerShell,
  execution from temp/user paths)

## Detection lifecycle covered
 
Emulate (Atomic Red Team) → confirm telemetry (Sysmon EID 13) → detect (KQL analytics rule)
→ raise incident (Sentinel/Defender) → apply suppression to prevent duplicate incidents →
document (this writeup).


