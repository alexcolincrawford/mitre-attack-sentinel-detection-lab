# T1218.011 — System Binary Proxy Execution: Rundll32

**Tactic:** Defense Evasion, Execution  
**ATT&CK:** [T1218.011](https://attack.mitre.org/techniques/T1218/011/)  
**Status:** ✅ Detected

## Summary

`rundll32.exe` is a legitimate Windows binary that can be abused to run code through unusual command-line arguments or script/HTML handlers. Attackers abuse it because it is a trusted Microsoft-signed binary that can proxy code execution while blending into normal system activity, often as part of fileless techniques or application-control bypasses.

This detection looks for `rundll32.exe` process creation with suspicious inline patterns such as `javascript:`, `vbscript:`, and `mshtml,RunHTMLApplication`, which are strongly associated with LOLBin abuse.

## Emulation

The behavior was emulated on the lab endpoint using the Atomic Red Team test for T1218.011, generating Sysmon process creation telemetry for rundll32.exe. The resulting process chain showed rundll32.exe spawning calc.exe through the test payload's LaunchINFSection invocation, confirming that the required telemetry was collected and successfully matched by the detection logic.

If reproducing in a controlled lab, run the Atomic Red Team test for T1218.011 from an elevated PowerShell session and clean up afterward.

## Telemetry source

- **Sysmon Event ID 1** (Process Create), collected via Azure Monitor Agent into the Log Analytics `Event` table.
- Sysmon configured with command-line capture enabled so the full `EventData` field includes the suspicious arguments.

**Why Sysmon EID 1?** LOLBin abuse is best identified at process creation time because the full command line reveals the exact execution method, parent process, and suspicious inline handlers. This is richer than a simple binary name match and is the best fit for `rundll32` abuse monitoring.

## Detection logic

Written against the Sysmon-via-AMA schema (`Event` table) and matching the `EventData` field for `rundll32` plus known suspicious execution patterns:

```kql
Event
| where Source == "Microsoft-Windows-Sysmon"
| where EventID == 1
| where EventData has "rundll32"
| where EventData has_any (
    "javascript:",
    "vbscript:",
    "mshtml,RunHTMLApplication",
    "mshtml,#135",
    "advpack.dll,LaunchINFSection",
    "ieadvpack.dll,LaunchINFSection",
    "syssetup.dll,SetupInfObjectInstallAction"
  )
| project TimeGenerated, Computer, RenderedDescription
| sort by TimeGenerated desc
```

This rule is intentionally **high-signal**. Legitimate `rundll32.exe` activity typically invokes expected DLL exports within standard operating system or application workflows. In contrast, inline script handlers, HTML application execution, and INF-based installation functions are relatively uncommon and are frequently associated with adversary tradecraft and LOLBin abuse.

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
| MITRE mapping | Defense Evasion / T1218.011 |

The 1-hour lookback helps absorb ingestion delay, while suppression prevents the same test or execution burst from generating duplicate incidents during repeated scheduled runs.

## Validation

The detection fired successfully and generated an incident for `T1218.011-Rundll32 (LOL Bins)` on `CLIENT01.lab.local`, confirming that the emulated activity was identified as expected.

![Incident confirmation in Microsoft Sentinel showing the T1218.011 Rundll32 incident](screenshots/1.%20Incident%20Confirmation.png)

The incident details show the detection description and confirm the alert category as Defense evasion.

![Inspect record showing the incident details and alert context for the Rundll32 detection](screenshots/2.%20Inspect%20Record.png)

Notable activity observed during alert investigation includes:

The process creation event records rundll32.exe, a legitimate Windows binary commonly abused as a LOLBin, spawning calc.exe (PID 5812) via an invocation of advpack.dll,LaunchINFSection. The event also captures a working directory of C:\Users\Administrator\AppData\Local\Temp\ and establishes the parent-child process relationship (rundll32.exe → calc.exe). Together, these artifacts provide clear evidence of execution through the LaunchINFSection function and demonstrate the LOLBin-based execution behavior targeted by the detection logic.

## False-positive considerations

`rundll32.exe` is a legitimate Windows utility and may be used by software installers, driver packages, administrative tools, and system configuration workflows. While the command-line patterns targeted by this rule are uncommon in routine operations, legitimate activity can occasionally resemble abuse. The detection can be tuned by allow-listing known-good installers, trusted parent processes, and approved command-line patterns.

Higher-priority events include executions involving script handlers, HTML application execution, temporary-directory staging, obfuscated arguments, or unusual parent processes such as Office applications, browsers, scripting engines, or user-launched executables.

## Detection lifecycle covered

Emulate (Atomic Red Team) → Validate telemetry (Sysmon EID 1) → Detect suspicious `rundll32.exe` execution in Sentinel → Generate incident → Investigate process and command-line evidence → Tune suppression and allow-lists → Document findings
