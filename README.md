# SOC Detection Lab — MITRE ATT&CK on Microsoft Sentinel

🚧 Work in progress 🚧

Detection-engineering home lab. Adversary techniques are emulated with Atomic Red Team, detected with custom KQL analytics rules in Microsoft Sentinel, and mapped to MITRE ATT&CK.

## Objectives

- Build a reproducible detection pipeline from endpoint telemetry to Sentinel incidents.
- Implement custom KQL-based analytics rules for selected ATT&CK techniques.
- Validate detections end-to-end: emulate → detect → triage → document.
- Demonstrate detection engineering fundamentals: scope, telemetry, logic, tuning, and validation.

## Architecture

A local, isolated VMware network hosts three VMs:

- **CLIENT01** (Windows 11) – primary detection target
- **DC01** (Windows Server 2022, Domain Controller) – domain-level telemetry (onboarding in progress)
- **Kali Linux** – attacker machine

Both Windows hosts run **Sysmon** with the SwiftOnSecurity configuration. Azure Arc connects them to Azure, where the **Azure Monitor Agent (AMA)** is deployed. Data Collection Rules (DCRs) specify which logs are collected:

- Sysmon Operational log
- Windows Security log

Logs are forwarded to a **Log Analytics Workspace (LAW)** and visualized/detected in **Microsoft Sentinel** (via the Microsoft Defender portal). Sentinel analytics rules run KQL queries to detect malicious activity and raise incidents.

**Current telemetry coverage:** CLIENT01 is fully onboarded. DC01 onboarding is in progress and will extend coverage to domain-level telemetry (e.g., Kerberos service-ticket events for Kerberoasting detection).

![SOC Lab Architecture](architecture/soc_lab_architecture_local_to_sentinel.svg)

## Detection coverage

Coverage is visualized in the MITRE ATT&CK Navigator layer, showing techniques emulated with Atomic Red Team and detected via custom KQL analytics rules in Sentinel.

![ATT&CK Coverage Map](https://github.com/user-attachments/assets/d7528806-01ff-4dcc-91e8-3edc636f087f)

[🧭 Open interactive ATT&CK coverage map](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/main/mitre-att%26ck-coverage/layer.json)


## Detections

## Detections

| Technique | Tactic | Status |
|---|---|---|
| [T1059.001 PowerShell](detections/T1059.001-powershell/writeup.md) | Execution | ✅ Detected |
| [T1059.003 Windows Command Shell](detections/T1059.003-windows-command-shell/writeup.md) | Execution | ✅ Detected |
| [T1547.001 Registry Run Keys](detections/T1547.001-registry-run-key-persistence/writeup.md) | Persistence, Privilege Escalation | ✅ Detected |
| [T1053.005 Scheduled Task](detections/T1053.005-scheduled-task/writeup.md) | Execution, Persistence, Privilege Escalation | ✅ Detected |
| [T1112 Modify Registry](detections/T1112-modify-registry/writeup.md) | Defense Impairment, Persistence | ✅ Detected |
| [T1218.011 System Binary Proxy Execution: Rundll32](detections/T1218.011-Rundll32/writeup.md) | Stealth | ✅ Detected |
| T1558.003 Kerberoasting | Credential Access | 🔲 Planned |
| T1087 Account Discovery | Discovery | 🔲 Planned |
| T1018 Remote System Discovery | Discovery | 🔲 Planned |
| T1021.001 Remote Desktop Protocol | Lateral Movement | 🔲 Planned |

Each detection writeup covers:

- Technique and ATT&CK mapping  
- Emulation approach (Atomic Red Team)  
- Telemetry source (Sysmon event IDs, Windows logs)  
- Detection logic (KQL analytics rule)  
- Validation (Sentinel incident, evidence)  
- False-positive considerations  
- Detection lifecycle

## Incident triage reports

Multi-technique attack-chain triage scenarios are planned once additional detections are in place. These will show how to correlate related alerts into a coherent incident narrative.

## What I learned

Key takeaways and lessons learned will be added as the project progresses and more detections are validated.
