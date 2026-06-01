# SOC Detection Lab — MITRE ATT&CK on Microsoft Sentinel

🚧 Work in progress 🚧

Detection-engineering home lab. Adversary techniques emulated with Atomic Red Team,
detected with custom KQL analytics rules in Microsoft Sentinel, mapped to MITRE ATT&CK.

## Architecture

Using VMware, a local isolated network hosts three VMs: CLIENT01 (Windows 11), DC01 (Windows Server 2022 configured as a Domain Controller), and a Kali Linux attacker. Both Windows hosts run Sysmon with the SwiftOnSecurity configuration. Azure Arc connects the two Windows hosts to Azure, where the Azure Monitor Agent (AMA) is deployed to each. Data Collection Rules (DCRs) define which logs the agent collects: the Sysmon Operational log and the Windows Security log. These are forwarded to a Log Analytics Workspace (LAW), where they are stored. Microsoft Sentinel runs on top of the workspace (managed through the Microsoft Defender portal), where KQL-based analytics rules detect malicious activity and raise incidents.

Note: CLIENT01 is currently onboarded to the pipeline. DC01 onboarding is **in progress** and will extend coverage to domain-level telemetry (e.g. Kerberos service-ticket events for Kerberoasting detection).

This is depicted in the below diagram.
![SOC Lab Architecture](architecture/soc_lab_architecture_local_to_sentinel.svg)

## Detection coverage

Detection coverage shown via the MITRE ATT&CK Navigator, showing techniques emulated with Atomic Red Team and detected via custom KQL analytics rules in Microsoft Sentinel.

<img width="2500" height="1000" alt="image" src="https://github.com/user-attachments/assets/d7528806-01ff-4dcc-91e8-3edc636f087f" />

[_Click Here To Open interactive ATT&CK coverage map_](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/alexcolincrawford/mitre-attack-sentinel-detection-lab/main/mitre-att%26ck-coverage/layer.json)

**Detected (4):** T1059.001 PowerShell · T1059.003 Windows Command Shell · T1547.001 Registry Run Keys · T1053.005 Scheduled Task

**Planned (6):** T1112 Modify Registry · T1218.011 Rundll32 · T1003.001 LSASS Memory · T1558.003 Kerberoasting · T1087 Account Discovery · T1018 Remote System Discovery

## Detections

## Detections

| Technique | Tactic | Status |
|---|---|---|
| [T1059.001 PowerShell](detections/T1059.001-powershell/writeup.md) | Execution | ✅ Detected |
| [T1059.003 Windows Command Shell](detections/T1059.003-windows-command-shell/writeup.md) | Execution | ✅ Detected |
| [T1547.001 Registry Run Keys](detections/T1547.001-registry-run-key-persistence/writeup.md) | Persistence, Privilege Escalation | ✅ Detected |
| [T1053.005 Scheduled Task](detections/T1053.005-scheduled-task/writeup.md) | Execution, Persistence, Privilege Escalation | ✅ Detected |
| T1112 Modify Registry | Defense Impairment, Persistence | 🔲 Planned |
| T1218.011 Rundll32 | Stealth | 🔲 Planned |
| T1003.001 LSASS Memory | Credential Access | 🔲 Planned |
| T1558.003 Kerberoasting | Credential Access | 🔲 Planned |
| T1087 Account Discovery | Discovery | 🔲 Planned |
| T1018 Remote System Discovery | Discovery | 🔲 Planned |

## Incident triage reports

Multi-technique attack-chain triage scenarios; planned once additional detections are in place

## What I learned

Key takeaways and lessons; added on project completion
