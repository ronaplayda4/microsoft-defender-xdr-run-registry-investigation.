# Microsoft Defender XDR: Windows Run Registry Investigation

## Executive Summary

This portfolio project documents the investigation of a medium-severity Microsoft Defender XDR incident titled **Endpoint - Windows RUN Registry Modified**. Two alerts were generated after `setup.exe` created or modified `RunOnce` registry values on a Windows 11 endpoint.

The activity initially matched a persistence behavior. Process-tree analysis, registry review, file reputation checks, digital-signature validation, and Microsoft Defender Advanced Hunting showed that the changes were part of recurring Microsoft Edge update and cleanup activity.

**Final verdict:** Benign  
**Impact:** No compromise identified  
**Remediation:** None required  
**MITRE ATT&CK:** T1547.001 — Registry Run Keys / Startup Folder

> This investigation was completed in an authorized SOC simulation environment. IP addresses and file hashes have been redacted or excluded from public evidence.

## Skills Demonstrated

- Microsoft Defender XDR incident triage
- Process-tree and parent-child process analysis
- Windows Registry persistence analysis
- KQL-based endpoint investigation
- File reputation and signature validation
- MITRE ATT&CK mapping
- Evidence-based alert classification
- SOC case documentation and QC submission

## Investigation Scope

The investigation sought to answer five questions:

1. What process modified the Windows Run registry key?
2. What executable was referenced by the registry value?
3. Was the process chain expected or suspicious?
4. Was the file trusted and known to security vendors?
5. Was this a one-time event or part of an established baseline?

## 1. Incident Triage

The incident contained two medium-severity alerts associated with the same Windows 11 endpoint. The first activity occurred at approximately 8:15 AM, followed by a second alert at approximately 9:14 AM. The alerts were categorized as **Persistence** and correlated because they occurred on the same device.

![Incident overview](evidence/01-incident-overview.png)

### Initial hypothesis

A program may have modified a Windows `Run` or `RunOnce` registry key to execute automatically at logon. Because legitimate installers also use these keys, the alert title alone was not sufficient to establish malicious persistence.

## 2. Process-Tree Analysis

The first alert showed the following general sequence:

`wininit.exe` → `services.exe` → `MicrosoftEdgeUpdate.exe` → Edge installer → `setup.exe` → `RunOnce` registry modification

![First alert process tree](evidence/02-first-alert-process-tree.png)

The second alert showed another Edge maintenance sequence involving `elevation_service.exe` and `setup.exe`. Its command-line arguments referenced renaming the Edge executable and deleting old versions.

![Second alert process tree](evidence/03-second-alert-process-tree.png)

The parent-child relationships were consistent with a system-level Microsoft Edge update. No suspicious PowerShell, command shell, script interpreter, temporary-directory payload, or unrelated user-launched process was observed in the alert chain.

## 3. Registry Evidence

The initiating `setup.exe` process created a value named `msedge_cleanup_{GUID}` under:

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

The value data referenced the Microsoft Edge/WebView installer and used arguments such as:

```text
--channel=stable --delete-old-versions --system-level --verbose-logging --on-logon
```

![RunOnce registry details](evidence/04-runonce-registry-details.png)

The `--on-logon` argument explains the use of `RunOnce`: the installer was configured to complete cleanup during the next logon and remove older Edge components.

## 4. MITRE ATT&CK Mapping

The observed behavior maps to **T1547.001 — Registry Run Keys / Startup Folder**, under the Persistence and Privilege Escalation tactics.

![MITRE ATT&CK mapping](evidence/05-mitre-mapping.png)

This mapping describes the behavior, not the verdict. Attackers can abuse these registry locations, but legitimate applications also use them for installation and maintenance.

## 5. File Reputation and Signature Validation

The referenced file was identified as `setup.exe`. Its hash was searched in VirusTotal without uploading the executable. The result returned **0/70 security-vendor detections**.

![VirusTotal result with hash redacted](evidence/06-virustotal-redacted.png)

VirusTotal also reported a valid digital signature and identified the file as Microsoft Edge Installer version `152.0.4191.62`. This matched the product name, version, path, and command-line evidence observed in Defender XDR.

![Digital-signature verification](evidence/07-signature-verification.png)

VirusTotal results were treated as supporting evidence rather than a standalone verdict. The conclusion relied on correlation between file reputation, signature, path, command line, and process ancestry.

## 6. Advanced Hunting

The investigation first queried registry telemetry broadly to confirm that the endpoint produced `DeviceRegistryEvents`. The search was then narrowed to the `msedge_cleanup_` value name.

```kusto
DeviceRegistryEvents
| where DeviceName == "mts-contractorpc1"
| where RegistryValueName startswith "msedge_cleanup_"
| project Timestamp,
          ActionType,
          RegistryKey,
          RegistryValueName,
          RegistryValueData,
          InitiatingProcessFileName,
          InitiatingProcessVersionInfoCompanyName,
          InitiatingProcessVersionInfoProductName,
          InitiatingProcessCommandLine,
          InitiatingProcessAccountName
| order by Timestamp desc
```

The query returned five matching events across three dates: August 19, August 29, and September 4. Each event was initiated by `setup.exe`, identified as Microsoft Corporation and Microsoft Edge Installer.

![Advanced Hunting baseline](evidence/08-advanced-hunting-baseline.png)

The expanded September 4 result confirmed:

- `RegistryValueSet` activity under `HKLM\...\RunOnce`
- An `msedge_cleanup_{GUID}` value name
- A Microsoft Edge installer path
- A stable-channel cleanup command
- Execution under the `SYSTEM` account

![Expanded Advanced Hunting evidence](evidence/09-advanced-hunting-event-details.png)

The historical recurrence established a normal maintenance baseline and reduced the likelihood of one-time malicious persistence.

## Evidence Assessment

| Evidence | Finding | Assessment |
|---|---|---|
| Alert behavior | `RunOnce` value modification | Potential persistence behavior requiring validation |
| Process ancestry | Windows services launched Microsoft Edge update components | Expected system process chain |
| Registry data | Edge installer configured to delete old versions at logon | Consistent with update cleanup |
| Execution account | `SYSTEM` | Consistent with system-level maintenance |
| File path and metadata | Microsoft Edge installation directory and product metadata | Expected |
| Digital signature | Valid Microsoft signature | Trusted publisher evidence |
| VirusTotal | 0/70 detections | No known malicious detection |
| Historical hunting | Five similar events across three dates | Recurring baseline behavior |

## Final Verdict

The alert was resolved as **Benign**. Microsoft Defender correctly detected a `RunOnce` registry modification, but the underlying behavior was legitimate Microsoft Edge update and cleanup activity. No malicious persistence, compromise, or actionable indicator of compromise was identified.

No containment or remediation was required. The investigation was documented and submitted for quality-control review.

## Key Takeaway

A MITRE ATT&CK match or a suspicious automated evidence label does not independently prove malicious activity. Reliable classification requires validating the process tree, registry data, command line, file trust, execution context, and historical baseline together.
