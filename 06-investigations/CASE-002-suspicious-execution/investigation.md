# CASE-002: Suspicious Execution Investigation

## 1. Case Overview

| Field | Details |
|---|---|
| Case ID | CASE-002 |
| Case Name | Suspicious Execution |
| Host | Windows endpoint |
| SIEM | Splunk Enterprise |
| Endpoint Telemetry | Sysmon and Windows PowerShell Operational |
| Primary Event | Sysmon Event ID 1 — Process Creation |
| Related Events | Sysmon Event IDs 5 and 11 |
| ATT&CK Mapping | T1059.001 — PowerShell |
| Investigation Status | Completed |
| Final Assessment | Inconclusive — no confirmed malicious execution |

## 2. Investigation Objective

Investigate potentially suspicious script-interpreter and LOLBin execution activity by examining:

- Process creation and command-line arguments.
- Parent-child process relationships.
- Process GUID correlation.
- Associated file creation events.
- PowerShell Script Block Logging.
- Available endpoint telemetry.

The objective was to determine whether the observed execution represented malicious activity, expected system behavior, or controlled detection-validation activity.

## 3. Initial Findings

A Splunk search for Sysmon Event ID 1 identified 38 events matching script-interpreter and selected parent-process conditions during the selected investigation period.

The reviewed results included:

| Timestamp | Process | Parent Process | Observation |
|---|---|---|---|
| 12:54:08 | powershell.exe | powershell.exe | PowerShell child process |
| 12:53:53 | powershell.exe | explorer.exe | PowerShell launched from Explorer |
| 12:01:25 | certutil.exe | powershell.exe | Controlled DET-005 validation |
| 11:21:48 | powershell.exe | wscript.exe | Controlled DET-004 validation |
| 11:20:51 | powershell.exe | cmd.exe | Controlled DET-004 validation |
| 11:11:40 | powershell.exe | cmd.exe | Controlled DET-003 validation |

Additional reviewed events included Splunk Universal Forwarder processes and Windows process activity.

The 38-event result was not treated as 38 confirmed suspicious executions. Only the events with available supporting details were assessed individually.

## 4. PowerShell Process Investigation

Two PowerShell processes were identified and correlated using Sysmon Process GUIDs.

### Parent process

| Field | Value |
|---|---|
| Image | powershell.exe |
| Process ID | 18672 |
| Parent Image | explorer.exe |
| Parent Process ID | 10380 |
| Process GUID | `{bc68e428-0861-6af7-461b-000000003200}` |
| Timestamp | 2026-11-13 12:53:53 |
| Integrity Level | Medium |
| SHA256 | `D8F182560210D43BAAF767D482AD1DC1207372522E91413B9D5E515A875E552D` |

The recorded parent command line was `"C:\WINDOWS\Explorer.EXE"`. The PowerShell command line shown in the process event did not contain additional command arguments.

### Child process

| Field | Value |
|---|---|
| Image | powershell.exe |
| Process ID | 9332 |
| Parent Process ID | 18672 |
| Process GUID | `{bc68e428-0870-6af7-4b1b-000000003200}` |
| Parent Process GUID | `{bc68e428-0861-6af7-461b-000000003200}` |
| Timestamp | 2026-11-13 12:54:08 |

The child process referenced the parent's Process GUID, establishing the parent-child relationship.

The child process hash and integrity level were not available in the captured output and are therefore not reported.

### PID Reuse Consideration

Additional events showed that PID 18672 had previously been assigned to Splunk Universal Forwarder processes.

This demonstrates why PID-only correlation is unreliable across time. Process GUIDs provide a stronger identifier for correlating process activity, particularly when Windows reuses process IDs.

## 5. Related Sysmon Events

The investigation correlated the two PowerShell processes with related Sysmon events.

| Event ID | Event Type | Observation |
|---|---|---|
| 1 | Process Creation | Parent and child PowerShell processes identified |
| 11 | File Create | Files created under temporary and Recent CustomDestinations directories |
| 5 | Process Terminated | Parent PowerShell process termination observed |

### File Creation Observations

The following file patterns were observed:

- `__PSScriptPolicyTest_*.ps1`
- `__PSScriptPolicyTest_*.psm1`
- Temporary files under the user's Recent CustomDestinations directory.
- `StartupProfileData-Interactive` under the PowerShell user profile directory.

The `__PSScriptPolicyTest_*` filenames are consistent with PowerShell execution-policy testing behavior. However, the available events do not independently establish the exact cause of every file creation.

The parent PowerShell process termination was observed at approximately 12:54:12.

The captured results did not establish the termination status of the child process.

## 6. PowerShell Script Block Logging

Windows PowerShell Operational Event ID 4104 was searched to identify available script-block content associated with the investigation.

The focused investigation window, November 13, 2026, 12:50 PM–12:56 PM, returned no matching events.

A separate broader search previously displayed 111 Event ID 4104 records, but a later broad search returned zero. These inconsistent broad-search results were not treated as definitive evidence of missing telemetry across the entire period.

### Assessment

Script-block content for the investigated execution could not be established from the focused search.

This limits the ability to determine the exact PowerShell commands or script content executed by the two processes.

The absence of matching Event ID 4104 records does not prove that no PowerShell commands were executed.

## 7. Controlled Detection Tests

Several events matched previously conducted controlled validation activities:

| Detection | Test Activity | Assessment |
|---|---|---|
| DET-003 | PowerShell execution with `-ExecutionPolicy Bypass` | Controlled benign test |
| DET-004 | CMD and WScript launching PowerShell | Controlled benign test |
| DET-005 | CertUtil local Base64 decoding | Controlled benign test |

These events were associated with the project's detection-validation activities.

The CertUtil test involved local file decoding. It did not validate external file retrieval or payload execution.

## 8. MITRE ATT&CK Mapping

| Technique | Relevance |
|---|---|
| T1059.001 — PowerShell | PowerShell execution was observed |

This mapping describes the observed execution mechanism. It does not establish that an adversary performed the activity.

## 9. Investigation Assessment

**Final classification: Inconclusive.**

The investigation established:

1. A PowerShell process launched from Windows Explorer.
2. A second PowerShell process launched by the first PowerShell process.
3. Related Sysmon file creation events.
4. Termination of the parent PowerShell process.
5. Several separate events matching controlled detection-validation tests.

However, the available evidence did not establish:

- The exact script-block content of the investigated execution.
- A confirmed malicious payload.
- Confirmed command-and-control communication.
- A confirmed compromise or unauthorized execution.

The observed PowerShell chain cannot be conclusively classified as malicious or benign based on the available evidence.

## 10. Response and Recommendations

No destructive containment action was justified by the available evidence.

Recommended follow-up:

- Continue monitoring PowerShell process creation.
- Ensure PowerShell Script Block Logging is enabled and forwarded.
- Correlate Sysmon Event IDs 1, 3, 5, 11 and 22 where configured and available.
- Investigate unexpected parent-child process relationships.
- Preserve Process GUIDs, hashes, command lines and timestamps during future investigations.
- Validate telemetry collection by generating controlled PowerShell activity and confirming that corresponding events reach Splunk.

## 11. Evidence

| Screenshot | Description |
|---|---|
| `03-case-002-timeline.png` | Correlated Sysmon process and file activity |
| `04-case-002-investigation.png` | PowerShell Script Block Logging search result |

## 12. Limitations

- The investigation used endpoint telemetry from a single Windows endpoint.
- Only the reviewed subset of the 38 matching process events was individually assessed.
- Script-block content for the focused execution window was unavailable.
- The child process hash and integrity level were not captured in the available output.
- No conclusion about compromise can be made from the observed process chain alone.
- No external network or threat-intelligence correlation was established for this case.

## 13. Lessons Learned

- Process GUID correlation is more reliable than PID-only correlation.
- Parent-child relationships provide useful execution context.
- File creation events can add context to process investigations.
- Detection alerts require investigation and validation before classification.
- Missing telemetry must be documented as a limitation, not interpreted as proof of clean activity.

---

**Case Status:** Investigation completed.

**Final Outcome:** Inconclusive. No confirmed malicious execution or compromise identified from the available evidence.
