# CASE-001: Local Authentication Failures and Session Correlation

## 1. Case Summary

| Field | Details |
|---|---|
| Case ID | CASE-001 |
| Case Name | Local Authentication Failures and Session Correlation |
| Host | Windows 10 endpoint |
| SIEM | Splunk Enterprise |
| Log Source | Windows Security Event Log |
| Investigation Date | 2026-11-13 |
| Status | Inconclusive — further attribution required |
| Priority | Low, based on currently available evidence |

### Executive Summary

This investigation examined three failed authentication events associated with the local Windows account `DELL`, followed by successful authentication and session activity.

All three failures originated from the loopback address `127.0.0.1`. The events reported status `0xc000006d` and substatus `0xc000006a`, consistent with a logon failure caused by an incorrect password.

The Security event records identified `svchost.exe` as the associated process, with PID `0x988`, logon process `User32`, and authentication package `Negotiate`.

A current service lookup associated PID 2440 (`0x988`) with the Windows User Manager service. However, the currently observed process start time was 11:05:24, after the historical failures. Therefore, the current service mapping cannot establish which service owned that PID when the failures occurred. Historical process attribution remains unresolved.

Subsequent successful logons and explicit credential events were observed. These events provide session context but do not establish the cause of the failed attempts.

**Conclusion:** The available evidence does not confirm an attack or compromise. The three local authentication failures remain unexplained and require additional historical process-level telemetry for definitive attribution.

---

## 2. Investigation Scope

The investigation focused on:

- Windows Security Event ID 4625 — failed logon.
- Windows Security Event ID 4624 — successful logon.
- Windows Security Event ID 4634 — logoff.
- Windows Security Event ID 4648 — explicit credential usage.
- Authentication source IP and logon type.
- Associated process information.
- Correlation of authentication events using logon IDs.
- Available Sysmon process-creation telemetry.

The investigation was performed against the Windows endpoint logs forwarded to Splunk.

---

## 3. Initial Findings

Six failed logon events were identified in the investigated search period.

| Account | Failed attempts | Source IP | Logon Type | Classification |
|---|---:|---|---:|---|
| DELL | 3 | 127.0.0.1 | 2 | Unexplained local failures |
| SOC_Test01 | 1 | 127.0.0.1 | 3 | Controlled lab test |
| SOC_Test02 | 1 | 127.0.0.1 | 3 | Controlled lab test |
| SOC_Test03 | 1 | 127.0.0.1 | 3 | Controlled lab test |

The three `SOC_Test` failures were generated during the controlled password-spraying detection validation. They are expected test activity and are not treated as evidence of an actual attack.

The three `DELL` failures were not explained by the controlled tests.

### Authentication failure details

| Timestamp | Account | Logon Type | Status | Substatus |
|---|---|---:|---|---|
| 2026-11-13 07:50:54.255 | DELL | 2 | 0xc000006d | 0xc000006a |
| 2026-11-13 07:50:56.362 | DELL | 2 | 0xc000006d | 0xc000006a |
| 2026-11-13 09:07:09.144 | DELL | 2 | 0xc000006d | 0xc000006a |

Interpretation:

- `0xc000006d` indicates a general logon failure.
- `0xc000006a` indicates an incorrect password.
- Logon Type 2 represents an interactive logon.
- `127.0.0.1` is the local loopback address.

These fields describe the authentication failure but do not independently identify the application, service, or user action responsible.

---

## 4. Process Attribution

The failed authentication events contained the following process information:

| Field | Observed Value |
|---|---|
| Process Name | `C:\Windows\System32\svchost.exe` |
| Process ID | `0x988` |
| Decimal PID | `2440` |
| Logon Process | `User32` |
| Authentication Package | `Negotiate` |
| Workstation | `DESKTOP-EK3C8K3` |
| Source IP | `127.0.0.1` |

### Service attribution check

A current Windows service lookup associated PID 2440 with:

- Service: `UserManager`
- Display Name: `User Manager`
- State: Running
- Start Mode: Automatic

The current process start time was 11:05:24 on 2026-11-13.

This timestamp is later than the observed failed logons at 07:50 and 09:07.

Consequently, the current PID-to-service mapping cannot be used to attribute the historical failures. Windows can reuse process IDs after a process exits.

### Sysmon correlation

A search for Sysmon Event ID 1 process-creation records associated with PID 2440 did not return matching results in the available telemetry.

Therefore, the investigation could not establish:

- The historical parent process.
- The original process start time.
- The historical service-to-process relationship.
- The command line associated with the process.

**Assessment:** Process attribution is incomplete. The current User Manager association is not sufficient evidence that this service caused the historical authentication failures.

---

## 5. Authentication Session Correlation

The investigation correlated failed logons with nearby successful logons, explicit credential events, and logoff events.

### 07:50 authentication sequence

Two successful logon events were observed at approximately 07:50:59.

| Event ID | Observation |
|---|---|
| 4625 | Two failed DELL authentication attempts occurred at 07:50:54 and 07:50:56 |
| 4624 | Two successful DELL logon sessions appeared at 07:50:59 |
| 4648 | Explicit credential usage was recorded in the same sequence |
| 4634 | Logoff events matched both observed successful session IDs |

Successful session IDs:

- `0x375ae0d`
- `0x375ad83`

Both session IDs had corresponding logoff events.

### 08:12 authentication sequence

Two successful DELL logon sessions were observed at approximately 08:12:03.

Successful session IDs:

- `0x38f1174`
- `0x38f10f4`

Both session IDs had corresponding logoff events. An Event ID 4648 was also observed in this sequence.

### 09:07 authentication sequence

A failed DELL authentication event occurred at 09:07:09.

Two successful DELL logon sessions and an Event ID 4648 were observed at approximately 09:07:11.

Successful session IDs:

- `0x3e99791`
- `0x3e9974e`

A corresponding Event ID 4634 was visible for `0x3e9974e` in the available results. A matching logoff for the other session was not established from the captured output.

### Interpretation

Event ID 4648 records an attempt to use explicit credentials. It is not, by itself, proof of malicious activity.

The successful logons and corresponding logoff records provide useful session context. However, temporal proximity does not prove that the failed attempts and successful sessions were caused by the same process or user action.

---

## 6. Evidence Assessment

| Evidence | Finding | Assessment |
|---|---|---|
| Event ID 4625 | Three unexplained DELL failures | Requires further investigation |
| Source IP | `127.0.0.1` for all three DELL failures | Local-origin activity |
| Logon Type | Type 2 | Interactive authentication |
| Status/Substatus | `0xc000006d` / `0xc000006a` | Incorrect-password failure |
| Process | `svchost.exe`, PID `0x988` | Historical ownership unresolved |
| Logon Process | `User32` | Authentication context |
| Authentication Package | `Negotiate` | Authentication mechanism |
| Event ID 4648 | Explicit credential events observed | Contextual evidence, not proof of compromise |
| Event IDs 4624/4634 | Successful sessions and logoff activity observed | Session correlation available |
| Sysmon Event ID 1 | No matching process-creation record found | Process attribution limitation |

### Evidence that supports a local activity hypothesis

- All three failures originated from the loopback address.
- The failures were recorded as interactive logons.
- Successful local sessions and explicit credential events appeared in nearby sequences.

### Evidence that remains missing

- Historical process ownership for PID 2440.
- A matching Sysmon process-creation record.
- A verified application or service responsible for the failed attempts.
- Additional endpoint context explaining why the incorrect credentials were supplied.

No external source IP or confirmed malicious process was identified in the evidence reviewed.

---

## 7. MITRE ATT&CK Mapping

| Technique | Name | Relevance |
|---|---|---|
| T1110 | Brute Force | Authentication failures are relevant to brute-force monitoring, but these three failures do not establish a brute-force attack. |
| T1078 | Valid Accounts | Successful authentication events are relevant to account-use investigations, but no unauthorized account use was established. |

These are investigation-relevant techniques, not confirmed ATT&CK mappings for an attacker.

---

## 8. Incident Assessment

**Final classification: Inconclusive — unexplained local authentication failures.**

The investigation did not establish a confirmed compromise or malicious authentication attempt.

The three `DELL` failures are distinct from the controlled `SOC_Test` failures used for detection validation. The local source address and nearby session activity suggest local Windows or application-related authentication behavior may be involved. However, the available telemetry is insufficient to confirm that explanation.

The historical process attribution gap prevents a definitive root-cause determination.

---

## 9. Response and Recommended Actions

No destructive containment action was justified by the available evidence.

Recommended follow-up actions:

1. Continue monitoring Event IDs 4624, 4625, 4634, and 4648.
2. Investigate any recurrence of failed authentication events for the `DELL` account.
3. Preserve the relevant Windows Security logs for historical analysis.
4. Improve Sysmon process-creation collection and retention so future authentication events can be correlated with process activity.
5. Correlate process IDs with process creation times and, where available, Sysmon Process GUIDs rather than relying on PID alone.
6. Investigate repeated explicit credential events and their associated process context.
7. Escalate if failures recur with remote source addresses, suspicious parent-child process relationships, unexpected account activity, or other corroborating indicators.

---

## 10. Investigation Limitations

- The investigation relied on telemetry available in the local Windows endpoint and Splunk.
- The current service mapping was collected after the historical authentication events.
- PID reuse prevents reliable historical service attribution using the current process state.
- No matching Sysmon Event ID 1 record was available for the investigated PID.
- Event ID 4648 does not independently establish malicious credential use.
- Successful logons occurring after failures do not prove that the failures were legitimate.
- The investigation did not establish a definitive root cause.

---

## 11. Evidence Files

The following screenshots document the investigation:

| Evidence File | Description |
|---|---|
| `01-case-001-timeline.png` | Authentication timeline and correlated Security events |
| `02-case-001-investigation.png` | Failed DELL authentication events and process details |

Evidence directory:

`06-investigations/screenshots/`

---

## 12. Final Conclusion

CASE-001 demonstrates the investigation of failed local authentication events using Splunk and Windows Security telemetry.

The investigation separated known controlled test activity from unexplained endpoint activity, examined authentication status codes, reviewed process attribution, and correlated successful logon and logoff events.

The case remains inconclusive because the historical process responsible for the failed authentication attempts could not be identified.

The correct SOC outcome is to document the uncertainty, preserve the evidence, improve telemetry coverage, and continue monitoring rather than declare an unsupported benign or malicious verdict.
