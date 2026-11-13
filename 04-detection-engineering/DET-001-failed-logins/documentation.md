# DET-001 — Windows Failed Logon Detection

## 1. Overview

| Attribute | Value |
|---|---|
| Detection ID | DET-001 |
| Detection Name | Windows Failed Logon Detection |
| SIEM | Splunk Enterprise |
| Operating System | Windows 10 Pro |
| Log Source | Windows Security Log |
| Event ID | 4625 |
| Index | `main` |
| Sourcetype | `XmlWinEventLog:Security` |
| Status | Tested and validated |

## 2. Objective

Detect repeated failed login attempts against the same Windows account.

The detection identifies at least two failed logins within five minutes using Splunk SPL.

## 3. Detection Query

```spl
index=main source="WinEventLog:Security" "4625"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| bin _time span=5m
| stats count as failed_attempts by _time TargetUserName
| where failed_attempts >= 2
| sort -failed_attempts
```

## 4. Detection Logic

1. Collect Windows failed login events (Event ID 4625).
2. Extract the target username.
3. Group events into five-minute windows.
4. Count failures for each account.
5. Return accounts with two or more failures.

## 5. Important Event Fields

| Field | Description |
|---|---|
| Event ID 4625 | Failed login |
| TargetUserName | Account targeted |
| LogonType 2 | Interactive login |
| Status `0xc000006d` | Logon failure |
| SubStatus `0xc000006a` | Incorrect password |

## 6. Test Results

The detection was tested using controlled failed login attempts on the Windows endpoint.

- Three failed login events were received by Splunk.
- Two events occurred within the same five-minute window.
- One event occurred outside that window.
- The detection correctly identified the two matching events.

**Result: PASS — Detection logic successfully identified the controlled test activity.**

## 7. MITRE ATT&CK Mapping

| Technique | ID |
|---|---|
| Brute Force | T1110 |
| Password Guessing | T1110.001 |

These techniques provide investigation context. The test events do not prove an actual attack occurred.

## 8. Investigation

When the detection triggers:

- Identify the affected account.
- Review the timestamps and number of failures.
- Check the logon type and source address.
- Correlate with successful login events (4624).
- Determine whether the activity is legitimate or suspicious.

## 9. Limitations

- The threshold of two failures in five minutes is for lab testing, not production tuning.
- Legitimate users can also generate failed login events.
- This detection does not identify password spraying across multiple accounts.
- Scheduled alerts and automated responses have not been implemented.

## 10. Evidence

| Screenshot | Description |
|---|---|
| `01-failed-logon-events.png` | Failed login events in Splunk |
| `02-field-extraction.png` | Extracted Windows event fields |
| `03-detection-results.png` | Detection results showing two failures |

## 11. Final Status

**Implemented and validated in a controlled lab environment.**

This detection demonstrates Windows log collection, SPL field extraction, time-based event correlation, and threshold-based detection.
