# DET-001 — Windows Failed Logon Detection

## 1. Overview

| Attribute | Value |
|---|---|
| Detection ID | DET-001 |
| Detection Name | Windows Failed Logon Detection |
| Platform | Windows 10 Pro |
| SIEM | Splunk Enterprise |
| Data Source | Windows Security Event Log |
| Event ID | 4625 |
| Splunk Index | `main` |
| Sourcetype | `XmlWinEventLog:Security` |
| Severity | Low — initial lab classification |
| Validation Status | Passed — controlled test |

## 2. Objective

Detect repeated failed Windows authentication attempts against the same user account within a defined time window.

This detection uses Windows Security Event ID 4625 and Splunk Search Processing Language (SPL) to identify accounts with at least two failed logons within five minutes.

## 3. Detection Logic

The detection performs the following operations:

1. Searches Windows Security events for Event ID 4625.
2. Extracts the target username from the raw XML event.
3. Groups events into five-minute time windows.
4. Counts failed logons for each account.
5. Returns accounts with at least two failures in a window.

## 4. SPL Detection Query

```spl
index=main source="WinEventLog:Security" "4625"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| bin _time span=5m
| stats count as failed_attempts by _time TargetUserName
| where failed_attempts >= 2
| sort -failed_attempts
```

## 5. Relevant Windows Event Fields

| Field | Meaning |
|---|---|
| Event ID 4625 | Failed logon |
| TargetUserName | Account associated with the failed attempt |
| LogonType 2 | Interactive logon |
| Status `0xc000006d` | Logon failure |
| SubStatus `0xc000006a` | Incorrect password |

## 6. Validation and Results

The detection was tested using controlled failed logon attempts on the Windows endpoint.

### Observed results

- Three Event ID 4625 events were received by Splunk.
- Two events occurred within the same five-minute window.
- One additional event occurred outside that window.
- The detection returned the two events in the matching time bucket.
- The threshold condition was satisfied.

### Validation outcome

**PASS — The SPL query successfully identified the controlled test events meeting the configured threshold.**

This validates event ingestion, field extraction, time-window aggregation, and threshold filtering.

It does not establish that an actual brute-force attack occurred.

## 7. MITRE ATT&CK Context

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | T1110 | Repeated authentication failures can be relevant to brute-force activity |
| Password Guessing | T1110.001 | Potentially relevant when repeated password attempts are observed |

These are contextual mappings, not proof of malicious activity. Event ID 4625 alone does not establish attacker intent.

## 8. Investigation Guidance

When this detection triggers, an analyst should:

1. Identify the affected account.
2. Examine the timestamps and frequency of failed attempts.
3. Review the Windows logon type.
4. Inspect source IP and workstation information when available.
5. Correlate failures with successful logons (Event ID 4624).
6. Check whether the activity is associated with a legitimate user, service, scheduled task, or suspicious authentication pattern.

## 9. Response Considerations

Depending on investigation findings:

- Contact the account owner or system administrator.
- Check for account lockouts and related authentication events.
- Investigate suspicious source systems.
- Escalate confirmed malicious activity according to the incident response process.

Do not automatically disable accounts based solely on this detection.

## 10. Limitations

- The threshold of two failures within five minutes is a lab validation setting, not an enterprise-tuned threshold.
- Repeated failures may result from mistyped passwords or legitimate application activity.
- This query groups by account and time window; it does not independently identify password spraying across multiple accounts.
- Source IP extraction and correlation are not yet included in this detection.
- A search query has been validated; scheduled alerting and automated response have not been implemented or verified.

## 11. Evidence

| Screenshot | Evidence |
|---|---|
| `01-failed-logon-events.png` | Three Windows failed logon events received by Splunk |
| `02-field-extraction.png` | Extracted authentication fields |
| `03-detection-results.png` | Two failures identified in the same five-minute window |

## 12. Final Status

**Detection implemented and validated against controlled lab events.**

The detection demonstrates Windows authentication telemetry ingestion, SPL-based field extraction, time-window aggregation, threshold-based detection, and basic SOC investigation methodology.
