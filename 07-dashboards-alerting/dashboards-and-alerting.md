# Dashboards and Alerting

## 1. Overview

This section implements centralized security monitoring and alerting using Splunk Enterprise.

The dashboard provides visibility into Windows authentication activity, failed logons, endpoint process executions, and incoming telemetry sources.

A scheduled alert identifies repeated failed authentication attempts against the same Windows account.

## 2. SOC Security Monitoring Dashboard

**Dashboard name:** SOC Security Monitoring

**Description:** Windows security monitoring and threat detection dashboard.

The dashboard includes the following panels.

| Panel | Purpose |
|---|---|
| Total Security Events | Displays the volume of Windows Security events |
| Failed Logons | Tracks Windows Event ID 4625 |
| Sysmon Process Executions | Tracks Sysmon Event ID 1 |
| Authentication Activity | Compares successful and failed logons over time |
| Failed Logons by Username | Identifies accounts with repeated authentication failures |
| Top 10 Process Executions | Shows frequently observed process executions |
| Windows Telemetry by Source | Displays event volume by log source |

### Shared Time Range

A dashboard-level Time Range Picker controls the search period across the dashboard panels.

The time range can be adjusted to investigate recent activity or examine a broader historical period.

## 3. Dashboard Detection Queries

### Authentication Activity

Windows Event IDs:
- 4624 — Successful logon
- 4625 — Failed logon

```spl
index=main source="WinEventLog:Security"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| search EventID IN ("4624","4625")
| eval Authentication=case(
    EventID="4624","Successful Logons",
    EventID="4625","Failed Logons"
)
| timechart span=1h count by Authentication
```

### Failed Logons by Username

```spl
index=main source="WinEventLog:Security"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| search EventID="4625"
| where isnotnull(TargetUserName) AND TargetUserName!=""
| stats count AS FailedAttempts by TargetUserName
| sort - FailedAttempts
```

### Top 10 Process Executions

```spl
index=main source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| search EventID="1"
| where isnotnull(Image) AND Image!=""
| stats count AS ProcessExecutions by Image
| sort - ProcessExecutions
| head 10
```

### Windows Telemetry by Source

```spl
index=main
| stats count AS EventCount by source
| sort - EventCount
```

## 4. Scheduled Alert

**Alert name:** Windows - Repeated Failed Logons

**Description:** Detects three or more failed Windows logons for the same account within a five-minute bucket.

### Detection SPL

```spl
index=main source="WinEventLog:Security"
| rex field=_raw "<EventID>(?<EventID>\d+)</EventID>"
| rex field=_raw "<Data Name='TargetUserName'>(?<TargetUserName>[^<]+)</Data>"
| search EventID="4625"
| where isnotnull(TargetUserName) AND TargetUserName!=""
| bin _time span=5m
| stats count AS FailedAttempts by _time TargetUserName
| where FailedAttempts >= 3
| table _time TargetUserName FailedAttempts
| sort -_time
```

### Alert Configuration

| Setting | Configuration |
|---|---|
| Alert type | Scheduled |
| Intended schedule | Every 5 minutes |
| Search time range | Last 10 minutes |
| Trigger condition | Number of results greater than 0 |
| Trigger behavior | Once |
| Alert action | Add to Triggered Alerts |
| Severity | Medium |
| Permissions | Private |

The configured schedule and search time range should be checked in Splunk before treating the alert as independently verified.

### Alert Validation

A controlled validation generated three failed authentication events for the temporary test account `SOC_Test01`.

The alert search returned:

| Field | Observed result |
|---|---|
| Target account | SOC_Test01 |
| Failed attempts | 3 |
| Five-minute bucket | 2026-11-13 13:45 |
| Search result | Alert condition matched |

The test demonstrated that the detection query could identify three failed logons for the same account within a five-minute bucket.

These were controlled lab events, not evidence of a real brute-force attack.

## 5. Evidence

The following screenshots document the dashboard and alert implementation.

| Screenshot | Evidence |
|---|---|
| `01-security-overview.png` | Overall SOC monitoring dashboard |
| `02-authentication-dashboard.png` | Authentication activity and failed logons by username |
| `03-endpoint-dashboard.png` | Endpoint process monitoring panels |
| `04-alert-triggered.png` | Triggered alert search results |

## 6. Detection Limitations

- A high number of failed logons does not independently prove malicious activity.
- Legitimate users, misconfigured applications, and automated services can generate authentication failures.
- The detection uses fixed five-minute buckets rather than a continuously sliding five-minute window.
- A ten-minute search window overlaps consecutive scheduled executions and can produce repeated matches.
- Alert throttling and duplicate suppression require further validation.
- The current alert action adds results to Triggered Alerts; it does not automatically isolate endpoints or block accounts.
- The process execution panel shows frequency, not maliciousness.

## 7. Security Monitoring Value

This implementation demonstrates:

- Centralized Windows security telemetry monitoring.
- Authentication activity analysis.
- Sysmon process execution visibility.
- Splunk dashboard construction.
- Scheduled detection and alert configuration.
- Controlled alert validation.
- Recognition of detection limitations and false-positive considerations.

## 8. Future Improvements

- Validate the saved cron expression and actual execution interval.
- Implement alert throttling or suppression to reduce duplicate notifications.
- Improve authentication correlation using source IP, logon type, and host context.
- Add investigation workflows for triggered alerts.
- Develop risk-based detection logic and test against benign activity.
