# Splunk Windows SOC Detection Lab

A hands-on Security Operations Center (SOC) monitoring and detection engineering lab built with **Splunk Enterprise, Windows Event Logs, Sysmon, and Splunk Universal Forwarder**.

The project demonstrates an end-to-end security monitoring workflow: collecting endpoint telemetry, engineering SPL detections, conducting threat hunts, investigating suspicious activity, configuring alerts, and validating detection logic using controlled tests.

---

## Project Overview

This lab simulates a small SOC monitoring environment in which a Windows endpoint forwards security telemetry to Splunk Enterprise running on Ubuntu Server.

The collected telemetry is analyzed to identify suspicious authentication activity, PowerShell execution, unusual process relationships, LOLBin usage, and Windows account changes.

The objective is to demonstrate practical SOC Analyst skills through documented configurations, reusable detection queries, investigation reports, dashboards, and validation evidence.

## Lab Architecture

```text
                   WINDOWS ENDPOINT
                 Windows 10 Pro
                         |
          +--------------+--------------+
          |              |              |
      Security Logs    Sysmon       PowerShell
          |              |              |
          +--------------+--------------+
                         |
                 Splunk Universal
                    Forwarder
                         |
                  TCP Port 9997
                         |
                         v
                 UBUNTU SERVER VM
                  Splunk Enterprise
                         |
              +----------+----------+
              |          |          |
           SPL Search  Dashboards  Alerts
              |          |          |
              +----------+----------+
                         |
                  SOC Investigation
                  and Threat Hunting
```

### Environment

| Component | Technology |
|---|---|
| Endpoint | Windows 10 Pro |
| SIEM | Splunk Enterprise 10.6.1.1 |
| SIEM Server | Ubuntu Server 26.04 LTS |
| Log Forwarder | Splunk Universal Forwarder |
| Endpoint Telemetry | Sysmon |
| Virtualization | VMware Workstation Pro |
| Search Language | Splunk Processing Language (SPL) |
| Log Index | `main` |
| Splunk Web | TCP 8000 |
| Splunk Receiver | TCP 9997 |

## Telemetry Collection

The Windows endpoint forwards the following event channels to Splunk:

| Log Source | Purpose |
|---|---|
| Windows Security | Authentication and account activity |
| Windows System | Operating system and service events |
| Sysmon Operational | Process and endpoint activity |
| PowerShell Operational | PowerShell execution and script-block telemetry |

### Sysmon Telemetry

Sysmon provides additional endpoint visibility, including:

- Event ID 1 — Process creation
- Event ID 3 — Network connection
- Event ID 11 — File creation
- Event ID 16 — Sysmon configuration change
- Event ID 22 — DNS query

These event types provide supporting context for detection and investigation. Their collection and use depend on the active Sysmon configuration and available telemetry.

## Detection Engineering

The lab contains six detection scenarios implemented using SPL.

| Detection | Scenario | Description |
|---|---|---|
| DET-001 | Failed Logons | Identifies repeated Windows authentication failures |
| DET-002 | Password Spraying Pattern | Identifies failures involving multiple accounts within a time window |
| DET-003 | Suspicious PowerShell Execution | Identifies potentially suspicious PowerShell command-line indicators |
| DET-004 | Suspicious Parent-Child Processes | Identifies unusual relationships between script hosts and interpreters |
| DET-005 | LOLBin Execution | Identifies selected suspicious CertUtil command-line usage |
| DET-006 | Account Changes | Monitors selected Windows account management events |

Each detection includes SPL logic and documentation describing its objective, event source, detection logic, validation approach, and limitations.

### Detection Engineering Concepts

- Windows Event ID analysis
- SPL field extraction using `rex`
- Event filtering and aggregation
- Time-based detection logic
- Process and parent-process analysis
- Authentication monitoring
- False-positive considerations
- MITRE ATT&CK mapping

**Important:** Detection results are investigative indicators, not proof of malicious activity. The queries use heuristic logic and require contextual analysis.

## Threat Hunting

Threat hunting activities use collected endpoint telemetry to identify patterns that may require further investigation.

Hunting coverage includes:

- Successful and failed authentication activity
- Local authentication patterns and session correlation
- Process execution baselining
- Script interpreter activity
- Windows account management events

Hunting queries and findings are documented with supporting evidence and limitations.

## Security Investigations

Two investigation reports document the analysis process.

### CASE-001 — Authentication Activity Investigation

Investigates repeated failed authentication events, related successful logons, and session activity.

Key investigation areas:

- Windows Security Event IDs 4624, 4625, 4634, and 4648
- Source IP and logon type
- Authentication status and substatus
- Logon session correlation
- Process attribution limitations

**Assessment:** Inconclusive local authentication activity. No confirmed compromise was established.

### CASE-002 — Suspicious Execution Investigation

Investigates PowerShell and related process execution activity using Sysmon and PowerShell telemetry.

Key investigation areas:

- Sysmon process creation events
- Parent-child process relationships
- Process GUID correlation
- File creation activity
- PowerShell logging availability
- Execution context and command-line analysis

**Assessment:** Controlled benign activity was observed. No confirmed malicious execution or compromise was established.

## Dashboards and Alerting

### SOC Security Monitoring Dashboard

A Splunk dashboard provides visibility into authentication and endpoint activity.

Dashboard panels include:

- Authentication Activity
- Failed Logons by Username
- Top 10 Process Executions
- Windows Telemetry by Source

Additional KPI panels:

- Total Security Events
- Failed Logons
- Sysmon Process Executions

A shared time-range control supports analysis across the dashboard panels.

### Alert Configuration

**Alert name:** `Windows - Repeated Failed Logons`

The alert searches for repeated failed authentication events using a threshold of three failures within a five-minute aggregation bucket.

The alert was configured as a scheduled Splunk alert with a triggered-alert action.

Alert configuration and validation evidence are documented separately. Duplicate suppression and long-term scheduling reliability require further validation.

## Validation and Testing

Detection logic was evaluated using controlled activity on the lab endpoint.

| Test | Scenario | Result |
|---|---|---|
| TEST-001 | Three intentional failed logons | PASSED |
| TEST-002 | Successful authentication negative test | INCONCLUSIVE |
| TEST-003 | Detection query validation | PASSED |
| TEST-004 | Dashboard workflow review | COMPLETED |

### Positive Test — Repeated Failed Logons

A temporary local account was used to generate three intentional failed authentication attempts.

Observed telemetry:

- Event ID: 4625
- Target account: `SOC_VAL_POS`
- Source address: `127.0.0.1`
- Logon type: 3
- Failed attempts: 3

The detection query returned a matching result for the five-minute aggregation bucket.

**Result:** The controlled positive detection test passed.

### Negative Test — Successful Authentication

A successful authentication event (Event ID 4624) was observed in Splunk.

However, failed authentication events were also present in the broader search window. An isolated time interval proving zero failed logons was not established.

**Result:** Inconclusive. This limitation is retained in the validation report rather than being presented as a successful negative test.

## Repository Structure

```text
Splunk-Windows-SOC-Detection-Lab/
│
├── README.md
├── LICENSE
├── .gitignore
│
├── 01-architecture/
│   ├── architecture.md
│   └── screenshots/
│
├── 02-windows-telemetry/
│   ├── telemetry-configuration.md
│   ├── sysmon-config.xml
│   └── screenshots/
│
├── 03-splunk-setup/
│   ├── splunk-configuration.md
│   ├── inputs.conf.example
│   ├── outputs.conf.example
│   └── screenshots/
│
├── 04-detection-engineering/
│   ├── README.md
│   ├── DET-001-failed-logins/
│   ├── DET-002-password-spraying/
│   ├── DET-003-login-correlation/
│   ├── DET-004-suspicious-powershell/
│   ├── DET-005-lolbin-execution/
│   └── DET-006-account-changes/
│
├── 05-threat-hunting/
│   ├── hunting-report.md
│   ├── hunting-queries.spl
│   └── screenshots/
│
├── 06-investigations/
│   ├── CASE-001-authentication-attack/
│   ├── CASE-002-suspicious-execution/
│   └── screenshots/
│
├── 07-dashboards-alerting/
│   ├── dashboards-and-alerting.md
│   └── screenshots/
│
├── 08-validation-evidence/
│   ├── validation-report.md
│   └── screenshots/
│
└── docs/
    ├── troubleshooting-and-limitations.md
    └── references-and-lessons-learned.md
```

## Skills Demonstrated

**SIEM and SOC Operations**
- Splunk Enterprise
- Splunk Universal Forwarder
- SPL search and analysis
- Security monitoring
- Dashboard and alert configuration

**Endpoint Security**
- Windows Event Logs
- Sysmon
- PowerShell logging
- Process execution analysis
- Windows authentication monitoring

**Detection Engineering**
- SPL detection development
- Event correlation
- Threshold-based detections
- False-positive analysis
- Detection validation

**Threat Hunting and Incident Response**
- Authentication hunting
- Process investigation
- Event timeline analysis
- Security investigation documentation
- MITRE ATT&CK mapping

## Limitations and Future Improvements

The current lab is a single-endpoint environment and does not represent a production enterprise SOC.

Potential improvements include:

- Add more Windows endpoints and centralized telemetry.
- Improve sliding-window authentication detection.
- Add additional network and DNS detections.
- Validate scheduled alert execution and duplicate suppression.
- Improve negative-test coverage.
- Expand investigation correlation across endpoint and network telemetry.
- Add Sigma rules and detection portability.
- Evaluate detections against additional controlled attack simulations.

## Learning Objectives

This project is designed to demonstrate the practical workflow of a SOC Analyst:

```text
ATTACK SIMULATION
       |
       v
TELEMETRY COLLECTION
       |
       v
DETECTION ENGINEERING
       |
       v
THREAT HUNTING
       |
       v
INVESTIGATION
       |
       v
RESPONSE PLANNING
       |
       v
VALIDATION AND IMPROVEMENT
```
GitHub: [@usmansk006](https://github.com/usmansk006)
