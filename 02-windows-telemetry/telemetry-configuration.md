# Windows Endpoint Telemetry

## 1. Overview

This section documents the Windows endpoint telemetry setup used in the Splunk SOC Monitoring Lab.

A physical Windows 10 Pro endpoint generates security and system events. The Splunk Universal Forwarder collects configured Windows event logs and forwards them to Splunk Enterprise running on an Ubuntu Server virtual machine.

Sysmon provides additional endpoint activity visibility for security monitoring and investigation.

## 2. Lab Environment

| Component | Configuration |
|---|---|
| Endpoint | Physical laptop |
| Operating System | Windows 10 Pro |
| SIEM | Splunk Enterprise |
| SIEM Server | Ubuntu Server VM |
| Log Forwarder | Splunk Universal Forwarder |
| Sysmon Version | 15.22 |
| Sysmon Schema | 4.91 |
| Splunk Index | `main` |

Private IP addresses, usernames and device identifiers are excluded.

## 3. Telemetry Sources

### Windows Security Logs

Windows Security logs provide authentication and account activity.

Important event IDs:

- **4624** — Successful logon
- **4625** — Failed logon
- **4688** — Process creation
- **4720** — User account created

These events support authentication monitoring and security investigations.

### PowerShell Operational Logs

PowerShell Operational logs provide visibility into PowerShell activity.

- **4104** — Script block logging
- **4103** — Module logging

Event ID 4104 was successfully observed in Splunk.

The PowerShell Operational channel is configured in the Splunk Universal Forwarder and event ingestion has been verified.

### Sysmon

Sysmon records detailed system activity in the Windows Event Log.

Installed version: **15.22**

Configuration schema: **4.91**

The Sysmon service and Operational event channel were successfully verified.

Event IDs observed during initial installation:

- **1** — Process creation
- **4** — Sysmon service state change
- **5** — Process termination
- **16** — Sysmon configuration change

The following events are targeted by the planned lab configuration:

| Event ID | Description | Security Use |
|---|---|---|
| 1 | Process creation | Suspicious process execution |
| 3 | Network connection | Network activity investigation |
| 11 | File creation | Suspicious file activity |
| 22 | DNS query | Domain lookup investigation |

The custom Sysmon configuration was applied successfully and its configuration change was verified through Event ID 16.

Sysmon Operational events were also successfully received and indexed in Splunk.

## 4. Splunk Universal Forwarder

The Splunk Universal Forwarder is installed and running on the Windows endpoint.

Configured Windows event sources include:

- Windows Security
- Windows System
- Sysmon Operational
- PowerShell Operational

All four event sources were successfully verified in Splunk under the `main` index.

## 5. Telemetry Flow

1. Windows generates operating system and security events.
2. Sysmon records selected endpoint activity.
3. PowerShell generates operational and script-related events.
4. Splunk Universal Forwarder collects configured event logs.
5. Events are forwarded to Splunk Enterprise.
6. Splunk indexes the data for monitoring, detection and investigation.

## 6. Validation Results

| Component | Validation Status |
|---|---|
| Windows 10 Pro | Verified |
| Windows Security Logs | Verified in Splunk |
| Windows System Logs | Verified in Splunk |
| PowerShell Operational Logs | Verified in Splunk |
| PowerShell Event ID 4104 | Observed in Splunk |
| Sysmon 15.22 | Installed and running |
| Sysmon Event ID 1 | Observed locally |
| Sysmon Event ID 16 | Configuration change verified |
| Custom Sysmon configuration | Applied and validated |
| Sysmon ingestion in Splunk | Verified |
| Universal Forwarder | Running |

## 7. Security Considerations

The lab uses a physical Windows endpoint connected to a private virtual machine environment.

The repository excludes:

- Private IP addresses
- Personal usernames
- Device hostnames
- Passwords and authentication secrets
- Sensitive command-line arguments

## 8. Objective

The objective of this telemetry setup is to establish a reliable Windows endpoint data source for Splunk-based SOC monitoring.

The collected telemetry will support:

- Security detection engineering
- Authentication monitoring
- Process execution analysis
- Threat hunting
- Incident investigation
- MITRE ATT&CK mapping

All implementation and validation claims are supported by actual lab evidence.
