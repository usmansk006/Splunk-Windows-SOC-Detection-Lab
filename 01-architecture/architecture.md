# SOC Lab Architecture

## 1. Project Overview

The Splunk Windows SOC Monitoring Lab is an enterprise-oriented Security Operations Center (SOC) monitoring environment designed to demonstrate Windows endpoint security monitoring, centralized log collection, detection engineering, threat hunting, and security incident investigation.

The lab integrates Windows 11 endpoint telemetry with Splunk Enterprise hosted on Ubuntu Server. Windows Security Event Logs, Sysmon telemetry, and PowerShell operational logs are collected and forwarded to the centralized SIEM platform for security analysis.

The environment demonstrates an end-to-end security monitoring workflow, from endpoint event generation to detection, investigation, and incident response.

## 2. Architecture Overview

The architecture consists of two primary virtual machines:

| Component | Operating System | Responsibility |
|---|---|---|
| Endpoint VM | Windows 11 | Generates endpoint and security telemetry |
| SIEM VM | Ubuntu Server | Hosts Splunk Enterprise |
| Endpoint Monitoring | Sysmon | Captures detailed endpoint activity |
| Log Forwarding | Splunk Universal Forwarder | Transmits Windows telemetry to Splunk |
| SIEM Platform | Splunk Enterprise | Centralized log analysis and detection |

## 3. Infrastructure Components

### 3.1 Windows 11 Endpoint

The Windows 11 virtual machine acts as the monitored endpoint.

It generates security telemetry through the following sources:

- Windows Security Event Logs
- Sysmon Operational Logs
- PowerShell Operational Logs

The endpoint provides visibility into authentication activity, process creation, command execution, account modifications, and other security-relevant events.

### 3.2 Sysmon

Microsoft Sysmon provides detailed system activity monitoring.

The lab uses Sysmon telemetry to support investigation of:

- Process creation
- Parent-child process relationships
- Process command-line arguments
- Network connection activity
- File and registry activity, where configured

Sysmon events are collected through the Windows Event Log infrastructure.

### 3.3 Splunk Universal Forwarder

Splunk Universal Forwarder operates on the Windows endpoint and collects configured Windows Event Log channels.

It forwards the collected telemetry to the centralized Splunk Enterprise instance for indexing and analysis.

### 3.4 Ubuntu Server and Splunk Enterprise

Ubuntu Server hosts Splunk Enterprise and provides the centralized SIEM environment.

Splunk Enterprise is responsible for:

- Receiving endpoint telemetry
- Indexing security events
- Searching and analyzing collected data
- Executing SPL detection queries
- Supporting threat hunting
- Providing security dashboards and alerting capabilities

## 4. Telemetry Data Flow

The lab implements the following telemetry pipeline:

1. Windows 11 generates operating system and security events.
2. Sysmon records detailed endpoint activity.
3. Windows Security and PowerShell logging provide additional security context.
4. Splunk Universal Forwarder collects the configured event channels.
5. Telemetry is transmitted to Splunk Enterprise on Ubuntu Server.
6. Splunk indexes the received events.
7. SPL searches analyze the indexed telemetry.
8. Detection rules identify potentially suspicious behavior.
9. Security events are investigated and documented.

## 5. Security Monitoring Objectives

The environment supports the following monitoring objectives:

| Security Area | Monitoring Objective |
|---|---|
| Authentication | Identify repeated failed login attempts |
| Password Attacks | Identify password-spraying patterns |
| Login Correlation | Correlate failed and successful authentication activity |
| PowerShell | Identify suspicious PowerShell execution |
| LOLBins | Monitor potentially suspicious legitimate binary execution |
| Account Management | Detect account creation and group membership changes |

## 6. SOC Operational Workflow

The lab follows a structured security operations workflow:

**Attack → Telemetry → Detection → Investigation → Threat Hunting → Response → Improvement → Retesting**

This workflow connects endpoint activity with SIEM detection logic and investigation procedures.

## 7. Architecture Security Considerations

The lab is designed for controlled security testing and monitoring.

The following considerations apply:

- Endpoint and SIEM communication is restricted to the configured virtual network.
- Only required telemetry channels are collected.
- Sysmon configuration is designed to provide useful security visibility while controlling event noise.
- Detection logic is evaluated against positive and negative test scenarios.
- Screenshots and configuration examples are maintained as implementation evidence.
- Sensitive credentials, private keys, and personal information are excluded from the public repository.

## 8. Architecture Evidence

The following diagrams document the implemented environment:

| Evidence | Description |
|---|---|
| `01-lab-architecture.png` | Overall Windows-to-Splunk architecture |
| `02-network-topology.png` | Virtual machine network topology and communication paths |
