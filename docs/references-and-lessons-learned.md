# References and Lessons Learned

## 1. Purpose

This document records the technical references used during the development of the Splunk SOC Monitoring Lab and the key lessons learned while configuring telemetry, engineering detections, investigating events, and validating the monitoring workflow.

## 2. Technical References

### Splunk Documentation

- [Splunk Enterprise Documentation](https://docs.splunk.com/Documentation/Splunk)
- [Splunk Universal Forwarder Documentation](https://docs.splunk.com/Documentation/Forwarder)
- [Monitor Windows Event Log Data](https://help.splunk.com/en/splunk-cloud-platform/get-started/get-data-in/10.1.2507/get-windows-data/monitor-windows-event-log-data-with-splunk-cloud-platform)
- [Splunk Search Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference)

### Microsoft Documentation

- [Windows Event Logging](https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging)
- [Audit Logon Events](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-logon)
- [PowerShell Logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging)

### Sysinternals

- [Sysmon Documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

### MITRE ATT&CK

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [Command and Scripting Interpreter: PowerShell — T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Deobfuscate/Decode Files or Information — T1140](https://attack.mitre.org/techniques/T1140/)

### Detection Engineering

- [Sigma Rules](https://github.com/SigmaHQ/sigma)

## 3. Lessons Learned

### 3.1 Telemetry Is the Foundation of Detection

Detection rules are only useful when the required telemetry is collected correctly.

Configuring the Universal Forwarder to collect Windows Security, Sysmon, and PowerShell Operational events established the foundation for the detection searches.

### 3.2 Validate Raw Events Before Writing SPL

A detection search should not be written based only on assumptions about event structure.

The correct workflow is:

1. Generate controlled activity.
2. Inspect the original Windows event.
3. Confirm its Event ID and fields.
4. Verify ingestion into Splunk.
5. Develop the SPL query.
6. Validate the search against the original event.

### 3.3 Detection Logic Requires Context

A failed authentication event does not automatically mean brute force.

A suspicious PowerShell command does not automatically mean malware.

A LOLBin execution does not automatically indicate malicious activity.

Detection engineering must consider:
- Event context.
- Parent and child processes.
- User and account activity.
- Source address.
- Frequency and timing.
- Expected system behavior.

### 3.4 Aggregation Windows Matter

Fixed time buckets can produce different results from sliding time windows.

For example, three failed logons within a five-minute bucket may not be detected if the events cross a bucket boundary.

Detection logic must be tested against its actual aggregation behavior.

### 3.5 Correlation Improves Investigations

A single event provides limited context.

Correlating Windows Security events with Sysmon process telemetry and PowerShell logs helps build a more useful investigation timeline.

### 3.6 False Positives Must Be Considered

Legitimate applications and Windows components can generate activity that resembles suspicious behavior.

A SOC analyst must establish a baseline and investigate anomalies rather than treating every detection as a confirmed incident.

### 3.7 Evidence Is Part of the Engineering Process

Screenshots, SPL queries, investigation reports, and validation results make the work reproducible.

Evidence should show actual test results. Unverified scenarios must be documented as inconclusive or not tested.

### 3.8 Negative Testing Is Important

A detection should be tested with both activity that should trigger it and activity that should not trigger it.

The negative authentication test in this project remains inconclusive because the successful login was observed alongside failed logons in the broader search window.

This limitation is intentionally documented rather than reported as a successful negative test.

## 4. Professional SOC Workflow

The project follows this operational workflow:

1. **Attack Simulation:** Generate controlled activity in an authorized lab.
2. **Telemetry Collection:** Collect endpoint and security events.
3. **Detection Engineering:** Develop SPL searches for relevant behavior.
4. **Investigation:** Examine related events and establish context.
5. **Threat Hunting:** Search for patterns that may not trigger existing detections.
6. **Response Planning:** Identify appropriate containment and remediation actions.
7. **Validation:** Test detection behavior with controlled scenarios.
8. **Improvement:** Refine detection logic based on observed results.

## 5. Final Learning Outcomes

The lab provided practical experience with:

- Splunk Enterprise installation and configuration.
- Universal Forwarder deployment.
- Windows Event Log collection.
- Sysmon telemetry.
- PowerShell logging.
- SPL search and aggregation.
- Windows authentication monitoring.
- Process execution analysis.
- LOLBin detection.
- Account management event monitoring.
- Threat hunting.
- Security investigations.
- Dashboard development.
- Scheduled alert configuration.
- Detection validation and evidence documentation.

## 6. Final Note

This project is a practical learning environment, not a claim of production SOC experience.

The documented results distinguish between implemented functionality, observed test evidence, and areas requiring additional validation.

The objective is to demonstrate the ability to collect telemetry, develop detections, investigate security events, and communicate technical findings using evidence.
