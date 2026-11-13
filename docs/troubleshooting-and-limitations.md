# Troubleshooting and Limitations

## 1. Overview

This document records common configuration and troubleshooting considerations encountered while building the Splunk SOC Monitoring Lab.

The environment consists of a Windows endpoint, Splunk Universal Forwarder, and Splunk Enterprise running on an Ubuntu Server virtual machine.

## 2. Troubleshooting

### 2.1 Windows Events Not Appearing in Splunk

**Possible causes:**
- Splunk Universal Forwarder service is stopped.
- Windows Event Log inputs are disabled.
- Forwarder cannot reach the Splunk receiver.
- Receiver is not listening on TCP port 9997.
- Search is using the wrong index or time range.

**Troubleshooting:**
1. Verify the `SplunkForwarder` Windows service is running.
2. Review the forwarder's `inputs.conf`.
3. Verify the configured receiving server and port.
4. Confirm Splunk receiving is enabled on TCP 9997.
5. Search the correct index and inspect the selected time range.

### 2.2 Sysmon Events Missing

**Possible causes:**
- Sysmon service is stopped.
- Sysmon configuration does not generate the expected event.
- The Universal Forwarder is not monitoring the Sysmon Operational channel.

**Troubleshooting:**
1. Check the Sysmon service status.
2. Review the active Sysmon configuration.
3. Verify the Microsoft-Windows-Sysmon/Operational input.
4. Generate a controlled process execution.
5. Confirm the event in Windows Event Viewer and Splunk.

### 2.3 PowerShell Script Block Events Missing

**Possible causes:**
- PowerShell Script Block Logging is not enabled.
- The wrong event channel is being searched.
- The search time range excludes the event.

**Troubleshooting:**
1. Verify PowerShell logging configuration.
2. Check the Microsoft-Windows-PowerShell/Operational channel.
3. Inspect Event ID 4104 locally.
4. Confirm the event reaches Splunk.

### 2.4 Incorrect Event Time Display

Splunk and Windows may display timestamps differently because of timezone settings.

**Troubleshooting:**
1. Check the Windows system timezone.
2. Check the Splunk user timezone preference.
3. Compare the same event using its timestamp and event details.
4. Avoid changing the system clock to correct a display difference.

A user timezone preference changes displayed timestamps; it does not rewrite the underlying event timestamp.

### 2.5 Detection Search Returns Unexpected Results

**Possible causes:**
- Incorrect event extraction.
- Incorrect field names.
- Search time range is too broad or too narrow.
- Detection threshold does not match the generated activity.
- Events are grouped into fixed time buckets.

**Troubleshooting:**
1. Search for the raw event first.
2. Confirm the Event ID.
3. Validate field extraction.
4. Review the aggregation logic.
5. Test with controlled activity.
6. Compare the detection result with the original events.

## 3. Known Project Limitations

| Area | Limitation |
|---|---|
| Environment | Single Windows endpoint and one Splunk server |
| Network | Lab environment, not a production enterprise network |
| Authentication detection | Limited to selected Windows authentication events |
| Password spraying | Detection logic uses a fixed aggregation window |
| Process detection | Heuristic process and parent-child relationships |
| PowerShell | Suspicious command-line indicators can produce false positives |
| LOLBins | CertUtil local decoding was tested; URL retrieval and payload execution were not |
| Alerting | Duplicate suppression and long-term alert reliability require further validation |
| Negative testing | Successful authentication was observed, but an isolated zero-failure interval was not validated |
| Threat hunting | Findings are limited to collected endpoint telemetry and available search periods |

## 4. Security Considerations

- Use temporary accounts for controlled validation.
- Do not perform testing against systems without authorization.
- Avoid storing passwords, tokens, private IP details, or sensitive endpoint information in public documentation.
- Redact sensitive information from screenshots before publishing.
- Treat detection results as investigation leads rather than proof of compromise.

## 5. Future Improvements

- Add additional Windows event sources.
- Improve authentication correlation and time-window logic.
- Validate alert throttling and duplicate suppression.
- Add more process and network detection scenarios.
- Introduce structured investigation timelines.
- Test detection logic against additional benign and adversarial lab simulations.
- Evaluate detection coverage against MITRE ATT&CK techniques.

## 6. Conclusion

Troubleshooting and limitations are documented to make the lab reproducible and to distinguish validated capabilities from areas requiring additional testing.

The project demonstrates selected SOC monitoring and detection workflows, but it is not a production-ready enterprise SIEM deployment.
