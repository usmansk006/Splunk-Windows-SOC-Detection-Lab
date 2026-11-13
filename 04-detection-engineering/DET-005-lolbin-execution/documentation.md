# DET-005 — Suspicious LOLBin Execution

## 1. Objective

Detect potentially suspicious execution of Windows native utilities commonly abused by attackers, using Sysmon process-creation telemetry and Splunk.

## 2. Data Source

- Log source: Microsoft-Windows-Sysmon/Operational
- Event ID: 1 — Process Creation
- SIEM: Splunk Enterprise
- Endpoint: Windows 10 Pro
- Forwarding: Splunk Universal Forwarder

## 3. Detection Logic

The detection identifies CertUtil execution involving selected command-line operations:

- `-decode`
- `-urlcache`
- `-encode`

These operations can be legitimate. Their presence alone does not establish malicious activity.

## 4. MITRE ATT&CK Mapping

- T1140 — Deobfuscate/Decode Files or Information
- T1105 — Ingress Tool Transfer (relevant when used to retrieve content)

The controlled decoding test directly validates file decoding behavior. It does not validate ingress tool transfer.

## 5. Validation

A controlled, benign test was performed using a locally generated Base64 text file.

Test command:

`certutil.exe -decode lolbin-test.b64 lolbin-test-decoded.txt`

Validation evidence:

- Sysmon Event ID 1 recorded the CertUtil process execution.
- Splunk received the event through the Universal Forwarder.
- The process image identified `certutil.exe`.
- The command line contained the `-decode` operation.
- The Splunk detection search returned the matching event.

Screenshot: `05-lolbin-detection.png`

## 6. Investigation Guidance

When an alert occurs:

1. Review the full command line and process image.
2. Identify the parent process and executing user.
3. Determine the input file and output destination.
4. Correlate with Sysmon file-creation events.
5. Review DNS and network telemetry for related downloads.
6. Investigate subsequent process execution.
7. Determine whether the activity is authorized.

## 7. Limitations

- CertUtil is a legitimate Windows utility.
- The selected command-line arguments can occur during legitimate administration.
- This detection is a heuristic, not proof of compromise.
- The current implementation is a Splunk search, not a scheduled production alert.
- The controlled validation covered local Base64 decoding only.
- URL-based retrieval and subsequent payload execution were not validated.

## 8. Evidence

`05-lolbin-detection.png` — Splunk search result showing the controlled CertUtil process-creation event.

## 9. Status

Implemented and validated in a controlled lab environment. Production alerting, broader LOLBin coverage, and additional attack simulations remain future improvements.
