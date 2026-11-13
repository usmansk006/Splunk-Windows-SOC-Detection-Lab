# DET-003: Suspicious PowerShell Execution Detection

## 1. Objective

Identify potentially suspicious PowerShell process executions by inspecting process command-line arguments captured through Sysmon.

The detection searches for commonly observed indicators, including:

- Encoded PowerShell commands
- Execution policy bypass
- Hidden PowerShell windows
- DownloadString usage
- Base64 decoding
- Dynamic expression execution

These indicators require investigation and do not independently establish malicious activity.

## 2. Data Source

| Field | Value |
|---|---|
| SIEM | Splunk Enterprise |
| Telemetry | Sysmon Operational |
| Event ID | 1 — Process Create |
| Index | `main` |
| Endpoint | Windows 10 Pro |
| Detection method | SPL command-line pattern matching |

## 3. Detection Logic

The detection:

1. Searches Sysmon Event ID 1 process-creation events.
2. Extracts the process image, command line, parent image and user.
3. Filters for Windows PowerShell processes.
4. Excludes the Splunk Universal Forwarder installation path.
5. Searches command lines for suspicious execution indicators.
6. Assigns a detection reason based on the matching indicator.

The SPL implementation is available in `detection.spl`.

## 4. Controlled Validation

A harmless PowerShell command was executed from Command Prompt:

`powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output 'SOC-DET003-TEST'"`

The command printed a test string and did not download or execute an external payload.

### Validation results

| Validation | Result |
|---|---|
| Sysmon Event ID 1 received | Verified |
| PowerShell executable extracted | Verified |
| Command-line arguments extracted | Verified |
| Parent process extracted | Verified |
| Execution policy bypass indicator matched | Verified |
| Detection reason assigned | Verified |

The detection returned the controlled test event with:

`Detection_Reason = Execution policy bypass`

This validates the telemetry collection, field extraction and detection logic against the controlled test.

## 5. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell execution monitoring |

The technique mapping describes the behavior being monitored. It does not mean the controlled test was malicious.

## 6. Limitations

- Command-line indicators can generate false positives.
- Execution-policy bypass is not inherently malicious.
- Attackers can use alternative syntax or obfuscation to evade simple pattern matching.
- This detection does not inspect the full contents of PowerShell scripts.
- The detection depends on Sysmon process-creation telemetry and available command-line data.
- The current implementation is a manual SPL search, not a scheduled alert.
- The current validation uses a controlled local test, not a real attack simulation.

## 7. Future Improvements

- Add parent-child process correlation.
- Correlate process creation with PowerShell Event ID 4104.
- Add risk scoring and severity classification.
- Tune exclusions for known legitimate administrative activity.
- Create a scheduled Splunk alert.
- Test additional indicators using harmless controlled commands.

## 8. Conclusion

This exercise demonstrates Windows process telemetry collection, SPL field extraction, command-line indicator matching and controlled validation of a PowerShell execution detection.
