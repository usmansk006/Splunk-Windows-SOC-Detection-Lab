# DET-004: Suspicious Parent-Child Process Detection

## 1. Objective

Identify potentially suspicious process relationships using Windows Sysmon process-creation telemetry.

The detection focuses on scripting hosts or Microsoft Office applications launching command interpreters.

Examples include:

- `wscript.exe` → `powershell.exe`
- `cscript.exe` → `cmd.exe`
- `winword.exe` → `powershell.exe`
- `excel.exe` → `cmd.exe`

These relationships may indicate suspicious execution chains but can also occur during legitimate administrative activity.

## 2. Data Source

| Field | Value |
|---|---|
| SIEM | Splunk Enterprise |
| Telemetry | Sysmon Operational |
| Event ID | 1 — Process Create |
| Index | `main` |
| Endpoint | Windows 10 Pro |
| Detection method | Parent-child process correlation |

## 3. Detection Logic

The detection:

1. Searches Sysmon Event ID 1.
2. Extracts process image and parent image.
3. Normalizes executable names.
4. Identifies selected scripting hosts and Office applications as parent processes.
5. Identifies command interpreters as child processes.
6. Assigns a detection reason to matching relationships.

The SPL implementation is available in `detection.spl`.

## 4. Controlled Validation

A harmless VBScript test was executed to launch PowerShell.

The child process executed:

`Write-Output 'SOC-DET004-WSCRIPT-TEST'`

### Observed process relationship

| Field | Result |
|---|---|
| Parent process | `wscript.exe` |
| Child process | `powershell.exe` |
| Sysmon Event ID | 1 |
| Command-line marker | `SOC-DET004-WSCRIPT-TEST` |
| Event received in Splunk | Verified |
| Detection query matched | Verified |

A separate CMD-to-PowerShell test was also observed in Sysmon telemetry.

These tests validate process-creation collection, parent-child field extraction and detection logic. They do not represent malicious activity.

## 5. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | PowerShell process execution |
| Command and Scripting Interpreter: Visual Basic | T1059.005 | VBScript execution through Windows Script Host |

The mappings describe the execution mechanisms being monitored, not a confirmed attack.

## 6. Limitations

- Legitimate scripts and Office automation can generate matching process relationships.
- The detection uses a predefined list of parent and child executables.
- Renamed or alternative executables may evade the current matching logic.
- Process relationships alone do not establish malicious intent.
- The current implementation is a manual SPL search, not a scheduled alert.
- Validation was performed using controlled local commands, not a real attack simulation.

## 7. Future Improvements

- Add process command-line analysis.
- Correlate process creation with file creation and PowerShell Event ID 4104.
- Add known-good application exclusions.
- Implement risk scoring and severity classification.
- Configure scheduled alerting.
- Investigate process ancestry and user context.

## 8. Conclusion

This lab exercise demonstrates Sysmon process-creation telemetry, SPL field extraction, parent-child process correlation and controlled validation of a behavioral detection.
