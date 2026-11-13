# Threat Hunting Report

## 1. Overview

This investigation reviews Windows endpoint telemetry collected by Splunk Enterprise through the Splunk Universal Forwarder.

The objective is to identify unusual authentication activity, examine process execution relationships, and review Windows account-management events.

**Environment**
- SIEM: Splunk Enterprise
- Endpoint: Windows 10 Pro
- Telemetry: Windows Security, Sysmon and PowerShell Operational logs
- Process telemetry: Sysmon Event ID 1
- Authentication telemetry: Windows Security Event IDs 4624, 4625, 4634 and 4648
- Account telemetry: Windows Security Event IDs 4720, 4722, 4724, 4725, 4726 and 4738

**Investigation period:** November 12–13, 2026, based on the recorded Splunk search windows.

## 2. Authentication Hunting

### Objective

Review successful and failed logons, identify repeated authentication failures, and correlate logon sessions with their corresponding logoff events.

### Data sources

Windows Security event logs.

### Observations

The authentication count search returned:

| Event ID | Description | Events |
|---|---|---:|
| 4624 | Successful logon | 262 |
| 4625 | Failed logon | 6 |

The six failed logons consisted of:

- Three failures involving the temporary SOC_Test01, SOC_Test02 and SOC_Test03 accounts.
- Three failures involving the local DELL account.

All six reported the loopback address `127.0.0.1`.

The three test-account failures were generated during controlled lab validation. The DELL failures were interactive logon attempts (Logon Type 2). Their status values were `0xc000006d`, with substatus `0xc000006a`, indicating an incorrect-password condition.

### Session correlation

The investigation correlated Event IDs 4624, 4634 and 4648.

Two successful DELL logon sessions were observed:

- `0x375ae0d`
- `0x375ad83`

Both IDs had corresponding Event ID 4634 logoff events.

An Event ID 4648 was also observed in the same sequence, with SYSTEM (`0x3e7`) as the subject logon ID.

### Assessment

The test-account failures were expected lab activity. The DELL failures were local authentication failures followed by successful local logon activity.

The available evidence does not establish an external brute-force attack. The exact service responsible for the DELL authentication sequence was not conclusively identified.

## 3. Process Hunting

### Objective

Examine Sysmon process-creation telemetry to understand executable activity, parent-child relationships, command-line arguments and execution context.

### Data source

Sysmon Operational log, Event ID 1.

### Baseline observations

The initial process-creation search returned **2,100 events** in the selected search window.

Observed examples included:

- Chrome spawning renderer and utility processes.
- Microsoft Edge WebView2 spawning renderer processes.
- Splunk Forwarder components launched by `splunkd.exe`.
- Windows service processes launched by `services.exe`.
- Conexant audio software activity.

These relationships were treated as baseline observations, not automatically classified as malicious.

### Investigation considerations

Process relationships requiring closer examination include:

- Office applications launching command interpreters.
- Script hosts launching PowerShell.
- Unexpected PowerShell or CMD command-line arguments.
- LOLBins executing unusual commands.
- Executables running from unusual directories or under unexpected accounts.

### Assessment and limitation

The baseline confirms that Sysmon process-creation telemetry is reaching Splunk and that process fields can be extracted for investigation.

A process should not be classified as malicious solely because of its executable name or parent-child relationship. The command line, user context, executable location, signature, surrounding events and endpoint context must also be considered.

The targeted process-hunting screenshot should be used to record the actual query results and any validated process relationships. No malicious process finding is claimed solely from the 2,100-event baseline.

## 4. Windows Account Hunting

### Objective

Identify account creation, enablement, password-reset attempts, disablement, deletion and modification activity.

### Data source

Windows Security event logs.

### Event IDs reviewed

| Event ID | Activity |
|---|---|
| 4720 | Account created |
| 4722 | Account enabled |
| 4724 | Password reset attempted |
| 4725 | Account disabled |
| 4726 | Account deleted |
| 4738 | Account changed |

### Observations

The account-change search returned 18 events:

| Event ID | Activity | Count |
|---|---|---:|
| 4720 | Account created | 3 |
| 4722 | Account enabled | 3 |
| 4724 | Password reset attempted | 3 |
| 4726 | Account deleted | 3 |
| 4738 | Account changed | 6 |

The events included activity involving the temporary SOC_Test accounts created during lab validation.

The recorded sequence included account creation, enablement, modification, password-reset attempts and deletion.

### Assessment

The account-management events were consistent with the controlled account-testing activity performed in the lab.

Event ID 4724 records a password-reset attempt; it does not independently prove that the password reset succeeded.

The event counts and activity classifications describe observed telemetry, not proof of malicious account manipulation.

## 5. Investigation Summary

| Hunting area | Result | Assessment |
|---|---|---|
| Authentication | 262 successful and 6 failed logons | Reviewed; three test failures and three unexplained local failures |
| Process execution | 2,100 Sysmon Event ID 1 events | Baseline reviewed; no malicious finding established from count alone |
| Account management | 18 account-change events | Controlled test activity observed |

## 6. Limitations

- The investigation covers the available lab telemetry and selected search windows, not an entire enterprise environment.
- Loopback source addresses indicate local reporting for the observed authentication events; they do not establish the absence of all other attack activity.
- Process names and parent-child relationships require contextual validation.
- Event ID 4724 indicates a password-reset attempt, not necessarily a successful reset.
- No external attack, compromise or malicious execution is claimed without supporting evidence.
- Search results are dependent on configured Windows auditing, Sysmon configuration, forwarding and retention.

## 7. Conclusion

This threat-hunting exercise demonstrates the use of Splunk to review Windows authentication activity, correlate logon sessions, examine process-creation telemetry and investigate account-management events.

The investigation identified expected lab-generated authentication and account activity, established a baseline of process-creation telemetry, and documented areas requiring further contextual analysis.

The findings provide a basis for improving detection logic, refining telemetry coverage and conducting repeatable validation in the lab.

## 8. Evidence

Screenshots are stored in `screenshots/`:

- `01-authentication-hunting.png`
- `02-process-hunting.png`
- `03-account-hunting.png`

The screenshots should correspond to the actual Splunk searches and results described in this report.
