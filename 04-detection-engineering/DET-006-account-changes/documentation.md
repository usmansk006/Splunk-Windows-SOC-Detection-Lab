# DET-006 — Windows Account Changes

## Objective

Detect and investigate Windows local account-management activity using Windows Security Event Logs and Splunk Enterprise.

The detection identifies account creation, enablement, password-reset attempts, modification, disabling, and deletion.

## Lab Environment

- Endpoint: Windows 10 Pro
- SIEM: Splunk Enterprise
- Log collection: Splunk Universal Forwarder
- Telemetry source: Windows Security Event Log
- Search index: `main`

## Event IDs Monitored

| Event ID | Activity |
|---|---|
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempted |
| 4725 | User account disabled |
| 4726 | User account deleted |
| 4738 | User account changed |

## Detection Logic

The SPL detection:

1. Searches Windows Security events.
2. Extracts Event ID and account-related fields.
3. Identifies relevant account-management activities.
4. Assigns a suggested severity.
5. Displays the timestamp, activity, initiating account, affected account, and event ID.

Severity is a triage aid. It does not establish malicious intent.

## Validation

Three temporary local test accounts were used to generate controlled account-management activity.

Observed events:

- 3 account creation events (4720)
- 3 account enablement events (4722)
- 3 password-reset attempt events (4724)
- 6 account modification events (4738)
- 3 account deletion events (4726)

**Total: 18 observed events.**

The events were successfully received by Splunk and returned by the detection query.

## Investigation Workflow

When an account-management event is detected:

1. Identify the initiating account (`SubjectUserName`).
2. Identify the affected account (`TargetUserName`).
3. Review the event timestamp and event ID.
4. Verify whether the change was authorized.
5. Correlate the activity with Windows logon events (4624 and 4625).
6. Review related PowerShell and Sysmon process-creation telemetry.
7. Escalate unauthorized account changes according to incident-response procedures.

## MITRE ATT&CK Mapping

- **T1136.001 — Create Account: Local Account:** Relevant to unauthorized local account creation.
- **T1098 — Account Manipulation:** Relevant when adversaries modify accounts to maintain or expand access.
- **T1531 — Account Access Removal:** Potentially relevant when adversaries remove access to disrupt availability.

These mappings describe possible adversary behaviors, not proof that the observed test activity was malicious.

## Limitations

- Validation was performed on a standalone Windows endpoint, not an Active Directory domain.
- The test generated controlled administrative activity.
- Event ID 4724 does not by itself prove that a password reset succeeded.
- The detection uses event-based matching and does not establish whether an action was authorized.
- Severity values are heuristic triage labels.
- This is a Splunk search detection, not a scheduled production alert.
- Account lockout and unlock events (4740 and 4767) were not observed in this validation.

## Evidence

See `screenshots/06-account-changes-detection.png`.

## Status

Implemented and validated in a controlled Windows 10 and Splunk lab. Production alerting, domain-account coverage, and additional correlation logic remain future improvements.
