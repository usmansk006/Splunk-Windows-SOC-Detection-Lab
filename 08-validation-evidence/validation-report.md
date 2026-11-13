# Validation and Evidence Report

## 1. Objective

Validate the Splunk SOC Monitoring Lab's ability to ingest Windows security telemetry, identify selected security events, execute detection searches, and present monitoring results through dashboards and alerts.

## 2. Test Environment

- SIEM: Splunk Enterprise 10.6.1.1
- Endpoint: Windows 10 Pro
- Telemetry: Windows Security, Sysmon, PowerShell Operational logs
- Forwarder: Splunk Universal Forwarder
- Log index: `main`
- Test account: `SOC_VAL_POS`

## 3. Validation Results

| Test | Scenario | Result |
|---|---|---|
| TEST-001 | Repeated failed logons | PASSED |
| TEST-002 | Successful authentication / negative detection | INCONCLUSIVE |
| TEST-003 | Detection query validation | PASSED |
| TEST-004 | Dashboard workflow review | COMPLETED |

### TEST-001: Positive Detection — Repeated Failed Logons

**Objective:** Verify that repeated failed authentication events are ingested and identified by the detection query.

**Procedure:**
- Created the temporary account `SOC_VAL_POS`.
- Generated three intentional failed authentication attempts against the local IPC$ share.
- Queried Windows Security Event ID 4625 in Splunk.
- Executed the detection search using a threshold of three failures within a five-minute time bucket.

**Observed result:**

| Field | Value |
|---|---|
| Event ID | 4625 |
| Target account | SOC_VAL_POS |
| Source IP | 127.0.0.1 |
| Logon type | 3 |
| Failed attempts | 3 |
| Detection threshold | 3 within 5 minutes |

**Outcome:** PASSED. Three failed authentication events were ingested and the detection search returned one matching result.

**Evidence:** `screenshots/01-positive-test.png`

### TEST-002: Negative Detection — Successful Authentication

**Objective:** Check successful authentication telemetry and determine whether it is incorrectly identified as a failed-logon detection.

**Procedure:**
- Reset the temporary test account password.
- Performed a successful authentication attempt.
- Verified that Windows Security Event ID 4624 was ingested by Splunk.
- Reviewed the broader search window, which also contained failed authentication events.

**Observed result:**
- One successful authentication event (4624) was observed.
- Failed authentication events (4625) were also present in the broader search window.
- A sufficiently isolated time interval was not validated.

**Outcome:** INCONCLUSIVE. Successful authentication ingestion was verified, but the absence of a failed-logon detection during an isolated successful-login interval was not established.

**Evidence:** No dedicated screenshot captured.

### TEST-003: Detection Query Validation

**Objective:** Confirm that the repeated failed-logon detection search identifies the controlled test activity.

**Observed result:**

| Field | Value |
|---|---|
| Target account | SOC_VAL_POS |
| Detection time bucket | 2026-11-13 20:35 |
| Failed attempts | 3 |
| Threshold | 3 failures / 5 minutes |
| Search result | One matching result |

**Outcome:** PASSED. The detection query returned the expected account and threshold match.

**Evidence:** `screenshots/03-detection-validation.png`

### TEST-004: Dashboard Workflow Review

**Objective:** Review the SOC monitoring dashboard and confirm that the configured monitoring panels are available.

**Dashboard:** SOC Security Monitoring

Configured monitoring components:
- Total Security Events KPI
- Failed Logons KPI
- Sysmon Process Executions KPI
- Authentication Activity
- Failed Logons by Username
- Top 10 Process Executions
- Windows Telemetry by Source

**Outcome:** Dashboard review completed. The screenshot records the dashboard state at the time of capture.

**Evidence:** `screenshots/04-end-to-end-workflow.png`

## 4. Evidence Inventory

| Evidence | Description |
|---|---|
| 01-positive-test.png | Controlled failed-logon test and positive detection |
| 02-negative-test.png | Not captured; negative test remained inconclusive |
| 03-detection-validation.png | Detection query returned the expected threshold match |
| 04-end-to-end-workflow.png | SOC dashboard overview |

## 5. Limitations

- Validation was performed in a controlled lab environment.
- The failed-logon detection uses fixed five-minute time buckets.
- The positive test validates a specific repeated-failure pattern, not every brute-force or password-spraying technique.
- The negative test did not establish a clean interval containing only successful authentication.
- Dashboard review does not independently prove detection accuracy.
- Alert scheduling and duplicate suppression require separate validation.
- Detection results are indicators for investigation, not proof of malicious activity.

## 6. Conclusion

The lab demonstrated Windows telemetry ingestion into Splunk, detection of a controlled repeated failed-logon scenario, and presentation of security monitoring data through a dashboard.

The positive detection and query validation tests passed. The negative authentication test remains inconclusive and is documented accordingly.

Further work should focus on improving negative-test coverage, validating alert scheduling and suppression, and testing additional detection scenarios.
