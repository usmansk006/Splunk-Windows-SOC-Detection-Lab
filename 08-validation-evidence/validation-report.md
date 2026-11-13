## Test 1 — Positive Detection: Repeated Failed Logons

**Status:** Passed

**Objective:** Validate whether the detection identifies three or more failed Windows logons for the same account within a five-minute bucket.

**Test account:** SOC_VAL_POS

**Test procedure:**
1. Created a temporary local Windows account.
2. Generated three intentional failed authentication attempts using the local IPC$ endpoint.
3. Verified Windows Security Event ID 4625 events in Splunk.
4. Executed the five-minute aggregation detection query.

**Observed results:**

| Field | Result |
|---|---|
| Event ID | 4625 |
| Target account | SOC_VAL_POS |
| Source IP | 127.0.0.1 |
| Logon type | 3 |
| Failed events | 3 |
| Aggregated bucket | 2026-11-13 15:05 |
| Detection result | 3 failed attempts |

**Conclusion:** The detection successfully identified the controlled authentication failures and returned one result for the account within the five-minute bucket.

**Evidence:** `screenshots/01-positive-test.png`

**Limitation:** This validates the controlled detection scenario. It does not establish detection effectiveness against every brute-force or password-spraying technique.
