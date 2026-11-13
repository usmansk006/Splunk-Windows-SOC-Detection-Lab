# DET-002: Multi-Account Failed Logon Detection

## 1. Objective

Detect repeated failed authentication attempts from a single source IP address against multiple user accounts within a short time window.

This activity may be consistent with password spraying.

## 2. Data Source

| Field | Value |
|---|---|
| SIEM | Splunk Enterprise |
| Log Source | Windows Security |
| Event ID | 4625 |
| Event Description | An account failed to log on |
| Index | `main` |
| Detection Window | 30-minute time buckets |
| Lab Threshold | At least 3 distinct accounts |

## 3. Detection Logic

The detection:

1. Searches Windows Security Event ID 4625.
2. Extracts the target username and source IP address.
3. Groups failed logons by source IP and five-minute time bucket.
4. Counts failed attempts and distinct targeted accounts.
5. Identifies source IPs associated with failures against at least three distinct accounts.

The SPL query is provided in `detection.spl`.

## 4. Controlled Validation

Three temporary local test accounts were created:

- `SOC_Test01`
- `SOC_Test02`
- `SOC_Test03`

A deliberately incorrect password was supplied for each account during a controlled network-logon test.

The resulting Windows Security events were forwarded to Splunk.

### Validation observations

| Validation | Result |
|---|---|
| Event ID 4625 received | Verified |
| Target usernames extracted | Verified |
| Source IP extracted | Verified |
| Three distinct test accounts identified | Verified |
| Failed logon aggregation | Verified |
| thirty-minute detection query | Validated in the lab |

The controlled test used the loopback address `127.0.0.1` as its source IP.

This validates the aggregation and detection logic. It does not represent a real remote password-spraying attack.

## 5. MITRE ATT&CK Mapping

| Technique | ID | Relevance |
|---|---|---|
| Brute Force | T1110 | Repeated authentication failures |
| Password Spraying | T1110.003 | One source targeting multiple accounts |

The observed pattern is consistent with password spraying, but the Windows failed-logon events do not establish that the same password was used against every account.

## 6. Limitations

- The current query uses fixed five-minute time buckets, not a sliding time window.
- The validation uses loopback traffic rather than a remote source.
- The test-account filter is specific to this controlled validation.
- Failed logons alone do not prove password spraying.
- The query is a search-based detection, not a scheduled alert.
- Production deployment requires threshold tuning, benign-source exclusions and validation against remote authentication telemetry.

## 7. Future Improvements

- Generalize the query to monitor all relevant accounts.
- Implement a sliding-window detection.
- Add scheduled alerting and severity classification.
- Investigate source IP reputation and authentication context.
- Correlate failed logons with successful authentication events.

## 8. Conclusion

This lab exercise demonstrates Windows failed-logon telemetry collection, SPL field extraction, distinct-account aggregation and detection validation using controlled test events.
