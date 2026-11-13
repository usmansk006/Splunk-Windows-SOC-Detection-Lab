# Splunk Enterprise Configuration

## 1. Overview

Splunk Enterprise is deployed on an Ubuntu Server VM. It receives Windows endpoint telemetry through the Splunk Universal Forwarder.

## 2. Lab Configuration

| Component | Configuration |
|---|---|
| SIEM Server | Ubuntu Server |
| SIEM Platform | Splunk Enterprise |
| Monitored Endpoint | Windows 10 Pro |
| Log Forwarder | Splunk Universal Forwarder |
| Receiving Port | TCP 9997 |
| Splunk Web Interface | TCP 8000 |
| Event Index | `main` |

## 3. Receiving Configuration

Splunk Enterprise is configured to receive forwarded events on TCP port `9997`.

The receiving service was verified as listening on the Ubuntu server.

## 4. Universal Forwarder

The Splunk Universal Forwarder is installed and running on the Windows endpoint.

It forwards the following Windows event channels:

- Windows Security
- Windows System
- Sysmon Operational
- PowerShell Operational

The forwarder connection was verified, and events from all four sources were confirmed in Splunk under the `main` index.

## 5. Configuration Files

Example configuration files are provided in this directory:

- `inputs.conf.example` — Windows event channels collected by the Universal Forwarder.
- `outputs.conf.example` — Destination configuration used to forward events to Splunk Enterprise.

These are reference examples. They do not contain the actual private IP address or credentials used in the lab.

## 6. Validation

| Validation | Status |
|---|---|
| Splunk Enterprise installed | Verified |
| Receiving port TCP 9997 | Verified listening |
| Splunk Web TCP 8000 | Configured |
| Universal Forwarder service | Running |
| Forwarder connection | Active |
| Windows Security events | Received |
| Windows System events | Received |
| Sysmon events | Received |
| PowerShell events | Received |

## 7. Data Flow

Windows Event Logs → Splunk Universal Forwarder → TCP 9997 → Splunk Enterprise → Search and Investigation.

## 8. Security Notes

- Private IP addresses and credentials are excluded from published configuration examples.
- Example files are provided for documentation purposes.
- Event collection and forwarding were validated in the lab environment.
