# SOC Investigation Report

## Incident 1: Possible Brute-Force Activity

### Detection

Multiple failed login attempts were detected from a single source IP.

### Evidence

- Source IP: 192.168.56.10
- Target Username: admin
- Failed Attempts: 5
- Severity: HIGH
- Alert Type: BRUTE_FORCE

### Analysis

Repeated authentication failures from the same source indicate
possible brute-force activity against the account.

### MITRE ATT&CK

T1110 - Brute Force

### Recommended Response

- Investigate the source IP.
- Review authentication logs for additional activity.
- Consider temporarily blocking the source if confirmed malicious.
- Reset or protect the targeted account if required.

---

## Incident 2: Suspicious HTTP 403 Activity

### Detection

An HTTP 403 response was observed for access to the `/admin` path.

### Evidence

- Source IP: 192.168.56.30
- Requested Path: /admin
- HTTP Status: 403
- Severity: MEDIUM
- Alert Type: HTTP_403

### Analysis

The request attempted to access a restricted web resource.
The event requires additional investigation to determine whether
the activity was legitimate or suspicious.

### Recommended Response

- Review additional web-server requests from the source IP.
- Check authentication and access logs.
- Correlate the event with network telemetry.
- Escalate if repeated unauthorized access is observed.

---

## Overall Investigation Summary

The Virtual SOC Lab generated and analyzed authentication,
web-server, DNS, and network telemetry.

Two security alerts were generated:

1. HIGH - Possible brute-force activity
2. MEDIUM - HTTP 403 suspicious web access

The events were analyzed using Python-based detection logic
and documented for further SIEM analysis in Splunk.
