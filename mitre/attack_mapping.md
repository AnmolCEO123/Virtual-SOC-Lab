# MITRE ATT&CK Mapping

## 1. Brute Force

**Observed Activity:** Multiple failed login attempts from the same source IP.

**MITRE Technique:** T1110 - Brute Force

**Detection Evidence:**

- 5 failed login attempts
- Source IP: 192.168.56.10
- Target username: admin

**Severity:** High

---

## 2. Network Service Scanning

**Observed Activity:** Network connections identified during lab monitoring.

**MITRE Technique:** T1046 - Network Service Scanning

**Detection Evidence:**

- TCP connection monitoring
- Network telemetry collected from the lab environment

**Severity:** Medium

---

## 3. Web-Based Suspicious Activity

**Observed Activity:** HTTP 403 response for `/admin`.

**Detection Evidence:**

- Source IP: 192.168.56.30
- Requested path: `/admin`
- HTTP status: 403

**Severity:** Medium

---

## Investigation Summary

The lab detected authentication failures, suspicious web access,
DNS activity, and TCP network connections. These events were
analyzed as part of a defensive SOC monitoring workflow.
