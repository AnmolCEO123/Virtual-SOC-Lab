# Splunk SPL Detection Queries

## 1. Show all SOC alerts

index=main sourcetype=soc_alerts
| table \_time severity alert_type src_ip path description

## 2. Detect brute-force activity

index=main sourcetype=soc_alerts alert_type=BRUTE_FORCE
| stats count by src_ip
| sort - count

## 3. Find HTTP 403 events

index=main sourcetype=soc_alerts alert_type=HTTP_403
| table \_time severity src_ip path description

## 4. Analyze DNS activity

index=main sourcetype=network_logs
| search "DNS_QUERY"
| table \_time src_ip query

## 5. Analyze TCP connections

index=main sourcetype=network_logs
| search "TCP_CONNECTION"
| table \_time src_ip dst_ip dst_port

## 6. Failed login analysis

index=main sourcetype=auth_logs
| search "LOGIN_FAILURE"
| stats count by src_ip username
| sort - count
