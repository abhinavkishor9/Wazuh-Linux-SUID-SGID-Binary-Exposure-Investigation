# Lab Timeline 

## 2026-11-03 — Investigation Timeline

All timestamps are in IST (UTC+05:30).

### System Baseline and SUID/SGID Inventory

| Activity | Observation | Result |
|---|---|---|
| Inspected operating system and host details | Rocky Linux 9.8, VMware, x86-64 | Environment identified |
| Checked Wazuh version | Version 4.13.1, revision rc1 | Baseline established |
| Checked Manager service | Active | Verified |
| Checked Syscheck and Analysisd processes | Both running | Verified |
| Searched the filesystem for SUID/SGID files | Existing privileged executables identified | Inventory collected |
| Saved initial inventory | `/root/lab126-suid-sgid-baseline.txt` | Baseline file created and verified |
| Inspected `/usr/bin/passwd` | Mode 4755, owner root, group root | Metadata verified |
| Checked RPM ownership of `/usr/bin/passwd` | `passwd-0.80-12.el9.x86_64` | Package ownership verified |

Exact command execution times for these baseline activities were not captured.

### Test Preparation and Configuration

| Activity | Observation | Result |
|---|---|---|
| Created `/var/tmp/lab126` | Root-owned directory, mode 0755 | Test location created |
| Copied `/usr/bin/id` as `suid-test` | Owner root, group root, mode 755 | SUID test file prepared |
| Copied `/usr/bin/id` as `sgid-test` | Owner root, group wheel, mode 755 | SGID test file prepared |
| Backed up Manager configuration | `ossec.conf.pre-lab126` | Backup created |
| Backed up local detection rules | `local_rules.xml.pre-lab126` | Backup created |
| Checked custom rule ID 100620 | No existing match returned | ID available at time of check |
| Added real-time FIM monitoring | `/var/tmp/lab126` | Monitoring path configured |
| Added custom detection rule | Rule ID 100620, level 12 | Detection configured |
| Validated XML, Syscheck, and Analysisd configurations | No validation errors reported | Validation passed |
| Restarted Wazuh Manager | Service returned active | Restart successful |
| Checked Syscheck and Analysisd | Both processes running | Verified |

Exact execution times for the configuration edits, validation commands, and first Manager restart were not captured.

### Initial FIM Scan and Operational Warnings

| Time (IST) | Activity / Observation | Result |
|---|---|---|
| 07:36:09 | Syscheck logged that a FIM scan started. | Scan started |
| 07:36:14–07:36:18 | IndexerConnector initialization warnings appeared for multiple `wazuh-states-*` indices. | Separate operational warnings |
| 07:37:15 | Syscheck logged that the FIM scan ended. | Initial scan ended |
| 07:37:15 | FIM sync module started. | Synchronization module started |
| 07:42:14 | Existing `custom-ticket` integration reported a connection-refused error. | Unrelated integration error |

### FIM Restart and Real-Time Monitoring

| Time (IST) | Activity / Observation | Result |
|---|---|---|
| 08:02:35 | Syscheck received a shutdown signal. | Syscheck stopped |
| 08:02:49 | Syscheck started again with PID 9308. | Process started |
| 08:02:49 | Manager logs listed `/var/tmp/lab126` with permission, ownership, hash, and realtime monitoring options. | Target path registered |
| 08:02:49 | FIM scan started. | Scan started |
| 08:02:53 | Existing `custom-ticket` integration again reported connection refused. | Separate integration error |
| 08:03:05 | Syscheck reported that real-time FIM monitoring had started. | Monitoring active |

### Controlled SUID and SGID Permission Changes

| Time (IST) | Activity / Observation | Result |
|---|---|---|
| 08:04:59.370 | FIM detected the SUID permission change on `suid-test`. | Rule ID 100620, level 12 |
| 08:05:12.620 | FIM detected the SGID permission change on `sgid-test`. | Rule ID 100620, level 12 |

#### SUID Detection

| Attribute | Value |
|---|---|
| Alert ID | 1793673299.656515 |
| Rule ID | 100620 |
| File | /var/tmp/lab126/suid-test |
| Previous Permissions | rwxr-xr-x |
| Updated Permissions | rwsr-xr-x |
| Owner:Group | root:root |
| MITRE ATT&CK | T1548.001 |

#### SGID Detection

| Attribute | Value |
|---|---|
| Alert ID | 1793673312.658593 |
| Rule ID | 100620 |
| File | /var/tmp/lab126/sgid-test |
| Previous Permissions | rwxr-xr-x |
| Updated Permissions | rwxr-sr-x |
| Owner:Group | root:wheel |
| MITRE ATT&CK | T1548.001 |

### Wazuh Discover Observation

| Time (IST) | Activity / Observation | Result |
|---|---|---|
| 08:06:50.703 | Discover screenshot displayed a sudo-decoded event for a `grep` command querying `alerts.json`. | Separate sudo event observed |

The visible event identified root as both the source and destination user. It was not treated as a SUID/SGID FIM alert or evidence of a non-root-to-root privilege transition.

### Cleanup

| Activity | Observation | Result |
|---|---|---|
| Removed `suid-test` | Test executable deleted | Cleanup performed |
| Removed `sgid-test` | Test executable deleted | Cleanup performed |
| Removed `/var/tmp/lab126` | Directory removal completed | Cleanup performed |
| Checked test directory | `No such file or directory` | Removal verified |

The exact cleanup time was not captured. Separate FIM deletion alerts were not included in the supplied evidence.

