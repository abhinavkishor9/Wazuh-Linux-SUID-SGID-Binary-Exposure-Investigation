
# Investigation Notes — Linux SUID/SGID Binary Exposure Investigation using Wazuh

## 1. Investigation Summary

The investigation evaluated the presence of privileged SUID/SGID executables on a Rocky Linux 9.8 system and tested whether Wazuh could detect changes to these special permission bits.

An initial filesystem inventory was generated to identify existing SUID/SGID files, their permission modes, owners, groups, and locations. The binary `/usr/bin/passwd` was examined as an example of a legitimate package-managed SUID executable.

A dedicated test directory was created, containing two root-owned copies of `/usr/bin/id`. Wazuh FIM was configured to monitor this directory in real time. A custom detection rule, ID `100620`, was added to identify permission changes involving the special `s` permission indicator.

The controlled tests generated two successful detections: one for SUID and one for SGID. Both alerts were recorded with rule level 12 and MITRE ATT&CK mapping T1548.001.

## 2. System Baseline

The environment was identified using `hostnamectl` and Wazuh control commands.

| Attribute | Observed Value |
|---|---|
| Hostname | localhost |
| Operating System | Rocky Linux 9.8 (Blue Onyx) |
| Kernel | 5.14.0-687.31.1.el9_8.x86_64 |
| Virtualization | VMware |
| Architecture | x86-64 |
| Wazuh Version | 4.13.1 |
| Wazuh Revision | rc1 |
| Wazuh Type | server |
| Wazuh Agent ID | 000 |
| Agent Name | localhost.localdomain |
| Manager Service | active |

The initial process check confirmed:

- `wazuh-syscheckd` was running.
- `wazuh-analysisd` was running.

## 3. Existing SUID/SGID Inventory

The filesystem was searched for regular files with either the SUID or SGID permission bit.

The search excluded transient virtual filesystems and used the following permission filters:

- `-perm -4000` for SUID.
- `-perm -2000` for SGID.

The inventory was generated using:

```bash
sudo find / \
  \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune \
  -o -type f \( -perm -4000 -o -perm -2000 \) \
  -printf '%m %u:%g %p\n' 2>/dev/null | sort
```

The initial output included several system binaries, including:

| Permission Mode | Owner:Group | Path |
|---|---|---|
| 2555 | root:ssh_keys | /usr/libexec/openssh/ssh-keysign |
| 2711 | root:lock | /usr/sbin/lockdev |
| 2711 | root:slocate | /usr/bin/locate |
| 2755 | root:tty | /usr/bin/write |
| 4111 | root:root | /usr/bin/sudo |
| 4711 | root:root | /usr/bin/chfn |
| 4711 | root:root | /usr/bin/chsh |
| 4750 | root:dbus | /usr/libexec/dbus-1/dbus-daemon-launch-helper |
| 4750 | root:sssd | /usr/libexec/sssd/krb5_child |
| 4755 | root:root | /usr/bin/passwd |
| 4755 | root:root | /usr/bin/su |
| 4755 | root:root | /usr/bin/mount |
| 4755 | root:root | /usr/bin/umount |
| 4755 | root:root | /usr/bin/pkexec |

The complete inventory was saved to:

`/root/lab126-suid-sgid-baseline.txt`

The initial attempt to display this file returned a file-not-found error because the baseline had not yet been created. The inventory command was subsequently piped through `tee` to generate the file, and the saved contents were verified.

### Verification of `/usr/bin/passwd`

The following command was used:

```bash
sudo stat -c '%A %a %U:%G %n' /usr/bin/passwd
```

Output:

```text
-rwsr-xr-x 4755 root:root /usr/bin/passwd
```

Package ownership was checked using:

```bash
rpm -qf /usr/bin/passwd
```

Result:

```text
passwd-0.80-12.el9.x86_64
```

This established that the inspected SUID binary was owned by root and associated with an installed RPM package.

Its presence was not treated as suspicious merely because the SUID bit was enabled.

## 4. Test Directory and File Preparation

The dedicated monitoring directory was created:

`/var/tmp/lab126`

Its initial ownership and permissions were configured as:

- Owner: root
- Group: root
- Mode: 0755

Two copies of `/usr/bin/id` were placed in the directory.

| Test File | Initial Owner | Initial Group | Initial Mode |
|---|---|---|---:|
| suid-test | root | root | 755 |
| sgid-test | root | wheel | 755 |

The initial permission verification returned:

```text
-rwxr-xr-x 755 root:wheel /var/tmp/lab126/sgid-test
-rwxr-xr-x 755 root:root /var/tmp/lab126/suid-test
```

Both files initially had normal executable permissions without the SUID or SGID bits.

The two files were copies of the same source executable and had matching size and checksum values in the subsequent FIM event records.

## 5. Configuration Backup

Before modifying Wazuh configuration, the Manager configuration was copied to:

`/var/ossec/etc/ossec.conf.pre-lab126`

The directory listing reported a file size of 9,493 bytes.

The local detection rules were also backed up to:

`/var/ossec/etc/rules/local_rules.xml.pre-lab126`

A search was performed to check whether custom rule ID `100620` was already in use:

```bash
sudo grep -R 'id="100620"' /var/ossec/etc/rules/
```

No matching output was returned at the time of the check.

## 6. FIM Monitoring Configuration

The existing `<syscheck>` configuration was updated to monitor:

`/var/tmp/lab126`

The directory was configured using:

```xml
<directories check_all="yes" realtime="yes">/var/tmp/lab126</directories>
```

This enabled full attribute checking and real-time monitoring for the controlled test directory.

The following commands completed without returning validation errors:

```bash
sudo xmllint --noout /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-syscheckd -t
sudo /var/ossec/bin/wazuh-analysisd -t
```

The Wazuh Manager was restarted successfully.

The service-state check returned:

```text
active
```

Both relevant processes were running:

```text
wazuh-syscheckd is running...
wazuh-analysisd is running...
```

### FIM Initialization

The Manager log recorded:

```text
2026/11/03 07:36:09 wazuh-syscheckd: INFO: (6008): File integrity monitoring scan started.
2026/11/03 07:37:15 wazuh-syscheckd: INFO: (6009): File integrity monitoring scan ended.
2026/11/03 07:37:15 wazuh-syscheckd: INFO: FIM sync module started.
```

After a subsequent Syscheck restart, the log confirmed that the test directory was configured for real-time monitoring:

```text
2026/11/03 08:02:49 wazuh-syscheckd: INFO: (6003): Monitoring path: '/var/tmp/lab126', with options 'size | permissions | owner | group | mtime | inode | hash_md5 | hash_sha1 | hash_sha256 | realtime'.
```

Real-time monitoring was confirmed as started:

```text
2026/11/03 08:03:05 wazuh-syscheckd: INFO: (6012): Real-time file integrity monitoring started.
```

This provided operational evidence that the configured directory was under real-time FIM monitoring before the permission-change tests.

## 7. Custom Detection Rule

A custom rule was added to:

`/var/ossec/etc/rules/local_rules.xml`

The rule used:

| Attribute | Value |
|---|---|
| Rule ID | 100620 |
| Level | 12 |
| Parent Rule | 550 |
| File Scope | /var/tmp/lab126 |
| Permission Match | `s` |
| Groups | local, suid_sgid |
| MITRE ID | T1548.001 |
| Technique | Setuid and Setgid |
| Tactics | Privilege Escalation, Defense Evasion |

The rule was designed to match FIM modification events within the test directory when the permission field contained the special `s` indicator.

The installed rule was successfully validated using `wazuh-analysisd -t`.

## 8. Controlled SUID Test

The SUID bit was enabled on the test executable:

```bash
sudo chmod u+s /var/tmp/lab126/suid-test
```

The subsequent metadata inspection showed:

```text
-rwsr-xr-x 4755 root:root /var/tmp/lab126/suid-test
```

### FIM Detection

Wazuh generated the following alert:

| Attribute | Value |
|---|---|
| Alert Timestamp | 2026-11-03 08:04:59.370 IST |
| Alert ID | 1793673299.656515 |
| Rule ID | 100620 |
| Rule Level | 12 |
| Agent ID | 000 |
| Agent Name | localhost.localdomain |
| File | /var/tmp/lab126/suid-test |
| Event Type | modified |
| FIM Mode | realtime |

The alert's `full_log` field showed:

```text
File '/var/tmp/lab126/suid-test' modified
Mode: realtime
Changed attributes: permission
Permissions changed from 'rwxr-xr-x' to 'rwsr-xr-x'
```

The structured `syscheck` details included:

| Field | Value |
|---|---|
| perm_before | rwxr-xr-x |
| perm_after | rwsr-xr-x |
| uid_after | 0 |
| gid_after | 0 |
| uname_after | root |
| gname_after | root |
| changed_attributes | permission |
| event | modified |

The alert contained the MITRE ATT&CK mapping:

`T1548.001 — Setuid and Setgid`

## 9. Controlled SGID Test

The SGID bit was enabled on the second test executable:

```bash
sudo chmod g+s /var/tmp/lab126/sgid-test
```

The resulting metadata was:

```text
-rwxr-sr-x 2755 root:wheel /var/tmp/lab126/sgid-test
```

### FIM Detection

Wazuh generated the following alert:

| Attribute | Value |
|---|---|
| Alert Timestamp | 2026-11-03 08:05:12.620 IST |
| Alert ID | 1793673312.658593 |
| Rule ID | 100620 |
| Rule Level | 12 |
| Agent ID | 000 |
| Agent Name | localhost.localdomain |
| File | /var/tmp/lab126/sgid-test |
| Event Type | modified |
| FIM Mode | realtime |

The alert's `full_log` field showed:

```text
File '/var/tmp/lab126/sgid-test' modified
Mode: realtime
Changed attributes: permission
Permissions changed from 'rwxr-xr-x' to 'rwxr-sr-x'
```

The structured `syscheck` details included:

| Field | Value |
|---|---|
| perm_before | rwxr-xr-x |
| perm_after | rwxr-sr-x |
| uid_after | 0 |
| gid_after | 10 |
| uname_after | root |
| gname_after | wheel |
| changed_attributes | permission |
| event | modified |

The alert also contained the MITRE ATT&CK T1548.001 mapping.

## 10. Detection Summary

| Test | File | Permission Change | Rule ID | Level | Result |
|---|---|---|---:|---:|---|
| SUID | suid-test | 755 to 4755 | 100620 | 12 | Detected |
| SGID | sgid-test | 755 to 2755 | 100620 | 12 | Detected |

Both permission changes were detected through real-time FIM.

The first alert reported `firedtimes: 1`; the second reported `firedtimes: 2`.

The alerts were generated by the local Manager identity:

- Agent ID: `000`
- Agent name: `localhost.localdomain`
- Cluster name: `wazuh`
- Cluster node: `node01`

## 11. Additional Wazuh Discover Observation

A separate Wazuh Discover screenshot captured an event at:

`2026-11-03 08:06:50.703`

The visible event details included:

| Field | Value |
|---|---|
| Index | wazuh-alerts-4.x-2026.11.03 |
| Agent ID | 000 |
| Agent Name | localhost.localdomain |
| Cluster Name | wazuh |
| Cluster Node | node01 |
| Command | `/bin/grep -F '"id":"100620"' /var/ossec/logs/alerts/alerts.json` |
| Source User | root |
| Destination User | root |
| Working Directory | /root |
| TTY | pts/0 |
| Decoder | sudo |
| Decoder Comment | First time user executed the sudo command |

This was a separate sudo-decoded event associated with searching the local alert file.

It should not be confused with the FIM SUID/SGID detections. The visible screenshot did not include a complete rule ID field, so no specific sudo rule ID is attributed to this record.

The source and destination user fields both showed root, which also means it does not demonstrate a non-root-to-root privilege transition.

## 12. Operational Warnings

Two unrelated types of warnings were observed during the exercise.

### IndexerConnector Warnings

The Manager log reported initialization failures for several `wazuh-states-*` indices, including vulnerability, package, system, process, port, hardware, and network-related indices.

These messages were recorded separately from the FIM permission-change detections.

### Existing Custom Ticket Integration

The Manager log also reported:

```text
Unable to run integration for custom-ticket
Connection refused
```

The errors occurred at 07:42:14 and 08:02:53.

The message indicates that the configured ticket receiver endpoint was not accepting the connection at those times. This was associated with the existing custom ticket integration from Lab 124.

The supplied evidence does not show that this issue prevented Syscheck from monitoring files or generating the SUID/SGID alerts.

## 13. Cleanup

After the two permission-change alerts were collected, the test executables were removed:

```bash
sudo rm -f /var/tmp/lab126/suid-test
sudo rm -f /var/tmp/lab126/sgid-test
sudo rmdir /var/tmp/lab126
```

The final directory check returned:

```text
ls: cannot access '/var/tmp/lab126': No such file or directory
```

This confirmed that the controlled test directory had been removed.

The available evidence does not include separate alert records for the cleanup deletions. They are therefore not reported as verified FIM deletion detections.

## 14. Findings and Assessment

| Area | Finding | Assessment |
|---|---|---|
| System baseline | Rocky Linux 9.8, Wazuh 4.13.1 | Verified |
| Initial SUID/SGID inventory | Saved to the root baseline file | Verified |
| Existing passwd binary | SUID 4755, root:root, RPM-owned | Verified |
| FIM configuration | `/var/tmp/lab126` configured for realtime monitoring | Verified |
| Configuration validation | XML, Syscheck, and Analysisd tests completed without reported errors | Verified |
| Manager service | Active after restart | Verified |
| Syscheck process | Running | Verified |
| Analysisd process | Running | Verified |
| Custom detection rule | Rule ID 100620, level 12 | Verified |
| SUID change detection | `suid-test`, permission 755 to 4755 | Verified |
| SGID change detection | `sgid-test`, permission 755 to 2755 | Verified |
| MITRE mapping | T1548.001 | Verified |
| Test binary execution | Not performed after setting special bits | Verified by lab procedure |
| Test cleanup | Files and test directory removed | Verified |
| IndexerConnector warnings | Present during the exercise | Observed; separate issue |
| Custom ticket integration errors | Connection refused | Observed; separate issue |
| Unauthorized privilege escalation | Not demonstrated | Not established |
| Malicious persistence | Not demonstrated | Not established |

## 15. Conclusion

The investigation successfully demonstrated that Wazuh FIM can detect controlled changes to SUID and SGID permission bits within a monitored directory.

Custom Rule ID `100620` generated two level-12 alerts. The SUID alert identified the transition from `rwxr-xr-x` to `rwsr-xr-x`, while the SGID alert identified the transition from `rwxr-xr-x` to `rwxr-sr-x`.

Both alerts contained file ownership and permission details and were mapped to MITRE ATT&CK T1548.001.

The exercise validated real-time FIM monitoring, custom rule matching, and alert generation. It did not demonstrate that either test binary was executed with elevated privileges, that a non-root account created the permission changes, or that the system was compromised.

The final test artifacts were removed successfully.
