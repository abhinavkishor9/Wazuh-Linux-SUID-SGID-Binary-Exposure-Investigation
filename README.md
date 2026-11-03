# Linux SUID/SGID Binary Exposure Investigation using Wazuh

## Overview

This lab investigates Linux SUID and SGID executable permissions using Wazuh File Integrity Monitoring (FIM). It focuses on identifying existing privileged binaries, establishing an initial inventory, monitoring permission changes, and detecting unexpected special permission bits.

The investigation was conducted on a Rocky Linux 9.8 virtual machine running Wazuh 4.13.1. An initial SUID/SGID inventory was generated to identify existing privileged executables and their ownership. A known system binary, `/usr/bin/passwd`, was examined to establish an example of a legitimate package-managed SUID executable.

A dedicated test directory was then created under `/var/tmp/lab126`. Two copies of `/usr/bin/id` were prepared with normal executable permissions. Wazuh FIM was configured to monitor the directory in real time, and a custom detection rule was added to identify permission changes involving SUID or SGID bits.

The controlled tests successfully triggered Wazuh Rule ID `100620` for both SUID and SGID permission changes. The alerts included the file paths, previous and updated permissions, ownership details, and MITRE ATT&CK mapping.

The test files were removed after evidence collection.

## Lab Objectives

- Understand Linux SUID and SGID permission mechanisms.
- Identify existing SUID/SGID binaries and establish an initial inventory.
- Examine file ownership, group ownership, permissions, and package ownership.
- Configure Wazuh FIM to monitor a controlled directory in real time.
- Develop a custom rule to detect special permission-bit changes.
- Validate FIM and detection-engine configurations before restarting the Manager.
- Generate controlled SUID and SGID permission changes.
- Correlate FIM alerts with file metadata and the original baseline.
- Map detected behavior to MITRE ATT&CK T1548.001.
- Distinguish privileged file exposure from confirmed exploitation or compromise.
- Document unrelated service warnings and operational limitations.

## Environment

| Component | Details |
|---|---|
| Virtualization | VMware |
| Operating System | Rocky Linux 9.8 (Blue Onyx) |
| Kernel | 5.14.0-687.31.1.el9_8.x86_64 |
| Architecture | x86-64 |
| Hostname | localhost |
| Wazuh Manager | 4.13.1 |
| Wazuh Revision | rc1 |
| Wazuh Agent ID | 000 |
| Manager / Agent Name | localhost.localdomain |
| FIM Process | wazuh-syscheckd |
| Analysis Process | wazuh-analysisd |
| Monitored Directory | /var/tmp/lab126 |
| Custom Rule ID | 100620 |
| Alert Output | /var/ossec/logs/alerts/alerts.json |

## Investigation Workflow

### 1. System Baseline

The operating system, Wazuh version, Manager service, Syscheck process, and Analysisd process were checked.

The Manager was active, and both `wazuh-syscheckd` and `wazuh-analysisd` were running.

### 2. Existing SUID/SGID Inventory

The filesystem was searched for regular files carrying either special permission bit.

The inventory included system binaries such as:

- `/usr/bin/sudo`
- `/usr/bin/passwd`
- `/usr/bin/su`
- `/usr/bin/chage`
- `/usr/bin/chfn`
- `/usr/bin/chsh`
- `/usr/bin/pkexec`
- `/usr/bin/mount`
- `/usr/bin/umount`

The initial inventory was saved to:

`/root/lab126-suid-sgid-baseline.txt`

The file metadata for `/usr/bin/passwd` showed:

- Permissions: `4755`
- Owner: `root`
- Group: `root`
- Package: `passwd-0.80-12.el9.x86_64`

This provided an example of an existing package-managed SUID binary.

### 3. Controlled Test Files

A dedicated directory was created:

`/var/tmp/lab126`

Two copies of `/usr/bin/id` were prepared:

| File | Initial Permissions | Ownership |
|---|---|---|
| suid-test | 755 | root:root |
| sgid-test | 755 | root:wheel |

Both files initially had normal executable permissions without SUID or SGID enabled.

### 4. Wazuh FIM Configuration

The Manager configuration was backed up to:

`/var/ossec/etc/ossec.conf.pre-lab126`

The local rules file was also backed up to:

`/var/ossec/etc/rules/local_rules.xml.pre-lab126`

The following directory was added to the existing Syscheck configuration with real-time monitoring:

`/var/tmp/lab126`

The effective monitoring configuration used:

- Full file attribute checks.
- Real-time monitoring.
- Permission and ownership tracking.
- File metadata and checksum collection.

### 5. Custom Detection Rule

A custom rule was added to `local_rules.xml`:

| Attribute | Value |
|---|---|
| Rule ID | 100620 |
| Rule Level | 12 |
| Group | local, suid_sgid |
| MITRE ATT&CK | T1548.001 |
| Technique | Setuid and Setgid |
| Tactics | Privilege Escalation, Defense Evasion |

The rule matched FIM modification events for files under `/var/tmp/lab126` when the reported permission string contained the special `s` permission indicator.

## Validation

The following validation commands completed without reporting errors:

- `xmllint --noout` for the Manager configuration.
- `wazuh-syscheckd -t` for Syscheck configuration.
- `wazuh-analysisd -t` for detection-rule validation.

After the Manager restart:

- Wazuh Manager was active.
- `wazuh-syscheckd` was running.
- `wazuh-analysisd` was running.
- The configured test directory was reported as a real-time monitoring path.
- FIM real-time monitoring started.

## Verified Detection Results

### SUID Permission Change

The first test changed the `suid-test` file from normal executable permissions to SUID-enabled permissions.

| Attribute | Value |
|---|---|
| File | /var/tmp/lab126/suid-test |
| Previous permissions | rwxr-xr-x |
| Updated permissions | rwsr-xr-x |
| Previous mode | 755 |
| Updated mode | 4755 |
| Owner | root |
| Group | root |
| UID | 0 |
| GID | 0 |
| Wazuh Rule ID | 100620 |
| Rule Level | 12 |
| Alert ID | 1793673299.656515 |
| Alert Timestamp | 2026-11-03 08:04:59.370 IST |

The alert recorded a permission change and included the T1548.001 mapping.

### SGID Permission Change

The second test changed the `sgid-test` file from normal executable permissions to SGID-enabled permissions.

| Attribute | Value |
|---|---|
| File | /var/tmp/lab126/sgid-test |
| Previous permissions | rwxr-xr-x |
| Updated permissions | rwxr-sr-x |
| Previous mode | 755 |
| Updated mode | 2755 |
| Owner | root |
| Group | wheel |
| UID | 0 |
| GID | 10 |
| Wazuh Rule ID | 100620 |
| Rule Level | 12 |
| Alert ID | 1793673312.658593 |
| Alert Timestamp | 2026-11-03 08:05:12.620 IST |

The alert recorded the SGID permission change and included the same MITRE ATT&CK mapping.

### Detection Summary

| Test | Rule ID | Level | Result |
|---|---:|---:|---|
| SUID permission change | 100620 | 12 | Detected |
| SGID permission change | 100620 | 12 | Detected |

Both events were generated by FIM in real-time mode and recorded under the `syscheck` location.

## Additional Operational Observations

During the exercise, the Manager logs also contained unrelated warnings:

- IndexerConnector initialization failures involving `wazuh-states-*` indices.
- Custom ticket integration connection failures with `Connection refused` from the previous alert-to-ticket lab.

These issues were recorded separately and were not demonstrated to have prevented FIM from detecting the SUID and SGID permission changes.

A separate Wazuh Discover screenshot showed a sudo-decoded event for a `grep` command used to search `alerts.json`. The visible record identified root as both the source and destination user. It was not treated as a SUID/SGID detection or evidence of privilege escalation.

## Cleanup

The controlled test binaries were deleted:

- `/var/tmp/lab126/suid-test`
- `/var/tmp/lab126/sgid-test`

The test directory `/var/tmp/lab126` was then removed. A subsequent directory check confirmed that it no longer existed.

The initial SUID/SGID inventory and configuration backups were retained for investigation records.

## Final Assessment

The lab successfully demonstrated real-time Wazuh FIM detection of controlled SUID and SGID permission changes.

Custom Rule ID `100620` generated two level-12 alerts, one for each special permission-bit test. Both alerts included the changed file permissions, file ownership information, and MITRE ATT&CK T1548.001 mapping.

The investigation established that Wazuh can detect unexpected special permission changes within a configured monitoring path. It did not demonstrate exploitation of a vulnerable binary, unauthorized privilege elevation, or malicious persistence.

## Scope and Safety

This was a controlled file-permission monitoring exercise.

- Test binaries were copies of `/usr/bin/id`.
- Permission changes were performed from the root shell.
- The test binaries were not executed after special permission bits were applied.
- No protected data was accessed.
- The test files were removed after evidence collection.
- Existing system binaries were inventoried but not modified.

Do not commit live system configuration files, sensitive hashes where they expose operational details, credentials, or unredacted security logs to a public repository.

## Future Enhancements

- Establish a package-aware approved SUID/SGID baseline.
- Monitor SUID/SGID changes outside the controlled test directory.
- Correlate permission changes with Linux Auditd records.
- Investigate unexpected ownership changes and executable creation.
- Build a custom detection for newly created root-owned SUID executables in writable directories.
- Add alert-to-ticket integration for high-confidence privileged file exposure.
- Test detection of special permission-bit removal and restoration.
