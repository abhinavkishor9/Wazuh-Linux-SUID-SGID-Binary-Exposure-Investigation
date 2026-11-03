# Wazuh-Linux-SUID-SGID-Binary-Exposure-Investigation
## Overview
Linux provides special file permission bits called **SUID (Set User ID)** and **SGID (Set Group ID)**. These permissions change the effective identity under which an executable runs.

Normally, a program executes with the privileges of the user who launches it. SUID and SGID modify this behavior:

- **SUID:** An executable runs with the effective user ID of its file owner.
- **SGID:** An executable runs with the effective group ID of its file group.

For example, legitimate system binaries such as `/usr/bin/passwd` use SUID to perform operations that require controlled access to protected system files. These permissions are not inherently malicious, but unexpected or improperly configured privileged binaries can introduce security exposure.

### How SUID and SGID Permissions Appear

SUID and SGID permissions are visible in the output of `ls -l` and can also be represented using numeric permission modes.

| Permission | Example | Numeric Mode | Meaning |
|---|---|---:|---|
| Normal executable | `-rwxr-xr-x` | 0755 | Runs with the caller's effective identity |
| SUID executable | `-rwsr-xr-x` | 4755 | Runs with the file owner's effective UID |
| SGID executable | `-rwxr-sr-x` | 2755 | Runs with the file group's effective GID |
| SUID and SGID | `-rwsr-sr-x` | 6755 | Both special permission bits are set |

The `s` replaces the normal execute permission in the corresponding position.

If the special permission bit is set but the corresponding execute permission is absent, an uppercase `S` appears instead of lowercase `s`.

### How Attackers Abuse SUID/SGID Binaries

Attackers who have already obtained sufficient privileges may create or modify SUID/SGID binaries to establish another path to elevated access.

Common abuse scenarios include:

1. **Unexpected SUID binary creation:** A root-owned executable is placed in a location accessible to ordinary users and assigned the SUID bit.
2. **Existing executable modification:** A legitimate binary receives an unexpected SUID or SGID permission.
3. **Misconfigured privileged binaries:** An executable has excessive functionality that can expose protected files or privileged operations.
4. **Persistence through privileged executables:** A modified binary provides a recurring method to execute operations under its owner's or group's identity.

An important distinction is that an ordinary user cannot simply set the SUID bit on a root-owned file to obtain root privileges. The user must have sufficient permission to modify the file. When executed, the program uses the file owner's effective identity rather than automatically granting privileges based on who launched it.

An unexpected root-owned SUID binary can therefore indicate that privileged access was previously obtained or that an administrative configuration was changed.

### Role of Wazuh

Wazuh can help identify suspicious SUID/SGID exposure through multiple monitoring and detection capabilities.

| Capability | Investigation Purpose |
|---|---|
| File Integrity Monitoring (FIM) | Detects file creation, modification, ownership, and permission changes |
| Auditd | Records relevant system calls, including operations that modify special permission bits |
| Custom Detection Rules | Identifies suspicious permission changes and maps them to MITRE ATT&CK |
| Command Monitoring | Supports inventory checks and comparison of privileged binaries against an approved baseline |
| Security Configuration Assessment (SCA) | Provides recurring compliance checks when appropriate policies are configured |

FIM can monitor selected directories for permission and ownership changes. An initial inventory, scheduled checks, or custom scripts can also help identify privileged executables that are absent from an approved baseline.

These capabilities complement each other:

- **Inventory establishes what currently exists.**
- **FIM identifies changes to monitored files.**
- **Auditd can provide additional evidence about relevant system operations.**
- **Custom rules classify events and generate investigation alerts.**
- **Baseline comparison helps distinguish expected privileged binaries from unexpected exposure.**

In this lab, the primary detection mechanism was Wazuh FIM combined with a custom rule that identified SUID/SGID permission changes in a controlled directory.

### MITRE ATT&CK Mapping

**T1548.001 — Setuid and Setgid**

| Attribute | Details |
|---|---|
| Technique ID | T1548.001 |
| Technique | Setuid and Setgid |
| Tactics | Privilege Escalation, Defense Evasion |
| Investigation Focus | Abuse of special Linux executable permission bits |

The technique covers abuse of SUID and SGID mechanisms to execute programs with elevated user or group privileges.

**Important distinction:** The presence of an SUID or SGID bit does not automatically indicate malicious activity. Investigation should consider the binary's purpose, file path, ownership, package origin, permission history, and whether the change was authorized. A FIM alert establishes that a monitored file attribute changed; it does not independently prove exploitation, unauthorized access, or compromise.


This lab investigates Linux SUID and SGID executable permissions using Wazuh File Integrity Monitoring (FIM). It focuses on identifying existing privileged binaries, establishing an initial inventory, monitoring permission changes, and detecting unexpected special permission bits.

The investigation was conducted on a Rocky Linux 9.8 virtual machine running Wazuh 4.13.1. An initial SUID/SGID inventory was generated to identify existing privileged executables and their ownership. A known system binary, `/usr/bin/passwd`, was examined to establish an example of a legitimate package-managed SUID executable.

A dedicated test directory was then created under `/var/tmp/lab126`. Two copies of `/usr/bin/id` were prepared with normal executable permissions. Wazuh FIM was configured to monitor the directory in real time, and a custom detection rule was added to identify permission changes involving SUID or SGID bits.

The controlled tests successfully triggered Wazuh Rule ID `100620` for both SUID and SGID permission changes. The alerts included the file paths, previous and updated permissions, ownership details, and MITRE ATT&CK mapping.

The test files were removed after evidence collection.

## Lab Objectives

The objectives of this lab are to:

- Understand the purpose and security implications of SUID and SGID special permission bits in Linux.
- Identify executable files carrying SUID or SGID permissions across the filesystem.
- Establish an inventory of existing privileged binaries, including their ownership, group, permissions, and file locations.
- Examine legitimate privileged executables and verify their package ownership to distinguish expected configurations from potential exposure.
- Understand how unexpected permission changes can introduce privilege escalation risks.
- Configure Wazuh File Integrity Monitoring (FIM) to monitor a dedicated directory for real-time file attribute changes.
- Develop and validate a custom Wazuh detection rule for identifying SUID/SGID permission changes.
- Generate controlled SUID and SGID permission modifications to test the detection mechanism.
- Examine FIM alert details, including previous and updated permissions, file ownership, group ownership, timestamps, and file paths.
- Correlate detected permission changes with the initial SUID/SGID inventory.
- Understand the relationship between special permission-bit abuse and MITRE ATT&CK technique T1548.001.
- Differentiate between a privileged file modification and confirmed privilege escalation or system compromise.
- Identify unrelated monitoring and integration issues without attributing them incorrectly to FIM.
- Verify the removal of controlled test artifacts and document the final system state.
- Produce an evidence-based assessment of privileged binary exposure, detection effectiveness, and investigation limitations.

## Lab Scenario

A Rocky Linux 9.8 virtual machine running Wazuh 4.13.1 is being assessed to understand how unexpected SUID and SGID permission changes can introduce privileged executable exposure and how such changes can be detected through File Integrity Monitoring (FIM).

The investigation begins with an examination of existing SUID/SGID binaries across the Linux filesystem. Their permission modes, ownership, group assignments, and package origins are reviewed to distinguish expected system configurations from potentially unusual privileged executables. For example, the existing `/usr/bin/passwd` binary is found to have SUID permissions and is associated with an installed RPM package.

To evaluate detection capabilities, a dedicated test directory is created containing two root-owned copies of `/usr/bin/id`. Both executables initially have normal permissions. Wazuh FIM is then configured to monitor the directory in real time, and a custom detection rule is introduced to identify file modifications involving the special `s` permission indicator.

The investigation proceeds through two controlled tests:

- **SUID permission change:** The SUID bit is enabled on the first test executable, changing its permissions from `755` to `4755`.
- **SGID permission change:** The SGID bit is enabled on the second test executable, changing its permissions from `755` to `2755`.

Wazuh detects both modifications through real-time FIM and generates custom Rule ID `100620` alerts at level 12. The alerts contain the affected file paths, previous and updated permissions, ownership information, and MITRE ATT&CK mapping T1548.001.

The investigation also considers the surrounding operational context. IndexerConnector initialization warnings and connection failures from an existing ticket integration are observed in the Manager logs. These are documented separately rather than assumed to have affected the successful FIM detections. A separate sudo-decoded event is also identified in Wazuh Discover, but it is not treated as evidence of SUID/SGID permission changes.

After collecting the detection evidence, both controlled test executables are removed and the test directory is deleted.

The investigation focuses on determining:

- Whether the existing privileged binaries are expected and appropriately managed.
- Whether Wazuh can detect changes to SUID and SGID permission bits.
- Whether the generated alerts accurately reflect the modified file attributes.
- Whether the detected changes can be associated with a relevant MITRE ATT&CK technique.
- Whether the available evidence indicates configuration exposure, unauthorized modification, or confirmed privilege escalation.

**Scenario objective:** Evaluate Linux privileged executable exposure, establish an initial SUID/SGID inventory, implement real-time Wazuh FIM monitoring, and validate custom detection of controlled special permission-bit changes.

**Scope limitation:** This is a controlled file-integrity monitoring and detection exercise. The test executables are not executed after enabling SUID or SGID permissions. No exploitation, unauthorized privilege elevation, or malicious persistence is performed. Detection of a special permission-bit change establishes a file modification, not proof of compromise or malicious intent.

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

