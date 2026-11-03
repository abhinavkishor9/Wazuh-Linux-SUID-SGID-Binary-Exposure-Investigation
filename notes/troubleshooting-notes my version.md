# Troubleshooting Notes 

## 1. Terminal Commands Affected by Bracketed-Paste Characters

### Observation

Some initial terminal commands failed with messages such as:

```text
bash: sudo: command not found
bash: [200~sudo: command not found
bash: sort~: command not found
```

The terminal input contained bracketed-paste control characters such as `^[[200~` and an unintended trailing character.

### Resolution

The affected commands were entered again without the extra characters.

The SUID/SGID inventory command subsequently executed successfully and returned the expected file listings.

**Lesson:** When a command unexpectedly fails with a command-not-found error, inspect the actual terminal input before assuming that a required utility is missing.

---

## 2. Baseline File Not Found

### Observation

The first attempt to read:

```text
/root/lab126-suid-sgid-baseline.txt
```

returned:

```text
cat: /root/lab126-suid-sgid-baseline.txt: No such file or directory
```

### Explanation

The inventory had been displayed in the terminal, but the baseline file had not yet been created.

### Resolution

The search output was piped through `tee`:

```bash
sudo find / \
  \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune \
  -o -type f \( -perm -4000 -o -perm -2000 \) \
  -printf '%m %u:%g %p\n' 2>/dev/null | sort \
  | sudo tee /root/lab126-suid-sgid-baseline.txt >/dev/null
```

The resulting file was read successfully, and the inventory was confirmed.

**Lesson:** A terminal listing is not a saved baseline. Preserve the output explicitly before relying on it for later comparisons.

---

## 3. Interpreting Existing SUID/SGID Files

### Observation

The initial inventory contained several root-owned privileged executables, including:

- `/usr/bin/passwd`
- `/usr/bin/su`
- `/usr/bin/sudo`
- `/usr/bin/mount`
- `/usr/bin/umount`
- `/usr/bin/pkexec`

For `/usr/bin/passwd`, the metadata was:

```text
-rwsr-xr-x 4755 root:root /usr/bin/passwd
```

RPM ownership was confirmed:

```text
passwd-0.80-12.el9.x86_64
```

### Explanation

A privileged permission bit does not automatically indicate malicious activity. Many system binaries require SUID or SGID to perform legitimate operations.

### Resolution

The initial inventory was treated as a baseline rather than a list of confirmed vulnerabilities.

The `passwd` executable was checked for ownership and package association before interpreting its permission mode.

**Lesson:** Investigate the file owner, group, package ownership, path, and expected system function before classifying a privileged executable as unauthorized.

---

## 4. Real-Time FIM Monitoring Not Yet Confirmed

### Objective

Wazuh must be monitoring the test directory before the controlled permission changes occur.

### Verification

The Manager log reported:

```text
Directory set for real time monitoring: '/var/tmp/lab126'.
```

It later recorded:

```text
Real-time file integrity monitoring started.
```

The relevant startup message was recorded at:

```text
2026/11/03 08:03:05
```

### Explanation

A directory entry in `ossec.conf` is not sufficient evidence that real-time monitoring has started.

The Syscheck startup log provides operational confirmation that the path has been registered and real-time monitoring is active.

### Resolution

The permission changes were performed after the log confirmed that real-time monitoring had started.

**Lesson:** Verify the monitoring process and its configured paths before generating test events.

---

## 5. Configuration Validation

### Validation Commands

The following commands were executed:

```bash
sudo xmllint --noout /var/ossec/etc/ossec.conf
sudo /var/ossec/bin/wazuh-syscheckd -t
sudo /var/ossec/bin/wazuh-analysisd -t
```

No validation errors were reported.

The Manager restart completed, and the service returned:

```text
active
```

The process check showed:

```text
wazuh-syscheckd is running...
wazuh-analysisd is running...
```

### Explanation

These checks validate different parts of the configuration:

- `xmllint` checks XML syntax.
- `wazuh-syscheckd -t` validates Syscheck configuration.
- `wazuh-analysisd -t` validates detection-rule configuration.
- Service and process checks confirm that the relevant daemons are running.

**Lesson:** Validate both the FIM configuration and custom detection rules before restarting the Manager.

---

## 6. Custom Rule Not Triggering

### Investigation

The custom rule used:

- Rule ID: `100620`
- Parent rule: `550`
- File path filter: `/var/tmp/lab126`
- Permission field match: `s`
- Rule level: `12`
- MITRE ATT&CK mapping: `T1548.001`

The rule was validated using:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

### Troubleshooting Approach

If the rule does not trigger:

1. Confirm that Syscheck is running.
2. Confirm that the directory appears in the Syscheck monitoring logs.
3. Confirm that real-time monitoring has started.
4. Check whether a FIM event is generated for the file modification.
5. Inspect the original event fields before adjusting the custom rule.
6. Verify that the event includes the expected file path and permission information.
7. Confirm that the parent rule and custom rule conditions match the actual event structure.

### Verified Result

The rule successfully matched both test permission changes.

The resulting alerts showed:

```text
Permissions changed from 'rwxr-xr-x' to 'rwsr-xr-x'
```

and:

```text
Permissions changed from 'rwxr-xr-x' to 'rwxr-sr-x'
```

**Lesson:** Inspect the original FIM event before changing custom rule conditions. The successful test confirmed that the configured file and permission matching worked in this environment.

---

## 7. Distinguishing SUID and SGID Alerts

### SUID Test

The command:

```bash
sudo chmod u+s /var/tmp/lab126/suid-test
```

produced:

```text
-rwsr-xr-x 4755 root:root /var/tmp/lab126/suid-test
```

The event showed a transition from:

```text
rwxr-xr-x
```

to:

```text
rwsr-xr-x
```

### SGID Test

The command:

```bash
sudo chmod g+s /var/tmp/lab126/sgid-test
```

produced:

```text
-rwxr-sr-x 2755 root:wheel /var/tmp/lab126/sgid-test
```

The event showed a transition from:

```text
rwxr-xr-x
```

to:

```text
rwxr-sr-x
```

### Explanation

Both permission changes matched the same custom rule because the rule was designed to detect the special `s` indicator in either applicable permission position.

The file ownership information distinguished the two test cases:

| Test | Owner | Group | UID | GID |
|---|---|---|---:|---:|
| SUID | root | root | 0 | 0 |
| SGID | root | wheel | 0 | 10 |

**Lesson:** Interpret the position of the special permission indicator and correlate it with the file's ownership information to distinguish SUID from SGID.

---

## 8. Understanding the FIM Alert Details

### Observation

Both custom alerts contained:

- Rule ID `100620`.
- Rule level `12`.
- MITRE ATT&CK ID `T1548.001`.
- FIM mode `realtime`.
- Changed attribute `permission`.
- Previous and updated permission strings.
- File owner and group information.
- File metadata and checksums.

### Explanation

The FIM event records the observed change in file metadata. It does not independently establish who performed the change or whether the action was malicious.

The controlled permission changes were issued from the root shell. This is consistent with the administrative context shown in the terminal commands.

### Resolution

The investigation compared the `syscheck` metadata with the terminal `stat` output.

**Lesson:** Use FIM to establish what changed, and use authentication or audit records when investigating who performed the operation.

---

## 9. Interpreting the Separate Wazuh Discover Sudo Event

### Observation

The Wazuh Discover screenshot showed:

```text
Command:
 /bin/grep -F '"id":"100620"' /var/ossec/logs/alerts/alerts.json

Source User: root
Destination User: root
Working Directory: /root
TTY: pts/0
Decoder: sudo
Decoder Comment: First time user executed the sudo command
```

The screenshot timestamp was:

`2026-11-03 08:06:50.703`

### Explanation

This was a separate sudo-decoded event associated with the command used to search the local Wazuh alert file.

It was not the SUID or SGID FIM alert.

The visible source and destination user fields both identified root. The screenshot therefore does not demonstrate a non-root user obtaining elevated privileges.

The screenshot also did not expose the complete detection rule ID, so a particular sudo rule ID should not be assigned to it based only on the visible decoder comment.

### Resolution

The Discover record was documented separately from the two Rule ID 100620 FIM alerts.

**Lesson:** A sudo decoder event and a FIM permission-change alert represent different event types. Correlate them using the actual command, event fields, and timestamps rather than treating them as the same detection.

---

## 10. IndexerConnector Warnings

### Observation

Manager logs reported IndexerConnector initialization failures for multiple `wazuh-states-*` indices, including vulnerability and inventory-related indices.

### Explanation

These were operational warnings associated with the Manager-to-Indexer integration.

The supplied evidence also showed that Syscheck started real-time monitoring and generated the two local FIM alerts.

### Resolution Status

**Separate issue; not resolved in this lab.**

No Indexer configuration or authentication changes were made as part of the SUID/SGID investigation.

**Lesson:** Keep Indexer connectivity issues separate from FIM detection results. One should not automatically be treated as the cause of the other.

---

## 11. Existing Custom Ticket Integration Connection Refused

### Observation

The Manager log recorded:

```text
Unable to run integration for custom-ticket
Connection refused
```

The errors were recorded at:

- 2026-11-03 07:42:14
- 2026-11-03 08:02:53

### Explanation

The existing custom ticket integration from Lab 124 attempted to contact its configured local receiver, but the connection was refused.

This was separate from the FIM monitoring configuration and detection rule.

### Resolution Status

**Unresolved in this lab.**

The mock ticket receiver was not repaired or restarted as part of Lab 126.

**Lesson:** Residual integrations from previous labs can generate background errors. Document them separately rather than attributing unrelated failures to the current detection workflow.

---

## 12. Cleanup and FIM Deletion Events

### Cleanup Commands

The test files were removed:

```bash
sudo rm -f /var/tmp/lab126/suid-test
sudo rm -f /var/tmp/lab126/sgid-test
sudo rmdir /var/tmp/lab126
```

The final directory check returned:

```text
ls: cannot access '/var/tmp/lab126': No such file or directory
```

### Interpretation

The test artifacts were removed successfully.

The available evidence did not include separate FIM alert records for these deletions. Therefore, deletion detection is not claimed as a validated result.

**Lesson:** Validate cleanup independently and do not claim that a cleanup operation generated an alert unless the corresponding event is available.

---

