# Windows Security Engineering & Threat Detection Lab

## Overview

This project is a hands-on Windows security engineering and threat detection lab designed to simulate how an endpoint can be securely configured, monitored, tested, and investigated within a controlled environment.

The lab combines defensive security engineering with security monitoring. Rather than focusing only on detecting suspicious activity, the project also examines how security controls such as host firewalls, account privileges, endpoint protection, network segmentation, logging, and telemetry can be configured to reduce attack surface and improve visibility.

The environment integrates Windows security auditing, Sysmon endpoint telemetry, Splunk Universal Forwarder, and Splunk Enterprise to support controlled security testing, detection development, and evidence-based investigation.

## Project Objectives

The main objectives of this lab are to:

- Establish a secure and recoverable Windows lab environment.
- Apply and validate Windows security controls using least-privilege principles.
- Configure controlled communication between authorized lab systems.
- Establish endpoint telemetry using Windows logs and Sysmon.
- Forward relevant security events to Splunk for centralized analysis.
- Generate controlled and non-destructive security events.
- Develop and validate detections based on observed telemetry.
- Investigate activity using repeatable security-analysis methods.
- Document security decisions, configuration changes, findings, and evidence.

## Lab Environment

The environment is hosted in **Oracle VirtualBox** and currently consists of three virtual machines.

| System | Primary Role | Network Configuration |
|---|---|---|
| Windows 11 Enterprise Evaluation | Protected and monitored Windows endpoint | NAT + Host-only |
| Kali Linux | Authorized security-testing workstation | Host-only |
| Ubuntu Server | Supporting Linux/server system | Host-only |

### Network Design

The lab uses a **VirtualBox host-only network** for communication between the virtual machines. This keeps lab traffic separated from the wider network while allowing the systems to communicate directly.

The Windows VM also has a **NAT adapter**. This provides outbound Internet access when required for activities such as Windows updates and downloading trusted security tools, without directly exposing the Windows VM to inbound Internet connections.

Current host-only addressing:

| System | IPv4 Address |
|---|---|
| Kali Linux | `192.168.56.101` |
| Ubuntu Server | `192.168.56.102` |
| Windows 11 | `192.168.56.104` |

Windows NAT address:

`10.0.2.15`

> **Note:** The host-only addresses are currently assigned dynamically and may change. Network-dependent security controls are therefore verified whenever addressing changes.

## Security Approach

The lab follows a defensive, least-privilege approach. Services and network access are not broadly enabled simply to make testing easier. Access is introduced only when required, restricted to the systems that need it, and validated before additional functionality is added.

For example, ICMP Echo Requests to the Windows endpoint were permitted only from the Kali testing system rather than enabling unrestricted inbound ICMP access across the entire lab network.

Security protections such as Microsoft Defender Antivirus, Windows Defender Firewall, and User Account Control remain enabled unless a specific controlled test requires a documented configuration change.

## Windows Security Baseline

Before introducing additional monitoring tools or generating controlled security events, the Windows endpoint was reviewed to establish its initial security posture.

The purpose of this baseline is to confirm that important defensive controls are enabled and to provide a reference point for later configuration changes and testing.

### Windows Defender Firewall

Windows Defender Firewall was enabled across the available firewall profiles.

Rather than broadly enabling inbound ICMP traffic, a custom inbound rule was created for controlled connectivity testing.

The rule permits:

- Protocol: ICMPv4
- ICMP type: Echo Request
- Source: Kali Linux (`192.168.56.101`)
- Destination: Windows host-only interface (`192.168.56.104`)
- Firewall profile: Public
- Action: Allow

The rule was intentionally scoped to the Kali testing system rather than allowing ICMP Echo Requests from every device on the host-only network.

Connectivity testing confirmed that Kali could successfully receive ping replies from the Windows endpoint, while the Ubuntu Server did not receive replies under the current configuration.

This result was treated as an observed behavior rather than definitive proof of firewall enforcement until supporting network-layer checks were performed.

### Microsoft Defender Antivirus

Microsoft Defender Antivirus was verified using PowerShell.

The baseline confirmed that:

- Antivirus protection was enabled.
- Real-time protection was enabled.
- Antivirus signatures had been updated.

Defender protections were left enabled to preserve a realistic defensive environment throughout the lab.

### Account Privileges and UAC

The Windows lab account is a member of the local Administrators group.

However, testing with `whoami /groups` showed that the normal PowerShell session was running with a **Medium Mandatory Integrity Level**, and the Administrators group was marked as **deny-only** within the non-elevated session.

This demonstrates Windows User Account Control (UAC) behavior: membership in the Administrators group does not automatically grant every process elevated administrative privileges.

Administrative elevation must be explicitly approved when required.

### User Account Control

UAC was verified through the Windows User Account Control settings interface.

The system was configured at the Windows default notification level:

> Notify only when apps try to make changes to the computer.

The setting was retained rather than weakened for convenience.

### Patch Management

Windows Update status was reviewed as part of the baseline.

During the initial baseline assessment, Windows updates were paused. Updates were subsequently resumed, available updates were installed, and Windows Update later reported the system as up to date. This confirmed an improved patch-management baseline before controlled security testing. Update status should be reviewed periodically because new security patches may become available.

Security testing in this project will not rely on intentionally leaving the operating system unpatched unless a future test specifically requires a documented and isolated vulnerable configuration.

### Baseline Evidence

- `10_project5_icmp_firewall_rule_created.png` — Scoped Windows Firewall ICMP rule
- `11_kali_to_windows_ping_after_ip_and_firewall_fix.png` — Successful Kali-to-Windows connectivity test
- `12_ubuntu_to_windows_ping_no_reply.png` — Ubuntu-to-Windows connectivity observation
- `13_windows_defender_antivirus_baseline.png` — Microsoft Defender baseline
- `14_windows_account_non_elevated_baseline.png` — Windows account privilege baseline
- `15_windows_uac_default_baseline.png` — UAC configuration
- `16_windows_update_paused_baseline.png` — Initial Windows Update status


## Implementation and Detection Results

### Windows Security Monitoring

The Windows 11 endpoint was configured with native process creation auditing, command-line logging, and PowerShell Script Block Logging.

Sysmon provided additional visibility into process execution, network connections, file creation, registry modifications, and DNS activity.

The Splunk Universal Forwarder transmitted Windows Security, Sysmon Operational, and PowerShell Operational logs to Splunk Enterprise for centralized analysis.

### Validated Security Investigations

**1. PowerShell ExecutionPolicy Bypass**

A controlled PowerShell command using `-ExecutionPolicy Bypass` was detected through Sysmon Event ID 1.

The investigation captured the executable, command line, parent process, user, and integrity level.

[View Detection SPL](splunk_queries/powershell_executionpolicy_bypass_detection.spl)

**2. Windows Run-Key Modification**

Sysmon Event ID 13 recorded a controlled registry modification involving a Windows Run-key location.

The reusable SPL search identifies PowerShell modifications to monitored Run-key paths. Such activity requires context because legitimate software may also modify these locations.

[View Detection SPL](splunk_queries/powershell_run_key_persistence_detection.spl)

**3. DNS Query Investigation**

Sysmon Event ID 22 recorded a controlled DNS lookup, which was successfully indexed in Splunk.

The investigation extracted the queried domain and DNS response information. Process attribution was unavailable for the specific event because its Image field reported an unknown process.

[View Investigation SPL](splunk_queries/sysmon_dns_query_investigation.spl)

### Key Outcomes

The project demonstrated endpoint security configuration, centralized telemetry collection, controlled detection validation, and evidence-based security investigation.

The tests established specific detection capabilities in an isolated lab, not comprehensive production detection coverage.

### Project Documentation

- [Technical Report](reports/technical_report.md)
- [Detection Validation Summary](notes/detection_validation_summary.md)
