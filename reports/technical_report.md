# Windows Security Engineering & Threat Detection Lab
## Technical Report

### 1. Executive Summary

This project implemented a controlled Windows security engineering and threat detection laboratory using Oracle VirtualBox, Windows 11 Enterprise Evaluation, Kali Linux, Ubuntu Server, Sysmon, and Splunk.

The lab combined endpoint security configuration, Windows event auditing, centralized telemetry collection, controlled security testing, and behavior-based detection development.

Three investigation scenarios were validated:
- PowerShell execution with the ExecutionPolicy Bypass argument.
- PowerShell modification of a Windows Run-key registry location.
- DNS query activity captured through Sysmon Event ID 22.

The testing demonstrated successful telemetry collection and analysis while also identifying limitations in event attribution and potential false-positive conditions.

### 2. Lab Architecture

The virtual environment consisted of:

- Windows 11 Enterprise Evaluation: monitored endpoint.
- Kali Linux: authorized security-testing workstation.
- Ubuntu Server: supporting Linux system.
- Splunk Enterprise: centralized security event analysis.
- Splunk Universal Forwarder: Windows event forwarding.
- Sysmon: detailed Windows endpoint telemetry.

The VirtualBox host-only network provided communication between lab systems.

Host-only IP addresses observed:
- Kali Linux: 192.168.56.101
- Ubuntu Server: 192.168.56.102
- Windows 11: 192.168.56.104

Windows also used a NAT adapter for outbound connectivity.

### 3. Windows Security Baseline

The baseline included Windows Defender Firewall, Microsoft Defender Antivirus, User Account Control, Windows Update, process creation auditing, and PowerShell logging.

Security protections were retained during controlled testing rather than broadly disabled for convenience.

A scoped firewall rule permitted ICMPv4 Echo Requests from the Kali testing system to the Windows host-only interface.

### 4. Telemetry Collection and Forwarding

Windows security auditing was configured to collect process creation events (Event ID 4688), including command-line information.

PowerShell Script Block Logging was enabled and verified using Event ID 4104.

Sysmon was configured to collect selected process, network, file, registry, and DNS activity.

The Splunk Universal Forwarder successfully forwarded Windows security telemetry to Splunk for investigation.

### 5. Detection Validation

#### 5.1 PowerShell ExecutionPolicy Bypass Detection

A controlled PowerShell process was launched using the -ExecutionPolicy Bypass argument and a harmless Write-Output command.

Before the test, the detection search returned no matching events. After the test, Sysmon Event ID 1 recorded the process execution, and Splunk returned the expected event.

The investigation included the process image, command line, parent process, user account, and integrity level.

Result: The behavior-based SPL detection successfully identified the controlled PowerShell execution.

Limitation: ExecutionPolicy Bypass is not inherently malicious. Legitimate administrative activities may use this argument.

#### 5.2 PowerShell Run-Key Modification Detection

A controlled registry modification was performed to test visibility into Windows Run-key activity.

Sysmon Event ID 13 captured the registry value modification, and the event was successfully investigated in Splunk.

The detection was generalized to identify PowerShell processes modifying monitored Run-key locations without relying on the unique test marker.

Result: The detection identified a potentially persistence-related registry modification.

Limitation: Registry Run-key changes can also result from legitimate software installation and configuration.

#### 5.3 DNS Query Investigation

A controlled DNS lookup was generated for:

kalifa-dns-test-20261006.example.com

Sysmon Event ID 22 recorded the DNS query, and Splunk successfully indexed the event.

The investigation extracted the query name and DNS response information.

However, the Image field was reported as <unknown process> for the observed event.

Result: DNS telemetry was successfully collected and forwarded to Splunk.

Limitation: Complete originating-process attribution was unavailable for this specific event. The DNS query alone does not establish malicious activity.

### 6. Findings and Limitations

#### 6.1 Verified Findings

The following findings were supported by controlled testing and Splunk investigation:

1. Windows security controls, including Microsoft Defender Antivirus, Windows Defender Firewall, and User Account Control, were reviewed and retained during testing.

2. Windows Security Event ID 4688 and Sysmon Event ID 1 recorded process creation activity, providing complementary visibility into process execution.

3. The Splunk Universal Forwarder established a connection to the Splunk receiver at 192.168.56.1:9997. Windows Security, Sysmon Operational, and PowerShell Operational events were subsequently confirmed in Splunk.

4. PowerShell execution with the -ExecutionPolicy Bypass argument was identified using a behavior-based SPL search.

5. Sysmon Event ID 13 captured a controlled Windows Run-key modification, supporting investigation of potentially persistence-related registry activity.

6. Sysmon Event ID 22 recorded a controlled DNS query, demonstrating visibility into DNS activity.

#### 6.2 Limitations and Investigation Considerations

- ExecutionPolicy Bypass is not inherently malicious. Legitimate scripts and administrative tools may use it.

- Windows Run-key modifications can be performed by legitimate applications. Registry events require investigation of the responsible process, target value, and surrounding activity.

- The controlled DNS event reported the originating Image as an unknown process. The DNS query was confirmed, but attribution to a specific executable was not established.

- Some Windows events were forwarded in XML format and required SPL field extraction to produce structured investigation tables.

- Splunk search time ranges affected event visibility. Historical events could appear under All time even when narrower searches returned no results.

- The validated SPL searches demonstrated detection capability against the observed test activity. Production alert tuning, false-positive evaluation, and automated incident response were not established by these tests.

#### 6.3 Security Engineering Lessons

The lab demonstrated the importance of maintaining defensive controls while enabling security monitoring.

Endpoint telemetry must be validated at multiple stages: event generation, local collection, forwarding, indexing, and investigation.

Security findings should be supported by observable evidence rather than assuming that suspicious-looking activity is malicious.

The combination of Windows security configuration, Sysmon telemetry, and Splunk analysis provided a practical foundation for further detection engineering.

### 7. Evidence and Supporting Files

#### 7.1 Evidence Screenshots

The following screenshots provide supporting evidence for the implementation and detection validation:

| Evidence | Screenshot |
|---|---|
| Sysmon custom configuration verified | [Screenshot 35](../screenshots/35_sysmon_active_custom_configuration_verified.png) |
| Splunk forwarding connection established | [Screenshot 59](../screenshots/59_splunk_forwarder_connection_to_indexer_established.png) |
| PowerShell Event ID 4104 successfully forwarded | [Screenshot 65](../screenshots/65_powershell_event_4104_successfully_forwarded_to_splunk.png) |
| ExecutionPolicy Bypass detection validated | [Screenshot 72](../screenshots/72_powershell_executionpolicy_bypass_detection_validated.png) |
| PowerShell process context investigated | [Screenshot 73](../screenshots/73_powershell_bypass_detection_with_process_context.png) |
| Controlled registry modification investigated | [Screenshot 74](../screenshots/74_controlled_run_key_registry_event_extracted_in_splunk.png) |
| Run-key persistence detection validated | [Screenshot 75](../screenshots/75_powershell_run_key_persistence_detection_validated.png) |
| Controlled DNS query verified | [Screenshot 76](../screenshots/76_controlled_dns_query_sysmon_event22_verified_in_splunk.png) |

#### 7.2 Reusable SPL Queries

- [PowerShell ExecutionPolicy Bypass Detection](../splunk_queries/powershell_executionpolicy_bypass_detection.spl)
- [PowerShell Run-Key Persistence Detection](../splunk_queries/powershell_run_key_persistence_detection.spl)
- [Sysmon DNS Query Investigation](../splunk_queries/sysmon_dns_query_investigation.spl)

#### 7.3 Supporting Documentation

The project includes a Sysmon XML configuration file, Windows security baseline evidence, and a separate [Detection Validation Summary](../notes/detection_validation_summary.md).

Screenshots document observed behavior. The saved SPL searches support reproduction of the investigations, subject to the availability of corresponding telemetry and event formats.

### 8. Conclusion

The Windows Security Engineering & Threat Detection Lab demonstrated the implementation of a controlled Windows endpoint security and monitoring environment.

The project combined defensive security configuration, Windows audit policies, Sysmon telemetry, and centralized log collection through Splunk Universal Forwarder and Splunk Enterprise.

Three security investigation scenarios were successfully validated:

1. Detection of PowerShell execution using the ExecutionPolicy Bypass argument.
2. Identification of PowerShell modifications to Windows Run-key registry locations.
3. Investigation of DNS query activity using Sysmon Event ID 22.

The investigations demonstrated how endpoint telemetry can support the identification and analysis of potentially suspicious behavior.

The project also highlighted important limitations, including incomplete process attribution in a DNS event, the need for contextual analysis, and the possibility of false positives.

These tests validated specific detection and investigation capabilities in an isolated lab. They did not establish production-level detection coverage or automated incident response.

Overall, the project strengthened practical experience in Windows security engineering, endpoint monitoring, Splunk SIEM operations, detection development, troubleshooting, and evidence-based security investigation.

The completed lab provides a foundation for more advanced security engineering and cloud security projects.




