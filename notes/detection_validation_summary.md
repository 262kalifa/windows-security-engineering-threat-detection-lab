# Detection Validation Summary

## 1. PowerShell ExecutionPolicy Bypass

A controlled PowerShell process was launched with the `-ExecutionPolicy Bypass` argument and a harmless `Write-Output` command.

The initial Splunk search returned no matching events before the test. After the controlled activity was generated, Sysmon Event ID 1 recorded the process and the detection returned the expected event.

Observed context included the process image, complete command line, parent process, user account, and integrity level.

Finding: The behavior-based SPL detection successfully identified PowerShell launched with `-ExecutionPolicy Bypass`.

Note: This argument is not inherently malicious and requires contextual investigation.

## 2. PowerShell Run-Key Modification

Existing Sysmon Event ID 13 telemetry showed legitimate software such as Microsoft Edge modifying Windows Run-key locations.

A controlled Run-key test was also present in the telemetry. The event showed PowerShell modifying:

Software\Microsoft\Windows\CurrentVersion\Run\SysmonLabTest\Marker

The behavior-based detection was then generalized to identify PowerShell modifying a `CurrentVersion\Run` location without relying on the unique test marker.

Finding: Sysmon and Splunk successfully identified a potentially persistence-related registry modification performed by PowerShell.

Note: Run-key modifications can also be legitimate and should not automatically be classified as malicious.

## 3. DNS Query Investigation

A controlled DNS lookup was generated for:

kalifa-dns-test-20261006.example.com

Sysmon Event ID 22 recorded the query and Splunk successfully indexed it.

The event contained the expected query name and DNS response information. However, the Image field was reported as `<unknown process>`.

Finding: DNS telemetry was successfully collected and forwarded, but complete originating-process attribution was unavailable for this specific event.

## Overall Result

The lab successfully demonstrated:

- Windows endpoint telemetry collection with Sysmon
- forwarding of security telemetry through Splunk Universal Forwarder
- behavioral SPL detection
- controlled detection validation
- field extraction for analyst investigation
- identification of telemetry limitations and potential false positives
