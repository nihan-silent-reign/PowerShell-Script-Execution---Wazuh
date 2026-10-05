# PowerShell-Script-Execution---Wazuh
Investigation -- PowerShell Script Execution


SOC Investigation #11 — PowerShell Script Execution

Overview

Investigated a Wazuh alert triggered by PowerShell executing a .ps1 script from a user-accessible location.

The investigation was performed in a controlled Windows 11 SOC lab using Wazuh + Sysmon.

Detection

* SIEM: Wazuh
* Endpoint: Windows 11
* Telemetry: Sysmon
* Event: Process Creation (Event ID 1)
* Process: powershell.exe
* Script: soc-test.ps1
* Detection: PowerShell execution with ExecutionPolicy Bypass

Lab Activity

A benign PowerShell script was intentionally created and executed to generate a realistic SOC detection.

Example command:

powershell.exe -ExecutionPolicy Bypass -File "C:\Users\Nihan\Desktop\soc-test.ps1"

The script contained only non-malicious commands used for SOC testing.

Investigation

1. Process Analysis

Reviewed the process creation event and examined:

* Process name
* Parent process
* User account
* Command line
* Script path
* Timestamp

2. Command-Line Analysis

The use of:

-ExecutionPolicy Bypass

was treated as a suspicious indicator because attackers may use it to bypass PowerShell execution-policy restrictions.

However, this indicator alone does not establish that the activity is malicious.

3. Script Analysis

The script contents were reviewed:

Write-Host "SOC Lab Test Script"
Get-Process

No malicious payload, persistence mechanism, credential access, download activity, or destructive command was identified.

Investigation Outcome

Classification: Benign / Authorized Lab Activity

The alert was intentionally generated as part of a controlled SOC detection exercise.

Although the command line contained a potentially suspicious PowerShell execution technique, the script itself was verified to contain benign commands.

MITRE ATT&CK: T1059.001 — PowerShell
MITRE TACTIC: Execution
RULE ID : 92029
RULE LEVEL: 6
PARENT PROESS ID: 6984


  

SOC Analyst Takeaway

This investigation demonstrates why a SOC analyst should not classify an alert as malicious based on a single indicator.

The analyst should correlate:

Alert → Command Line → Parent Process → User → Script → Process Activity → Context

before determining whether the activity is malicious or legitimate.

Skills Demonstrated

* Wazuh alert analysis
* Windows process analysis
* PowerShell investigation
* Command-line analysis
* False-positive/benign activity classification
* MITRE ATT&CK mapping
* SOC incident documentation
