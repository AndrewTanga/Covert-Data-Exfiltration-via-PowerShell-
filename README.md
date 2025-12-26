# Threat Hunting Case Study – Covert Data Exfiltration via PowerShell & 7Zip

## Overview

This lab documents a full end-to-end threat hunting investigation performed using **Microsoft Defender for Endpoint (MDE)** telemetry. The goal was to identify suspicious file activity, correlate it with process execution and network behavior, and determine whether the observed activity represented benign administrative behavior or covert data exfiltration.

The investigation uncovered **silent installation and abuse of 7-Zip via PowerShell**, automated data archiving masquerading as backup activity, and outbound network communication consistent with stealthy exfiltration.

This case study demonstrates practical threat-hunting methodology, pivot logic, and investigative reasoning rather than signature-based alert review.

---

## Environment

* **Endpoint:** Windows VM (`winandre`)
* **Telemetry Source:** Microsoft Defender for Endpoint
* **Tables Used:**

  * `DeviceFileEvents`
  * `DeviceProcessEvents`
  * `DeviceNetworkEvents`

---

## Investigation Methodology

The investigation followed a structured hunting flow:

```
File Artifact → Timestamp Pivot → Process Execution → Network Activity → Adversary Intent
```

Rather than starting from alerts, the hunt began with **low-level artifacts** and built context outward.

---

## Step 1 – File Activity: ZIP Archive Creation

Initial hunting focused on archive creation activity, a common precursor to data staging and exfiltration.

```kql
DeviceFileEvents
| where DeviceName == "winandre"
| where FileName endswith ".zip"
| order by Timestamp desc
```
![1](https://github.com/user-attachments/assets/50205e9d-6120-4f73-9260-5b09d6e21980)

### Findings

* Repeated ZIP archive creation observed
* Files staged in locations resembling backup directories
* Activity appeared regular and automated, blending into expected administrative noise

This warranted deeper inspection.

---

## Step 2 – Process Correlation Around Archive Creation

A specific ZIP creation timestamp was selected and used as a pivot point to inspect process activity immediately before and after the event.

```kql
let VMName = "winandre";
let specificTime = datetime(2025-12-26T00:40:18.419395Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 2m) .. (specificTime + 2m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine
```
![2](https://github.com/user-attachments/assets/a975f21d-e30e-430f-933e-4a4b1af0a20f)

### Findings

* Silent execution of `7z2408-x64.exe /S`
* PowerShell executed with `ExecutionPolicy Bypass`
* 7-Zip used to archive employee data automatically
* Command execution chain consistent with scripted, non-interactive behavior

This confirmed **living-off-the-land style abuse** using legitimate tooling.

---

## Step 3 – Behavioral Detection via Regex (Advanced)

To generalize detection beyond static filenames, a regex-based approach was used to identify silent archive utility execution variants.

```kql
| where ProcessCommandLine matches regex @"(?i)(7z|7za|7zr).*?\s(/S|/silent|/quiet|/qn)"
```

### Why Regex Matters

* Captures multiple binary variants and execution patterns
* Detects attacker tradecraft evolution
* Reduces reliance on brittle string matching

This reflects **detection engineering thinking**, not ad-hoc searching.

---

## Step 4 – Network Activity & Exfiltration Analysis

The same timestamp pivot was used to inspect outbound network activity.

```kql
let VMName = "winandre";
let specificTime = datetime(2025-12-26T00:40:18.419395Z);
DeviceNetworkEvents
| where Timestamp between ((specificTime - 5m) .. (specificTime + 5m))
| where DeviceName == VMName
| order by Timestamp desc
```
![3](https://github.com/user-attachments/assets/b67508af-9b09-417c-928f-9ece1e81bfbb)

### Findings

* Consistent outbound HTTPS traffic during archive creation
* Data transmission aligned temporally with ZIP staging
* Activity blended into normal HTTPS traffic patterns

This strongly suggests **covert exfiltration over common web protocols**.

---

## Timeline Summary

1. PowerShell executed silently with execution policy bypass
2. 7-Zip installed without user interaction
3. Employee data collected locally
4. Data archived repeatedly to appear as routine backups
5. Archives staged and transmitted externally
6. Activity designed to blend into normal administrative behavior

The operation was **intentional, automated, and covert**.

---

## MITRE ATT&CK Mapping

### Execution

* **TA0002** – Execution
* **T1059.001** – Command and Scripting Interpreter: PowerShell

### Collection

* **TA0009** – Collection
* **T1005** – Data from Local System
* **T1560.001** – Archive Collected Data: Archive via Utility

### Exfiltration

* **TA0010** – Exfiltration
* **T1041** – Exfiltration Over C2 Channel
* **T1567** – Exfiltration Over Web Service

> Note: Persistence and indicator removal were not conclusively observed and are intentionally excluded to maintain evidentiary integrity.

---

## False Positive Considerations

Legitimate administrative backup activity typically:

* Uses pre-installed backup agents
* Runs under known service accounts
* Follows predictable schedules
* Does not involve ad-hoc installation of compression utilities via PowerShell

The observed behavior deviates from these norms.

---

## Response Recommendations

* Isolate affected endpoint
* Collect and analyze PowerShell scripts
* Validate outbound destinations against business requirements
* Hunt for similar activity across environment
* Assess scope of data exposure

---

## Skills Demonstrated

* Threat hunting methodology
* Cross-table telemetry correlation
* Temporal analysis
* Living-off-the-Land detection
* Regex-based behavioral detection
* MITRE ATT&CK mapping
* SOC-ready investigative reporting

---

## Disclaimer

This lab was conducted in a controlled environment for educational and skill-development purposes. No real employee data was exposed.

---

**Author:** Andrei



