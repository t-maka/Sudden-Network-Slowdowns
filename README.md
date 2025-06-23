# 🕵️**Sudden-Network-Slowdowns**

## Scenario: 
The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

## 🧭 Timeline Summary and Findings

### 🔍 Observation

`labwill-vm-mde` made multiple failed connection attempts to both **itself** and another host on the same network.

```kusto
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| summarize ConnectionCount = count() by DeviceName, ActionType, LocalIP, RemoteIP
| order by ConnectionCount
```

![Connection requests against host](https://github.com/user-attachments/assets/eadc2133-8ba1-49ec-bacb-b750f7470ee7)


---
### 🚩 Port Scanning Detected
After reviewing the failed connection attempts from the suspected host (10.0.0.84) in chronological order, I identified a port scan in progress, indicated by the sequential pattern of the targeted ports. There were several port scans being conducted :

```kusto
let IPInQuestion = "10.0.0.184";
DeviceNetworkEvents
| where ActionType == "ConnectionFailed"
| where LocalIP == IPInQuestion
| order by Timestamp desc

```

---
### 🧪 Suspicious Script Execution
We pivoted to DeviceProcessEvents and observed a suspicious script execution:

- Script Name: portscan.ps1
- Execution Time: 2025-06-23T13:50:56.8200509Z

```kusto
let VMName = "labwill-vm-mde";
let specificTime = datetime(2025-06-23T13:52:23.8067297Z);
DeviceProcessEvents
| where Timestamp between ((specificTime - 10m) .. (specificTime + 10m))
| where DeviceName == VMName
| order by Timestamp desc
| project Timestamp, FileName, InitiatingProcessCommandLine
```


---

### 🖥️ Local Inspection
🔎 Upon accessing the device, the PowerShell script used for scanning was located in the local filesystem.
![portscan prog](https://github.com/user-attachments/assets/fed3763a-bdc8-45f9-a5b1-76038548b712)

---

### 👤 User Attribution & Response
- User Account Involved: labusertest
- Account Status: Not part of an admin-approved setup

---

### ✅ Actions Taken:

- Isolated the device
- Performed a full malware scan (no detections found)
- Submitted a request for reimage/rebuild

---

### 🧰 MITRE ATT&CK Framework Mapping
|  | **Tactic**                   | **Technique Name**                          | **Technique ID** |
| ------------------------------------- | ---------------------------- | ------------------------------------------- | ---------------- |
| 🕵️‍♂️                                | Discovery                    | Network Service Scanning                    | T1046            |
| 🛠️                                   | Execution                    | Command & Scripting Interpreter: PowerShell | T1059.001        |
| ⏰ *(optional)*                        | Execution                    | Scheduled Task/Job                          | T1053            |
| 🧑‍💼                                 | Initial Access / Persistence | Valid Accounts                              | T1078            |
| 🎭 *(optional)*                       | Defense Evasion              | Masquerading                                | T1036            |

---

📝 Note: This investigation highlights the importance of monitoring outbound connection failures and script executions, which can help in early detection of lateral movement or reconnaissance within a network.

---

## Created By:
- **Author Name**: Tinan Makadjibeye  
- **Author Contact**: [LinkedIn profile](https://www.linkedin.com/in/makadjibeye-tinan)  
- **Date**: June 2025
  
---
