# Sudden-Network-Slowdowns

Scenario: The server team has noticed a significant network performance degradation on some of their older devices attached to the network in the 10.0.0.0/16 network. After ruling out external DDoS attacks, the security team suspects something might be going on internally.

---

# 🕵️ Incident Investigation: Port Scanning Activity detected


## 🧭 Timeline Summary and Findings

### 🔍 Observation

`labwill-vm-mde` made multiple failed connection attempts to both **itself** and another host on the same network.

![Failed connection attempts](https://github.com/user-attachments/assets/d4ef59f6-6171-4985-bff4-bfa0477ad8b1)

![Connection requests against host](https://github.com/user-attachments/assets/eadc2133-8ba1-49ec-bacb-b750f7470ee7)


---
### 🚩 Port Scanning Detected
After reviewing the failed connection attempts from the suspected host (10.0.0.84) in chronological order, I identified a port scan in progress, indicated by the sequential pattern of the targeted ports. There were several port scans being conducted :

![port scanning detected](https://github.com/user-attachments/assets/32f40fcd-98ca-4e08-aae5-9d281e493f80)

---
### 🧪 Suspicious Script Execution
We pivoted to DeviceProcessEvents and observed a suspicious script execution:

- Script Name: portscan.ps1
- Execution Time: 2025-06-23T13:50:56.8200509Z

![suspicious script detected](https://github.com/user-attachments/assets/995c31c0-4562-4c05-a124-2c7a4711d209)

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

### 📌 Key Takeaways
- PowerShell continues to be a common vector for reconnaissance activity.
- Failed outbound connections can reveal internal threats early.
- User behavior monitoring is essential for detecting misuse of legitimate credentials.

---

