![Malware_Glossary_1](https://github.com/user-attachments/assets/0e6c1361-e475-4710-8bf2-b53981090472)
<p>Credit : https://sosafe-awareness.com</p>

# 🚨 Malicious File/Script Download Attempt – Threat Investigation Using Let’s Defend SIEM

### Purpose of Analysis

This investigation was conducted in response to a SIEM alert triggered by a **Malicious File/Script Download Attempt**. The primary goal was to analyze the suspicious activity, confirm its malicious nature, assess the impact on the organization, and provide remediation steps based on standard SOC playbooks.

---

### 🔍 Alert Overview

* **Event ID:** 76
* **Event Time:** March 14, 2021, 07:15 PM
* **Rule:** SOC137 – Malicious File/Script Download Attempt
* **Level:** Security Analyst
* **Source Address:** 172.16.17.37
* **Source Hostname:** NicolasPRD
* **File Name:** `INVOICE PACKAGE LINK TO DOWNLOAD.docm`
* **File Hash:** `f2d0c66b801244c059f636d08a474079`
* **File Size:** 16.66 KB
* **Device Action:** Blocked
* **File (Password: infected):** Download

---

### ⚠️ What Triggered This Alert?

The alert was generated when a `.docm` file—**commonly used to deliver malicious macros**—was downloaded from an untrusted source. Endpoint security flagged the file as suspicious and blocked the download attempt. The filename and behavior were consistent with phishing campaigns designed to trick users into enabling macros to execute malicious code.

---

### 🧪 Step 1: Initial Triage

Curious about the file’s threat level, I began by submitting the hash to **VirusTotal**.
Reanalysis showed that **40 out of 65 vendors flagged it as malicious**, confirming our suspicion.

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/f398a8e4-12a5-4d19-983d-0c47c960740f"/>

➡️ **Summary**: This file was highly likely part of a phishing campaign using embedded macros to execute a payload.

---

### 🛠️ Step 2: Containment Verification

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/1c466b17-8311-4bd6-9272-cb3a954404dd"/>

Following the SOC playbook, the first action was to verify if the malware had been quarantined:

* ✅ Accessed **Endpoint Security Dashboard**
* 🔍 Located host **NicolasPRD** via IP `172.16.17.37`
* ❌ Device was **not contained**

<img width="931" alt="image" src="https://github.com/user-attachments/assets/967ebcc7-aefe-4956-bc39-d0c838783112"/>

Checked terminal history: All commands predated the alert timestamp — no suspicious post-event activity was observed.

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/dbaf3163-9434-498f-98bd-156c66f4d1f3"/>

---

### 📚 Step 3: Log Correlation

Searched logs for activity from the source IP:

* No unusual behavior or connections linked to the alert time.
* User actions appeared routine and occurred before the flagged incident.

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/b25d1f2c-2cf3-4d44-be11-74cf0e310f44"/>

---

### 🧬 Step 4: Malware Behavior Analysis

Analyzed the file hash again in **VirusTotal**, focusing on behavioral insights: 

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/8da71d5f-3b0e-41db-a3f3-4ff8e187a0ff"/>
<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/a4de99ec-b39b-4512-8a99-be80642b79f0"/>

#### Key Observations:

* **Document uses VBA Macro (AutoOpen)** to run malicious code
* Macro executes obfuscated **PowerShell commands** to download payloads
* Connects to remote host: `188.114.97.0:443` (associated with `filetransfer.io`)
* Exhibits **Living-Off-The-Land Binaries (LOLBins)** behavior
* Tactics observed include:

  * T1059 (Command and Scripting Interpreter)
  * T1106 (Native API Execution)

#### Contacted C2 Domains/IPs:

Also, in Virustotal’s relations tab you can access contacted IP addresses and domains, these are flagged as malicious 

* `lati10.ddns.net`
* `178.175.67.109`
* `188.114.96.0`
* `188.114.97.0`
  
<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/92c8f63e-9e68-4b31-a6b4-57e41960cfff"/>

It is certain that this file can be indeed considered as **Malicious**.

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/ab8dd7f5-3274-438d-86ce-b23b4190646c"/>

---

### 🔎 Step 5: Endpoint Contact Check

To determine if the C2 infrastructure was contacted, I searched the logs for connections to flagged domains and IPs.

✅ **No endpoint communications with the C2 addresses** were found — a positive outcome. 

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/6ed87c92-397f-480b-8026-166f94bab425"/>

I double-checked the user's logs to ensure no contact was made with the malicious IP address and that no contact occurred during and after the time of the incident.

<img width="931" alt="image" style="display: block; margin: 0 auto;" src="https://github.com/user-attachments/assets/2ea28877-a8e5-42f1-9c23-eb2542103425"/>

---

### ✅ Step 6: Final Review

Since:

* The file was blocked,
* The device didn’t execute it,
* No outbound C2 communication occurred,

➡️ We concluded there was **no breach or compromise**.

---

### 🗂️ Indicators of Compromise (IOCs) – Why They Matter

Recording **IOCs** (such as hashes, IPs, and domains) is crucial for:

* Enhancing detection rules
* Threat intelligence enrichment
* Historical correlation in future investigations

**Malicious File Hash:**
`08d4fd5032b8b24072bdff43932630d4200f68404d7e12ffeeda2364c8158873`

---

### 💬 Analyst Comments

> *“The malicious document used a macro to attempt a PowerShell payload download. Fortunately, the file was blocked before execution, and there is no evidence of network or endpoint compromise. No further action required beyond ongoing vigilance.”*

---

### 🔚 Conclusion

This investigation was an excellent exercise in threat detection, validation, and incident triage. It reaffirmed the importance of:

* **Early detection and blocking**
* **Endpoint visibility**
* **Timely analyst intervention**

Although the file was indeed **malicious**, **no damage was done**, thanks to proactive alerting and security controls. The case was closed as a **True Positive (TP)**, with **no further remediation required**.
