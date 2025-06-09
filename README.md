# Threat Hunting & MITRE ATT&CK Mapping  
## An Analysis of Cyber Incidents in Australian Universities  
**By Luekrit Kongkamon**  
*Academic Project | Cybersecurity Analysis | MITRE ATT&CK | Incident Response*

---

## Tools & Frameworks Used

- **MITRE ATT&CK Framework**  
- **Threat Intelligence Analysis**  
- **CVE Research (PrintNightmare)**  
- **SIEM & XDR Concepts**  
- **Zero Trust (NIST & Microsoft)**  
- **Cloud Access Security Broker (CASB)**  

---

## Understanding Adversary Behaviour with MITRE ATT&CK

In cybersecurity, understanding how adversaries operate is crucial for effective defence. The MITRE ATT&CK® (Adversarial Tactics, Techniques, and Common Knowledge) framework can analyse recent cyber incidents affecting Australian universities.

MITRE ATT&CK is a globally recognized, living knowledge base that documents and categorizes the tactics, techniques, and procedures (TTPs) used by adversaries during cyberattacks. Developed and maintained by the MITRE Corporation, it provides a comprehensive framework for understanding how attackers achieve their objectives within a target environment.
<h3> Key elements of MITRE ATT&CK include: </h3>

- **Tactics** (why): High-level goals like Initial Access or Impact  
- **Techniques** (how): Actions like Phishing or Command Execution  
- **Sub-techniques**: Detailed variants of techniques  
- **Procedures**: Real-world examples of how attackers apply techniques  

In this project, I applied the MITRE ATT&CK framework to investigate 3 high-profile cyber incidents affecting Australian universities.

---

## Incident 1: ANU – Ransomware Attack by FSociety (2025)

### Summary:
In February 2025, **Australian National University (ANU)** was attacked by the **FSociety ransomware group**, which demanded payment or else sensitive research and personal data would be leaked.

### Attack Flow:
- **Initial Access**: Spear phishing (🛠️ T1566.001)  
- **Execution**: PowerShell commands (🛠️ T1059.001)  
- **Privilege Escalation**: Local privilege abuse  
- **Lateral Movement**: Remote Desktop Protocol (🛠️ T1021.001)  
- **Exfiltration**: Over HTTPS channels (🛠️ T1041)  
- **Impact**: File encryption (🛠️ T1486)  

### Impact:
- Widespread campus-wide file encryption  
- Downtime in learning/research systems  
- Reputational damage  
- Full extent of data exposure undisclosed  

### Recommendations:
- Email filtering and phishing awareness  
- Disable/monitor PowerShell  
- Deploy EDR and network segmentation  
- Adopt Zero Trust access controls

---

## Incident 2: WSU – Credential Abuse & Long-Term Exfiltration (2023–2025)

### Summary:
**Western Sydney University (WSU)** experienced a **two-year breach** through its **Single Sign-On (SSO)** system. Attackers used **valid credentials** to extract over **580TB** of data without detection.

### Attack Flow:
- **Initial Access**: Stolen or reused credentials (🛠️ T1078)  
- **Discovery**: Cloud resource enumeration (🛠️ T1619)  
- **Exfiltration**: Cloud storage transfers (🛠️ T1537, T1567)  

### Impact:
- 580TB of student/staff data leaked  
- Data posted on the dark web  
- Over 10,000 individuals affected  

### Root Causes:
- Weak MFA policies  
- No alerting on login anomalies  
- Lack of CASB monitoring  

### Recommendations:
- Enforce MFA on all systems  
- Deploy CASB tools  
- Monitor SSO login behavior and session reuse  
- Conduct periodic identity audits

---

## Incident 3: QUT – Ransomware via PrintNightmare (2022)

### Summary:
In December 2022, **Queensland University of Technology (QUT)** was hit by ransomware that exploited the **PrintNightmare vulnerability (CVE-2021-34527)**.

### Attack Flow:
- **Initial Access**: Exploiting vulnerable Print Spooler (🛠️ T1190)  
- **Lateral Movement**: SMB shares (🛠️ T1021.002)  
- **Impact**: Ransom notes printed across campus; files encrypted (🛠️ T1486)

### Impact:
- Over 11,000 users affected  
- Services and systems disrupted  
- Public trust damaged  

### Recommendations:
- Patch management policy for critical CVEs  
- Disable legacy services like Print Spooler  
- Segment networks and isolate high-value assets

---

## Lessons Learned

| University | Key Lesson |
|---------------|------------|
| ANU | Early phishing detection, endpoint defense, PowerShell control |
| WSU | Stronger IAM and anomaly detection in cloud |  
| QUT | Patch known vulnerabilities, remove legacy systems |

---

## Recommendations for University Security Teams

-  **Zero Trust Architecture**: Never trust, always verify  
-  **MFA Everywhere**: Across cloud, SSO, VPN, admin accounts  
-  **SIEM/XDR Integration**: Real-time detection and alerting  
-  **Patch Management**: Automate high-severity CVE updates  
-  **Red Team Exercises**: Test detection and incident response  
-  **Identity Access Reviews**: Remove excessive privileges  
-  **Cybersecurity Awareness Training**: For students and staff  
-  **CASB Monitoring**: Watch cloud behavior and exfiltration  

---

