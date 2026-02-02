# 🛡️ Digital Forensics & Threat Analysis Project

## 📌 Project Overview
This project is a **comprehensive Digital Forensics and Cybersecurity investigation** that simulates real-world forensic workflows used to analyze **suspicious files, malicious artifacts, and post-exploitation activity**.

The project combines **metadata forensics**, **malware intelligence analysis**, and **reverse-shell behavior investigation** to demonstrate how attackers operate and how defenders can detect and mitigate such threats.

All analysis was conducted in a **controlled, isolated lab environment** for academic and learning purposes.

---

## 🎯 Project Objectives
- Identify tampering and manipulation in digital files
- Analyze malware behavior using threat intelligence platforms
- Observe reverse-shell attack techniques
- Correlate host-based and network-based forensic evidence
- Understand detection and prevention strategies

---

## 🧩 Project Architecture
```
Digital-Forensics-Threat-Analysis/
├── exiftool-analysis/        # Image metadata & file integrity investigation
├── villain-reverse-shell/    # Reverse shell attack & detection analysis
├── virustotal-scan/          # Malware intelligence & behavior analysis
└── README.md
```

Each module represents a **phase of a real forensic investigation pipeline**.

---

## 🔍 Module 1: Image Metadata & File Integrity Analysis
**Folder:** `exiftool-analysis`

### Problem Statement
A suspicious image file was provided with inconsistent properties.  
The goal was to determine whether the file was original or had been altered.

### Approach
- File signature (magic bytes) verification
- EXIF metadata extraction
- Timestamp and software inspection
- Hex-level and string analysis

### Key Findings
- File extension mismatch (`.png` filename with **JPEG JFIF header**)
- Editing software identified: **GIMP 2.10.24**
- Camera and GPS metadata removed
- Original timestamps missing
- File determined to be **edited and re-exported**, not original

### Outcome
Successfully identified **metadata tampering and file renaming**, a common anti-forensics technique.

---

## 🧪 Module 2: Reverse Shell Attack & Detection Analysis
**Folder:** `villain-reverse-shell`

### Problem Statement
Analyze how a reverse shell establishes communication and how such activity can be detected by defenders.

### Lab Environment
- Attacker: Kali Linux (Villain Framework)
- Victim: Windows 10 Pro
- Network: Host-Only VirtualBox network
- Payload: PowerShell reverse TCP

### Analysis Performed
- Process execution monitoring (Sysmon)
- Network traffic inspection (Wireshark)
- Host enumeration command analysis
- Parent-child process relationship tracking

### Key Observations
- Reverse shell initiated outbound connection, bypassing inbound firewall rules
- PowerShell abused as a Living-off-the-Land Binary (LOLBin)
- Clear correlation between process execution and network events

### Outcome
Demonstrated how **post-exploitation activity** appears in host and network logs and how it can be detected.

---

## 🧬 Module 3: Malware Intelligence & Behavior Analysis
**Folder:** `virustotal-scan`

### Problem Statement
Analyze a suspicious document-based malware sample using open-source threat intelligence.

### Analysis Highlights
- Multi-engine antivirus detection via VirusTotal
- Malicious behaviors identified:
  - PowerShell-based Defender exclusions
  - Process injection
  - Registry-based persistence
  - SMTP-based data exfiltration
  - Anti-analysis and anti-debugging techniques

### Indicators of Compromise (IOCs)
- Malicious domains and IP addresses
- Registry modification patterns
- Dropped payload files

### Outcome
Confirmed the sample as **malicious**, with behavior consistent with modern document-delivered malware.

---

## 🛠️ Tools & Technologies Used
- ExifTool
- VirusTotal
- Sysmon
- Wireshark
- PowerShell
- Kali Linux
- Windows 10 (Virtual Machines)

---

## ⚠️ Ethical & Safety Considerations
- All experiments performed in isolated VMs
- No production systems involved
- No live malware deployment
- Educational and academic use only

---

## 📈 Key Learnings
- Metadata manipulation is a common anti-forensics technique
- Reverse shells rely on outbound connections to evade firewalls
- Malware often combines multiple evasion and persistence techniques
- Effective detection requires **host + network correlation**

---

## 👤 Author
**Christy Dsouza**  
B.Tech CSE (AI & ML)  
Christ University, Bangalore  

---

## 📜 License
This project is intended for **educational and academic purposes only**.
