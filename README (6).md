# 🔍 IR Investigation Lab

A hands-on incident response investigation project analyzing a real-world meterpreter LSASS credential dumping attack using Sysmon event logs. This project simulates the workflow of a Tier 1 SOC analyst investigating a confirmed malicious credential theft incident.

---

## 📌 Project Overview

**Analyst:** Young Li Vui  
**Date:** June 2026  
**Project Type:** Cybersecurity Home Lab — Incident Response  
**Focus Areas:** Digital Forensics, Incident Response, Threat Hunting, MITRE ATT&CK

---

## 🎯 Objective

Investigate a real attack dataset (EVTX logs) from scratch — reconstruct the full attack timeline, identify malicious techniques, map to MITRE ATT&CK, and produce a professional incident response report.

---

## 🧰 Tools & Technologies

| Tool | Purpose |
|------|---------|
| Windows Event Viewer | EVTX log analysis |
| Sysmon | Telemetry source (Event ID 8, 10) |
| MITRE ATT&CK Navigator | Technique mapping |
| EVTX-ATTACK-SAMPLES (GitHub) | Real-world attack dataset |

---

## 🚨 Incident Summary

| Field | Value |
|---|---|
| **Report ID** | IR-2026-002 |
| **Severity** | Critical |
| **Host** | IEWIN7 |
| **Attack Type** | Fileless Meterpreter LSASS Credential Dump |
| **Techniques** | T1055 — Process Injection, T1003.001 — LSASS Memory |
| **Total Events** | 9 Sysmon events (2× Event ID 8, 7× Event ID 10) |
| **Outcome** | Confirmed Malicious — Full credential extraction |

---

## 🔬 What Was Investigated

A suspicious executable (`voice_mail.msg.exe`) launched from a network share (`\\VBOXSVR\HTools\`) injected shellcode threads into `lsass.exe` using `CreateRemoteThread`, then accessed lsass memory with `GrantedAccess: 0x1f1fff` (PROCESS_ALL_ACCESS) to extract all cached credentials — consistent with Meterpreter's `hashdump` module.

The attack was **fully fileless** — all malicious code ran from unmapped memory, invisible to traditional antivirus.

---

## 🗺️ MITRE ATT&CK Techniques Identified

| Tactic | Technique | ID |
|---|---|---|
| Execution | Malicious File | T1204.002 |
| Defense Evasion | Process Injection | T1055 |
| Defense Evasion | Reflective Code Loading | T1620 |
| Credential Access | LSASS Memory | T1003.001 |

---

## 📁 Repository Contents

| File | Description |
|------|-------------|
| `IR-2026-002-Meterpreter-LSASS-Hashdump.md` | Full incident response report |
| `screenshots/` | Evidence screenshots from investigation |

---

## 🔄 Investigation Workflow

```text
Downloaded real attack EVTX dataset (EVTX-ATTACK-SAMPLES)
    ↓
Opened in Windows Event Viewer
    ↓
Identified 9 Sysmon events (Event ID 8 + 10)
    ↓
Extracted forensic fields — SourceImage, GrantedAccess, CallTrace
    ↓
Reconstructed attack timeline
    ↓
Mapped techniques to MITRE ATT&CK
    ↓
Wrote professional IR report with IOCs and recommendations
```

---

## 🧠 Key Findings

- `GrantedAccess: 0x1f1fff` = PROCESS_ALL_ACCESS on lsass — unambiguously malicious
- Six consecutive `UNKNOWN` module calls in CallTrace = fileless shellcode execution
- Double thread injection (TID 1744 + TID 3656) = attacker redundancy, mature threat actor
- All 9 events in same millisecond = fully automated Meterpreter framework, not manual

---

## 💼 Skills Demonstrated

`Incident Response` `Digital Forensics` `Sysmon Analysis` `MITRE ATT&CK` `Threat Hunting` `Log Analysis` `IOC Identification` `Malware Behavior Analysis` `IR Report Writing` `Credential Dumping Detection`

---

## 🔗 Related Project

This project complements my [Elastic SIEM Home Lab](https://github.com/yduduu/elastic-siem-home-lab) — together they cover the full SOC analyst workflow:

| Project | Focus |
|---|---|
| Elastic SIEM Home Lab | Detection Engineering, Alert Triage |
| IR Investigation Lab (this) | Forensic Investigation, Incident Response |

---

## 📚 References

- https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES
- https://attack.mitre.org/techniques/T1003/001/
- https://attack.mitre.org/techniques/T1055/
- https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon
