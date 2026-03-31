---
name: report_format
description: 规定了攻击溯源智能体输出最终调查报告时的标准格式、排版要求以及进程树的绘制规范。
---

When generating your forensic report, you MUST strictly include the following sections:

#### **INCIDENT OVERVIEW**
A concise summary (2-3 sentences) of the incident, including the attack type, the compromised asset, and the impact.

#### **ATTACK ARTIFACTS & SOURCE**
List all key indicators of compromise (IOCs) and attack source details identified.
- **Compromised Host**: (Agent ID/Name)
- **Initial Vector**: (e.g., Phishing, Drive-by download, Exploit)
- **Malicious Files/Payloads**: (List suspicious files with full paths)
- **Compromised/Tainted Processes**: (List processes hijacked or spawned by attackers)
- **Network Indicators**: (List Attacker IPs, Domains, Ports involved in C2 or exfiltration)

#### **PROCESS EXECUTION TREE**
Based on the individual logs you retrieved, manually construct and visualize the attack chain. You MUST adhere to the **CORE INVESTIGATION PRINCIPLE**: accurately trace the specific malicious execution path while aggressively filtering out unrelated system noise, benign background services, and irrelevant sibling processes.

**Process Tree Visualization Rules**:
- When presenting a process tree, you MUST format each process node on EXACTLY ONE LINE. Each node's line MUST explicitly display the following three elements ONLY:
  1. **Process Name**
  2. **PID**
  3. **Timestamp** (Must be strictly formatted as **Beijing Time / UTC+8**).
     - **NO PLACEHOLDERS ALLOWED**: You MUST extract and write the actual numerical time value (e.g., `2020-09-04 15:30:54.541`). NEVER output descriptive text, brackets, or placeholders. You MUST look back at your retrieved context and insert the real value.
     - **CRITICAL TIMEZONE RULE**: Check the raw log carefully before calculating. If the timestamp string already contains `+0800`, it is ALREADY in Beijing Time—**YOU MUST USE IT AS-IS AND DO NOT ADD 8 HOURS**. Only add 8 hours mathematically if you are converting a raw UTC field (e.g., a time ending in `Z` or the `utcTime` field).
- **CRITICAL FILTERING RULE**:
  - **No Orphan Merging**: You MUST NOT attach a process to this tree if it does not share a strict `ParentProcessGuid` or `ParentProcessId` link with another node in the tree. Do not hallucinate links based purely on keyword search results.
  - **Evaluate Sibling Processes**: If a parent process spawns multiple child branches, critically evaluate their relevance. INCLUDE suspicious or anomalous siblings that occur around the time of the attack (e.g., multiple discovery commands spawned by a single script). EXCLUDE clearly benign, unrelated background noise (e.g., normal OS background tasks). Focus the visualization on all branches that contribute to the malicious narrative.
  - **Isolate Specific Execution Chains**: If multiple attacks or executions of the same payload are found (e.g., recurring scheduled tasks), focus ONLY on the specific execution instance (timeframe or PID) explicitly requested by the user. If the user does not specify a target, default to the most recent one. Do NOT mix processes from different historical executions into a single tree.
  - **Hide Unknown Roots**: If the root node of the tree is "Unknown" or has a missing PID/Timestamp, DO NOT display it. Start the visualization from the first identified valid process in the chain.
  - **Time Consistency Check**: Ensure that the timestamp of a child process is NOT earlier than its parent process. If you find such a case (e.g., Parent @ 18:55, Child @ 18:16), it indicates a logical error or PID reuse. You MUST flag this anomaly or exclude the inconsistent parent node to maintain a valid timeline.

Example format:
```
└── PID 404 (explorer.exe) @ 2026-03-05 09:00:00.000
    └── PID 1234 (cmd.exe) @ 2026-03-05 10:00:00.123
        ├── PID 5678 (whoami.exe) @ 2026-03-05 10:00:01.456
        └── PID 5680 (payload.exe) @ 2026-03-05 10:00:01.500
```

WRONG FORMAT (Every single process node MUST be represented on EXACTLY ONE continuous line.):
```
└── PID 7624 (cmd.exe) @ 2026-03-25 17:13:36.360
    └── Command: "C:\Windows\System32\cmd.exe" /c script.bat
        ├── PID 3244 (cmd.exe) @ 2026-03-25 17:13:52.939
        │   └── 命令: dir /b /a-d .\test-sets\"discovery"\*.bat
```

#### **ATTACK TIMELINE & EXECUTION FLOW**
Chronological sequence mapping events to MITRE ATT&CK tactical phases based on the process tree's command line evidence.
Example:
- **[2026-03-05 10:00:01.456]** - **[Execution / T1059.001]**: `powershell.exe` spawned with hidden window style and base64 encoded command.
- **[2026-03-05 10:00:01.500]** - **[Command and Control / T1105]**: Payload initiated an `Invoke-WebRequest` to a suspicious external IP.

#### **SUMMARY & TAKEAWAYS**
A comprehensive concluding summary of the findings, lateral movement evidence, and actionable next steps.
- **Tools Used**: Legitimate tools abused (e.g., mshta.exe, powershell.exe) vs malicious payloads.
- **Network Behavior**: Communication with internal/external IPs, suspicious domains, and C2 setup indicators.
- **Lateral Movement/Exfiltration**: Evidence (or lack thereof) of lateral movement, USB usage, or data exfiltration.
- **User Activity**: Analysis of user behavior (e.g., browsing history, file execution) leading up to the incident.
- **Key Takeaways & Recommendations**: Actionable next steps for remediation and hardening.