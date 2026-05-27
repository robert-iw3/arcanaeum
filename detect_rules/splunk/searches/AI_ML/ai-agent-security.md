### AI Agent Security Report
---

This report details the emerging threats to AI agents, focusing on prompt injection, indirect prompt injection, and the "Universal Antipattern" where untrusted input leads to malicious actions. It highlights how these vulnerabilities can be exploited for remote code execution and data exfiltration, emphasizing the need for robust security measures in AI-powered applications.

Recent research underscores that AI agents are highly susceptible to hijacking attacks, with major AI platforms like OpenAI's ChatGPT, Microsoft Copilot, and Google's Gemini demonstrating vulnerabilities to prompt injection and data exfiltration, often with little to no user interaction. This highlights a critical evolution in the threat landscape, as attackers can now manipulate AI agents to act as insider threats or to spread misinformation, leveraging the agent's autonomy and access to tools.

### Actionable Threat Data
---

Monitor for unusual or unexpected external network connections initiated by AI agents or LLM-powered applications, as this could indicate an attempt at data exfiltration or command and control (C2) activity resulting from prompt injection or tool misuse.

Implement robust input validation and sanitization for all data fed into LLMs and AI agents, especially from untrusted sources, to prevent direct and indirect prompt injection attacks. This includes scrutinizing data retrieved from external sources like web pages or databases that the agent might process.

Establish strict access controls and the principle of least privilege for AI agents and their associated tools, ensuring that agents only have the necessary permissions to perform their intended functions and cannot access or manipulate sensitive data or systems beyond their scope.

Log and monitor all actions taken by AI agents, particularly those involving external tool execution, file system modifications, or API calls, to detect anomalous behavior that could signify a successful prompt injection or malicious manipulation.

Develop and enforce policies for the use of AI-generated code and AI coding assistants, including mandatory human review and security scanning of all AI-generated code before deployment, given the high rate of vulnerabilities found in such code.

### Search
---
```sql
-- Name: Comprehensive AI Agent and IDE Threat Detection
-- Author: RW
-- Date: 2025-08-15
-- Description: This is a consolidated Splunk rule designed to detect a range of threats against AI Agents and Agentic IDEs, based on the 'From Prompts to Pwns' presentation. It combines multiple detection patterns including prompt injection (direct and indirect), AI-driven RCE, tool misuse, OSS watering hole attacks, and unauthorized IDE actions into a single query.
-- False Positive Sensitivity: Medium. This is a broad rule and will likely require tuning for your specific environment. Review the 'FP Tuning' comments within each section.
-- Tactics: Initial Access, Execution, Collection, Discovery, Exfiltration
-- Techniques: T1059, T1190, T1195.001, T1005, T1082, T1567

-- Data Sources: This rule requires logs from AI agent applications (prompts, responses, tool usage), and endpoint data like Sysmon (Process Create, File Create). Define macros for your specific indexes and sourcetypes.
-- Example Macro Definitions in macros.conf:
-- [define_ai_agent_sourcetypes]
-- definition = (sourcetype=ai_agent_logs OR sourcetype=ai_agent_tool_logs OR sourcetype=ai_agent_code_logs)
-- [define_endpoint_sourcetypes]
-- definition = ((sourcetype=xmlwineventlog:microsoft-windows-sysmon/operational) OR (sourcetype=linux:audit))

(index=* `define_ai_agent_sourcetypes_macro` OR `define_endpoint_sourcetypes_macro`)

-- Combine multiple detection logics into a single 'detection_method' field.
| eval detection_method=case(

    -- Detection 1: Direct Prompt Injection - Looks for keywords in user prompts to an AI agent.
    -- FP Tuning: Developers testing security may trigger this. Exclude known test accounts or specific benign prompts.
    (sourcetype="ai_agent_logs" AND (match(prompt, "(?i)ignore.*(previous|above).*instructions") OR match(prompt, "(?i)disregard.*instructions") OR match(prompt, "(?i)repeat.*(previous|your).*instructions") OR match(prompt, "(?i)reveal.*prompt") OR match(prompt, "(?i)</system prompt>"))), "Direct Prompt Injection",

    -- Detection 2: Indirect Prompt Injection - Looks for injection keywords in data retrieved by the agent (RAG).
    -- FP Tuning: Legitimate documents might contain these phrases. Exclude trusted data source URLs.
    (sourcetype="ai_agent_logs" AND isnotnull(retrieved_data) AND (match(retrieved_data, "(?i)ignore.*(previous|above).*instructions") OR match(retrieved_data, "(?i)run the following")) AND NOT (match(prompt, "(?i)ignore.*(previous|above).*instructions"))), "Indirect Prompt Injection",

    -- Detection 3: AI Agent RCE - Looks for suspicious code patterns generated/executed by an agent, like in CVE-2024-12366.
    -- FP Tuning: Some data science scripts might use these patterns. Exclude trusted applications or vetted scripts.
    (sourcetype="ai_agent_code_logs" AND (match(executed_code, "(?i)os\.system\(") OR match(executed_code, "(?i)subprocess\.run\(")) AND match(executed_code, "(?i)base64\.b64decode\(")), "AI Agent RCE via Code Generation",

    -- Detection 4: AI Agent Tool Misuse - Detects when an agent uses tools for discovery, sensitive file access, or exfil.
    -- FP Tuning: A DevOps agent might legitimately run discovery commands. Create allowlists for specific app/tool/param combinations.
    (sourcetype="ai_agent_tool_logs" AND (
        (tool_name IN ("cat", "type", "Get-Content") AND (match(tool_params, "/etc/passwd") OR match(tool_params, "\.ssh/id_rsa") OR match(tool_params, "secrets.txt"))) OR
        (tool_name IN ("bash", "powershell.exe", "cmd.exe") AND (match(tool_params, "whoami") OR match(tool_params, "hostname") OR match(tool_params, "net user"))) OR
        (tool_name IN ("curl", "wget") AND (match(tool_params, "-d\s") OR match(tool_params, "-X\s+POST")))
    )), "AI Agent Tool Misuse",

    -- Detection 5: OSS Watering Hole - Detects suspicious package installs or PowerShell download cradles.
    -- FP Tuning: Developers may install packages from git. Exclude known-good repositories or internal scripts.
    ((`define_endpoint_sourcetypes_macro`) AND (EventCode=1 OR event_id=1) AND (
        (process_name IN ("powershell.exe", "pwsh.exe") AND (match(process_command_line, "(?i)Invoke-Expression") OR match(process_command_line, "(?i)DownloadString"))) OR
        (process_name IN ("pip.exe", "uv.exe") AND match(process_command_line, "install\s+(git|http)") AND NOT match(process_command_line, "-r\s|--requirement")) OR
        (parent_process_name="python.exe" AND process_name="powershell.exe" AND match(process_command_line, "(?i)DownloadString"))
    )), "OSS Watering Hole Attack",

    -- Detection 6: Agentic IDE Execution - Detects suspicious processes spawned from IDEs or creation of malicious config files.
    -- FP Tuning: Developer extensions might run shell commands. Exclude known-good scripts or command lines.
    ((`define_endpoint_sourcetypes_macro`) AND (
        ((EventCode=1 OR event_id=1) AND parent_process_name IN ("cursor.exe", "Code.exe") AND process_name IN ("powershell.exe", "cmd.exe", "bash", "curl", "wget") AND (match(process_command_line, "(?i)Invoke-Expression") OR match(process_command_line, "whoami") OR match(process_command_line, "net user") OR match(process_command_line, "/etc/passwd"))) OR
        ((EventCode=11 OR event_id=11) AND file_name="*.cursorrules")
    )), "Agentic IDE Unauthorized Code Execution"
)

-- Filter for events that matched one of the detection logics.
| where isnotnull(detection_method)

-- Normalize fields from different sourcetypes into a common information model (CIM) like structure.
| eval user=coalesce(user, User, UserPrincipalName, AccountName),
       dest=coalesce(dest, host, DeviceName, dvc),
       parent_process=coalesce(parent_process, parent_process_name, ParentImage, InitiatingProcessFileName),
       process=coalesce(process, process_name, Image, FileName),
       command_line=coalesce(process_command_line, CommandLine, prompt, tool_name + " " + tool_params, executed_code, "File created: " + file_name),
       data_source=coalesce(data_source_url, retrieved_data)

-- Provide a human-readable description for the alert.
| eval description=case(
    detection_method="Direct Prompt Injection", "User '" + user + "' submitted a prompt with potential injection keywords.",
    detection_method="Indirect Prompt Injection", "AI Agent processed retrieved data containing potential injection keywords. Data Source: " + data_source,
    detection_method="AI Agent RCE via Code Generation", "AI Agent executed code with suspicious RCE patterns.",
    detection_method="AI Agent Tool Misuse", "AI Agent misused a tool. Details: " + command_line,
    detection_method="OSS Watering Hole Attack", "Suspicious process execution pattern related to OSS watering hole attack.",
    detection_method="Agentic IDE Unauthorized Code Execution", "Suspicious activity from Agentic IDE '" + parent_process + "'.",
    1=1, "No description available"
)

-- Select and rename fields for the final alert output.
| table _time, dest, user, parent_process, process, command_line, detection_method, description, sourcetype
| rename dest as "Endpoint", user as "User", parent_process as "Parent Process", process as "Process", command_line as "Command Line", detection_method as "Detection Method", description as "Description", sourcetype as "Source Type"
```