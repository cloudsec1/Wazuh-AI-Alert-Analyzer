Wazuh AI Alert Analyzer (AbuseIPDB + ChatGPT)
Hybrid SOC Automation Pipeline for IP Reputation & AI-Driven Alert Summaries
📌 Overview

This project integrates AbuseIPDB and ChatGPT into the Wazuh SIEM to build a fully automated SOC enrichment pipeline.

✔ Key Features

AbuseIPDB IP reputation checks for all high-severity alerts

Custom rule (100015) to detect positive reputation hits

State-aware Python AI analyzer

ChatGPT-powered alert summary + recommendations

Automated email notifications

Cron-based scheduled execution

This workflow reduces triage time, enriches alerts with intelligence, and provides SOC teams with actionable guidance.

1️⃣ Add Custom Rule in Wazuh (Rule 100015)

Create or edit:

/var/ossec/etc/rules/local_rules.xml

<group name="local,abuseipdb,enrichment,">
  <rule id="100015" level="15">
    <decoded_as>json</decoded_as>

    <!-- Ensure this came from the AbuseIPDB integration -->
    <field name="integration">^custom-abuseipdb$</field>

    <!-- Match only if AbuseIPDB score is NOT zero -->
    <field name="abuseipdb.abuse_confidence_score" negate="yes">^0$</field>

    <description>
      AbuseIPDB positive: $(abuseipdb.source.srcip) — score $(abuseipdb.abuse_confidence_score)%
    </description>

    <options>alert_by_email</options>
    <group>abuseipdb_positive,</group>
  </rule>
</group>

🔎 What this does:

Matches alerts enriched by AbuseIPDB

Ensures the IP has a positive score (>0)

Triggers advanced AI-based analysis

2️⃣ Add AbuseIPDB Integration in ossec.conf

Edit:

/var/ossec/etc/ossec.conf

<integration>
  <name>custom-abuseipdb.py</name>
  <hook_url>https://api.abuseipdb.com/api/v2/check</hook_url>
  <api_key>yourkey</api_key>
  <alert_format>json</alert_format>
  <level>15</level>
</integration>

Purpose:

Runs for ANY alert with level ≥ 15

Sends alert JSON to the integration script

Performs real-time IP reputation lookup

Integration Script:

🔗 https://github.com/cloudsec1/Wazuh-AI-Alert-Analyzer

3️⃣ Create State File for AI Analyzer

Prevents reprocessing or duplicate emails.

echo "0.0" | sudo tee /var/ossec/etc/ai_analyzer_state.txt
sudo chown root:wazuh /var/ossec/etc/ai_analyzer_state.txt
sudo chmod 660 /var/ossec/etc/ai_analyzer_state.txt

Benefits:

Tracks last processed alert ID

Ensures each alert is processed once

Avoids duplication in email notifications

Reduces API query costs

4️⃣ AI Analyzer Script

Create:

/opt/wazuh-ai-analyzer/analyzer.py

Full script available here:
🔗 https://github.com/cloudsec1/Wazuh-AI-Alert-Analyzer/blob/main/AI_Analyser_Wazuh_git.py

Script Responsibilities:

Parse /var/ossec/logs/alerts/alerts.json (JSON Lines format)

Extract newly generated alerts

Identify rule 100015

Parse AbuseIPDB results

Generate AI summary via ChatGPT API

Email the SOC team

Update state file

Core Logic:

get_last_processed_id()

update_last_processed_id()

parse_alert_data()

Main loop:

Skip if alert ID <= last processed

Process only rule.id == 100015

Send enriched alert to ChatGPT

Send email report

5️⃣ Run Analyzer via Cron (Every 5 Minutes)

Edit root crontab:

*/5 * * * * /usr/bin/python3 /opt/wazuh-ai-analyzer/analyzer.py >> /var/log/wazuh_ai_cron.log 2>&1

Why cron?

Reliable

Lightweight

Avoids active-response execution issues

Ensures consistent SOC workflow

6️⃣ Full Workflow Illustration
Wazuh Alert (level ≥ 15)
          ↓
AbuseIPDB Integration (custom-abuseipdb.py)
          ↓
Abuse score > 0?
          ↓ YES
Custom Rule 100015 triggers
          ↓
Alert written to alerts.json
          ↓
AI Analyzer (state-aware)
          ↓
ChatGPT API (summary + actions)
          ↓
Email sent to SOC team

7️⃣ Requirements
Packages:

Python 3

Wazuh Manager

Requests / JSON libraries

OpenAI / ChatGPT API key

AbuseIPDB API key

System:

Linux server

Cron service

Outbound internet for API calls

8️⃣ File Structure
/opt/wazuh-ai-analyzer/
│── analyzer.py
│── config.json (optional)
│── README.md

/var/ossec/etc/
│── ai_analyzer_state.txt
│── ossec.conf
│── rules/local_rules.xml

9️⃣ Credits

Special acknowledgment to SocFortress for their work on the AbuseIPDB integration pattern.
This project expands on their concepts by adding:

Custom Wazuh rule logic

State-aware alert processor

Full ChatGPT analysis pipeline

Email reporting

Cron execution engine

🔟 License

MIT License — free to use, modify, and distribute.
