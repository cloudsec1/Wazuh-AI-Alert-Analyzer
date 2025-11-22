# Wazuh-AI-Alert-Analyzer
Building an AI-Enhanced Alert Processing Pipeline in Wazuh Using AbuseIPDB &amp; ChatGPT
Wazuh AI Alert Analyzer (AbuseIPDB + ChatGPT)

This project adds automated alert enrichment to Wazuh using:

✔ AbuseIPDB IP reputation checks

✔ State-aware alert tracking

✔ ChatGPT API for threat interpretation

✔ Email notifications

✔ Cron-based scheduling

📌 Features
🔍 AbuseIPDB Enrichment

Every alert’s source IP is scanned using AbuseIPDB.
If the score is below the threshold (<0), the alert is passed for AI analysis.

🤖 AI Threat Analysis

Uses ChatGPT API to generate:

Alert summary

Possible threat intent

Risk level

Recommended next steps

🗂️ State Tracking

Each alert is processed only once, using:

/var/ossec/etc/ai_analyzer_state.txt

📧 Email Alerts

AI-enriched results are sent to the SOC team via SMTP.

🕒 Cron-Based Scheduling

Runs automatically every 5 minutes.

 Wazuh Integration

Add this block to /var/ossec/etc/ossec.conf:

<integration>
    <name>custom-abuseipdb</name>
    <command>abuseipdb.py</command>
    <run_on_start>false</run_on_start>
    <alert_format>json</alert_format>
</integration>

📁 Files in This Repository
File	Purpose
abuseipdb.py	IP reputation lookup & enrichment
analyzer.py	AI alert analysis + email summary
README.md	Documentation
🛠 Setup Instructions

Clone repo

Add to /opt/wazuh-ai-analyzer/

Update API keys in config section

Add integration block to Wazuh

Add cron entry:

*/5 * * * * /usr/bin/python3 /opt/wazuh-ai-analyzer/analyzer.py >> /var/log/wazuh_ai_cron.log 2>&1

📣 Contributions

Feel free to open issues or submit PRs.

📜 License

MIT
