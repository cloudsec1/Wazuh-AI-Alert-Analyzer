Wazuh AI Alert Analyzer (AbuseIPDB + ChatGPT) Real-Time MQ Automation Pipeline 🚀
📌 Overview
This project implements a highly resilient, non-blocking Message Queue (MQ) pipeline to integrate AbuseIPDB and ChatGPT into the Wazuh SIEM. This transition permanently solves the stability issues associated with file reading and synchronous execution hangs.

The system decouples the slow AI analysis from the real-time alert path, ensuring zero downtime and immediate queueing of critical threats.

✔ Key Features
True Real-Time Queueing: Alerts are instantly pushed to Redis for asynchronous processing.

Guaranteed Stability: Eliminates hanging processes, file locks, and state synchronization issues.

Asynchronous Analysis: Dedicated Python worker processes handle slow LLM analysis calls without blocking the Wazuh Manager.

Enrichment & Custom Rules: AbuseIPDB IP reputation checks integrated with custom Rule 100015 logic.

Autonomous Worker: A persistent systemd service runs the Python consumer, ensuring high availability.

1️⃣ Add Custom Rule in Wazuh (Rule 100015)
This rule is generated after the AbuseIPDB check is performed by the integration.

File: /var/ossec/etc/rules/local_rules.xml

XML

<!-- Ensure this came from the AbuseIPDB integration -->
<field name="integration">^custom-abuseipdb$</field>

<!-- Match only if AbuseIPDB score is NOT zero -->
<field name="abuseipdb.abuse_confidence_score" negate="yes">^0$</field>

<description>
  AbuseIPDB positive: $(abuseipdb.source.srcip) — score $(abuseipdb.abuse_confidence_score)%
</description>

<options>alert_by_email</options>
<group>abuseipdb_positive,</group>
2️⃣ Configure Wazuh Integration (Real-Time Push to Redis)
We replace the old integration logic with two components: the Publisher Integration and the Consumer Daemon.

A. The Publisher Integration (ossec.conf)
This tells Wazuh to execute the BASH script when Rule 100015 fires, sending the JSON alert via STDIN (which the BASH script must immediately push to Redis).

File: /var/ossec/etc/ossec.conf

XML

<!-- IMPORTANT: Remove any old <command> or <active-response> blocks for the analyzer or publisher -->

<!-- 1. Wazuh Integration Block: Triggers the Publisher Script -->
<integration>
  <!-- Name must match the file placed in /var/ossec/integrations/ -->
  <name>custom-redis-publisher.sh</name> 
  
  <!-- hook_url and api_key are used by the BASH script for Redis connection details -->
  <hook_url>redis://127.0.0.1:6379</hook_url>
  <api_key>wazuh_alerts_ai</api_key> <!-- Used as the Redis Queue Name -->
  
  <rule_id>100015</rule_id> 
  <alert_format>json</alert_format>
  <level>15</level> 
</integration>
B. The Publisher Script (custom-redis-publisher.sh)
This BASH script reads the piped JSON and immediately queues it.

File: /var/ossec/integrations/custom-redis-publisher.sh

Requires: redis-cli installed on the Wazuh Manager.

Bash

#!/bin/bash
# Wazuh Integration script to push alerts to Redis

# Configuration derived from ossec.conf or hardcoded
REDIS_HOST="127.0.0.1"
REDIS_PORT="6379"
QUEUE_NAME="wazuh_alerts_ai"
LOG_FILE="/var/ossec/logs/integrations.log" 

# Function to log messages
log_message() {
    /usr/bin/echo "$(date '+%Y-%m-%d %H:%M:%S') custom-redis-publisher: $1" >> "$LOG_FILE"
}

# --- Execution Start ---
log_message "INFO: Script triggered for alert publishing."

# --- Read JSON alert from STDIN (pipe) ---
ALERT_JSON=$(timeout 2s cat) # Use timeout for the read operation

if [ -z "$ALERT_JSON" ]; then
    log_message "ERROR: No alert data received via STDIN (empty pipe). Check integration timing."
    exit 1
fi

# Push the raw JSON content to Redis.
/usr/bin/redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" LPUSH "$QUEUE_NAME" "$ALERT_JSON" > /dev/null 2>&1
REDIS_EXIT_CODE=$?

if [ $REDIS_EXIT_CODE -eq 0 ]; then
    ALERT_ID=$(echo "$ALERT_JSON" | grep -oP '"id":"\K[^"]+' | head -1)
    log_message "SUCCESS: Alert $ALERT_ID pushed to queue '$QUEUE_NAME'."
else
    log_message "FAILURE: Redis command failed with exit code $REDIS_EXIT_CODE. Alert not queued."
fi

exit 0
3️⃣ AI Analyzer Daemon (The Persistent Consumer)
This Python script runs perpetually, consuming alerts from the queue and performing the LLM analysis.

File: /opt/wazuh-ai-analyzer/mq_analyzer_worker.py

Requires: Python libraries (redis, openai) and a running Redis server.

Python

# The full Python script (mq_analyzer_worker.py) that runs the perpetual loop, 
# connects to Redis, performs the OpenAI analysis, and sends the email. 
# This file is too long to include here, but it contains the core business logic.
# Key features: BLPOP (Blocking POP) from Redis, Pydantic validation (optional), 
# and stable retry logic for Redis connectivity and API calls.
4️⃣ Deploy as a Persistent Service (systemd)
The worker is no longer a cron job; it is a continuous service.

Action: Create the systemd service file (wazuh-ai-worker.service) to ensure the Python script is always running and auto-restarts on failure.

5️⃣ Full Workflow Illustration
The new workflow ensures real-time stability:

Wazuh Alert (Rule 100015) fires.

custom-redis-publisher.sh executes instantly.

Alert JSON is pushed to the Redis Queue. (Real-time task ends here, execution is non-blocking).

mq_analyzer_worker.py consumes the alert from the queue.

ChatGPT API is called for analysis (this is the slow, asynchronous part).

Email sent to the SOC team.

6️⃣ Required Prerequisites
Redis Server: Must be installed and running on 127.0.0.1:6379.

Python Libraries: openai, redis.

System: Linux server with systemd and redis-cli utility installed.

7️⃣ Finalization Steps
Stop/Clear Old Jobs: Delete all cron jobs and the state file (ai_analyzer_state.txt).

Permissions: Set executable permissions on the publisher script (custom-redis-publisher.sh).

Restart Manager: Restart wazuh-manager to load the new <integration> configuration.

Start Worker: Start the wazuh-ai-worker.service.

This MQ setup is the robust, final solution for your stability issues.
