#!/usr/bin/env python3

import sys
import json
import os
import smtplib
from email.mime.text import MIMEText
import logging
import io

try:
    from openai import OpenAI
except ImportError:
    print("Fatal error: 'openai' library not installed. Please run: pip install openai")
    sys.exit(1)

# --- HARDCODED CONFIGURATION & PATHS ---
CONFIG = {
    # OpenAI Configuration
    "OPENAI_API_KEY": "YOUR_OPENAI_API_KEY_HERE",
    # Email Configuration
    "SMTP_SERVER": "",
    "SMTP_PORT": ,
    "EMAIL_USERNAME": "",
    "EMAIL_PASSWORD": "", 
    "EMAIL_RECIPIENTS": "",
    # Thresholds
    "CRITICAL_SCORE": 80,
    "HIGH_SCORE": 60,
    "MEDIUM_SCORE": 30,
}

# --- FILE PATHS (Crucial for Cron Job) ---
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
STATE_FILE = "/var/ossec/etc/ai_analyzer_state.txt"
TARGET_RULE_ID = "100015"
LOG_FILE = "/var/log/wazuh_ai_cron.log" 
# --- END CONFIGURATION ---

# Setup logging to the cron log file
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('WazuhAIAnalyzer')

# Initialize OpenAI Client
try:
    client = OpenAI(api_key=CONFIG["OPENAI_API_KEY"])
    logger.info("OpenAI client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize OpenAI client: {e}")
    # In cron mode, we exit silently if API key is the only failure
    sys.exit(0) 

# --- STATE MANAGEMENT FUNCTIONS ---

def get_last_processed_id():
    """Retrieves the ID of the last processed alert."""
    try:
        with open(STATE_FILE, 'r') as f:
            return f.read().strip()
    except:
        return "0.0" # Start from the beginning if file is missing

def update_last_processed_id(alert_id):
    """Updates the last processed alert ID."""
    try:
        with open(STATE_FILE, 'w') as f:
            f.write(alert_id)
        return True
    except Exception as e:
        logger.error(f"Failed to update state file: {e}")
        return False

# --- UTILITY FUNCTIONS ---

def send_email_notification(subject, body, recipients):
    """Sends an email notification using the hardcoded SMTP configuration."""
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = CONFIG["EMAIL_USERNAME"]
        msg['To'] = recipients

        server = smtplib.SMTP(CONFIG["SMTP_SERVER"], CONFIG["SMTP_PORT"])
        server.starttls()
        server.login(CONFIG["EMAIL_USERNAME"], CONFIG["EMAIL_PASSWORD"])
        server.sendmail(CONFIG["EMAIL_USERNAME"], recipients.split(','), msg.as_string())
        server.quit()
        logger.info(f"Email notification sent successfully to {len(recipients.split(','))} recipients")
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

def parse_alert_data(alert):
    """Parses the direct alert JSON (not the AR wrapper) from alerts.json."""
    try:
        # Get Source IP safely
        source_ip = alert.get('data', {}).get('srcip') or alert.get('data', {}).get('abuseipdb', {}).get('source', {}).get('srcip', 'N/A')

        # Get Rule ID and Description
        rule_desc = alert.get('rule', {}).get('description', 'No description provided')

        # Get AbuseIPDB data (if available)
        abuseipdb_score = alert.get('data', {}).get('abuseipdb', {}).get('abuse_confidence_score', 0)
        # Convert score to int safely
        score = int(abuseipdb_score) if str(abuseipdb_score).isdigit() else 0
        
        # --- FIX for 'can only concatenate str (not "NoneType") to str' ---
        combined_desc = rule_desc
        if source_ip and source_ip != 'N/A':
            combined_desc += f" from IP: {source_ip}"
        
        if score > 0:
             combined_desc += f", AbuseIPDB Score: {score}%"

        # Determine severity for email subject (Using the hardcoded thresholds)
        if score >= CONFIG["CRITICAL_SCORE"]:
            severity = "CRITICAL"
        elif score >= CONFIG["HIGH_SCORE"]:
            severity = "HIGH"
        elif score >= CONFIG["MEDIUM_SCORE"]:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        return {
            'ip': source_ip,
            'description': combined_desc,
            'severity': severity,
            'full_alert': json.dumps(alert, indent=2)
        }

    except Exception as e:
        logger.error(f"Error parsing alert: {e}")
        return None

def analyze_with_openai(alert_data):
    """Calls the OpenAI API to analyze the alert and return a structured response."""
    
    prompt = f"""
    Analyze the following security alert. Provide a clear, actionable analysis suitable for a security operations center (SOC).
    
    **SEVERITY**: {alert_data['severity']}
    **DESCRIPTION**: {alert_data['description']}
    **FULL ALERT DATA**:
    {alert_data['full_alert']}

    Your response MUST be a single JSON object with the following fields:
    1. threat_summary: Concise summary of the threat.
    2. immediate_actions: List of 3 most urgent steps (e.g., blocking, isolation).
    3. investigation_steps: List of 3 detailed steps for a SOC analyst.
    4. confidence: Overall confidence level (Low, Medium, High).
    """

    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a highly skilled and concise SOC AI Analyst. Your response must strictly be a single, valid JSON object."},
                {"role": "user", "content": prompt}
            ],
            # This is the correct way to request JSON output from the standard openai library
            response_format={"type": "json_object"} 
        )
        
        analysis_text = response.choices[0].message.content
        return analysis_text

    except Exception as e:
        logger.error(f"OpenAI API call failed: {e}")
        return f"AI Analysis Failed: {e}"

# --- CRON MAIN FUNCTION ---

def process_cron_alerts():
    """Reads alerts.json and processes new alerts based on state file."""
    logger.info("-" * 40)
    logger.info("CRON JOB STARTED: Processing new alerts.")
    
    last_id = get_last_processed_id()
    new_last_id = last_id
    alerts_processed = 0

    try:
        # alerts.json contains one JSON object per line (JSONL format)
        with open(ALERTS_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    alert = json.loads(line)
                    alert_id = alert.get('id', '0.0')

                    # 1. Skip already processed alerts (simple string/version comparison)
                    if alert_id <= last_id:
                        continue

                    # 2. Check for the target rule ID (100015)
                    if alert.get('rule', {}).get('id') == TARGET_RULE_ID:
                        
                        logger.info(f"New alert found (ID: {alert_id}). Starting analysis.")
                        
                        # 3. Parse and Analyze
                        alert_data = parse_alert_data(alert)
                        if alert_data:
                            ai_analysis = analyze_with_openai(alert_data)
                            
                            # 4. Format and Notify
                            email_subject = f"[{alert_data['severity']}] AI Analyzed Alert: {alert_data['description']}"
                            email_body = f"AI Analysis Complete:\n\n{ai_analysis}\n\n---\nFull Alert JSON:\n{alert_data['full_alert']}"
                            
                            if send_email_notification(email_subject, email_body, CONFIG["EMAIL_RECIPIENTS"]):
                                logger.info(f"Alert {alert_id} processed and notification sent successfully.")
                                alerts_processed += 1
                            else:
                                logger.error(f"Alert {alert_id} failed to send email.")

                    # 5. Track the highest ID processed
                    if alert_id > new_last_id:
                        new_last_id = alert_id
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Skipping line due to invalid JSON: {e}")
                except Exception as e:
                    logger.error(f"Unexpected error processing alert ID {alert_id}: {e}")

        # 6. Update state
        if new_last_id != last_id:
            update_last_processed_id(new_last_id)
            logger.info(f"State updated to {new_last_id}")

    except FileNotFoundError:
        logger.error(f"Alerts file not found at {ALERTS_FILE}. Check Wazuh Manager paths.")
    
    logger.info(f"CRON JOB FINISHED: Processed {alerts_processed} new alerts.")

if __name__ == "__main__":
    process_cron_alerts()