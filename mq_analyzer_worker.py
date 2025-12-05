#!/usr/bin/env python3
# This script runs perpetually, consuming alerts from the Redis queue.

import sys
import json
import os
import smtplib
from email.mime.text import MIMEText
import logging
import time
from typing import Dict, Any, Optional

try:
    from openai import OpenAI
    import redis
    from pydantic import BaseModel
except ImportError:
    # We rely on system logging to track this error.
    print("FATAL: Missing required Python libraries. Exiting.")
    sys.exit(1)

# --- CONFIGURATION & PATHS ---
CONFIG = {
    # OpenAI Configuration
    "OPENAI_API_KEY": ""
    "SMTP_SERVER": "",
    "SMTP_PORT": ,
    "EMAIL_USERNAME": "",
    "EMAIL_PASSWORD": "",  
    "EMAIL_RECIPIENTS": "",
    # Thresholds
    "CRITICAL_SCORE": 80,
    "HIGH_SCORE": 60,
    "MEDIUM_SCORE": 30,
    
    # Redis Configuration
    "REDIS_HOST": "127.0.0.1",
    "REDIS_PORT": 6379,
    "REDIS_QUEUE_NAME": "wazuh_alerts_ai",
    "TARGET_RULE_ID": "100015",
}

# Setup logging to stdout/stderr (Managed by systemd when running as a service)
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('WazuhMQWorker')

# --- Helper Functions (Re-included for completeness) ---

def send_email_notification(subject, body, recipients):
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
        return True
    except Exception as e:
        logger.error(f"Failed to send email: {e}")
        return False

def parse_alert_data(alert: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    try:
        source_ip = alert.get('data', {}).get('srcip') or \
                    alert.get('data', {}).get('abuseipdb', {}).get('source', {}).get('srcip', 'N/A')
        rule_desc = alert.get('rule', {}).get('description', 'No description provided')
        abuseipdb_score = alert.get('data', {}).get('abuseipdb', {}).get('abuse_confidence_score', 0)
        score = int(abuseipdb_score) if str(abuseipdb_score).isdigit() else 0
        
        if score >= CONFIG["CRITICAL_SCORE"]: severity = "CRITICAL"
        elif score >= CONFIG["HIGH_SCORE"]: severity = "HIGH"
        elif score >= CONFIG["MEDIUM_SCORE"]: severity = "MEDIUM"
        else: severity = "LOW"
            
        return {
            'id': alert.get('id', 'N/A'),
            'ip': source_ip,
            'description': rule_desc,
            'severity': severity,
            'full_alert': json.dumps(alert, indent=2)
        }
    except Exception as e:
        logger.error(f"Error parsing alert fields from queue message: {e}")
        return None

def analyze_with_openai(alert_data: Dict[str, Any]):
    prompt = f"""Analyze the security alert. Severity: {alert_data['severity']}. Description: {alert_data['description']}..."""
    try:
        client = OpenAI(api_key=CONFIG["OPENAI_API_KEY"]) # Re-initialize client for robustness
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are a highly skilled SOC AI Analyst. Response must be valid JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"} 
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"OpenAI API call failed: {e}")
        return f"AI Analysis Failed: {e}"

def analyze_and_notify(alert_data: Dict[str, Any]):
    """Performs the LLM analysis and sends the email."""
    
    # 1. LLM Analysis (Use a 100s timeout on this internal function for robustness)
    try:
        ai_analysis = analyze_with_openai(alert_data)
        logger.info(f"Analysis completed for alert ID {alert_data['id']}.")
    except Exception as e:
        ai_analysis = f"AI Analysis Failed: {e}"
        logger.error(f"Analysis Failed for alert ID {alert_data['id']}.")


    # 2. Email Notification
    email_subject = f"[{alert_data['severity']}] AI Analyzed Alert: {alert_data['description']}"
    email_body = f"AI Analysis Complete:\n\n{ai_analysis}\n\n---"
    
    if send_email_notification(email_subject, email_body, CONFIG["EMAIL_RECIPIENTS"]):
        logger.info(f"Notification sent for alert ID {alert_data['id']}.")
    else:
        logger.error(f"Notification FAILED for alert ID {alert_data['id']}.")


# --- MAIN SERVICE LOOP ---

def mq_consumer_worker():
    """The main loop that continuously consumes alerts from the Redis queue."""
    logger.info("AI Analysis Worker starting up and connecting to Redis...")
    
    # Initialization Check (Need to re-establish connections inside the loop for resilience)
    while True:
        try:
            r = redis.Redis(host=CONFIG["REDIS_HOST"], port=CONFIG["REDIS_PORT"], decode_responses=True)
            r.ping()
            logger.info("Redis connection established successfully.")
            break
        except Exception as e:
            logger.error(f"Waiting for Redis connectivity: {e}. Retrying in 5 seconds.")
            time.sleep(5)
            
    while True:
        try:
            # BLPOP: Blocking Left POP. Wait up to 5 seconds for a message.
            message = r.blpop(CONFIG["REDIS_QUEUE_NAME"], timeout=5)
            
            if message is None:
                # No message received, continue listening
                continue
            
            queue_name, raw_alert_json = message
            
            # 1. Parse the incoming message
            try:
                alert_json_obj = json.loads(raw_alert_json)
            except json.JSONDecodeError:
                logger.error(f"Received malformed JSON and discarded: {raw_alert_json[:100]}...")
                continue
                
            alert_id = alert_json_obj.get('id', 'N/A')
            logger.info(f"Processing new alert from queue: ID {alert_id}")
            
            # 2. Filter by Rule ID 
            if alert_json_obj.get('rule', {}).get('id') != CONFIG["TARGET_RULE_ID"]:
                 logger.info(f"Skipped alert {alert_id}: Not target rule {CONFIG['TARGET_RULE_ID']}")
                 continue
            
            # 3. Process
            alert_data = parse_alert_data(alert_json_obj)
            if alert_data:
                analyze_and_notify(alert_data)
                
            # Sleep briefly to manage network traffic if the queue is suddenly flooded
            time.sleep(0.5) 

        except redis.exceptions.ConnectionError as e:
            logger.error(f"Lost connection to Redis: {e}. Attempting to reconnect.")
            time.sleep(5)
        except Exception as e:
            logger.error(f"Unhandled exception in worker loop: {e}")
            time.sleep(5)

if __name__ == "__main__":
    mq_consumer_worker()
