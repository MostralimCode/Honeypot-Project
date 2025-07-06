#!/usr/bin/env python3
import requests
import json
import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
import time

class HoneypotAlerting:
    def __init__(self):
        load_dotenv()
        self.elk_host = "192.168.2.124:9200"
        
        # Configuration email (à personnaliser)
        self.smtp_server = "mail.protonmail.ch"
        self.smtp_port = 587
        self.email_user = os.getenv('EMAIL_USER')
        self.email_password = os.getenv('EMAIL_PASSWORD')
        self.alert_recipient = os.getenv('ALERT_RECIPIENT')

    def check_brute_force_attacks(self):
        """Détecte les attaques par force brute"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-5m"
                                }
                            }
                        },
                        {
                            "terms": {
                                "event_type": ["auth_attempt", "brute_force_detected"]
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "attacks_by_ip": {
                    "terms": {
                        "field": "ip.keyword",
                        "min_doc_count": 10,
                        "size": 10
                    }
                }
            }
        }
        
        try:
            response = requests.post(
                f"http://{self.elk_host}/honeypot-*/_search",
                json=query,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                attacks = data.get('aggregations', {}).get('attacks_by_ip', {}).get('buckets', [])
                
                if attacks:
                    for attack in attacks:
                        ip = attack['key']
                        count = attack['doc_count']
                        self.send_alert(
                            f"🚨 ATTAQUE FORCE BRUTE",
                            f"IP: {ip}\nNombre de tentatives: {count}\nDétectée à: {datetime.now()}"
                        )
                        print(f"🚨 Alerte: Force brute depuis {ip} ({count} tentatives)")
                        
        except Exception as e:
            print(f"Erreur vérification force brute: {e}")
    
    def check_sql_injection_attacks(self):
        """Détecte les injections SQL"""
        query = {
            "query": {
                "bool": {
                    "must": [
                        {
                            "range": {
                                "@timestamp": {
                                    "gte": "now-5m"
                                }
                            }
                        },
                        {
                            "term": {
                                "attack_type": "sql_injection"
                            }
                        }
                    ]
                }
            },
            "aggs": {
                "attacks_by_ip": {
                    "terms": {
                        "field": "ip.keyword",
                        "size": 10
                    }
                }
            }
        }
        
        try:
            response = requests.post(
                f"http://{self.elk_host}/honeypot-*/_search",
                json=query,
                headers={'Content-Type': 'application/json'}
            )
            
            if response.status_code == 200:
                data = response.json()
                total_hits = data.get('hits', {}).get('total', {}).get('value', 0)
                
                if total_hits > 0:
                    attacks = data.get('aggregations', {}).get('attacks_by_ip', {}).get('buckets', [])
                    for attack in attacks:
                        ip = attack['key']
                        count = attack['doc_count']
                        self.send_alert(
                            f"🚨 INJECTION SQL DÉTECTÉE",
                            f"IP: {ip}\nNombre d'attaques: {count}\nDétectée à: {datetime.now()}"
                        )
                        print(f"🚨 Alerte: Injection SQL depuis {ip} ({count} attaques)")
                        
        except Exception as e:
            print(f"Erreur vérification SQL injection: {e}")
    
    def send_alert(self, subject, message):
        """Envoie une alerte par email"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_user
            msg['To'] = self.alert_recipient
            msg['Subject'] = f"[HONEYPOT ALERT] {subject}"
            
            body = f"""
ALERTE SYSTÈME HONEYPOT
=======================

{message}

Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Source: Système de détection honeypot

Vérifiez immédiatement les logs pour plus de détails.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_user, self.email_password)
            text = msg.as_string()
            server.sendmail(self.email_user, self.alert_recipient, text)
            server.quit()
            
            print(f"✅ Alerte envoyée: {subject}")
            
        except Exception as e:
            print(f"❌ Erreur envoi email: {e}")
    
    def run_monitoring(self):
        """Lance la surveillance en continu"""
        print("🔍 Démarrage du monitoring honeypot...")
        while True:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Vérification des alertes...")
            
            self.check_brute_force_attacks()
            self.check_sql_injection_attacks()
            
            # Attendre 5 minutes avant la prochaine vérification
            time.sleep(300)

if __name__ == "__main__":
    alerting = HoneypotAlerting()
    
    # Test des alertes sans email
    print("🧪 Test des alertes...")
    alerting.check_brute_force_attacks()
    alerting.check_sql_injection_attacks()