#!/usr/bin/env python3
import requests
import json
import os
from datetime import datetime
from dotenv import load_dotenv

class HoneypotDiscordAlerting:
    def __init__(self):
        load_dotenv()
        
        self.elk_host = "localhost:9200"
        self.discord_webhook = os.getenv('DISCORD_WEBHOOK_URL')
        
        if not self.discord_webhook:
            print("⚠️  DISCORD_WEBHOOK_URL manquant dans .env")
            self.discord_enabled = False
        else:
            self.discord_enabled = True
            print("✅ Discord webhook configuré")
    
    def send_discord_alert(self, title, message, color=16711680):  # Rouge par défaut
        """Envoie une alerte Discord"""
        if not self.discord_enabled:
            return
            
        embed = {
            "embeds": [{
                "title": f"🚨 {title}",
                "description": message,
                "color": color,
                "timestamp": datetime.utcnow().isoformat(),
                "footer": {
                    "text": "Système de détection Honeypot"
                }
            }]
        }
        
        try:
            response = requests.post(self.discord_webhook, json=embed)
            if response.status_code == 204:
                print(f"✅ Alerte Discord envoyée: {title}")
            else:
                print(f"❌ Erreur Discord: {response.status_code}")
        except Exception as e:
            print(f"❌ Erreur envoi Discord: {e}")
    
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
                        
                        message = f"**IP:** {ip}\n**Tentatives:** {count}\n**Détectée:** {datetime.now().strftime('%H:%M:%S')}"
                        
                        self.send_discord_alert("ATTAQUE FORCE BRUTE", message)
                        print(f"🚨 Alerte: Force brute depuis {ip} ({count} tentatives)")
                        
        except Exception as e:
            print(f"Erreur vérification force brute: {e}")
    
    def test_discord(self):
        """Test du webhook Discord"""
        self.send_discord_alert(
            "TEST SYSTÈME", 
            "Le système d'alertes honeypot fonctionne correctement !",
            65280  # Vert
        )

if __name__ == "__main__":
    alerting = HoneypotDiscordAlerting()
    alerting.test_discord()
    alerting.check_brute_force_attacks()