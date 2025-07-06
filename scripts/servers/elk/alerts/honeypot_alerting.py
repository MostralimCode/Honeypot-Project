#!/usr/bin/env python3
import requests
import json
import os
import time
from datetime import datetime
from dotenv import load_dotenv

class HoneypotDiscordAlerting:
    def __init__(self):
        load_dotenv()
        
        self.elk_host = "localhost:9200"
        self.discord_webhook = os.getenv('DISCORD_WEBHOOK_URL')
        
        # Configuration pour éviter les problèmes de pool de connexions
        self.session = requests.Session()
        
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
            response = self.session.post(
                f"http://{self.elk_host}/honeypot-*/_search",
                json=query,
                headers={'Content-Type': 'application/json'},
                timeout=10
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
                else:
                    print("✅ Aucune attaque par force brute détectée")
                        
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
            response = self.session.post(
                f"http://{self.elk_host}/honeypot-*/_search",
                json=query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                total_hits = data.get('hits', {}).get('total', {}).get('value', 0)
                
                if total_hits > 0:
                    attacks = data.get('aggregations', {}).get('attacks_by_ip', {}).get('buckets', [])
                    for attack in attacks:
                        ip = attack['key']
                        count = attack['doc_count']
                        
                        message = f"**IP:** {ip}\n**Attaques:** {count}\n**Détectée:** {datetime.now().strftime('%H:%M:%S')}"
                        
                        self.send_discord_alert("INJECTION SQL DÉTECTÉE", message, 16776960)  # Orange
                        print(f"🚨 Alerte: Injection SQL depuis {ip} ({count} attaques)")
                else:
                    print("✅ Aucune injection SQL détectée")
                        
        except Exception as e:
            print(f"Erreur vérification SQL injection: {e}")
    
    def check_critical_alerts(self):
        """Détecte les alertes critiques"""
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
                                "severity": "critical"
                            }
                        }
                    ]
                }
            }
        }
        
        try:
            response = self.session.post(
                f"http://{self.elk_host}/honeypot-*/_search",
                json=query,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                total_hits = data.get('hits', {}).get('total', {}).get('value', 0)
                
                if total_hits > 0:
                    message = f"**Nombre d'alertes:** {total_hits}\n**Période:** 5 dernières minutes\n**Détectée:** {datetime.now().strftime('%H:%M:%S')}"
                    
                    self.send_discord_alert("ALERTES CRITIQUES", message, 10038562)  # Violet
                    print(f"🚨 Alerte: {total_hits} alertes critiques détectées")
                else:
                    print("✅ Aucune alerte critique")
                        
        except Exception as e:
            print(f"Erreur vérification alertes critiques: {e}")
    
    def test_discord(self):
        """Test du webhook Discord"""
        self.send_discord_alert(
            "TEST SYSTÈME", 
            "Le système d'alertes honeypot fonctionne correctement !",
            65280  # Vert
        )
    
    def run_monitoring(self):
        """Lance la surveillance en continu"""
        print("🔍 Démarrage du monitoring honeypot...")
        while True:
            print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Vérification des alertes...")
            
            self.check_brute_force_attacks()
            self.check_sql_injection_attacks()
            self.check_critical_alerts()
            
            print("⏳ Attente 5 minutes avant prochaine vérification...")
            time.sleep(300)  # 5 minutes

if __name__ == "__main__":
    alerting = HoneypotDiscordAlerting()
    
    # Test initial
    print("🧪 Test du système...")
    alerting.test_discord()
    alerting.check_brute_force_attacks()
    alerting.check_sql_injection_attacks()
    alerting.check_critical_alerts()
    
    # Décommentez la ligne suivante pour lancer la surveillance continue
    # alerting.run_monitoring()