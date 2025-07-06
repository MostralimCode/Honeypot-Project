#!/usr/bin/env python3
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from datetime import datetime
import json
import glob
import os

class HTTPHoneypotPDFReport:
    def __init__(self):
        self.width, self.height = A4
        
    def analyze_http_logs(self):
        stats = {
            'total_events': 0,
            'unique_ips': set(),
            'attack_types': {},
            'top_payloads': {},
            'countries': {},
            'user_agents': {}
        }
        
        # Chercher les logs HTTP (ajustez le chemin selon votre structure)
        log_patterns = [
            "/root/honeypot-http/logs/*.log",
            "/var/log/honeypot-http/*.log",
            "/opt/honeypot-http/logs/*.log"
        ]
        
        log_files = []
        for pattern in log_patterns:
            log_files.extend(glob.glob(pattern))
        
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        try:
                            # Vos logs HTTP sont en JSON d'après votre code
                            data = json.loads(line.strip())
                            stats['total_events'] += 1
                            
                            if 'ip' in data:
                                stats['unique_ips'].add(data['ip'])
                            
                            if 'attack_type' in data:
                                attack_type = data['attack_type']
                                stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1
                            
                            if 'payload' in data and data['payload']:
                                payload = data['payload'][:50]  # Tronquer pour le rapport
                                stats['top_payloads'][payload] = stats['top_payloads'].get(payload, 0) + 1
                            
                            if 'country' in data:
                                country = data['country']
                                stats['countries'][country] = stats['countries'].get(country, 0) + 1
                            
                            if 'user_agent' in data and data['user_agent']:
                                ua = data['user_agent'][:30]  # Tronquer
                                stats['user_agents'][ua] = stats['user_agents'].get(ua, 0) + 1
                                
                        except json.JSONDecodeError:
                            continue
            except FileNotFoundError:
                continue
                
        if stats['total_events'] == 0:
            print("⚠️  Aucun log HTTP trouvé")
            
        return stats
    
    def generate_report(self):
        print("🔍 Analyse des logs HTTP...")
        stats = self.analyze_http_logs()
        
        c = canvas.Canvas("rapport_http_honeypot.pdf", pagesize=A4)
        
        # En-tête
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, self.height - 60, "RAPPORT HTTP HONEYPOT")
        c.setFont("Helvetica", 12)
        c.drawString(50, self.height - 85, f"Généré le: {datetime.now().strftime('%d/%m/%Y à %H:%M')}")
        c.line(50, self.height - 100, self.width - 50, self.height - 100)
        
        # Résumé
        y = 650
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "RÉSUMÉ HTTP")
        y -= 30
        
        c.setFont("Helvetica", 11)
        c.drawString(70, y, f"• {stats['total_events']} attaques web capturées")
        y -= 20
        c.drawString(70, y, f"• {len(stats['unique_ips'])} IPs uniques")
        y -= 40
        
        # Top types d'attaques
        if stats['attack_types']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Types d'attaques web:")
            y -= 20
            c.setFont("Helvetica", 10)
            for attack_type, count in sorted(stats['attack_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {attack_type}: {count}")
                y -= 15
        
        y -= 20
        
        # Top payloads
        if stats['top_payloads']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Payloads malveillants les plus fréquents:")
            y -= 20
            c.setFont("Helvetica", 8)
            for payload, count in sorted(stats['top_payloads'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {payload}... ({count}x)")
                y -= 12
        
        y -= 20
        
        # Top pays
        if stats['countries']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Pays d'origine des attaques:")
            y -= 20
            c.setFont("Helvetica", 10)
            for country, count in sorted(stats['countries'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {country}: {count}")
                y -= 15
        
        c.save()
        print("✅ Rapport HTTP généré: rapport_http_honeypot.pdf")

if __name__ == "__main__":
    generator = HTTPHoneypotPDFReport()
    generator.generate_report()