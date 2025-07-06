#!/usr/bin/env python3
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from datetime import datetime
import json
import os

class HTTPHoneypotPDFReport:
    def __init__(self):
        self.width, self.height = A4
        
    def analyze_http_logs(self):
        stats = {
            'total_events': 0,
            'unique_ips': set(),
            'attack_types': {},
            'severity_levels': {},
            'top_paths': {},
            'top_user_agents': {},
            'methods': {}
        }
        
        # Vos fichiers de logs HTTP exacts
        log_files = [
            "/var/log/honeypot/api_access.log",
            "/var/log/honeypot/critical_alerts.log", 
            "/var/log/honeypot/sql_injection.log",
            "/var/log/honeypot/http_honeypot.log"
        ]
        
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            try:
                                data = json.loads(line.strip())
                                stats['total_events'] += 1
                                
                                # IP unique
                                if 'ip' in data:
                                    stats['unique_ips'].add(data['ip'])
                                
                                # Type d'attaque
                                if 'attack_type' in data:
                                    attack_type = data['attack_type']
                                    stats['attack_types'][attack_type] = stats['attack_types'].get(attack_type, 0) + 1
                                
                                # Sévérité
                                if 'severity' in data:
                                    severity = data['severity']
                                    stats['severity_levels'][severity] = stats['severity_levels'].get(severity, 0) + 1
                                
                                # Paths les plus attaqués
                                if 'path' in data:
                                    path = data['path']
                                    stats['top_paths'][path] = stats['top_paths'].get(path, 0) + 1
                                
                                # User agents
                                if 'user_agent' in data and data['user_agent']:
                                    ua = data['user_agent'][:40]  # Tronquer
                                    stats['top_user_agents'][ua] = stats['top_user_agents'].get(ua, 0) + 1
                                
                                # Méthodes HTTP
                                if 'method' in data:
                                    method = data['method']
                                    stats['methods'][method] = stats['methods'].get(method, 0) + 1
                                    
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    print(f"Erreur lecture {log_file}: {e}")
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
        
        # Types d'attaques
        if stats['attack_types']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Types d'attaques:")
            y -= 20
            c.setFont("Helvetica", 10)
            for attack_type, count in sorted(stats['attack_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {attack_type}: {count}")
                y -= 15
        
        y -= 20
        
        # Sévérité
        if stats['severity_levels']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Niveaux de sévérité:")
            y -= 20
            c.setFont("Helvetica", 10)
            for severity, count in sorted(stats['severity_levels'].items(), key=lambda x: x[1], reverse=True):
                c.drawString(90, y, f"• {severity}: {count}")
                y -= 15
        
        y -= 20
        
        # Paths les plus attaqués
        if stats['top_paths']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Chemins les plus attaqués:")
            y -= 20
            c.setFont("Helvetica", 9)
            for path, count in sorted(stats['top_paths'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {path}: {count}")
                y -= 12
        
        c.save()
        print("✅ Rapport HTTP généré: rapport_http_honeypot.pdf")

if __name__ == "__main__":
    generator = HTTPHoneypotPDFReport()
    generator.generate_report()