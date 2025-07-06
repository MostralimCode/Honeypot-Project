#!/usr/bin/env python3
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from datetime import datetime
import json
import glob

class FTPHoneypotPDFReport:
    def __init__(self):
        self.width, self.height = A4
        
    def analyze_ftp_logs(self):
        stats = {
            'total_events': 0,
            'unique_ips': set(),
            'attack_types': {},
            'top_usernames': {},
            'countries': {}
        }
        
        # Lire sessions.json
        sessions_file = "/root/honeypot-ftp/logs/sessions.json"
        try:
            with open(sessions_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line.strip())
                        stats['total_events'] += 1
                        
                        if 'ip' in data:
                            stats['unique_ips'].add(data['ip'])
                        
                        if 'event_type' in data:
                            event_type = data['event_type']
                            stats['attack_types'][event_type] = stats['attack_types'].get(event_type, 0) + 1
                        
                        if 'username' in data:
                            username = data['username']
                            stats['top_usernames'][username] = stats['top_usernames'].get(username, 0) + 1
                        
                        if 'geo_info' in data and 'country' in data['geo_info']:
                            country = data['geo_info']['country']
                            stats['countries'][country] = stats['countries'].get(country, 0) + 1
                            
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            print("⚠️  Aucun log FTP trouvé")
            
        return stats
    
    def generate_report(self):
        print("🔍 Analyse des logs FTP...")
        stats = self.analyze_ftp_logs()
        
        c = canvas.Canvas("rapport_ftp_honeypot.pdf", pagesize=A4)
        
        # En-tête
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, self.height - 60, "RAPPORT FTP HONEYPOT")
        c.setFont("Helvetica", 12)
        c.drawString(50, self.height - 85, f"Généré le: {datetime.now().strftime('%d/%m/%Y à %H:%M')}")
        c.line(50, self.height - 100, self.width - 50, self.height - 100)
        
        # Résumé
        y = 650
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "RÉSUMÉ FTP")
        y -= 30
        
        c.setFont("Helvetica", 11)
        c.drawString(70, y, f"• {stats['total_events']} événements capturés")
        y -= 20
        c.drawString(70, y, f"• {len(stats['unique_ips'])} IPs uniques")
        y -= 40
        
        # Top types d'attaques
        if stats['attack_types']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Types d'événements:")
            y -= 20
            c.setFont("Helvetica", 10)
            for event_type, count in sorted(stats['attack_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {event_type}: {count}")
                y -= 15
        
        y -= 20
        
        # Top usernames
        if stats['top_usernames']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Usernames les plus tentés:")
            y -= 20
            c.setFont("Helvetica", 10)
            for username, count in sorted(stats['top_usernames'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {username}: {count}")
                y -= 15
        
        c.save()
        print("✅ Rapport FTP généré: rapport_ftp_honeypot.pdf")

if __name__ == "__main__":
    generator = FTPHoneypotPDFReport()
    generator.generate_report()