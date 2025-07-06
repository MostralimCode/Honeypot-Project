from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from datetime import datetime
import json
import glob

class HoneypotPDFReport:
    def __init__(self):
        self.width, self.height = A4
        
    def analyze_logs(self):
        stats = {'total_attacks': 0, 'unique_ips': set(), 'attack_types': {}}
        
        log_files = glob.glob("/root/honeypot-ftp/logs/*.log")
        
        for log_file in log_files:
            with open(log_file, 'r') as f:
                for line in f:
                    if 'data: {' in line:
                        try:
                            json_part = line.split('data: ')[-1].strip()
                            data = json.loads(json_part)
                            stats['total_attacks'] += 1
                            if 'ip' in data:
                                stats['unique_ips'].add(data['ip'])
                            if 'event_type' in data:
                                event_type = data['event_type']
                                stats['attack_types'][event_type] = stats['attack_types'].get(event_type, 0) + 1
                        except:
                            continue
        return stats
    
    def generate_report(self):
        print("🔍 Analyse des logs...")
        stats = self.analyze_logs()
        
        c = canvas.Canvas("rapport_honeypot.pdf", pagesize=A4)
        
        # En-tête
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, self.height - 60, "RAPPORT HONEYPOT")
        c.setFont("Helvetica", 12)
        c.drawString(50, self.height - 85, f"Généré le: {datetime.now().strftime('%d/%m/%Y à %H:%M')}")
        
        # Statistiques
        y = 650
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "RÉSUMÉ")
        y -= 30
        
        c.setFont("Helvetica", 11)
        c.drawString(70, y, f"• {stats['total_attacks']} tentatives d'attaque")
        y -= 20
        c.drawString(70, y, f"• {len(stats['unique_ips'])} IPs uniques")
        y -= 40
        
        c.setFont("Helvetica-Bold", 12)
        c.drawString(70, y, "Types d'attaques:")
        y -= 20
        
        c.setFont("Helvetica", 10)
        for attack_type, count in stats['attack_types'].items():
            c.drawString(90, y, f"• {attack_type}: {count}")
            y -= 15
        
        c.save()
        print("✅ Rapport généré: rapport_honeypot.pdf")

if __name__ == "__main__":
    generator = HoneypotPDFReport()
    generator.generate_report()