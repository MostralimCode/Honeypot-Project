#!/usr/bin/env python3
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from datetime import datetime
import json
import os
import glob

class SSHHoneypotPDFReport:
    def __init__(self):
        self.width, self.height = A4
        
    def analyze_ssh_logs(self):
        stats = {
            'total_events': 0,
            'unique_ips': set(),
            'event_types': {},
            'top_usernames': {},
            'top_passwords': {},
            'commands': {},
            'countries': {}
        }
        
        # Chemin vers les logs Cowrie
        cowrie_log_dir = "/root/cowrie/var/log/cowrie"
        
        # Fichiers JSON de Cowrie
        log_files = glob.glob(f"{cowrie_log_dir}/*.json*") + glob.glob(f"{cowrie_log_dir}/cowrie.json*")
        
        for log_file in log_files:
            if os.path.exists(log_file):
                try:
                    with open(log_file, 'r') as f:
                        for line in f:
                            try:
                                data = json.loads(line.strip())
                                stats['total_events'] += 1
                                
                                # IP source
                                if 'src_ip' in data:
                                    stats['unique_ips'].add(data['src_ip'])
                                
                                # Type d'événement Cowrie
                                if 'eventid' in data:
                                    event_type = data['eventid']
                                    stats['event_types'][event_type] = stats['event_types'].get(event_type, 0) + 1
                                
                                # Tentatives de login
                                if data.get('eventid') == 'cowrie.login.failed':
                                    if 'username' in data:
                                        username = data['username']
                                        stats['top_usernames'][username] = stats['top_usernames'].get(username, 0) + 1
                                    if 'password' in data:
                                        password = data['password'][:20]  # Tronquer
                                        stats['top_passwords'][password] = stats['top_passwords'].get(password, 0) + 1
                                
                                # Commandes exécutées
                                if data.get('eventid') == 'cowrie.command.input':
                                    if 'input' in data:
                                        command = data['input'].split()[0] if data['input'].split() else data['input']
                                        stats['commands'][command] = stats['commands'].get(command, 0) + 1
                                
                                # Géolocalisation (si disponible)
                                if 'src_ip' in data:
                                    # Cowrie peut avoir des infos de géolocalisation
                                    if 'country' in data:
                                        country = data['country']
                                        stats['countries'][country] = stats['countries'].get(country, 0) + 1
                                    
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    print(f"Erreur lecture {log_file}: {e}")
                    continue
                
        if stats['total_events'] == 0:
            print("⚠️  Aucun log SSH/Cowrie trouvé")
            
        return stats
    
    def generate_report(self):
        print("🔍 Analyse des logs SSH (Cowrie)...")
        stats = self.analyze_ssh_logs()
        
        c = canvas.Canvas("rapport_ssh_honeypot.pdf", pagesize=A4)
        
        # En-tête
        c.setFont("Helvetica-Bold", 20)
        c.drawString(50, self.height - 60, "RAPPORT SSH HONEYPOT (COWRIE)")
        c.setFont("Helvetica", 12)
        c.drawString(50, self.height - 85, f"Généré le: {datetime.now().strftime('%d/%m/%Y à %H:%M')}")
        c.line(50, self.height - 100, self.width - 50, self.height - 100)
        
        # Résumé
        y = 650
        c.setFont("Helvetica-Bold", 14)
        c.drawString(50, y, "RÉSUMÉ SSH")
        y -= 30
        
        c.setFont("Helvetica", 11)
        c.drawString(70, y, f"• {stats['total_events']} événements SSH capturés")
        y -= 20
        c.drawString(70, y, f"• {len(stats['unique_ips'])} IPs uniques")
        y -= 40
        
        # Types d'événements
        if stats['event_types']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Types d'événements:")
            y -= 20
            c.setFont("Helvetica", 10)
            for event_type, count in sorted(stats['event_types'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {event_type}: {count}")
                y -= 15
        
        y -= 20
        
        # Usernames les plus tentés
        if stats['top_usernames']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Usernames les plus tentés:")
            y -= 20
            c.setFont("Helvetica", 10)
            for username, count in sorted(stats['top_usernames'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {username}: {count}")
                y -= 15
        
        y -= 20
        
        # Mots de passe les plus tentés
        if stats['top_passwords']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Mots de passe les plus tentés:")
            y -= 20
            c.setFont("Helvetica", 9)
            for password, count in sorted(stats['top_passwords'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {password}: {count}")
                y -= 12
        
        y -= 20
        
        # Commandes exécutées
        if stats['commands']:
            c.setFont("Helvetica-Bold", 12)
            c.drawString(70, y, "Commandes les plus exécutées:")
            y -= 20
            c.setFont("Helvetica", 10)
            for command, count in sorted(stats['commands'].items(), key=lambda x: x[1], reverse=True)[:5]:
                c.drawString(90, y, f"• {command}: {count}")
                y -= 15
        
        c.save()
        print("✅ Rapport SSH généré: rapport_ssh_honeypot.pdf")

if __name__ == "__main__":
    generator = SSHHoneypotPDFReport()
    generator.generate_report()