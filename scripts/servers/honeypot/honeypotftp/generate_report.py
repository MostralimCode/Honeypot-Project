#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script pour générer des rapports d'attaques à partir des logs du honeypot
"""

import json
import argparse
from datetime import datetime, timedelta
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd
from typing import Dict, Any

class ReportGenerator:
    """Génère des rapports visuels et textuels des attaques"""
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = Path(log_dir)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = Path(f"reports/report_{self.timestamp}")
        self.report_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_full_report(self, hours: int = 24):
        """Génère un rapport complet des dernières X heures"""
        print(f"[+] Generating report for the last {hours} hours...")
        
        # Collecter les données
        sessions_data = self.load_session_logs(hours)
        
        # Analyser les données
        summary = self.analyze_sessions(sessions_data)
        
        # Générer les visualisations
        self.create_visualizations(summary)
        
        # Générer le rapport texte
        self.create_text_report(summary)
        
        # Créer un HTML report
        self.create_html_report(summary)
        
        print(f"[+] Report generated in: {self.report_dir}")
        return self.report_dir
    
    def load_session_logs(self, hours: int) -> list:
        """Charge les logs de session des X dernières heures"""
        sessions = []
        sessions_file = self.log_dir / "sessions.json"
        
        if not sessions_file.exists():
            print(f"[-] No sessions log file found at {sessions_file}")
            return sessions
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with open(sessions_file, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    if 'timestamp' in data:
                        log_time = datetime.fromisoformat(data['timestamp'])
                        if log_time > cutoff_time:
                            sessions.append(data)
                except json.JSONDecodeError:
                    continue
        
        return sessions
    
    def analyze_sessions(self, sessions: list) -> Dict[str, Any]:
        """Analyse les sessions pour créer un résumé"""
        summary = {
            'total_sessions': 0,
            'unique_ips': set(),
            'auth_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'brute_force_attempts': 0,
            'directory_traversal_attempts': 0,
            'sensitive_file_accesses': 0,
            'top_usernames': {},
            'top_commands': {},
            'countries': {},
            'attack_timeline': [],
            'top_ips': {},
            'vulnerability_exploits': {'auth': 0, 'traversal': 0, 'file_access': 0}
        }
        
        for session in sessions:
            event_type = session.get('event_type', '')
            
            if event_type == 'session_summary':
                summary['total_sessions'] += 1
                summary['unique_ips'].add(session.get('ip', ''))
                
                # Analyse des commandes
                for cmd in session.get('commands', []):
                    cmd_name = cmd.get('command', 'unknown')
                    summary['top_commands'][cmd_name] = summary['top_commands'].get(cmd_name, 0) + 1
            
            elif event_type == 'auth_attempt':
                summary['auth_attempts'] += 1
                if session.get('success'):
                    summary['successful_logins'] += 1
                else:
                    summary['failed_logins'] += 1
                
                username = session.get('username', 'unknown')
                summary['top_usernames'][username] = summary['top_usernames'].get(username, 0) + 1
                
                summary['vulnerability_exploits']['auth'] += 1
            
            elif event_type == 'brute_force_detected':
                summary['brute_force_attempts'] += 1
            
            elif event_type == 'directory_traversal':
                summary['directory_traversal_attempts'] += 1
                summary['vulnerability_exploits']['traversal'] += 1
            
            elif event_type == 'sensitive_file_access':
                summary['sensitive_file_accesses'] += 1
                summary['vulnerability_exploits']['file_access'] += 1
            
            # Analyse des pays
            geo_info = session.get('geo_info', {})
            if geo_info and 'country' in geo_info:
                country = geo_info['country']
                summary['countries'][country] = summary['countries'].get(country, 0) + 1
            
            # Analyse des IPs
            if 'ip' in session:
                ip = session['ip']
                summary['top_ips'][ip] = summary['top_ips'].get(ip, 0) + 1
        
        # Convertir les sets en listes
        summary['unique_ips'] = list(summary['unique_ips'])
        
        return summary
    
    def create_visualizations(self, summary: Dict[str, Any]):
        """Crée des visualisations graphiques"""
        # 1. Diagramme des types d'attaques
        plt.figure(figsize=(10, 6))
        attack_types = {
            'Brute Force': summary['brute_force_attempts'],
            'Directory Traversal': summary['directory_traversal_attempts'],
            'Sensitive File Access': summary['sensitive_file_accesses'],
            'Failed Logins': summary['failed_logins']
        }
        plt.bar(attack_types.keys(), attack_types.values())
        plt.title('Types of Attacks Detected')
        plt.ylabel('Count')
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(self.report_dir / 'attack_types.png')
        plt.close()
        
        # 2. Top 10 commandes
        top_commands = sorted(summary['top_commands'].items(), key=lambda x: x[1], reverse=True)[:10]
        if top_commands:
            plt.figure(figsize=(12, 6))
            cmds, counts = zip(*top_commands)
            plt.bar(cmds, counts)
            plt.title('Top 10 FTP Commands Used')
            plt.ylabel('Count')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(self.report_dir / 'top_commands.png')
            plt.close()
        
        # 3. Distribution géographique
        if summary['countries']:
            plt.figure(figsize=(12, 8))
            top_countries = sorted(summary['countries'].items(), key=lambda x: x[1], reverse=True)[:10]
            countries, counts = zip(*top_countries)
            plt.bar(countries, counts)
            plt.title('Attack Origins by Country')
            plt.ylabel('Number of Attacks')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(self.report_dir / 'geographic_distribution.png')
            plt.close()
        
        # 4. Rapport succès/échec auth
        plt.figure(figsize=(8, 6))
        auth_data = {
            'Successful': summary['successful_logins'],
            'Failed': summary['failed_logins']
        }
        plt.pie(auth_data.values(), labels=auth_data.keys(), autopct='%1.1f%%')
        plt.title('Authentication Success Rate')
        plt.tight_layout()
        plt.savefig(self.report_dir / 'auth_success_rate.png')
        plt.close()
    
    def create_text_report(self, summary: Dict[str, Any]):
        """Crée un rapport texte détaillé"""
        report_text = f"""
FTP Honeypot Attack Report
Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
=====================================

SUMMARY
-------
Total Sessions: {summary['total_sessions']}
Unique IPs: {len(summary['unique_ips'])}
Total Authentication Attempts: {summary['auth_attempts']}
Successful Logins: {summary['successful_logins']}
Failed Logins: {summary['failed_logins']}
Brute Force Attempts: {summary['brute_force_attempts']}
Directory Traversal Attempts: {summary['directory_traversal_attempts']}
Sensitive File Accesses: {summary['sensitive_file_accesses']}

TOP TARGETS
-----------
Top 5 Usernames:
"""
        top_users = sorted(summary['top_usernames'].items(), key=lambda x: x[1], reverse=True)[:5]
        for username, count in top_users:
            report_text += f"  {username}: {count} attempts\n"
        
        report_text += "\nTop 5 IP Addresses:\n"
        top_ips = sorted(summary['top_ips'].items(), key=lambda x: x[1], reverse=True)[:5]
        for ip, count in top_ips:
            report_text += f"  {ip}: {count} connections\n"
        
        report_text += "\nGeographic Distribution:\n"
        top_countries = sorted(summary['countries'].items(), key=lambda x: x[1], reverse=True)[:5]
        for country, count in top_countries:
            report_text += f"  {country}: {count} attacks\n"
        
        # Sauvegarder le rapport
        with open(self.report_dir / 'attack_report.txt', 'w') as f:
            f.write(report_text)
    
    def create_html_report(self, summary: Dict[str, Any]):
        """Crée un rapport HTML avec les visualisations"""
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>FTP Honeypot Attack Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .section {{ margin-bottom: 30px; }}
        .stat-box {{ 
            background: #f5f5f5; 
            padding: 15px; 
            margin: 10px 0; 
            border-radius: 5px; 
            display: inline-block;
            min-width: 200px;
        }}
        .chart {{ margin: 20px 0; }}
        img {{ max-width: 100%; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>FTP Honeypot Attack Report</h1>
    <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="section">
        <h2>Summary</h2>
        <div class="stat-box">
            <h3>Total Sessions</h3>
            <p>{summary['total_sessions']}</p>
        </div>
        <div class="stat-box">
            <h3>Unique IPs</h3>
            <p>{len(summary['unique_ips'])}</p>
        </div>
        <div class="stat-box">
            <h3>Auth Attempts</h3>
            <p>{summary['auth_attempts']}</p>
        </div>
        <div class="stat-box">
            <h3>Brute Force</h3>
            <p>{summary['brute_force_attempts']}</p>
        </div>
    </div>
    
    <div class="section">
        <h2>Attack Types</h2>
        <img src="attack_types.png" alt="Attack Types">
    </div>
    
    <div class="section">
        <h2>Top Commands</h2>
        <img src="top_commands.png" alt="Top Commands">
    </div>
    
    <div class="section">
        <h2>Geographic Distribution</h2>
        <img src="geographic_distribution.png" alt="Geographic Distribution">
    </div>
    
    <div class="section">
        <h2>Authentication Success Rate</h2>
        <img src="auth_success_rate.png" alt="Authentication Success Rate">
    </div>
    
    <div class="section">
        <h2>Top Targeted Usernames</h2>
        <table>
            <tr><th>Username</th><th>Attempts</th></tr>
"""
        top_users = sorted(summary['top_usernames'].items(), key=lambda x: x[1], reverse=True)[:10]
        for username, count in top_users:
            html_content += f"            <tr><td>{username}</td><td>{count}</td></tr>\n"
        
        html_content += """
        </table>
    </div>
</body>
</html>
"""
        with open(self.report_dir / 'report.html', 'w') as f:
            f.write(html_content)

def main():
    parser = argparse.ArgumentParser(description='Generate FTP Honeypot Attack Report')
    parser.add_argument('--hours', type=int, default=24, help='Hours to analyze (default: 24)')
    parser.add_argument('--log-dir', default='logs', help='Log directory (default: logs)')
    
    args = parser.parse_args()
    
    generator = ReportGenerator(args.log_dir)
    report_dir = generator.generate_full_report(args.hours)
    
    print(f"\n[+] Report generated successfully!")
    print(f"[+] Open the report: {report_dir}/report.html")

if __name__ == "__main__":
    main()