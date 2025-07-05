#!/usr/bin/env python3
import json
import requests
from datetime import datetime, timedelta
from fpdf import FPDF
import argparse

ES_URL = "http://192.168.2.124:9200"

class SimpleHoneypotReport(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=15)
    
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'RAPPORT HONEYPOT', 0, 1, 'C')
        self.ln(5)
    
    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()} - {datetime.now().strftime("%d/%m/%Y %H:%M")}', 0, 0, 'C')

def get_honeypot_data(days=7):
    query = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {
                    "gte": f"now-{days}d"
                }
            }
        },
        "aggs": {
            "by_type": {
                "terms": {"field": "honeypot_type.keyword", "size": 10}
            },
            "by_ip": {
                "terms": {"field": "src_ip.keyword", "size": 10}
            },
            "by_country": {
                "terms": {"field": "geoip.country_name.keyword", "size": 10}
            }
        }
    }
    
    try:
        response = requests.post(
            f"{ES_URL}/honeypot-*/_search",
            headers={"Content-Type": "application/json"},
            json=query,
            timeout=30
        )
        
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Erreur HTTP: {response.status_code}")
            return None
            
    except Exception as e:
        print(f"Erreur: {e}")
        return None

def generate_simple_report(days=7, output_file=None):
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"rapport_honeypot_{timestamp}.pdf"
    
    print(f"Récupération des données pour les {days} derniers jours...")
    data = get_honeypot_data(days)
    
    if not data:
        print("❌ Impossible de récupérer les données")
        return None
    
    print("📄 Génération du PDF...")
    pdf = SimpleHoneypotReport()
    pdf.add_page()
    
    # Titre et période
    pdf.set_font('Arial', 'B', 14)
    start_date = (datetime.now() - timedelta(days=days)).strftime("%d/%m/%Y")
    end_date = datetime.now().strftime("%d/%m/%Y")
    pdf.cell(0, 10, f'Période: {start_date} - {end_date}', 0, 1)
    pdf.ln(5)
    
    # Statistiques générales
    total_events = data.get('hits', {}).get('total', {}).get('value', 0)
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 8, f'Total événements: {total_events}', 0, 1)
    pdf.ln(5)
    
    # Par service
    if 'aggregations' in data and 'by_type' in data['aggregations']:
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Répartition par service:', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        for bucket in data['aggregations']['by_type']['buckets']:
            service = bucket['key']
            count = bucket['doc_count']
            percentage = (count / total_events * 100) if total_events > 0 else 0
            pdf.cell(0, 6, f'  • {service}: {count} ({percentage:.1f}%)', 0, 1)
        pdf.ln(5)
    
    # Top IP
    if 'by_ip' in data['aggregations']:
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Top 5 IP attaquantes:', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        for bucket in data['aggregations']['by_ip']['buckets'][:5]:
            ip = bucket['key']
            count = bucket['doc_count']
            pdf.cell(0, 6, f'  • {ip}: {count} attaques', 0, 1)
        pdf.ln(5)
    
    # Top pays
    if 'by_country' in data['aggregations']:
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Top 5 pays:', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        for bucket in data['aggregations']['by_country']['buckets'][:5]:
            country = bucket['key'] if bucket['key'] else 'Inconnu'
            count = bucket['doc_count']
            pdf.cell(0, 6, f'  • {country}: {count} attaques', 0, 1)
    
    try:
        pdf.output(output_file)
        print(f"✅ Rapport généré: {output_file}")
        return output_file
    except Exception as e:
        print(f"❌ Erreur: {e}")
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--days', type=int, default=7)
    parser.add_argument('--output', type=str)
    
    args = parser.parse_args()
    generate_simple_report(days=args.days, output_file=args.output)