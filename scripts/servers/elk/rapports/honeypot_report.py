#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
        date_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        self.cell(0, 10, 'Page {} - {}'.format(self.page_no(), date_str), 0, 0, 'C')

def get_honeypot_data(days=7):
    query = {
        "size": 0,
        "query": {
            "range": {
                "@timestamp": {
                    "gte": "now-{}d".format(days)
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
        print("Connexion a Elasticsearch...")
        response = requests.post(
            "{}/honeypot-*/_search".format(ES_URL),
            headers={"Content-Type": "application/json"},
            json=query,
            timeout=30
        )
        
        if response.status_code == 200:
            print("Donnees recuperees avec succes")
            return response.json()
        else:
            print("Erreur HTTP: {}".format(response.status_code))
            print("Reponse: {}".format(response.text))
            return None
            
    except Exception as e:
        print("Erreur de connexion: {}".format(str(e)))
        return None

def generate_simple_report(days=7, output_file=None):
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = "rapport_honeypot_{}.pdf".format(timestamp)
    
    print("Recuperation des donnees pour les {} derniers jours...".format(days))
    data = get_honeypot_data(days)
    
    if not data:
        print("Impossible de recuperer les donnees")
        return None
    
    print("Generation du PDF...")
    pdf = SimpleHoneypotReport()
    pdf.add_page()
    
    # Titre et période
    pdf.set_font('Arial', 'B', 14)
    start_date = (datetime.now() - timedelta(days=days)).strftime("%d/%m/%Y")
    end_date = datetime.now().strftime("%d/%m/%Y")
    pdf.cell(0, 10, 'Periode: {} - {}'.format(start_date, end_date), 0, 1)
    pdf.ln(5)
    
    # Statistiques générales
    total_events = 0
    if 'hits' in data and 'total' in data['hits']:
        if isinstance(data['hits']['total'], dict):
            total_events = data['hits']['total'].get('value', 0)
        else:
            total_events = data['hits']['total']
    
    pdf.set_font('Arial', '', 12)
    pdf.cell(0, 8, 'Total evenements: {}'.format(total_events), 0, 1)
    pdf.ln(5)
    
    # Par service
    if 'aggregations' in data and 'by_type' in data['aggregations']:
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Repartition par service:', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        for bucket in data['aggregations']['by_type']['buckets']:
            service = bucket['key']
            count = bucket['doc_count']
            if total_events > 0:
                percentage = (count * 100.0) / total_events
            else:
                percentage = 0
            
            line = '  • {}: {} ({:.1f}%)'.format(service, count, percentage)
            pdf.cell(0, 6, line, 0, 1)
        pdf.ln(5)
    
    # Top IP
    if 'aggregations' in data and 'by_ip' in data['aggregations']:
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Top 5 IP attaquantes:', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        buckets = data['aggregations']['by_ip']['buckets'][:5]
        for bucket in buckets:
            ip = bucket['key']
            count = bucket['doc_count']
            line = '  • {}: {} attaques'.format(ip, count)
            pdf.cell(0, 6, line, 0, 1)
        pdf.ln(5)
    
    # Top pays
    if 'aggregations' in data and 'by_country' in data['aggregations']:
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Top 5 pays:', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        buckets = data['aggregations']['by_country']['buckets'][:5]
        for bucket in buckets:
            country = bucket['key'] if bucket['key'] else 'Inconnu'
            count = bucket['doc_count']
            line = '  • {}: {} attaques'.format(country, count)
            pdf.cell(0, 6, line, 0, 1)
    
    try:
        pdf.output(output_file)
        print("Rapport genere: {}".format(output_file))
        return output_file
    except Exception as e:
        print("Erreur lors de la generation: {}".format(str(e)))
        return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Generateur de rapport honeypot')
    parser.add_argument('--days', type=int, default=7, help='Nombre de jours')
    parser.add_argument('--output', type=str, help='Fichier de sortie')
    
    args = parser.parse_args()
    
    # Test de connectivité d'abord
    try:
        print("Test de connectivite Elasticsearch...")
        response = requests.get("{}/".format(ES_URL), timeout=10)
        if response.status_code == 200:
            print("Elasticsearch accessible")
        else:
            print("Elasticsearch non accessible (code: {})".format(response.status_code))
            exit(1)
    except Exception as e:
        print("Erreur de connexion Elasticsearch: {}".format(str(e)))
        exit(1)
    
    # Génération du rapport
    result = generate_simple_report(days=args.days, output_file=args.output)
    
    if result:
        print("Generation terminee avec succes")
    else:
        print("Echec de la generation")