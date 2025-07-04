#!/bin/bash

# ==============================================================================
# CORRECTION DES ERREURS ÉTAPE 6.2 - FTP HONEYPOT VERS ELK
# ==============================================================================

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_status "=== CORRECTION DES ERREURS FTP-ELK ==="
echo ""

# ==============================================================================
# 1. CORRECTION DU LOGGER PYTHON (ERREUR IMPORT)
# ==============================================================================

print_status "1. Correction du logger Python..."

# Logger FTP corrigé (sans logging.handlers qui pose problème)
cat > "/root/honeypot-ftp/src/logger_elk_fixed.py" << 'EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import json
import os
import socket
import time
from datetime import datetime
from typing import Dict, Any, Optional

class FTPHoneypotELKLogger:
    """
    Logger FTP Honeypot simplifié pour ELK Stack
    Version corrigée sans dépendances problématiques
    """
    
    def __init__(self, log_dir: str = "logs", elk_host: str = "192.168.2.124", elk_port: int = 5046):
        self.log_dir = log_dir
        self.elk_host = elk_host
        self.elk_port = elk_port
        
        # Créer le dossier de logs
        os.makedirs(log_dir, exist_ok=True)
        
        # Configurer le logging simple
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        self.logger = logging.getLogger('ftp_honeypot')
    
    def _send_to_elk(self, log_data: Dict[str, Any]) -> bool:
        """Envoie les données vers Logstash"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.elk_host, self.elk_port))
            
            json_log = json.dumps(log_data) + '\n'
            sock.sendall(json_log.encode('utf-8'))
            sock.close()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to send to ELK: {e}")
            return False
    
    def _write_local_log(self, filename: str, message: str):
        """Écrit dans un fichier de log local"""
        try:
            filepath = os.path.join(self.log_dir, filename)
            with open(filepath, 'a') as f:
                f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
        except Exception as e:
            self.logger.error(f"Failed to write local log: {e}")
    
    def log_connection(self, client_ip: str, client_port: int):
        """Log une nouvelle connexion FTP"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'honeypot_type': 'ftp',
            'honeypot_service': 'custom_ftp',
            'event_type': 'connection',
            'client_ip': client_ip,
            'client_port': client_port,
            'server_ip': '192.168.2.117',
            'server_port': 21,
            'message': f'New FTP connection from {client_ip}:{client_port}'
        }
        
        # Log local
        self._write_local_log('ftp_server.log', f"Connection from {client_ip}:{client_port}")
        self._write_local_log('sessions.json', json.dumps(log_data))
        
        # Envoi vers ELK
        self._send_to_elk(log_data)
    
    def log_authentication(self, client_ip: str, username: str, password: str, success: bool):
        """Log une tentative d'authentification"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'honeypot_type': 'ftp',
            'honeypot_service': 'custom_ftp',
            'event_type': 'authentication',
            'client_ip': client_ip,
            'username': username,
            'password': password,
            'success': success,
            'severity': 'critical' if success else 'medium',
            'alert_score': 10 if success else 5,
            'message': f'FTP auth {"success" if success else "failed"} - {username}@{client_ip}'
        }
        
        # Log local
        status = "SUCCESS" if success else "FAILED"
        self._write_local_log('auth_attempts.log', f"Auth {status} - {client_ip} - {username}:{password}")
        self._write_local_log('sessions.json', json.dumps(log_data))
        
        # Envoi vers ELK
        self._send_to_elk(log_data)
    
    def log_command(self, client_ip: str, username: str, command: str, args: str = ""):
        """Log une commande FTP"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'honeypot_type': 'ftp',
            'honeypot_service': 'custom_ftp',
            'event_type': 'command',
            'client_ip': client_ip,
            'username': username,
            'command': command,
            'args': args,
            'full_command': f"{command} {args}".strip(),
            'message': f'FTP command: {command} {args}'
        }
        
        # Log local
        self._write_local_log('commands.log', f"{client_ip} [{username}] {command} {args}")
        self._write_local_log('sessions.json', json.dumps(log_data))
        
        # Envoi vers ELK
        self._send_to_elk(log_data)
    
    def log_security_event(self, client_ip: str, event_type: str, details: Dict[str, Any], severity: str = "high"):
        """Log un événement de sécurité"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'honeypot_type': 'ftp',
            'honeypot_service': 'custom_ftp',
            'event_type': 'security_event',
            'security_event_type': event_type,
            'client_ip': client_ip,
            'severity': severity,
            'alert_score': 8,
            'details': details,
            'message': f'FTP security event: {event_type}'
        }
        
        # Log local
        self._write_local_log('security_events.log', f"{event_type} from {client_ip}: {details}")
        self._write_local_log('sessions.json', json.dumps(log_data))
        
        # Envoi vers ELK
        self._send_to_elk(log_data)
EOF

print_success "✓ Logger Python corrigé créé"

# ==============================================================================
# 2. CORRECTION DE L'INTÉGRATION
# ==============================================================================

print_status "2. Correction du script d'intégration..."

cat > "/root/honeypot-ftp/integrate_elk_fixed.py" << 'EOF'
#!/usr/bin/env python3
"""
Script d'intégration ELK corrigé pour le honeypot FTP
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    from logger_elk_fixed import FTPHoneypotELKLogger
    
    # Instance globale du logger ELK
    elk_logger = FTPHoneypotELKLogger(
        log_dir="logs",
        elk_host="192.168.2.124", 
        elk_port=5046
    )
    
    print("✓ Logger ELK initialisé avec succès")
    ELK_AVAILABLE = True
    
except ImportError as e:
    print(f"⚠ Logger ELK non disponible: {e}")
    ELK_AVAILABLE = False
    elk_logger = None

# Fonctions utilitaires sécurisées
def log_ftp_connection(client_ip, client_port=21):
    if ELK_AVAILABLE and elk_logger:
        elk_logger.log_connection(client_ip, client_port)
    else:
        print(f"LOG: Connection from {client_ip}:{client_port}")

def log_ftp_auth(client_ip, username, password, success):
    if ELK_AVAILABLE and elk_logger:
        elk_logger.log_authentication(client_ip, username, password, success)
    else:
        status = "SUCCESS" if success else "FAILED"
        print(f"LOG: Auth {status} - {client_ip} - {username}")

def log_ftp_command(client_ip, username, command, args=""):
    if ELK_AVAILABLE and elk_logger:
        elk_logger.log_command(client_ip, username, command, args)
    else:
        print(f"LOG: {client_ip} [{username}] {command} {args}")

def log_ftp_security_event(client_ip, event_type, details, severity="high"):
    if ELK_AVAILABLE and elk_logger:
        elk_logger.log_security_event(client_ip, event_type, details, severity)
    else:
        print(f"LOG: Security event {event_type} from {client_ip}")

if __name__ == "__main__":
    # Test du logger
    print("=== TEST DU LOGGER FTP ELK CORRIGÉ ===")
    print("")
    
    # Test de connexion
    log_ftp_connection("203.0.113.100", 21)
    print("✓ Test connexion envoyé")
    
    # Test d'authentification échouée
    log_ftp_auth("203.0.113.100", "admin", "123456", False)
    print("✓ Test auth échouée envoyé")
    
    # Test d'authentification réussie
    log_ftp_auth("203.0.113.100", "anonymous", "", True)
    print("✓ Test auth réussie envoyé")
    
    # Test de commande
    log_ftp_command("203.0.113.100", "anonymous", "LIST", "/")
    print("✓ Test commande envoyé")
    
    # Test d'événement de sécurité
    log_ftp_security_event("203.0.113.100", "directory_traversal", 
                          {"path": "../../etc/passwd"}, "critical")
    print("✓ Test sécurité envoyé")
    
    print("")
    print("Tests terminés. Vérifiez:")
    print("- Logs locaux: /root/honeypot-ftp/logs/")
    print("- Elasticsearch: curl -s 'http://192.168.2.124:9200/honeypot-ftp-*/_search?size=5'")
EOF

chmod +x "/root/honeypot-ftp/integrate_elk_fixed.py"

print_success "✓ Script d'intégration corrigé"

# ==============================================================================
# 3. CORRECTION DE FILEBEAT (CONFIGURATION SIMPLIFIÉE)
# ==============================================================================

print_status "3. Correction de Filebeat..."

# Arrêter Filebeat
systemctl stop filebeat 2>/dev/null

# Configuration Filebeat simplifiée
cat > /etc/filebeat/filebeat.yml << 'EOF'
# Configuration Filebeat simplifiée pour honeypots

filebeat.inputs:
# Logs JSON Cowrie
- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json
  fields:
    honeypot_type: ssh
    honeypot_service: cowrie
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

# Logs JSON FTP
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/sessions.json
  fields:
    honeypot_type: ftp
    honeypot_service: custom_ftp
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

# Output vers Logstash
output.logstash:
  hosts: ["192.168.2.124:5044"]

# Configuration basique
name: "honeypot-filebeat"
tags: ["honeypots"]

# Logging
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 3
  permissions: 0644
EOF

# Tester la configuration
print_status "Test de la configuration Filebeat..."
if filebeat test config -c /etc/filebeat/filebeat.yml; then
    print_success "✓ Configuration Filebeat valide"
    
    # Redémarrer Filebeat
    systemctl start filebeat
    sleep 3
    
    if systemctl is-active filebeat >/dev/null 2>&1; then
        print_success "✓ Filebeat redémarré avec succès"
    else
        print_error "Échec du redémarrage de Filebeat"
    fi
else
    print_error "Configuration Filebeat invalide"
fi

# ==============================================================================
# 4. SCRIPT DE TEST CORRIGÉ
# ==============================================================================

print_status "4. Création d'un script de test corrigé..."

cat > /opt/test_ftp_elk_fixed.sh << 'EOF'
#!/bin/bash

echo "=== TEST FTP HONEYPOT VERS ELK (CORRIGÉ) ==="
echo "Timestamp: $(date)"
echo ""

# Test du logger Python directement
echo "🧪 Test du logger Python..."
cd /root/honeypot-ftp
python3 integrate_elk_fixed.py

echo ""

# Vérifier les logs générés
echo "🔍 Vérification des logs locaux..."
if [ -d "/root/honeypot-ftp/logs" ]; then
    echo "Fichiers dans logs/:"
    ls -la /root/honeypot-ftp/logs/
    
    echo ""
    if [ -f "/root/honeypot-ftp/logs/sessions.json" ]; then
        echo "Derniers événements JSON:"
        tail -3 /root/honeypot-ftp/logs/sessions.json
    fi
fi

echo ""

# Test de connectivité vers ELK
echo "🔌 Test de connectivité Logstash..."
if nc -z 192.168.2.124 5046; then
    echo "✅ Port 5046 accessible"
else
    echo "❌ Port 5046 non accessible"
fi

# Attendre et vérifier dans Elasticsearch
echo ""
echo "⏳ Attente 10 secondes pour indexation..."
sleep 10

echo "🔍 Vérification dans Elasticsearch..."
ES_COUNT=$(curl -s "http://192.168.2.124:9200/honeypot-ftp-*/_search?size=0" 2>/dev/null | jq -r '.hits.total.value // .hits.total' 2>/dev/null)

if [ "$ES_COUNT" ] && [ "$ES_COUNT" -gt 0 ]; then
    echo "✅ $ES_COUNT événements FTP trouvés dans Elasticsearch"
    
    echo "Exemples:"
    curl -s "http://192.168.2.124:9200/honeypot-ftp-*/_search?size=3&sort=@timestamp:desc" | jq -r '.hits.hits[]._source | "\(.timestamp) - \(.event_type) - \(.client_ip)"' 2>/dev/null
else
    echo "⚠ Aucun événement FTP dans Elasticsearch"
    echo "Vérification des indices disponibles:"
    curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*" 2>/dev/null
fi

echo ""
echo "=== TEST TERMINÉ ==="
EOF

chmod +x /opt/test_ftp_elk_fixed.sh

print_success "✓ Script de test corrigé créé"

# ==============================================================================
# 5. TEST IMMÉDIAT
# ==============================================================================

print_status "5. Test immédiat du logger corrigé..."

cd /root/honeypot-ftp
python3 integrate_elk_fixed.py

echo ""

# ==============================================================================
# RÉSUMÉ
# ==============================================================================

print_status "=== CORRECTIONS APPLIQUÉES ==="
echo ""
print_success "✅ CORRECTIONS RÉALISÉES:"
echo "   • Logger Python sans dépendances problématiques"
echo "   • Script d'intégration sécurisé"
echo "   • Configuration Filebeat simplifiée"
echo "   • Script de test corrigé"
echo ""

print_status "📋 FICHIERS CORRIGÉS:"
echo "   • /root/honeypot-ftp/src/logger_elk_fixed.py"
echo "   • /root/honeypot-ftp/integrate_elk_fixed.py"
echo "   • /etc/filebeat/filebeat.yml (simplifié)"
echo "   • /opt/test_ftp_elk_fixed.sh"
echo ""

print_status "🔧 PROCHAINES ÉTAPES:"
echo "1. Tester: /opt/test_ftp_elk_fixed.sh"
echo "2. Vérifier: systemctl status filebeat"
echo "3. Intégrer dans votre honeypot FTP existant"
echo ""

print_success "✅ CORRECTIONS TERMINÉES!"
EOF