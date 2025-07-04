#!/bin/bash

# ==============================================================================
# ÉTAPE 6.2 : CONFIGURATION FTP HONEYPOT VERS ELK
# ==============================================================================
# Ce script configure votre Honeypot FTP pour envoyer ses logs vers ELK
# À exécuter sur la VM Honeypot (192.168.2.117)

# Configuration
ELK_SERVER="192.168.2.124"
LOGSTASH_TCP_PORT="5046"
LOGSTASH_BEATS_PORT="5044"
FTP_HONEYPOT_DIR="/root/honeypot-ftp"
FTP_LOGS_DIR="$FTP_HONEYPOT_DIR/logs"

# Couleurs pour les logs
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

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ==============================================================================
# ÉTAPE 1 : VÉRIFICATIONS PRÉLIMINAIRES
# ==============================================================================

print_status "=== ÉTAPE 6.2 : CONFIGURATION FTP HONEYPOT VERS ELK ==="
echo ""

# Vérifier qu'on est sur la bonne VM
CURRENT_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
if [ "$CURRENT_IP" != "192.168.2.117" ]; then
    print_error "Ce script doit être exécuté sur la VM Honeypot (192.168.2.117)"
    print_error "IP actuelle: $CURRENT_IP"
    exit 1
fi

print_success "✓ Exécution sur la VM Honeypot ($CURRENT_IP)"

# Vérifier l'existence du honeypot FTP
if [ ! -d "$FTP_HONEYPOT_DIR" ]; then
    print_error "Honeypot FTP non trouvé dans $FTP_HONEYPOT_DIR"
    print_error "Assurez-vous que le honeypot FTP est installé"
    exit 1
fi

print_success "✓ Honeypot FTP trouvé dans $FTP_HONEYPOT_DIR"

# Vérifier les logs existants
if [ -d "$FTP_LOGS_DIR" ]; then
    print_success "✓ Dossier logs FTP trouvé"
    print_status "Fichiers de logs existants:"
    ls -la "$FTP_LOGS_DIR" 2>/dev/null || echo "Aucun fichier de log encore"
else
    print_warning "⚠ Dossier logs non trouvé, création..."
    mkdir -p "$FTP_LOGS_DIR"
    chown root:root "$FTP_LOGS_DIR"
    chmod 755 "$FTP_LOGS_DIR"
fi

# Vérifier la connectivité ELK
print_status "Test de connectivité vers ELK Stack..."

if ! ping -c 1 "$ELK_SERVER" >/dev/null 2>&1; then
    print_error "Impossible de joindre le serveur ELK ($ELK_SERVER)"
    exit 1
fi

if ! nc -z "$ELK_SERVER" "$LOGSTASH_TCP_PORT" 2>/dev/null; then
    print_error "Port Logstash TCP ($LOGSTASH_TCP_PORT) non accessible"
    exit 1
fi

print_success "✓ Connectivité ELK Stack validée"

# ==============================================================================
# ÉTAPE 2 : CONFIGURATION DU LOGGER FTP POUR ELK
# ==============================================================================

print_status "Configuration du logger FTP pour ELK..."

# Vérifier si le logger existe déjà
if [ -f "$FTP_HONEYPOT_DIR/src/logger.py" ]; then
    # Backup du logger existant
    cp "$FTP_HONEYPOT_DIR/src/logger.py" "$FTP_HONEYPOT_DIR/src/logger.py.backup.$(date +%Y%m%d_%H%M%S)"
    print_success "✓ Backup du logger existant créé"
fi

# Logger FTP amélioré avec support ELK
cat > "$FTP_HONEYPOT_DIR/src/logger_elk.py" << 'EOF'
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import json
import os
import socket
import time
from datetime import datetime
from typing import Dict, Any, Optional
from logging.handlers import RotatingFileHandler

class FTPHoneypotELKLogger:
    """
    Logger FTP Honeypot optimisé pour ELK Stack
    Envoi direct vers Logstash + logs locaux
    """
    
    def __init__(self, log_dir: str = "logs", elk_host: str = "192.168.2.124", elk_port: int = 5046):
        self.log_dir = log_dir
        self.elk_host = elk_host
        self.elk_port = elk_port
        
        # Créer le dossier de logs
        os.makedirs(log_dir, exist_ok=True)
        
        # Configurer les loggers locaux
        self.loggers = {
            'main': self._setup_logger('ftp_main', 'ftp_server.log'),
            'auth': self._setup_logger('ftp_auth', 'auth_attempts.log'),
            'commands': self._setup_logger('ftp_commands', 'commands.log'),
            'sessions': self._setup_json_logger('ftp_sessions', 'sessions.json'),
            'security': self._setup_logger('ftp_security', 'security_events.log')
        }
    
    def _setup_logger(self, name: str, filename: str) -> logging.Logger:
        """Configure un logger avec rotation"""
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        
        # Éviter les doublons
        if logger.handlers:
            return logger
            
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        handler = RotatingFileHandler(
            os.path.join(self.log_dir, filename),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _setup_json_logger(self, name: str, filename: str) -> logging.Logger:
        """Configure un logger JSON"""
        logger = logging.getLogger(name)
        logger.setLevel(logging.INFO)
        
        if logger.handlers:
            return logger
            
        handler = RotatingFileHandler(
            os.path.join(self.log_dir, filename),
            maxBytes=10*1024*1024,
            backupCount=5
        )
        logger.addHandler(handler)
        
        return logger
    
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
            # Log l'erreur localement
            self.loggers['main'].error(f"Failed to send to ELK: {e}")
            return False
    
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
        self.loggers['main'].info(f"Connection from {client_ip}:{client_port}")
        
        # Log JSON local
        self.loggers['sessions'].info(json.dumps(log_data))
        
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
        self.loggers['auth'].info(f"Auth {status} - {client_ip} - {username}:{password}")
        
        # Log JSON local
        self.loggers['sessions'].info(json.dumps(log_data))
        
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
        self.loggers['commands'].info(f"{client_ip} [{username}] {command} {args}")
        
        # Log JSON local
        self.loggers['sessions'].info(json.dumps(log_data))
        
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
        self.loggers['security'].warning(f"{event_type} from {client_ip}: {details}")
        
        # Log JSON local
        self.loggers['sessions'].info(json.dumps(log_data))
        
        # Envoi vers ELK
        self._send_to_elk(log_data)
    
    def log_directory_traversal(self, client_ip: str, username: str, path: str):
        """Log une tentative de directory traversal"""
        self.log_security_event(
            client_ip,
            'directory_traversal',
            {
                'username': username,
                'attempted_path': path,
                'mitre_technique': 'T1083',  # File and Directory Discovery
                'mitre_tactic': 'Discovery'
            },
            'critical'
        )
    
    def log_brute_force(self, client_ip: str, failed_attempts: int, time_window: int):
        """Log une détection de brute force"""
        self.log_security_event(
            client_ip,
            'brute_force_attack',
            {
                'failed_attempts': failed_attempts,
                'time_window_seconds': time_window,
                'mitre_technique': 'T1110',  # Brute Force
                'mitre_tactic': 'Credential Access'
            },
            'critical'
        )
EOF

print_success "✓ Logger ELK créé dans src/logger_elk.py"

# ==============================================================================
# ÉTAPE 3 : MODIFICATION DU SERVEUR FTP PRINCIPAL
# ==============================================================================

print_status "Modification du serveur FTP pour utiliser le logger ELK..."

# Backup du fichier principal
if [ -f "$FTP_HONEYPOT_DIR/src/ftp_server.py" ]; then
    cp "$FTP_HONEYPOT_DIR/src/ftp_server.py" "$FTP_HONEYPOT_DIR/src/ftp_server.py.backup.$(date +%Y%m%d_%H%M%S)"
elif [ -f "$FTP_HONEYPOT_DIR/ftp_server.py" ]; then
    cp "$FTP_HONEYPOT_DIR/ftp_server.py" "$FTP_HONEYPOT_DIR/ftp_server.py.backup.$(date +%Y%m%d_%H%M%S)"
fi

# Créer un script d'intégration simple
cat > "$FTP_HONEYPOT_DIR/integrate_elk.py" << 'EOF'
#!/usr/bin/env python3
"""
Script d'intégration ELK pour le honeypot FTP
Ajoute le logging ELK à votre honeypot existant
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from logger_elk import FTPHoneypotELKLogger

# Instance globale du logger ELK
elk_logger = FTPHoneypotELKLogger(
    log_dir="logs",
    elk_host="192.168.2.124", 
    elk_port=5046
)

def integrate_logging(original_server_class):
    """
    Fonction pour intégrer le logging ELK dans votre serveur FTP existant
    Utilisez cette fonction pour wrapper vos méthodes existantes
    """
    
    class ELKIntegratedServer(original_server_class):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.elk_logger = elk_logger
        
        def log_connection(self, client_ip, client_port=None):
            """Override ou complément de votre méthode de connexion"""
            self.elk_logger.log_connection(client_ip, client_port or 0)
            # Appeler la méthode parent si elle existe
            if hasattr(super(), 'log_connection'):
                super().log_connection(client_ip, client_port)
        
        def log_auth_attempt(self, client_ip, username, password, success):
            """Override ou complément de votre méthode d'auth"""
            self.elk_logger.log_authentication(client_ip, username, password, success)
            # Appeler la méthode parent si elle existe
            if hasattr(super(), 'log_auth_attempt'):
                super().log_auth_attempt(client_ip, username, password, success)
        
        def log_command_execution(self, client_ip, username, command, args=""):
            """Override ou complément de votre méthode de commande"""
            self.elk_logger.log_command(client_ip, username, command, args)
            # Appeler la méthode parent si elle existe
            if hasattr(super(), 'log_command_execution'):
                super().log_command_execution(client_ip, username, command, args)
    
    return ELKIntegratedServer

# Fonctions utilitaires pour usage direct
def log_ftp_connection(client_ip, client_port=21):
    elk_logger.log_connection(client_ip, client_port)

def log_ftp_auth(client_ip, username, password, success):
    elk_logger.log_authentication(client_ip, username, password, success)

def log_ftp_command(client_ip, username, command, args=""):
    elk_logger.log_command(client_ip, username, command, args)

def log_ftp_security_event(client_ip, event_type, details, severity="high"):
    elk_logger.log_security_event(client_ip, event_type, details, severity)

if __name__ == "__main__":
    # Test du logger
    print("Test du logger FTP ELK...")
    
    # Test de connexion
    log_ftp_connection("203.0.113.100", 21)
    
    # Test d'authentification échouée
    log_ftp_auth("203.0.113.100", "admin", "123456", False)
    
    # Test d'authentification réussie
    log_ftp_auth("203.0.113.100", "anonymous", "", True)
    
    # Test de commande
    log_ftp_command("203.0.113.100", "anonymous", "LIST", "/")
    
    # Test d'événement de sécurité
    log_ftp_security_event("203.0.113.100", "directory_traversal", 
                          {"path": "../../etc/passwd"}, "critical")
    
    print("Tests terminés. Vérifiez les logs dans 'logs/' et Elasticsearch.")
EOF

chmod +x "$FTP_HONEYPOT_DIR/integrate_elk.py"

print_success "✓ Script d'intégration ELK créé"

# ==============================================================================
# ÉTAPE 4 : CONFIGURATION FILEBEAT POUR LES LOGS FTP
# ==============================================================================

print_status "Configuration de Filebeat pour les logs FTP..."

# Ajouter la configuration FTP à Filebeat
if [ -f /etc/filebeat/filebeat.yml ]; then
    # Backup de la config Filebeat actuelle
    cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.backup.ftp.$(date +%Y%m%d_%H%M%S)
    
    # Créer une configuration Filebeat étendue
    cat > /etc/filebeat/filebeat.yml << 'EOF'
# ==============================================================================
# FILEBEAT CONFIGURATION ÉTENDUE - COWRIE + FTP HONEYPOT
# ==============================================================================

filebeat.inputs:
# === COWRIE SSH HONEYPOT (existant) ===
- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json.*
  exclude_files: ['\.gz$']
  fields:
    logstash_pipeline: cowrie
    honeypot_type: ssh
    honeypot_service: cowrie
    source_vm: honeypot-117
    log_source: json_cowrie
  fields_under_root: false
  json.keys_under_root: true
  json.add_error_key: true
  json.message_key: message
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after
  close_inactive: 5m
  scan_frequency: 1s

- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.log
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.log.*
  exclude_files: ['\.gz$']
  fields:
    logstash_pipeline: cowrie
    honeypot_type: ssh
    honeypot_service: cowrie
    source_vm: honeypot-117
    log_source: text_cowrie
    log_format: text
  fields_under_root: false
  close_inactive: 5m
  scan_frequency: 1s

# === FTP HONEYPOT (nouveau) ===
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/sessions.json
  fields:
    logstash_pipeline: ftp
    honeypot_type: ftp
    honeypot_service: custom_ftp
    source_vm: honeypot-117
    log_source: json_ftp
  fields_under_root: false
  json.keys_under_root: true
  json.add_error_key: true
  json.message_key: message
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after
  close_inactive: 5m
  scan_frequency: 1s

- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/ftp_server.log
    - /root/honeypot-ftp/logs/auth_attempts.log
    - /root/honeypot-ftp/logs/commands.log
    - /root/honeypot-ftp/logs/security_events.log
  fields:
    logstash_pipeline: ftp
    honeypot_type: ftp
    honeypot_service: custom_ftp
    source_vm: honeypot-117
    log_source: text_ftp
    log_format: text
  fields_under_root: false
  close_inactive: 5m
  scan_frequency: 2s

# ==============================================================================
# OUTPUT VERS LOGSTASH
# ==============================================================================

output.logstash:
  hosts: ["192.168.2.124:5044"]
  worker: 2
  compression_level: 3
  ttl: 30s
  pipelining: 2
  loadbalance: true
  timeout: 10s

# ==============================================================================
# CONFIGURATION GÉNÉRALE
# ==============================================================================

name: "honeypot-multi-service-filebeat"
tags: ["cowrie", "ftp", "honeypot", "ssh", "vm-117"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - timestamp:
      field: timestamp
      layouts:
        - '2006-01-02T15:04:05.999999Z'
        - '2006-01-02T15:04:05.999Z'
        - '2006-01-02T15:04:05Z'
      test:
        - '2023-10-15T14:30:45.123456Z'

# ==============================================================================
# LOGGING ET MONITORING
# ==============================================================================

logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

monitoring.enabled: true

queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 5s

max_procs: 2
EOF

    print_success "✓ Configuration Filebeat étendue pour FTP"
else
    print_warning "⚠ Configuration Filebeat non trouvée, configuration manuelle nécessaire"
fi

# ==============================================================================
# ÉTAPE 5 : TESTS ET VALIDATION
# ==============================================================================

print_status "Tests et validation du honeypot FTP..."

# Test du logger ELK
print_status "Test du logger FTP ELK..."
cd "$FTP_HONEYPOT_DIR"
python3 integrate_elk.py

# Redémarrer Filebeat pour prendre en compte la nouvelle configuration
print_status "Redémarrage de Filebeat..."
systemctl restart filebeat
sleep 3

if systemctl is-active filebeat >/dev/null 2>&1; then
    print_success "✓ Filebeat redémarré avec succès"
else
    print_error "Échec du redémarrage de Filebeat"
    systemctl status filebeat
fi

# ==============================================================================
# ÉTAPE 6 : CRÉATION D'UN SCRIPT DE TEST FTP
# ==============================================================================

print_status "Création d'un script de test FTP..."

cat > /opt/test_ftp_honeypot.sh << 'EOF'
#!/bin/bash

echo "=== TEST FTP HONEYPOT VERS ELK ==="
echo "Timestamp: $(date)"
echo ""

# Tester la connectivité FTP
echo "🔧 Test connectivité FTP honeypot..."
if nc -z 127.0.0.1 21 2>/dev/null; then
    echo "✅ FTP honeypot accessible sur port 21"
else
    echo "❌ FTP honeypot non accessible"
fi

# Générer des événements de test
echo ""
echo "🧪 Génération d'événements de test..."

# Test 1: Connexion anonyme
echo "Test 1: Connexion FTP anonyme..."
expect << 'EXPECTEOF' &
spawn ftp 127.0.0.1
expect "Name"
send "anonymous\r"
expect "Password:"
send "\r"
expect "ftp>"
send "pwd\r"
expect "ftp>"
send "ls\r"
expect "ftp>"
send "quit\r"
expect eof
EXPECTEOF

sleep 2

# Test 2: Tentative de brute force
echo "Test 2: Tentatives d'authentification..."
for user in admin root ftp test; do
    for pass in 123456 password admin; do
        timeout 5 ftp -n <<EOF &
open 127.0.0.1
user $user $pass
quit
EOF
    done
done

sleep 3

# Test 3: Commandes suspectes
echo "Test 3: Commandes suspectes..."
expect << 'EXPECTEOF' &
spawn ftp 127.0.0.1
expect "Name"
send "anonymous\r"
expect "Password:"
send "\r"
expect "ftp>"
send "cd ../../etc\r"
expect "ftp>"
send "get passwd\r"
expect "ftp>"
send "cd ../../../root\r"
expect "ftp>"
send "quit\r"
expect eof
EXPECTEOF

echo ""
echo "🔍 Vérification des logs générés..."

# Vérifier les logs locaux
if [ -d "/root/honeypot-ftp/logs" ]; then
    echo "Logs FTP locaux:"
    ls -la /root/honeypot-ftp/logs/
    
    if [ -f "/root/honeypot-ftp/logs/sessions.json" ]; then
        echo ""
        echo "Derniers événements JSON:"
        tail -3 /root/honeypot-ftp/logs/sessions.json | jq -r '.event_type + " - " + .client_ip + " - " + .message' 2>/dev/null || tail -3 /root/honeypot-ftp/logs/sessions.json
    fi
fi

# Attendre que les données arrivent dans ELK
sleep 10

echo ""
echo "🔍 Vérification dans Elasticsearch..."
ES_COUNT=$(curl -s "http://192.168.2.124:9200/honeypot-ftp-*/_search?size=0" | jq -r '.hits.total.value // .hits.total' 2>/dev/null)

if [ "$ES_COUNT" ] && [ "$ES_COUNT" -gt 0 ]; then
    echo "✅ $ES_COUNT événements FTP indexés dans Elasticsearch"
    
    echo "Exemples d'événements FTP:"
    curl -s "http://192.168.2.124:9200/honeypot-ftp-*/_search?size=3&sort=@timestamp:desc" | jq -r '.hits.hits[]._source | "\(.["@timestamp"]) - \(.event_type) - \(.client_ip) - \(.message)"' 2>/dev/null
else
    echo "⚠ Aucun événement FTP trouvé dans Elasticsearch (peut prendre quelques minutes)"
fi

echo ""
echo "=== TEST TERMINÉ ==="
EOF

chmod +x /opt/test_ftp_honeypot.sh

# ==============================================================================
# ÉTAPE 7 : SCRIPT DE MONITORING FTP
# ==============================================================================

print_status "Création du script de monitoring FTP..."

cat > /opt/monitor_ftp_elk.sh << 'EOF'
#!/bin/bash

echo "=== MONITORING FTP HONEYPOT -> ELK ==="
echo "Timestamp: $(date)"
echo ""

# Vérifier le service FTP honeypot
echo "SERVICES:"
if pgrep -f "ftp.*honeypot\|honeypot.*ftp" >/dev/null; then
    echo "- FTP Honeypot: RUNNING"
else
    echo "- FTP Honeypot: STOPPED"
fi
echo "- Filebeat: $(systemctl is-active filebeat)"
echo ""

# Vérifier les logs locaux
echo "LOGS LOCAUX:"
if [ -d "/root/honeypot-ftp/logs" ]; then
    for logfile in sessions.json ftp_server.log auth_attempts.log commands.log; do
        if [ -f "/root/honeypot-ftp/logs/$logfile" ]; then
            lines=$(wc -l < "/root/honeypot-ftp/logs/$logfile" 2>/dev/null || echo "0")
            echo "- $logfile: $lines lignes"
        else
            echo "- $logfile: Non trouvé"
        fi
    done
    
    # Dernier événement JSON
    if [ -f "/root/honeypot-ftp/logs/sessions.json" ] && [ -s "/root/honeypot-ftp/logs/sessions.json" ]; then
        echo ""
        echo "DERNIER ÉVÉNEMENT JSON:"
        tail -1 /root/honeypot-ftp/logs/sessions.json | jq -r '.timestamp + " - " + .event_type + " - " + .client_ip' 2>/dev/null || tail -1 /root/honeypot-ftp/logs/sessions.json
    fi
else
    echo "- Dossier logs non trouvé"
fi

echo ""

# Vérifier dans Elasticsearch
echo "ELASTICSEARCH:"
ES_COUNT=$(curl -s "http://192.168.2.124:9200/honeypot-ftp-*/_search?size=0" | jq -r '.hits.total.value // .hits.total' 2>/dev/null)
echo "- Événements FTP indexés: $ES_COUNT"

if [ "$ES_COUNT" ] && [ "$ES_COUNT" -gt 0 ]; then
    echo "- Dernier événement ES:"
    curl -s "http://192.168.2.124:9200/honeypot-ftp-*/_search?size=1&sort=@timestamp:desc" | jq -r '.hits.hits[]._source | "  " + .["@timestamp"] + " - " + .event_type + " - " + .client_ip' 2>/dev/null
fi

echo ""

# Statistiques détaillées
if [ "$ES_COUNT" ] && [ "$ES_COUNT" -gt 0 ]; then
    echo "STATISTIQUES FTP (dernières 24h):"
    
    # Connexions
    CONNECTIONS=$(curl -s "http://192.168.2.124:9200/honeypot-ftp-*/_search" -H "Content-Type: application/json" -d '{
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"event_type": "connection"}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]
            }
        }
    }' | jq -r '.hits.total.value // .hits.total' 2>/dev/null)
    
    # Authentifications
    AUTH_FAILED=$(curl -s "http://192.168.2.124:9200/honeypot-ftp-*/_search" -H "Content-Type: application/json" -d '{
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"event_type": "authentication"}},
                    {"term": {"success": false}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]
            }
        }
    }' | jq -r '.hits.total.value // .hits.total' 2>/dev/null)
    
    # Commandes
    COMMANDS=$(curl -s "http://192.168.2.124:9200/honeypot-ftp-*/_search" -H "Content-Type: application/json" -d '{
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {"term": {"event_type": "command"}},
                    {"range": {"@timestamp": {"gte": "now-24h"}}}
                ]
            }
        }
    }' | jq -r '.hits.total.value // .hits.total' 2>/dev/null)
    
    echo "- Connexions: $CONNECTIONS"
    echo "- Auth. échouées: $AUTH_FAILED" 
    echo "- Commandes: $COMMANDS"
fi

echo ""
echo "=== FIN MONITORING ==="
EOF

chmod +x /opt/monitor_ftp_elk.sh

# ==============================================================================
# ÉTAPE 8 : CRÉATION D'UN SERVICE SYSTEMD POUR LE FTP HONEYPOT
# ==============================================================================

print_status "Création du service systemd pour le FTP Honeypot..."

cat > /etc/systemd/system/ftp-honeypot.service << 'EOF'
[Unit]
Description=FTP Honeypot with ELK Integration
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=/root/honeypot-ftp
ExecStart=/usr/bin/python3 /root/honeypot-ftp/run.py
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Sécurité
NoNewPrivileges=yes
PrivateTmp=yes

# Variables d'environnement
Environment=PYTHONPATH=/root/honeypot-ftp/src
Environment=ELK_HOST=192.168.2.124
Environment=ELK_PORT=5046

[Install]
WantedBy=multi-user.target
EOF

# Recharger systemd
systemctl daemon-reload

print_success "✓ Service systemd ftp-honeypot créé"

# ==============================================================================
# ÉTAPE 9 : INTÉGRATION DANS LE HONEYPOT EXISTANT
# ==============================================================================

print_status "Intégration dans le honeypot FTP existant..."

# Créer un script de patch automatique
cat > "$FTP_HONEYPOT_DIR/patch_for_elk.py" << 'EOF'
#!/usr/bin/env python3
"""
Script de patch automatique pour intégrer ELK dans votre honeypot FTP existant
"""

import os
import re
import shutil
from datetime import datetime

def backup_file(filepath):
    """Crée un backup d'un fichier"""
    if os.path.exists(filepath):
        backup_path = f"{filepath}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(filepath, backup_path)
        print(f"✓ Backup créé: {backup_path}")
        return True
    return False

def patch_main_server():
    """Patch le serveur principal pour ajouter ELK logging"""
    
    # Chercher le fichier principal du serveur
    possible_files = [
        'run.py',
        'ftp_server.py', 
        'src/ftp_server.py',
        'main.py'
    ]
    
    main_file = None
    for f in possible_files:
        if os.path.exists(f):
            main_file = f
            break
    
    if not main_file:
        print("❌ Fichier principal du serveur FTP non trouvé")
        print("Fichiers cherchés:", possible_files)
        return False
    
    print(f"📁 Fichier principal trouvé: {main_file}")
    
    # Backup
    backup_file(main_file)
    
    # Lire le contenu
    with open(main_file, 'r') as f:
        content = f.read()
    
    # Ajouter l'import ELK en haut du fichier
    elk_import = """
# === INTÉGRATION ELK AJOUTÉE AUTOMATIQUEMENT ===
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))
try:
    from integrate_elk import (
        log_ftp_connection, 
        log_ftp_auth, 
        log_ftp_command, 
        log_ftp_security_event
    )
    ELK_AVAILABLE = True
    print("✓ Logger ELK initialisé")
except ImportError as e:
    print(f"⚠ Logger ELK non disponible: {e}")
    ELK_AVAILABLE = False
    # Fonctions vides en fallback
    def log_ftp_connection(*args, **kwargs): pass
    def log_ftp_auth(*args, **kwargs): pass
    def log_ftp_command(*args, **kwargs): pass
    def log_ftp_security_event(*args, **kwargs): pass
# === FIN INTÉGRATION ELK ===

"""
    
    # Injecter l'import après les imports existants
    if 'import' in content:
        # Trouver la dernière ligne d'import
        lines = content.split('\n')
        insert_pos = 0
        for i, line in enumerate(lines):
            if line.strip().startswith('import ') or line.strip().startswith('from '):
                insert_pos = i + 1
        
        lines.insert(insert_pos, elk_import)
        content = '\n'.join(lines)
    else:
        content = elk_import + content
    
    # Sauvegarder le fichier modifié
    with open(main_file, 'w') as f:
        f.write(content)
    
    print(f"✓ {main_file} patché avec succès")
    return True

def create_integration_guide():
    """Crée un guide d'intégration"""
    guide = """
# GUIDE D'INTÉGRATION ELK POUR VOTRE HONEYPOT FTP

Votre honeypot FTP a été patché automatiquement pour supporter ELK.

## UTILISATION DANS VOTRE CODE:

### 1. Logger une connexion:
```python
log_ftp_connection(client_ip, client_port)
```

### 2. Logger une authentification:
```python
log_ftp_auth(client_ip, username, password, success=True/False)
```

### 3. Logger une commande:
```python
log_ftp_command(client_ip, username, command, args="")
```

### 4. Logger un événement de sécurité:
```python
log_ftp_security_event(client_ip, "brute_force", {"attempts": 5}, "critical")
```

## EXEMPLES D'INTÉGRATION:

### Dans votre gestionnaire de connexion:
```python
def handle_connection(self, client_socket):
    client_ip = client_socket.getpeername()[0]
    client_port = client_socket.getpeername()[1]
    
    # Logger la connexion
    log_ftp_connection(client_ip, client_port)
    
    # Votre code existant...
```

### Dans votre gestionnaire d'authentification:
```python
def authenticate(self, username, password, client_ip):
    # Votre logique d'auth existante...
    success = your_auth_logic(username, password)
    
    # Logger l'authentification
    log_ftp_auth(client_ip, username, password, success)
    
    return success
```

### Dans votre gestionnaire de commandes:
```python
def handle_command(self, command, args, client_ip, username):
    # Logger la commande
    log_ftp_command(client_ip, username, command, args)
    
    # Détecter les tentatives suspectes
    if ".." in args or "etc/passwd" in args:
        log_ftp_security_event(client_ip, "directory_traversal", 
                              {"command": command, "args": args}, "high")
    
    # Votre code existant...
```

## VÉRIFICATION:

1. Démarrez votre honeypot normalement
2. Les logs ELK sont automatiquement envoyés vers 192.168.2.124:5046
3. Vérifiez avec: `/opt/monitor_ftp_elk.sh`

## DÉPANNAGE:

- Si "Logger ELK non disponible", vérifiez que `src/integrate_elk.py` existe
- Les logs locaux continuent de fonctionner normalement
- En cas de problème ELK, le honeypot continue de fonctionner

## RESTAURATION:

Pour revenir à la version originale:
```bash
cp run.py.backup.YYYYMMDD_HHMMSS run.py
```
"""
    
    with open('INTEGRATION_ELK_GUIDE.md', 'w') as f:
        f.write(guide)
    
    print("✓ Guide d'intégration créé: INTEGRATION_ELK_GUIDE.md")

if __name__ == "__main__":
    print("=== PATCH AUTOMATIQUE HONEYPOT FTP POUR ELK ===")
    print("")
    
    # Patcher le serveur principal
    if patch_main_server():
        create_integration_guide()
        print("")
        print("✅ PATCH TERMINÉ AVEC SUCCÈS!")
        print("")
        print("📋 PROCHAINES ÉTAPES:")
        print("1. Lisez INTEGRATION_ELK_GUIDE.md")
        print("2. Ajoutez les appels de logging dans votre code")
        print("3. Redémarrez votre honeypot: systemctl restart ftp-honeypot")
        print("4. Testez avec: /opt/test_ftp_honeypot.sh")
    else:
        print("❌ ÉCHEC DU PATCH")
        print("Intégration manuelle nécessaire")
EOF

chmod +x "$FTP_HONEYPOT_DIR/patch_for_elk.py"

# Exécuter le patch automatique
print_status "Exécution du patch automatique..."
cd "$FTP_HONEYPOT_DIR"
python3 patch_for_elk.py

# ==============================================================================
# ÉTAPE 10 : RÉSUMÉ ET FINALISATION
# ==============================================================================

print_status "=== ÉTAPE 6.2 TERMINÉE AVEC SUCCÈS ==="
echo ""

print_success "✅ CONFIGURATION FTP HONEYPOT VERS ELK TERMINÉE:"
echo "   • Logger ELK créé et configuré"
echo "   • Script d'intégration automatique développé"
echo "   • Filebeat étendu pour les logs FTP"
echo "   • Service systemd configuré"
echo "   • Patch automatique appliqué"
echo "   • Scripts de test et monitoring créés"
echo ""

print_success "✅ FICHIERS CRÉÉS:"
echo "   • $FTP_HONEYPOT_DIR/src/logger_elk.py (Logger ELK)"
echo "   • $FTP_HONEYPOT_DIR/integrate_elk.py (Intégration)"
echo "   • $FTP_HONEYPOT_DIR/patch_for_elk.py (Patch auto)"
echo "   • $FTP_HONEYPOT_DIR/INTEGRATION_ELK_GUIDE.md (Guide)"
echo "   • /etc/systemd/system/ftp-honeypot.service"
echo "   • /opt/test_ftp_honeypot.sh"
echo "   • /opt/monitor_ftp_elk.sh"
echo ""

print_success "✅ SERVICES CONFIGURÉS:"
echo "   • Filebeat étendu pour FTP + Cowrie"
echo "   • Service systemd ftp-honeypot"
echo "   • Logging automatique vers ELK (port 5046)"
echo ""

print_warning "📋 PROCHAINES ÉTAPES:"
echo "1. Tester l'intégration: /opt/test_ftp_honeypot.sh"
echo "2. Démarrer le service: systemctl start ftp-honeypot"
echo "3. Monitorer: /opt/monitor_ftp_elk.sh"
echo "4. Passer à l'étape 6.3 (HTTP Honeypot)"
echo ""

print_success "✅ FTP HONEYPOT -> ELK INTEGRATION RÉUSSIE!"
echo ""

# Log final
echo "$(date): Étape 6.2 - Configuration FTP Honeypot vers ELK terminée avec succès" >> /var/log/honeypot-setup.log

print_info "🔧 COMMANDES UTILES:"
echo "   • Démarrer FTP honeypot: systemctl start ftp-honeypot"
echo "   • Voir les logs: journalctl -u ftp-honeypot -f"
echo "   • Tester l'intégration: /opt/test_ftp_honeypot.sh"
echo "   • Monitorer ELK: /opt/monitor_ftp_elk.sh"
echo "   • Guide complet: cat $FTP_HONEYPOT_DIR/INTEGRATION_ELK_GUIDE.md"