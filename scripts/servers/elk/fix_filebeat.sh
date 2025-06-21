#!/bin/bash
# Correction rapide de la configuration Filebeat
# VM Honeypot: 192.168.2.117

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

echo "=== CORRECTION CONFIGURATION FILEBEAT ==="
echo ""

# Arrêter Filebeat
print_status "Arrêt de Filebeat..."
systemctl stop filebeat

# Corriger la configuration
print_status "Correction de la configuration..."

# Remplacer la ligne problématique
sed -i 's/rotateeverybytes: 100MB/rotate_every_kb: 102400/' /etc/filebeat/filebeat.yml

# Alternative : supprimer complètement la ligne problématique
sed -i '/rotateeverybytes:/d' /etc/filebeat/filebeat.yml

# Créer une configuration corrigée complète
print_status "Création de la configuration corrigée..."

cat > /etc/filebeat/filebeat.yml << 'EOF'
# Configuration Filebeat Optimale - CORRIGÉE
# VM Honeypot: 192.168.2.117 → VM ELK: 192.168.2.124

filebeat.inputs:

# COWRIE SSH HONEYPOT
- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json*
  exclude_files: ['\.gz$', '\.bak$']
  fields:
    honeypot_type: ssh
    honeypot_service: cowrie
    log_format: json
    source_vm: "192.168.2.117"
    infrastructure: honeypot
    priority: high
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after
  scan_frequency: 2s

- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.log*
  exclude_files: ['\.gz$', '\.bak$', '\.json*']
  fields:
    honeypot_type: ssh
    honeypot_service: cowrie
    log_format: text
    source_vm: "192.168.2.117"
    infrastructure: honeypot
    priority: medium
  fields_under_root: true
  scan_frequency: 5s

# HTTP HONEYPOT
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/http_honeypot.log
  fields:
    honeypot_type: http
    honeypot_service: http_main
    attack_category: general
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

- type: log
  enabled: true
  paths:
    - /var/log/honeypot/api_access.log
  fields:
    honeypot_type: http
    honeypot_service: http_api
    attack_category: api_abuse
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

- type: log
  enabled: true
  paths:
    - /var/log/honeypot/sql_injection.log
  fields:
    honeypot_type: http
    honeypot_service: http_sql
    attack_category: sql_injection
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

- type: log
  enabled: true
  paths:
    - /var/log/honeypot/critical_alerts.log
  fields:
    honeypot_type: http
    honeypot_service: http_critical
    attack_category: critical
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

- type: log
  enabled: true
  paths:
    - /var/log/honeypot/sql_error.log
  fields:
    honeypot_type: http
    honeypot_service: http_sql_error
    attack_category: sql_error
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

# FTP HONEYPOT
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/sessions.json
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_sessions
    attack_category: session
    log_format: json
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after

- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/auth_attempts.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_auth
    attack_category: authentication
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/commands.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_commands
    attack_category: command_execution
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/ftp_server.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_server
    attack_category: general
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/security_events.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_security
    attack_category: security_event
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true

- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/transfers.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_transfers
    attack_category: file_transfer
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true

# LOGS SYSTÈME
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
  fields:
    honeypot_type: system
    honeypot_service: system_auth
    attack_category: system
    source_vm: "192.168.2.117"
    infrastructure: honeypot_system
  fields_under_root: true

# PROCESSORS
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded

# OUTPUT VERS LOGSTASH
output.logstash:
  hosts: ["192.168.2.124:5044"]
  compression_level: 3
  bulk_max_size: 2048
  worker: 2
  timeout: 30s
  max_retries: 3
  backoff.init: 1s
  backoff.max: 60s

# CONFIGURATION GÉNÉRALE
name: "honeypot-filebeat-corrected"
tags: ["honeypot", "filebeat", "security", "production"]

# LOGGING SIMPLIFIÉ (SANS ERREUR)
logging:
  level: info
  to_files: true
  files:
    path: /var/log/filebeat
    name: filebeat
    keepfiles: 7
    permissions: 0644

# PERFORMANCE
queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 5s

# SÉCURITÉ
setup.template.enabled: false
setup.ilm.enabled: false
setup.kibana.enabled: false

# GESTION ERREURS
ignore_older: 24h
close_inactive: 5m
clean_inactive: 72h
EOF

print_status "✅ Configuration corrigée créée"

# Permissions
chown root:root /etc/filebeat/filebeat.yml
chmod 600 /etc/filebeat/filebeat.yml

# Test de configuration
print_status "Test de la configuration corrigée..."
if filebeat test config; then
    print_status "✅ Configuration valide"
else
    print_error "❌ Configuration encore invalide"
    exit 1
fi

# Redémarrer Filebeat
print_status "Redémarrage de Filebeat..."
systemctl start filebeat
systemctl enable filebeat

sleep 3

if systemctl is-active --quiet filebeat; then
    print_status "✅ Filebeat démarré avec succès"
    print_info "Status: $(systemctl is-active filebeat)"
else
    print_error "❌ Échec du démarrage"
    journalctl -u filebeat --no-pager -n 5
fi

print_status "=== CORRECTION TERMINÉE ==="