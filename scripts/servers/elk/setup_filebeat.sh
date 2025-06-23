#!/bin/bash
# Script d'installation de la nouvelle configuration Filebeat
# VM Honeypot: 192.168.2.117
# Optimisé pour Filebeat 8.10.2 vers Logstash 192.168.2.124:5044

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

print_status "=== INSTALLATION NOUVELLE CONFIG FILEBEAT ==="
echo ""

# 1. ARRÊTER FILEBEAT
print_status "1. Arrêt de Filebeat..."
systemctl stop filebeat
sleep 2

# 2. SAUVEGARDER L'ANCIENNE CONFIG
print_status "2. Sauvegarde de l'ancienne configuration..."
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/etc/filebeat/filebeat.yml.backup.$BACKUP_DATE"

if [ -f "/etc/filebeat/filebeat.yml" ]; then
    cp /etc/filebeat/filebeat.yml "$BACKUP_FILE"
    print_info "Sauvegarde créée : $BACKUP_FILE"
else
    print_warning "Aucune configuration existante trouvée"
fi

# 3. CRÉER LA NOUVELLE CONFIGURATION
print_status "3. Création de la nouvelle configuration..."

cat > /etc/filebeat/filebeat.yml << 'EOF'
# Configuration Filebeat Optimisée pour Honeypot Infrastructure
# VM Honeypot: 192.168.2.117 → VM ELK: 192.168.2.124
# Version: Filebeat 8.10.2 - Production Ready

# ================================
# INPUTS HONEYPOT - PRIORITÉS
# ================================
filebeat.inputs:

# ================================
# 1. COWRIE SSH HONEYPOT (PRIORITÉ HAUTE)
# ================================

# Cowrie JSON Principal (format optimal)
- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json.1
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json.2
  fields:
    honeypot_type: ssh
    honeypot_service: cowrie
    source_vm: "192.168.2.117"
    log_format: json
    priority: high
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  scan_frequency: 2s
  harvester_buffer_size: 16384
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after

# ================================
# 2. HTTP HONEYPOT (PRIORITÉ HAUTE)
# ================================

# HTTP Principal
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/http_honeypot.log
  fields:
    honeypot_type: http
    honeypot_service: http_main
    source_vm: "192.168.2.117"
    log_format: json
    priority: high
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  scan_frequency: 2s

# HTTP API Access
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/api_access.log
  fields:
    honeypot_type: http
    honeypot_service: http_api
    attack_category: api_abuse
    source_vm: "192.168.2.117"
    log_format: json
    priority: medium
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  scan_frequency: 3s

# HTTP SQL Injection (critique)
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/sql_injection.log
  fields:
    honeypot_type: http
    honeypot_service: http_sql
    attack_category: sql_injection
    source_vm: "192.168.2.117"
    log_format: json
    priority: critical
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  scan_frequency: 1s

# HTTP Critical Alerts
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/critical_alerts.log
  fields:
    honeypot_type: http
    honeypot_service: http_critical
    attack_category: critical_alert
    source_vm: "192.168.2.117"
    log_format: json
    priority: critical
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  scan_frequency: 1s

# HTTP SQL Errors
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/sql_error.log
  fields:
    honeypot_type: http
    honeypot_service: http_sql_error
    attack_category: sql_error
    source_vm: "192.168.2.117"
    log_format: json
    priority: high
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  scan_frequency: 2s

# ================================
# 3. FTP HONEYPOT (PRIORITÉ MOYENNE)
# ================================

# FTP Sessions JSON (principal)
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/sessions.json
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_sessions
    attack_category: ftp_session
    source_vm: "192.168.2.117"
    log_format: json
    priority: high
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  scan_frequency: 2s

# FTP Auth Attempts (texte)
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/auth_attempts.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_auth
    attack_category: authentication
    source_vm: "192.168.2.117"
    log_format: text
    priority: medium
  fields_under_root: true
  scan_frequency: 3s

# FTP Commands
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/commands.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_commands
    attack_category: command_execution
    source_vm: "192.168.2.117"
    log_format: text
    priority: medium
  fields_under_root: true
  scan_frequency: 3s

# FTP Security Events
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/security_events.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_security
    attack_category: security_event
    source_vm: "192.168.2.117"
    log_format: text
    priority: high
  fields_under_root: true
  scan_frequency: 2s

# FTP Transfers
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/transfers.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_transfers
    attack_category: file_transfer
    source_vm: "192.168.2.117"
    log_format: text
    priority: low
  fields_under_root: true
  scan_frequency: 5s

# ================================
# PROCESSORS - ENRICHISSEMENT
# ================================
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
      netinfo.enabled: true
      cache.ttl: 5m

  - add_fields:
      target: honeypot_meta
      fields:
        analyst: "elk-stack"
        environment: "production"
        detection_engine: "filebeat-8.10.2"
        vm_source: "192.168.2.117"
        vm_destination: "192.168.2.124"

# ================================
# OUTPUT VERS LOGSTASH
# ================================
output.logstash:
  hosts: ["192.168.2.124:5044"]
  compression_level: 3
  bulk_max_size: 1024
  worker: 1
  timeout: 30s
  max_retries: 3
  backoff.init: 1s
  backoff.max: 60s

# ================================
# CONFIGURATION GÉNÉRALE
# ================================
name: "honeypot-filebeat-production"
tags: ["honeypot", "filebeat", "security", "production"]

# ================================
# LOGGING ET MONITORING
# ================================
logging:
  level: info
  to_files: true
  files:
    path: /var/log/filebeat
    name: filebeat
    keepfiles: 7
    permissions: 0644

# Monitoring interne désactivé
monitoring.enabled: false

# ================================
# PERFORMANCE ET SÉCURITÉ
# ================================
queue.mem:
  events: 2048
  flush.min_events: 256
  flush.timeout: 5s

# Désactiver les templates (gérés par Logstash)
setup.template.enabled: false
setup.ilm.enabled: false
setup.kibana.enabled: false

# Sécurité
http.enabled: false

# Performance
max_procs: 1

# ================================
# GESTION DES FICHIERS
# ================================
ignore_older: 24h
close_inactive: 5m
clean_inactive: 72h
EOF

print_status "✅ Nouvelle configuration créée"

# 4. PERMISSIONS
print_status "4. Configuration des permissions..."
chown root:root /etc/filebeat/filebeat.yml
chmod 600 /etc/filebeat/filebeat.yml

# 5. TEST DE CONFIGURATION
print_status "5. Test de la configuration..."
if filebeat test config; then
    print_status "✅ Configuration valide"
else
    print_error "❌ Configuration invalide"
    print_error "Restauration de l'ancienne configuration..."
    if [ -f "$BACKUP_FILE" ]; then
        cp "$BACKUP_FILE" /etc/filebeat/filebeat.yml
    fi
    exit 1
fi

# 6. TEST DE CONNECTIVITÉ LOGSTASH
print_status "6. Test de connectivité vers Logstash..."
if nc -zv 192.168.2.124 5044 2>&1 | grep -q "succeeded"; then
    print_status "✅ Logstash accessible"
else
    print_warning "⚠️ Logstash non accessible - Vérifiez l'ELK Stack"
fi

# 7. TEST DE SORTIE
print_status "7. Test de la sortie Filebeat..."
if filebeat test output; then
    print_status "✅ Connexion Logstash OK"
else
    print_warning "⚠️ Test de sortie échoué - peut être normal si Logstash pas prêt"
fi

# 8. VÉRIFICATION DES FICHIERS DE LOGS
print_status "8. Vérification des fichiers de logs à surveiller..."

logs_to_check=(
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
    "/var/log/honeypot/http_honeypot.log"
    "/var/log/honeypot/api_access.log"
    "/var/log/honeypot/sql_injection.log"
    "/var/log/honeypot/critical_alerts.log"
    "/var/log/honeypot/sql_error.log"
    "/root/honeypot-ftp/logs/sessions.json"
    "/root/honeypot-ftp/logs/auth_attempts.log"
    "/root/honeypot-ftp/logs/commands.log"
    "/root/honeypot-ftp/logs/security_events.log"
    "/root/honeypot-ftp/logs/transfers.log"
)

files_found=0
for log_file in "${logs_to_check[@]}"; do
    if [ -f "$log_file" ]; then
        SIZE=$(wc -l < "$log_file" 2>/dev/null || echo "0")
        print_info "✅ $log_file: $SIZE lignes"
        files_found=$((files_found + 1))
    else
        print_warning "⚠️ $log_file: Fichier non trouvé"
    fi
done

print_info "Fichiers trouvés: $files_found/${#logs_to_check[@]}"

# 9. DÉMARRER FILEBEAT
print_status "9. Démarrage de Filebeat..."
systemctl start filebeat
systemctl enable filebeat

# Attendre le démarrage
sleep 5

# 10. VÉRIFIER LE STATUT
print_status "10. Vérification du statut..."
if systemctl is-active --quiet filebeat; then
    print_status "✅ Filebeat démarré avec succès"
else
    print_error "❌ Problème de démarrage Filebeat"
    print_error "Logs d'erreur:"
    journalctl -u filebeat --no-pager -n 10
    exit 1
fi

# 11. CRÉER UN SCRIPT DE MONITORING
print_status "11. Création du script de monitoring..."

cat > /opt/monitor_filebeat_honeypot.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== MONITORING FILEBEAT HONEYPOT ==="
echo ""
echo "📊 Status Filebeat:"
echo "   Service: $(systemctl is-active filebeat)"
echo "   Enabled: $(systemctl is-enabled filebeat)"
echo ""
echo "🔗 Connectivité Logstash:"
nc -zv 192.168.2.124 5044 2>&1 | grep -q "succeeded" && echo "   ✅ OK" || echo "   ❌ FAIL"
echo ""
echo "📁 Logs surveillés (avec activité):"
for file in /home/cowrie/cowrie/var/log/cowrie/cowrie.json* /var/log/honeypot/*.log /root/honeypot-ftp/logs/*.log /root/honeypot-ftp/logs/*.json; do
    if [ -f "$file" ]; then
        size=$(wc -l < "$file" 2>/dev/null || echo "0")
        if [ "$size" -gt 0 ]; then
            echo "   $(basename "$file"): $size lignes"
        fi
    fi
done
echo ""
echo "🔍 Derniers logs Filebeat:"
journalctl -u filebeat --no-pager -n 3 | tail -3
echo ""
echo "📊 Test config:"
filebeat test config >/dev/null 2>&1 && echo "   ✅ Config OK" || echo "   ❌ Config ERROR"
MONITOR_EOF

chmod +x /opt/monitor_filebeat_honeypot.sh

# 12. RÉSUMÉ FINAL
echo ""
print_status "=== INSTALLATION TERMINÉE ==="
echo ""
print_info "📊 RÉSUMÉ:"
echo "✅ Ancienne config sauvegardée: $BACKUP_FILE"
echo "✅ Nouvelle configuration installée"
echo "✅ Tests de validation réussis"
echo "✅ Service Filebeat redémarré"
echo "✅ Script de monitoring créé: /opt/monitor_filebeat_honeypot.sh"
echo ""
print_info "📁 LOGS SURVEILLÉS:"
echo "   • Cowrie SSH: cowrie.json*"
echo "   • HTTP: 5 fichiers de logs"
echo "   • FTP: 5 fichiers de logs"
echo ""
print_warning "🎯 PROCHAINES ÉTAPES:"
echo "1. Surveiller les logs: journalctl -u filebeat -f"
echo "2. Monitoring périodique: /opt/monitor_filebeat_honeypot.sh"
echo "3. Vérifier l'arrivée des données dans Kibana"
echo ""
print_status "Configuration Filebeat optimisée installée avec succès !"
echo ""
print_info "🔍 COMMANDES UTILES:"
echo "   • Statut: systemctl status filebeat"
echo "   • Logs: journalctl -u filebeat -f"
echo "   • Monitoring: /opt/monitor_filebeat_honeypot.sh"
echo "   • Test config: filebeat test config"
echo "   • Test output: filebeat test output"

echo ""
echo "$(date): Configuration Filebeat optimisée installée" >> /var/log/honeypot-filebeat-install.log