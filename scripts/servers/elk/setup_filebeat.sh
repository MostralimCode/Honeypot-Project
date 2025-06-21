#!/bin/bash
# Script de déploiement Filebeat optimisé pour infrastructure honeypot
# VM Honeypot: 192.168.2.117 → VM ELK: 192.168.2.124
# Étape 6.1 - Configuration optimale

# ================================
# VARIABLES ET COULEURS
# ================================
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }
print_header() { echo -e "${CYAN}[===] $1${NC}"; }

# ================================
# VÉRIFICATIONS PRÉLIMINAIRES
# ================================

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

print_header "DÉPLOIEMENT FILEBEAT OPTIMISÉ - ÉTAPE 6.1"
echo ""

# Vérifier qu'on est sur la bonne VM
CURRENT_IP=$(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')
if [ "$CURRENT_IP" != "192.168.2.117" ]; then
    print_error "Ce script doit être exécuté sur la VM honeypot (192.168.2.117)"
    print_error "IP actuelle: $CURRENT_IP"
    exit 1
fi

print_status "✅ Déploiement sur VM honeypot : $CURRENT_IP"

# ================================
# VÉRIFICATION DES HONEYPOTS
# ================================

print_status "Vérification de la structure des honeypots..."

# Vérifier Cowrie
if [ -d "/home/cowrie/cowrie/var/log/cowrie/" ]; then
    COWRIE_FILES=$(find /home/cowrie/cowrie/var/log/cowrie/ -name "*.json*" -o -name "*.log*" | wc -l)
    print_status "✅ Cowrie SSH : $COWRIE_FILES fichiers de logs"
else
    print_warning "⚠️ Répertoire Cowrie non trouvé"
fi

# Vérifier HTTP
if [ -d "/var/log/honeypot/" ]; then
    HTTP_FILES=$(find /var/log/honeypot/ -name "*.log" | wc -l)
    print_status "✅ HTTP Honeypot : $HTTP_FILES fichiers de logs"
else
    print_warning "⚠️ Répertoire HTTP honeypot non trouvé"
fi

# Vérifier FTP
if [ -d "/root/honeypot-ftp/logs/" ]; then
    FTP_FILES=$(find /root/honeypot-ftp/logs/ -name "*.log" -o -name "*.json" | wc -l)
    print_status "✅ FTP Honeypot : $FTP_FILES fichiers de logs"
else
    print_warning "⚠️ Répertoire FTP honeypot non trouvé"
fi

echo ""

# ================================
# SAUVEGARDE ET ARRÊT
# ================================

print_status "Arrêt de Filebeat et sauvegarde..."

# Arrêter Filebeat
systemctl stop filebeat 2>/dev/null || print_info "Filebeat n'était pas en cours d'exécution"

# Sauvegarder l'ancienne configuration
BACKUP_DIR="/opt/filebeat-backups"
mkdir -p "$BACKUP_DIR"
BACKUP_FILE="$BACKUP_DIR/filebeat.yml.backup.$(date +%Y%m%d_%H%M%S)"

if [ -f "/etc/filebeat/filebeat.yml" ]; then
    cp /etc/filebeat/filebeat.yml "$BACKUP_FILE"
    print_status "✅ Sauvegarde créée : $BACKUP_FILE"
else
    print_info "Aucune configuration existante trouvée"
fi

# ================================
# DÉPLOIEMENT CONFIGURATION
# ================================

print_status "Déploiement de la configuration optimale..."

cat > /etc/filebeat/filebeat.yml << 'EOF'
# Configuration Filebeat Optimale pour Infrastructure Honeypot
# VM Honeypot: 192.168.2.117 → VM ELK: 192.168.2.124
# Support: SSH (Cowrie) + HTTP + FTP honeypots

# ================================
# FILEBEAT INPUTS - HONEYPOTS
# ================================
filebeat.inputs:

# ================================
# COWRIE SSH HONEYPOT
# ================================

# Input principal Cowrie JSON (PRIORITÉ 1)
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
  json.message_key: message
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after
  scan_frequency: 2s
  harvester_buffer_size: 32768
  max_bytes: 10485760

# Input Cowrie logs texte (complément)
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

# ================================
# HTTP HONEYPOT
# ================================

# HTTP Principal
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
    infrastructure: honeypot
    priority: medium
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  scan_frequency: 3s

# HTTP SQL Injection
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
    attack_category: critical
    source_vm: "192.168.2.117"
    infrastructure: honeypot
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
    infrastructure: honeypot
    priority: high
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  scan_frequency: 2s

# ================================
# FTP HONEYPOT
# ================================

# FTP Sessions JSON (PRIORITÉ 1)
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
    priority: high
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after
  scan_frequency: 2s

# FTP Auth Attempts
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/auth_attempts.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_auth
    attack_category: authentication
    log_format: text
    source_vm: "192.168.2.117"
    infrastructure: honeypot
    priority: high
  fields_under_root: true
  scan_frequency: 2s

# FTP Commands
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/commands.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_commands
    attack_category: command_execution
    log_format: text
    source_vm: "192.168.2.117"
    infrastructure: honeypot
    priority: medium
  fields_under_root: true
  scan_frequency: 3s

# FTP Server Logs
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/ftp_server.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_server
    attack_category: general
    log_format: text
    source_vm: "192.168.2.117"
    infrastructure: honeypot
    priority: medium
  fields_under_root: true
  scan_frequency: 5s

# FTP Security Events
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/security_events.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_security
    attack_category: security_event
    log_format: text
    source_vm: "192.168.2.117"
    infrastructure: honeypot
    priority: critical
  fields_under_root: true
  scan_frequency: 1s

# FTP Transfers
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/transfers.log
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_transfers
    attack_category: file_transfer
    log_format: text
    source_vm: "192.168.2.117"
    infrastructure: honeypot
    priority: medium
  fields_under_root: true
  scan_frequency: 3s

# ================================
# LOGS SYSTÈME (COMPARAISON)
# ================================

# System Auth Log
- type: log
  enabled: true
  paths:
    - /var/log/auth.log
  fields:
    honeypot_type: system
    honeypot_service: system_auth
    attack_category: system
    log_format: text
    source_vm: "192.168.2.117"
    infrastructure: honeypot_system
    priority: low
  fields_under_root: true
  scan_frequency: 10s

# ================================
# PROCESSORS - ENRICHISSEMENT
# ================================
processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
      netinfo.enabled: true
      cache.ttl: 5m
      geo.name: vm_honeypot
      geo.location: "FR-IDF-192.168.2.117"
      
  - timestamp:
      field: "@timestamp"
      layouts:
        - '2006-01-02T15:04:05.000Z'
        - '2006-01-02T15:04:05Z'
      test:
        - '2025-01-01T12:34:56.789Z'
        
  - add_fields:
      target: security
      fields:
        analyst: "elk-stack"
        environment: "honeypot"
        detection_engine: "filebeat"
        data_classification: "security_telemetry"

# ================================
# OUTPUT VERS LOGSTASH
# ================================
output.logstash:
  hosts: ["192.168.2.124:5044"]
  compression_level: 3
  bulk_max_size: 2048
  worker: 2
  timeout: 30s
  max_retries: 3
  backoff.init: 1s
  backoff.max: 60s
  loadbalance: true
  pipelining: 2

# ================================
# CONFIGURATION GÉNÉRALE
# ================================
name: "honeypot-filebeat-optimized"
tags: ["honeypot", "filebeat", "security", "elk-stack", "production"]

# ================================
# MONITORING ET LOGGING
# ================================
monitoring:
  enabled: false

logging:
  level: info
  to_files: true
  files:
    path: /var/log/filebeat
    name: filebeat
    keepfiles: 7
    permissions: 0644
    rotateeverybytes: 100MB
  metrics:
    enabled: true
    period: 30s

# ================================
# PERFORMANCE
# ================================
queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 5s

max_procs: 2

# ================================
# SÉCURITÉ
# ================================
setup.template.enabled: false
setup.ilm.enabled: false
setup.kibana.enabled: false

http:
  enabled: false

# ================================
# GESTION DES ERREURS
# ================================
ignore_older: 24h
close_inactive: 5m
clean_inactive: 72h
EOF

print_status "✅ Configuration optimale déployée"

# ================================
# PERMISSIONS ET SÉCURITÉ
# ================================

print_status "Configuration des permissions..."

# Permissions fichier de configuration
chown root:root /etc/filebeat/filebeat.yml
chmod 600 /etc/filebeat/filebeat.yml

# Créer répertoire de logs
mkdir -p /var/log/filebeat
chown filebeat:filebeat /var/log/filebeat 2>/dev/null || chown root:root /var/log/filebeat

# ================================
# TESTS DE VALIDATION
# ================================

print_status "Tests de validation..."

# Test de syntaxe
print_info "Test de la configuration..."
if filebeat test config -c /etc/filebeat/filebeat.yml; then
    print_status "✅ Configuration syntaxiquement valide"
else
    print_error "❌ Erreur de configuration détectée"
    print_error "Restauration de la sauvegarde..."
    if [ -f "$BACKUP_FILE" ]; then
        cp "$BACKUP_FILE" /etc/filebeat/filebeat.yml
        print_info "Configuration restaurée"
    fi
    exit 1
fi

# Test de connectivité vers Logstash
print_info "Test de connectivité vers ELK (192.168.2.124:5044)..."
if timeout 5 nc -z 192.168.2.124 5044 2>/dev/null; then
    print_status "✅ Logstash accessible sur port 5044"
else
    print_warning "⚠️ Logstash non accessible - normal si pas encore démarré"
fi

# Test de sortie Filebeat
print_info "Test de la sortie Filebeat..."
if filebeat test output -c /etc/filebeat/filebeat.yml; then
    print_status "✅ Connexion vers Logstash validée"
else
    print_warning "⚠️ Test de sortie échoué - normal si Logstash pas configuré"
fi

# ================================
# DÉMARRAGE ET ACTIVATION
# ================================

print_status "Démarrage de Filebeat..."

# Activer le service
systemctl enable filebeat

# Démarrer Filebeat
systemctl start filebeat

# Attendre le démarrage
sleep 5

# Vérifier le statut
if systemctl is-active --quiet filebeat; then
    print_status "✅ Filebeat démarré avec succès"
else
    print_error "❌ Échec du démarrage de Filebeat"
    print_error "Logs d'erreur:"
    journalctl -u filebeat --no-pager -n 10
    exit 1
fi

# ================================
# SCRIPTS DE MONITORING
# ================================

print_status "Création des scripts de monitoring..."

# Script de monitoring principal
cat > /opt/monitor_filebeat_honeypot.sh << 'MONITOR_EOF'
#!/bin/bash
# Script de monitoring Filebeat - Honeypots

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

echo "=== MONITORING FILEBEAT HONEYPOT ==="
echo "Date: $(date)"
echo ""

# Statut service
print_info "📊 STATUT SERVICE:"
echo "Service: $(systemctl is-active filebeat)"
echo "Enabled: $(systemctl is-enabled filebeat)"
echo "Uptime: $(systemctl show --property=ActiveEnterTimestamp filebeat | cut -d= -f2)"
echo ""

# Connectivité
print_info "🔗 CONNECTIVITÉ:"
if timeout 3 nc -z 192.168.2.124 5044 2>/dev/null; then
    print_status "✅ Logstash (192.168.2.124:5044) accessible"
else
    print_error "❌ Logstash inaccessible"
fi
echo ""

# Statistiques Filebeat (si API activée)
print_info "📈 STATISTIQUES FILEBEAT:"
if curl -s --connect-timeout 2 "http://localhost:5066/stats" >/dev/null 2>&1; then
    EVENTS=$(curl -s "http://localhost:5066/stats" | jq -r '.filebeat.events.active // "N/A"' 2>/dev/null)
    echo "Events actifs: $EVENTS"
else
    echo "API monitoring non activée (normal)"
fi
echo ""

# Fichiers surveillés
print_info "📁 FICHIERS SURVEILLÉS:"
echo "Cowrie JSON: $(find /home/cowrie/cowrie/var/log/cowrie/ -name '*.json*' -type f 2>/dev/null | wc -l) fichiers"
echo "Cowrie LOG: $(find /home/cowrie/cowrie/var/log/cowrie/ -name '*.log*' -not -name '*.json*' -type f 2>/dev/null | wc -l) fichiers"
echo "HTTP: $(find /var/log/honeypot/ -name '*.log' -type f 2>/dev/null | wc -l) fichiers"
echo "FTP: $(find /root/honeypot-ftp/logs/ -name '*.log' -o -name '*.json' -type f 2>/dev/null | wc -l) fichiers"
echo ""

# Tailles des logs récents
print_info "📊 ACTIVITÉ RÉCENTE (dernières 24h):"
echo "Cowrie JSON:"
find /home/cowrie/cowrie/var/log/cowrie/ -name '*.json*' -type f -newermt '24 hours ago' 2>/dev/null | while read file; do
    if [ -f "$file" ]; then
        SIZE=$(wc -l < "$file" 2>/dev/null || echo "0")
        echo "  $(basename "$file"): $SIZE lignes"
    fi
done

echo "HTTP Honeypot:"
find /var/log/honeypot/ -name '*.log' -type f -newermt '24 hours ago' 2>/dev/null | while read file; do
    if [ -f "$file" ]; then
        SIZE=$(wc -l < "$file" 2>/dev/null || echo "0")
        echo "  $(basename "$file"): $SIZE lignes"
    fi
done

echo "FTP Honeypot:"
find /root/honeypot-ftp/logs/ -name '*.log' -o -name '*.json' -type f -newermt '24 hours ago' 2>/dev/null | while read file; do
    if [ -f "$file" ]; then
        SIZE=$(wc -l < "$file" 2>/dev/null || echo "0")
        echo "  $(basename "$file"): $SIZE lignes"
    fi
done
echo ""

# Derniers logs Filebeat
print_info "🔍 DERNIERS LOGS FILEBEAT:"
journalctl -u filebeat --no-pager -n 5 --since "5 minutes ago" | tail -5
echo ""

# Erreurs récentes
print_info "❌ ERREURS RÉCENTES:"
ERROR_COUNT=$(journalctl -u filebeat --no-pager --since "1 hour ago" | grep -i error | wc -l)
if [ "$ERROR_COUNT" -gt 0 ]; then
    print_warning "$ERROR_COUNT erreurs détectées dans la dernière heure"
    journalctl -u filebeat --no-pager --since "1 hour ago" | grep -i error | tail -3
else
    print_status "Aucune erreur récente"
fi
echo ""

# Recommandations
print_info "💡 ACTIONS RECOMMANDÉES:"
echo "• Surveiller les logs: journalctl -u filebeat -f"
echo "• Vérifier ELK Stack: curl http://192.168.2.124:9200/_cluster/health"
echo "• Kibana dashboard: http://192.168.2.124:5601"
echo "• Script de test: /opt/test_filebeat_integration.sh"
MONITOR_EOF

chmod +x /opt/monitor_filebeat_honeypot.sh

# Script de test d'intégration
cat > /opt/test_filebeat_integration.sh << 'TEST_EOF'
#!/bin/bash
# Script de test d'intégration Filebeat → ELK

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

echo "=== TEST INTÉGRATION FILEBEAT → ELK ==="
echo ""

# Test 1: Connectivité Logstash
print_info "Test 1: Connectivité Logstash"
if timeout 5 nc -z 192.168.2.124 5044; then
    print_status "✅ Logstash accessible"
else
    print_error "❌ Logstash inaccessible"
    exit 1
fi

# Test 2: Elasticsearch
print_info "Test 2: Elasticsearch"
if curl -s --connect-timeout 5 "http://192.168.2.124:9200" >/dev/null; then
    print_status "✅ Elasticsearch accessible"
else
    print_error "❌ Elasticsearch inaccessible"
    exit 1
fi

# Test 3: Kibana
print_info "Test 3: Kibana"
if curl -s --connect-timeout 5 "http://192.168.2.124:5601" >/dev/null; then
    print_status "✅ Kibana accessible"
else
    print_error "❌ Kibana inaccessible"
fi

# Test 4: Génération de logs de test
print_info "Test 4: Génération de logs de test"

# Créer un log de test Cowrie
TEST_LOG='{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","eventid":"cowrie.login.failed","src_ip":"192.168.1.100","username":"test","password":"test123","protocol":"ssh","message":"Test Filebeat Integration"}'
echo "$TEST_LOG" >> /home/cowrie/cowrie/var/log/cowrie/cowrie.json

# Créer un log de test HTTP
TEST_HTTP='{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","attack_id":"test-integration","attack_type":"test","severity":"low","ip":"192.168.1.100","method":"GET","path":"/test","honeypot":"http","message":"Test HTTP Integration"}'
echo "$TEST_HTTP" >> /var/log/honeypot/http_honeypot.log

print_status "✅ Logs de test générés"

# Attendre traitement
print_info "Attente traitement (30 secondes)..."
sleep 30

# Test 5: Vérification indices Elasticsearch
print_info "Test 5: Vérification des indices"
INDICES=$(curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?h=index" 2>/dev/null)
if [ -n "$INDICES" ]; then
    print_status "✅ Indices honeypot trouvés:"
    echo "$INDICES" | sed 's/^/    /'
else
    print_error "❌ Aucun indice honeypot trouvé"
fi

echo ""
print_info "🔗 LIENS UTILES:"
echo "• Elasticsearch: http://192.168.2.124:9200"
echo "• Kibana: http://192.168.2.124:5601" 
echo "• Logstash API: http://192.168.2.124:9600"
echo "• Monitoring: /opt/monitor_filebeat_honeypot.sh"
TEST_EOF

chmod +x /opt/test_filebeat_integration.sh

# Script de redémarrage sécurisé
cat > /opt/restart_filebeat_safe.sh << 'RESTART_EOF'
#!/bin/bash
# Redémarrage sécurisé de Filebeat

GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

echo "=== REDÉMARRAGE SÉCURISÉ FILEBEAT ==="

# Test de configuration
print_info "Test de la configuration..."
if ! filebeat test config; then
    print_error "❌ Configuration invalide - Arrêt"
    exit 1
fi

# Test de sortie
print_info "Test de la sortie..."
filebeat test output || print_info "Test de sortie échoué (normal si Logstash arrêté)"

# Redémarrage
print_info "Redémarrage de Filebeat..."
systemctl restart filebeat

sleep 3

if systemctl is-active --quiet filebeat; then
    print_status "✅ Filebeat redémarré avec succès"
    print_info "Monitoring: /opt/monitor_filebeat_honeypot.sh"
else
    print_error "❌ Échec du redémarrage"
    journalctl -u filebeat --no-pager -n 10
fi
RESTART_EOF

chmod +x /opt/restart_filebeat_safe.sh

print_status "✅ Scripts de monitoring créés"

# ================================
# VÉRIFICATION FINALE
# ================================

print_status "Vérification finale des fichiers de logs..."

# Fonction pour vérifier les fichiers
check_log_files() {
    local log_type="$1"
    shift
    local files=("$@")
    local found=0
    local total=0
    
    echo "--- $log_type ---"
    for file in "${files[@]}"; do
        total=$((total + 1))
        if [ -f "$file" ]; then
            SIZE=$(wc -l < "$file" 2>/dev/null || echo "0")
            print_status "✅ $(basename "$file"): $SIZE lignes"
            found=$((found + 1))
        else
            print_warning "⚠️ $(basename "$file"): Fichier non trouvé"
        fi
    done
    echo "Total: $found/$total fichiers trouvés"
    echo ""
}

# Vérifier tous les fichiers
cowrie_files=(
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.json.1"
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.log"
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.log.1"
)

http_files=(
    "/var/log/honeypot/http_honeypot.log"
    "/var/log/honeypot/api_access.log"
    "/var/log/honeypot/sql_injection.log"
    "/var/log/honeypot/critical_alerts.log"
    "/var/log/honeypot/sql_error.log"
)

ftp_files=(
    "/root/honeypot-ftp/logs/sessions.json"
    "/root/honeypot-ftp/logs/auth_attempts.log"
    "/root/honeypot-ftp/logs/commands.log"
    "/root/honeypot-ftp/logs/ftp_server.log"
    "/root/honeypot-ftp/logs/security_events.log"
    "/root/honeypot-ftp/logs/transfers.log"
)

check_log_files "COWRIE SSH" "${cowrie_files[@]}"
check_log_files "HTTP HONEYPOT" "${http_files[@]}"
check_log_files "FTP HONEYPOT" "${ftp_files[@]}"

# ================================
# RAPPORT FINAL
# ================================

print_header "DÉPLOIEMENT FILEBEAT TERMINÉ AVEC SUCCÈS"
echo ""

# Créer rapport de déploiement
REPORT_FILE="/opt/filebeat_deployment_report_$(date +%Y%m%d_%H%M%S).txt"
cat > "$REPORT_FILE" << EOF
=== RAPPORT DÉPLOIEMENT FILEBEAT OPTIMISÉ ===
Date: $(date)
VM: 192.168.2.117 → ELK: 192.168.2.124

✅ CONFIGURATION DÉPLOYÉE:
- Configuration: /etc/filebeat/filebeat.yml
- Sauvegarde: $BACKUP_FILE
- Scripts: /opt/*filebeat*.sh

✅ HONEYPOTS CONFIGURÉS:
- SSH (Cowrie): JSON + logs texte
- HTTP: 5 types de logs (API, SQL injection, etc.)
- FTP: 6 types de logs (sessions, auth, commands, etc.)
- Système: auth.log

✅ FONCTIONNALITÉS:
- Multi-input optimisé par type de honeypot
- Enrichissement métadonnées automatique
- Gestion rotation des logs
- Performance optimisée (compression, pipelining)
- Monitoring intégré

✅ SERVICES:
- Filebeat: $(systemctl is-active filebeat)
- Auto-start: $(systemctl is-enabled filebeat)

✅ CONNECTIVITÉ:
- Logstash: $(timeout 3 nc -z 192.168.2.124 5044 2>/dev/null && echo "OK" || echo "NOK")
- Configuration: VALIDÉE

🔧 SCRIPTS DISPONIBLES:
- Monitoring: /opt/monitor_filebeat_honeypot.sh
- Test intégration: /opt/test_filebeat_integration.sh
- Redémarrage sûr: /opt/restart_filebeat_safe.sh

📋 PROCHAINES ÉTAPES:
1. Vérifier l'ingestion dans Kibana: http://192.168.2.124:5601
2. Surveiller les logs: journalctl -u filebeat -f
3. Exécuter tests d'intégration: /opt/test_filebeat_integration.sh

Déploiement réalisé avec succès !
EOF

print_status "📄 Rapport généré: $REPORT_FILE"

echo ""
print_info "🎯 COMMANDES IMMÉDIATES:"
echo "# Surveiller Filebeat:"
echo "journalctl -u filebeat -f"
echo ""
echo "# Monitoring complet:"
echo "/opt/monitor_filebeat_honeypot.sh"
echo ""
echo "# Test d'intégration:"
echo "/opt/test_filebeat_integration.sh"
echo ""
echo "# Redémarrage sécurisé:"
echo "/opt/restart_filebeat_safe.sh"
echo ""

print_status "🚀 ÉTAPE 6.1 TERMINÉE AVEC SUCCÈS !"
print_info "📊 Filebeat optimisé pour infrastructure honeypot complète"
print_info "🔗 Prêt pour l'intégration avec ELK Stack (192.168.2.124)"

echo ""
print_header "FILEBEAT HONEYPOT OPÉRATIONNEL"