#!/bin/bash
# Script de correction Filebeat - VM Honeypot (192.168.2.117)
# Corrige les variables non résolues et les chemins de fichiers

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

print_status "=== CORRECTION CONFIGURATION FILEBEAT ==="

# 1. Vérifier qu'on est sur la bonne VM
CURRENT_IP=$(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')
if [ "$CURRENT_IP" != "192.168.2.117" ]; then
    print_error "Ce script doit être exécuté sur la VM honeypot (192.168.2.117)"
    print_error "IP actuelle: $CURRENT_IP"
    exit 1
fi

# 2. Arrêter Filebeat
print_status "Arrêt de Filebeat..."
systemctl stop filebeat

# 3. Sauvegarder l'ancienne configuration
print_status "Sauvegarde de l'ancienne configuration..."
BACKUP_FILE="/etc/filebeat/filebeat.yml.backup.$(date +%Y%m%d_%H%M%S)"
cp /etc/filebeat/filebeat.yml "$BACKUP_FILE"
print_info "Sauvegarde créée : $BACKUP_FILE"

# 4. Créer la nouvelle configuration corrigée
print_status "Création de la nouvelle configuration..."

cat > /etc/filebeat/filebeat.yml << 'EOF'
# Configuration Filebeat pour Honeypots vers ELK Stack
# VM Honeypot: 192.168.2.117 → VM ELK: 192.168.2.124

# ================================
# FILEBEAT INPUTS
# ================================
filebeat.inputs:

# Input pour Cowrie SSH Honeypot
- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json*
    - /home/cowrie/cowrie/var/log/cowrie/*.json*
  fields:
    honeypot_type: ssh
    honeypot_service: cowrie
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after

# Input pour HTTP Honeypot - Log principal
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

# Input pour HTTP Honeypot - Injections SQL
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

# Input pour HTTP Honeypot - Accès API
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

# Input pour HTTP Honeypot - Alertes critiques
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

# Input pour HTTP Honeypot - Erreurs SQL
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

# Input pour FTP Honeypot - Sessions JSON
- type: log
  enabled: true
  paths:
    - /root/honeypot-ftp/logs/sessions.json
  fields:
    honeypot_type: ftp
    honeypot_service: ftp_sessions
    attack_category: session
    source_vm: "192.168.2.117"
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

# Input pour FTP Honeypot - Log serveur général
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
  json.keys_under_root: true
  json.add_error_key: true

# Input pour FTP Honeypot - Tentatives d'authentification
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
  json.keys_under_root: true
  json.add_error_key: true

# Input pour FTP Honeypot - Commandes
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
  json.keys_under_root: true
  json.add_error_key: true

# Input pour FTP Honeypot - Événements de sécurité
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
  json.keys_under_root: true
  json.add_error_key: true

# Input pour FTP Honeypot - Transferts
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
  json.keys_under_root: true
  json.add_error_key: true

# Input pour logs système (auth.log pour comparaison)
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

# ================================
# FILEBEAT PROCESSORS
# ================================
processors:
  # Ajouter des métadonnées sur l'hôte
  - add_host_metadata:
      when.not.contains.tags: forwarded

# ================================
# OUTPUT VERS LOGSTASH (CORRIGÉ !)
# ================================
output.logstash:
  hosts: ["192.168.2.124:5044"]
  compression_level: 3
  bulk_max_size: 2048
  worker: 2

# ================================
# CONFIGURATION GÉNÉRALE
# ================================
name: "honeypot-filebeat"
tags: ["honeypot", "filebeat", "security"]

# Monitoring (désactivé)
monitoring.enabled: false

# Logging
logging.level: info
logging.to_files: true
logging.files:
  path: /var/log/filebeat
  name: filebeat
  keepfiles: 7
  permissions: 0644

# ================================
# PERFORMANCE ET SÉCURITÉ
# ================================
queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 5s

# Templates d'index (désactivé car géré par Logstash)
setup.template.enabled: false
setup.ilm.enabled: false
EOF

print_status "✅ Nouvelle configuration créée"

# 5. Vérifier les permissions
print_status "Configuration des permissions..."
chown root:root /etc/filebeat/filebeat.yml
chmod 600 /etc/filebeat/filebeat.yml

# 6. Test de la configuration
print_status "Test de la configuration..."
if filebeat test config; then
    print_status "✅ Configuration valide"
else
    print_error "❌ Configuration invalide"
    print_error "Restauration de l'ancienne configuration..."
    cp "$BACKUP_FILE" /etc/filebeat/filebeat.yml
    exit 1
fi

# 7. Test de connectivité vers Logstash
print_status "Test de connectivité vers Logstash..."
if nc -z 192.168.2.124 5044 2>/dev/null; then
    print_status "✅ Port 5044 accessible"
else
    print_warning "⚠️ Port 5044 non accessible - Logstash pas encore configuré"
fi

# 8. Test de sortie Filebeat
print_info "Test de la sortie Filebeat..."
if filebeat test output; then
    print_status "✅ Connexion Logstash OK"
else
    print_warning "⚠️ Connexion Logstash échoue - normal si Logstash pas configuré"
fi

# 9. Redémarrer Filebeat
print_status "Redémarrage de Filebeat..."
systemctl start filebeat
systemctl enable filebeat

# Attendre le démarrage
sleep 5

# 10. Vérifier le statut
if systemctl is-active --quiet filebeat; then
    print_status "✅ Filebeat démarré avec succès"
else
    print_error "❌ Problème de démarrage Filebeat"
    print_error "Logs d'erreur:"
    journalctl -u filebeat --no-pager -n 10
    exit 1
fi

# 11. Vérifier les fichiers de logs
print_status "Vérification des fichiers de logs..."

logs_to_check=(
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
    "/var/log/honeypot/http_honeypot.log"
    "/var/log/honeypot/sql_injection.log"
    "/var/log/honeypot/api_access.log"
    "/var/log/honeypot/critical_alerts.log"
    "/var/log/honeypot/sql_error.log"
    "/root/honeypot-ftp/logs/sessions.json"
    "/root/honeypot-ftp/logs/ftp_server.log"
    "/root/honeypot-ftp/logs/auth_attempts.log"
    "/root/honeypot-ftp/logs/commands.log"
    "/root/honeypot-ftp/logs/security_events.log"
    "/root/honeypot-ftp/logs/transfers.log"
)

for log_file in "${logs_to_check[@]}"; do
    if [ -f "$log_file" ]; then
        SIZE=$(wc -l < "$log_file" 2>/dev/null || echo "0")
        print_info "✅ $log_file: $SIZE lignes"
    else
        print_warning "⚠️ $log_file: Fichier manquant"
    fi
done

# 12. Créer un script de monitoring
print_status "Création du script de monitoring..."

cat > /opt/monitor_filebeat_honeypot.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== MONITORING FILEBEAT HONEYPOT ==="
echo ""
echo "📊 Status Filebeat:"
echo "Service: $(systemctl is-active filebeat)"
echo "Enabled: $(systemctl is-enabled filebeat)"
echo ""
echo "🔗 Connectivité:"
nc -z 192.168.2.124 5044 2>&1 | grep -q "succeeded" && echo "✅ Logstash accessible" || echo "❌ Logstash inaccessible"
echo ""
echo "📈 Statistiques Filebeat:"
curl -s "http://localhost:5066/stats" 2>/dev/null | jq -r '.filebeat.events.active // "N/A"' | sed 's/^/Events actifs: /' || echo "API non accessible"
echo ""
echo "📁 Logs surveillés:"
echo "Cowrie: $(find /home/cowrie/cowrie/var/log/cowrie/ -name '*.json*' -type f 2>/dev/null | wc -l) fichiers"
echo "HTTP: $(ls -1 /var/log/honeypot/*.log 2>/dev/null | wc -l) fichiers"
echo "FTP: $(ls -1 /root/honeypot-ftp/logs/*.log /root/honeypot-ftp/logs/*.json 2>/dev/null | wc -l) fichiers"
echo ""
echo "🔍 Derniers logs Filebeat:"
journalctl -u filebeat --no-pager -n 5 | tail -5
MONITOR_EOF

chmod +x /opt/monitor_filebeat_honeypot.sh

# 13. Résumé final
print_status "=== CORRECTION TERMINÉE ==="
echo ""
print_info "📊 RÉSUMÉ:"
echo "✅ Configuration Filebeat corrigée"
echo "✅ Variables résolues (192.168.2.124:5044)"
echo "✅ Chemins de logs ajustés (cowrie.json*)"
echo "✅ Service redémarré et activé"
echo "✅ Script de monitoring créé: /opt/monitor_filebeat_honeypot.sh"
echo ""
print_info "📁 FICHIERS:"
echo "Config actuelle: /etc/filebeat/filebeat.yml"
echo "Sauvegarde: $BACKUP_FILE"
echo "Monitoring: /opt/monitor_filebeat_honeypot.sh"
echo ""
print_warning "🎯 PROCHAINES ÉTAPES:"
echo "1. Configurer Logstash sur VM ELK (192.168.2.124)"
echo "2. Surveiller: /opt/monitor_filebeat_honeypot.sh"
echo "3. Logs en temps réel: journalctl -u filebeat -f"
echo ""
print_status "Filebeat prêt à envoyer vers ELK !"