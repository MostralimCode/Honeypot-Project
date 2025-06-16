#!/bin/bash
# scripts/integration/integrate_honeypots_elk.sh
# Intégration des honeypots (192.168.2.117) avec ELK Stack (192.168.2.124)

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

print_info() {
    echo -e "${BLUE}[i] $1${NC}"
}

# Variables
HONEYPOT_IP="192.168.2.117"
ELK_IP="192.168.2.124"
LOGSTASH_PORT="5044"

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root sur la VM HONEYPOT (192.168.2.117)"
    exit 1
fi

print_status "=== Intégration Honeypots vers ELK Stack ==="
echo "VM Honeypot: $HONEYPOT_IP"
echo "VM ELK: $ELK_IP"
echo ""

# ================================
# VÉRIFICATIONS PRÉLIMINAIRES
# ================================

print_status "Vérifications préliminaires..."

# Vérifier qu'on est sur la bonne VM
CURRENT_IP=$(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')
if [ "$CURRENT_IP" != "$HONEYPOT_IP" ]; then
    print_error "Ce script doit être exécuté sur la VM honeypot ($HONEYPOT_IP)"
    print_error "IP actuelle: $CURRENT_IP"
    exit 1
fi

# Vérifier la connectivité vers ELK
if ping -c 2 $ELK_IP >/dev/null 2>&1; then
    print_status "✓ Connectivité vers VM ELK OK"
else
    print_error "✗ Impossible de joindre la VM ELK ($ELK_IP)"
    exit 1
fi

# Tester Logstash port
if nc -z $ELK_IP $LOGSTASH_PORT 2>/dev/null; then
    print_status "✓ Logstash accessible sur port $LOGSTASH_PORT"
else
    print_warning "⚠ Port Logstash ($LOGSTASH_PORT) pas accessible - nous l'activerons"
fi

# ================================
# INSTALLATION DE FILEBEAT
# ================================

print_status "Installation de Filebeat..."

# Ajouter le repository Elastic si pas déjà fait
if [ ! -f /usr/share/keyrings/elasticsearch-keyring.gpg ]; then
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list
    apt update
fi

# Installer Filebeat
apt install -y filebeat

print_status "Filebeat installé"

# ================================
# VÉRIFICATION DES LOGS HONEYPOTS
# ================================

print_status "Vérification des emplacements des logs honeypots..."

# Vérifier les emplacements réels des logs
print_info "État actuel des logs:"

# Cowrie
COWRIE_LOG="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
if [ -f "$COWRIE_LOG" ]; then
    echo "  ✓ Cowrie: $(wc -l < $COWRIE_LOG) lignes dans $COWRIE_LOG"
else
    echo "  ⚠ Cowrie: $COWRIE_LOG n'existe pas encore"
    mkdir -p /home/cowrie/cowrie/var/log/cowrie/
    touch $COWRIE_LOG
fi

# HTTP Honeypot
HTTP_DIR="/var/log/honeypot"
echo "  ✓ HTTP: $(ls -1 $HTTP_DIR/*.log 2>/dev/null | wc -l) fichiers de logs HTTP"
for log_file in $HTTP_DIR/*.log; do
    [ -f "$log_file" ] && echo "    - $(basename $log_file): $(wc -l < $log_file) lignes"
done

# FTP Honeypot
FTP_DIR="/root/honeypot-ftp/logs"
echo "  ✓ FTP: $(ls -1 $FTP_DIR/*.log $FTP_DIR/*.json 2>/dev/null | wc -l) fichiers de logs FTP"
for log_file in $FTP_DIR/*.log $FTP_DIR/*.json; do
    [ -f "$log_file" ] && echo "    - $(basename $log_file): $(wc -l < $log_file) lignes"
done

print_status "Répertoires de logs préparés"

# ================================
# CONFIGURATION DE FILEBEAT
# ================================

print_status "Configuration de Filebeat pour les honeypots..."

# Sauvegarder la configuration originale
cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.backup.$(date +%Y%m%d_%H%M%S)

# Configuration Filebeat spécialisée honeypots
cat > /etc/filebeat/filebeat.yml << EOF
# Configuration Filebeat pour Honeypots vers ELK Stack
# VM Honeypot: $HONEYPOT_IP → VM ELK: $ELK_IP

# ================================
# FILEBEAT INPUTS
# ================================
filebeat.inputs:

# Input pour Cowrie SSH Honeypot
- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json
    - /home/cowrie/cowrie/var/log/cowrie/*.json
  fields:
    honeypot_type: ssh
    honeypot_service: cowrie
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

# Input pour HTTP Honeypot - Attaques XSS
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/xss.log
  fields:
    honeypot_type: http
    honeypot_service: http_xss
    attack_category: xss
    source_vm: $HONEYPOT_IP
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

# Input pour HTTP Honeypot - Traversée de chemin
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/path_traversal.log
  fields:
    honeypot_type: http
    honeypot_service: http_traversal
    attack_category: path_traversal
    source_vm: $HONEYPOT_IP
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

# Input pour HTTP Honeypot - Téléchargements
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/file_upload.log
  fields:
    honeypot_type: http
    honeypot_service: http_upload
    attack_category: file_upload
    source_vm: $HONEYPOT_IP
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

# Input pour HTTP Honeypot - Tentatives de connexion
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/login_attempt.log
  fields:
    honeypot_type: http
    honeypot_service: http_auth
    attack_category: authentication
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
    infrastructure: honeypot
  fields_under_root: true
  json.keys_under_root: true
  json.add_error_key: true

# Input pour HTTP Honeypot - Formulaire de contact
- type: log
  enabled: true
  paths:
    - /var/log/honeypot/contact_form.log
  fields:
    honeypot_type: http
    honeypot_service: http_contact
    attack_category: spam_injection
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
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
    source_vm: $HONEYPOT_IP
    infrastructure: honeypot_system
  fields_under_root: true

# ================================
# FILEBEAT PROCESSORS
# ================================
processors:
  # Ajouter des métadonnées sur l'hôte
  - add_host_metadata:
      when.not.contains.tags: forwarded
  
  # Ajouter timestamp si manquant
  - timestamp:
      field: "@timestamp"
      layouts:
        - '2006-01-02T15:04:05.000Z'
        - '2006-01-02T15:04:05Z'
      test:
        - '2023-06-15T14:30:45.123Z'

# ================================
# OUTPUT VERS LOGSTASH
# ================================
output.logstash:
  hosts: ["$ELK_IP:$LOGSTASH_PORT"]
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

print_status "Configuration Filebeat créée"

# ================================
# CONFIGURATION DES PERMISSIONS
# ================================

print_status "Configuration des permissions..."

# Permissions pour Filebeat
chown root:root /etc/filebeat/filebeat.yml
chmod 600 /etc/filebeat/filebeat.yml

# Ajouter l'utilisateur filebeat aux groupes nécessaires
usermod -a -G adm filebeat
usermod -a -G root filebeat

# Créer le répertoire de logs Filebeat
mkdir -p /var/log/filebeat
chown filebeat:filebeat /var/log/filebeat

print_status "Permissions configurées"

# ================================
# ACTIVATION DU PORT LOGSTASH SUR ELK
# ================================

print_status "Activation du port Beats sur Logstash..."

# Configuration pour activer l'input Beats dans Logstash
cat > /tmp/enable_beats_input.sh << 'EOF'
#!/bin/bash
# Script à exécuter sur la VM ELK pour activer l'input Beats

# Créer la configuration Beats input si elle n'existe pas
if [ ! -f /etc/logstash/conf.d/00-beats-input.conf ]; then
    cat > /etc/logstash/conf.d/00-beats-input.conf << 'EOL'
# Input Beats pour recevoir les données de Filebeat
input {
  beats {
    port => 5044
    type => "beats"
  }
}
EOL

    # Redémarrer Logstash
    systemctl restart logstash
    echo "Input Beats activé dans Logstash"
else
    echo "Input Beats déjà configuré"
fi
EOF

print_warning "Configuration Beats à appliquer sur la VM ELK:"
print_info "Copiez et exécutez ce script sur $ELK_IP:"
echo ""
cat /tmp/enable_beats_input.sh
echo ""

# ================================
# TESTS DE CONFIGURATION
# ================================

print_status "Tests de la configuration Filebeat..."

# Test de la syntaxe
if filebeat test config; then
    print_status "✓ Configuration Filebeat valide"
else
    print_error "✗ Erreur dans la configuration Filebeat"
    exit 1
fi

# Test de connexion vers Logstash (après activation)
print_info "Test de connexion vers Logstash..."
if filebeat test output; then
    print_status "✓ Connexion vers Logstash OK"
else
    print_warning "⚠ Connexion Logstash en attente (activez l'input Beats d'abord)"
fi

# ================================
# ACTIVATION DE FILEBEAT
# ================================

print_status "Activation de Filebeat..."

# Activer et démarrer Filebeat
systemctl enable filebeat
systemctl start filebeat

# Vérifier le statut
if systemctl is-active --quiet filebeat; then
    print_status "✓ Filebeat démarré avec succès"
else
    print_error "✗ Problème de démarrage Filebeat"
    journalctl -u filebeat --no-pager -n 10
fi

# ================================
# GÉNÉRATION DE DONNÉES DE TEST
# ================================

print_status "Génération de données de test..."

# Créer quelques logs de test pour vérifier l'intégration
cat > /tmp/generate_test_logs.sh << 'EOF'
#!/bin/bash
echo "Génération de logs de test pour validation ELK..."

# Logs Cowrie de test
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","eventid":"cowrie.login.failed","src_ip":"203.0.113.100","username":"admin","password":"123456","protocol":"ssh","message":"SSH login attempt from test"}' >> /var/log/cowrie/cowrie.json

# Logs HTTP de test
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","ip":"203.0.113.101","method":"POST","path":"/admin","attack_type":"sql_injection","data":{"search_term":"admin'"'"' OR 1=1--"},"user_agent":"Mozilla/5.0 (Test)","message":"SQL injection attempt"}' >> /var/log/honeypot/http_honeypot.log

# Logs FTP de test
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","ip":"203.0.113.102","event_type":"auth_attempt","username":"anonymous","success":false,"message":"FTP authentication attempt"}' >> /root/honeypot-ftp/logs/sessions.json

echo "Logs de test générés!"
EOF

chmod +x /tmp/generate_test_logs.sh
/tmp/generate_test_logs.sh

# ================================
# SCRIPTS UTILITAIRES
# ================================

print_status "Création des scripts utilitaires..."

# Script de monitoring Filebeat
cat > /opt/monitor_filebeat.sh << 'EOF'
#!/bin/bash
echo "=== État de Filebeat ==="

echo "Service: $(systemctl is-active filebeat)"
echo "Enabled: $(systemctl is-enabled filebeat)"

echo ""
echo "Derniers logs:"
journalctl -u filebeat --no-pager -n 5

echo ""
echo "Statistiques Filebeat:"
curl -s "http://localhost:5066/stats" | jq . 2>/dev/null || echo "API monitoring non accessible"

echo ""
echo "Fichiers de logs surveillés:"
echo "  Cowrie SSH: $(wc -l /home/cowrie/cowrie/var/log/cowrie/cowrie.json 2>/dev/null || echo '0 lignes')"
echo "  HTTP Principal: $(wc -l /var/log/honeypot/http_honeypot.log 2>/dev/null || echo '0 lignes')"
echo "  HTTP SQL: $(wc -l /var/log/honeypot/sql_injection.log 2>/dev/null || echo '0 lignes')"
echo "  HTTP XSS: $(wc -l /var/log/honeypot/xss.log 2>/dev/null || echo '0 lignes')"
echo "  HTTP Traversal: $(wc -l /var/log/honeypot/path_traversal.log 2>/dev/null || echo '0 lignes')"
echo "  HTTP Auth: $(wc -l /var/log/honeypot/login_attempt.log 2>/dev/null || echo '0 lignes')"
echo "  FTP Sessions: $(wc -l /root/honeypot-ftp/logs/sessions.json 2>/dev/null || echo '0 lignes')"
echo "  FTP Auth: $(wc -l /root/honeypot-ftp/logs/auth_attempts.log 2>/dev/null || echo '0 lignes')"
echo "  FTP Commands: $(wc -l /root/honeypot-ftp/logs/commands.log 2>/dev/null || echo '0 lignes')"
echo "  FTP Security: $(wc -l /root/honeypot-ftp/logs/security_events.log 2>/dev/null || echo '0 lignes')"
EOF

chmod +x /opt/monitor_filebeat.sh

# Script de génération de logs de test
cp /tmp/generate_test_logs.sh /opt/generate_test_logs.sh

print_status "Scripts utilitaires créés"

# ================================
# INFORMATIONS FINALES
# ================================

print_status "=== Intégration Honeypots → ELK configurée avec succès! ==="
echo ""
print_info "📊 CONFIGURATION:"
echo "   Source: VM Honeypot ($HONEYPOT_IP)"
echo "   Destination: VM ELK ($ELK_IP:$LOGSTASH_PORT)"
echo "   Agent: Filebeat"
echo ""
print_info "📁 LOGS SURVEILLÉS (15 sources):"
echo "   ✓ Cowrie SSH: /home/cowrie/cowrie/var/log/cowrie/cowrie.json"
echo "   ✓ HTTP Principal: /var/log/honeypot/http_honeypot.log"
echo "   ✓ HTTP SQL Injection: /var/log/honeypot/sql_injection.log"
echo "   ✓ HTTP XSS: /var/log/honeypot/xss.log"
echo "   ✓ HTTP Path Traversal: /var/log/honeypot/path_traversal.log"
echo "   ✓ HTTP File Upload: /var/log/honeypot/file_upload.log"
echo "   ✓ HTTP Login Attempts: /var/log/honeypot/login_attempt.log"
echo "   ✓ HTTP API Access: /var/log/honeypot/api_access.log"
echo "   ✓ HTTP Contact Form: /var/log/honeypot/contact_form.log"
echo "   ✓ HTTP Critical Alerts: /var/log/honeypot/critical_alerts.log"
echo "   ✓ FTP Sessions: /root/honeypot-ftp/logs/sessions.json"
echo "   ✓ FTP Server: /root/honeypot-ftp/logs/ftp_server.log"
echo "   ✓ FTP Auth: /root/honeypot-ftp/logs/auth_attempts.log"
echo "   ✓ FTP Commands: /root/honeypot-ftp/logs/commands.log"
echo "   ✓ FTP Security: /root/honeypot-ftp/logs/security_events.log"
echo "   ✓ FTP Transfers: /root/honeypot-ftp/logs/transfers.log"
echo "   ✓ Système: /var/log/auth.log"
echo ""
print_info "🔧 SCRIPTS DISPONIBLES:"
echo "   - /opt/monitor_filebeat.sh (monitoring)"
echo "   - /opt/generate_test_logs.sh (génération de données test)"
echo ""
print_warning "📋 ÉTAPES SUIVANTES:"
echo "1. Sur VM ELK ($ELK_IP), exécuter:"
echo "   bash /tmp/enable_beats_input.sh"
echo ""
echo "2. Vérifier l'ingestion:"
echo "   /opt/monitor_filebeat.sh"
echo ""
echo "3. Dans Kibana (http://$ELK_IP:5601):"
echo "   - Créer les index patterns"
echo "   - Explorer les données"
echo "   - Créer des tableaux de bord"
echo ""
print_status "Filebeat configuré et en cours d'envoi vers ELK!"

# Créer un fichier de statut
cat > /opt/honeypot-elk-integration-status.txt << EOF
=== Intégration Honeypots → ELK ===
Date: $(date)

✅ CONFIGURATION:
- VM Honeypot: $HONEYPOT_IP
- VM ELK: $ELK_IP
- Agent: Filebeat
- Port: $LOGSTASH_PORT

✅ LOGS INTÉGRÉS:
- Cowrie SSH (/var/log/cowrie/cowrie.json)
- HTTP Honeypot (/var/log/honeypot/http_honeypot.log)
- FTP Honeypot (/root/honeypot-ftp/logs/sessions.json)
- Système (/var/log/auth.log)

✅ STATUS:
- Filebeat: $(systemctl is-active filebeat)
- Configuration: Validée
- Logs de test: Générés

🔄 PROCHAINES ÉTAPES:
1. Activer input Beats sur VM ELK
2. Vérifier ingestion dans Kibana
3. Créer tableaux de bord

COMMANDES UTILES:
- Monitor: /opt/monitor_filebeat.sh
- Test logs: /opt/generate_test_logs.sh
EOF

echo "$(date): Intégration Honeypots → ELK configurée" >> /var/log/integration.log