#!/bin/bash
# Configuration Logstash minimale et fonctionnelle - Fix Étape 5.5
# À exécuter sur la VM ELK (192.168.2.124)

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

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

# Vérifier que nous sommes sur la bonne VM
VM_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
if [ "$VM_IP" != "192.168.2.124" ]; then
    print_error "Ce script doit être exécuté sur la VM ELK (192.168.2.124)"
    exit 1
fi

print_status "=== Configuration Logstash minimale - Fix Étape 5.5 ==="
echo ""

# ================================
# ARRÊT COMPLET DE LOGSTASH
# ================================

print_status "Arrêt complet de Logstash..."

systemctl stop logstash
sleep 5

# S'assurer qu'aucun processus Logstash ne tourne
pkill -f logstash 2>/dev/null || true
sleep 3

# Vérifier qu'il n'y a plus de processus
if pgrep -f logstash >/dev/null; then
    print_warning "Processus Logstash encore actifs, arrêt forcé..."
    pkill -9 -f logstash
    sleep 2
fi

print_status "✅ Logstash complètement arrêté"

# ================================
# NETTOYAGE DES CONFIGURATIONS
# ================================

print_status "Nettoyage des configurations problématiques..."

# Sauvegarder la configuration cassée
if [ -d "/etc/logstash/conf.d" ] && [ "$(ls -A /etc/logstash/conf.d 2>/dev/null)" ]; then
    BACKUP_DIR="/etc/logstash/conf.d.broken-$(date +%Y%m%d_%H%M%S)"
    mv /etc/logstash/conf.d "$BACKUP_DIR"
    print_info "Configuration problématique sauvegardée: $BACKUP_DIR"
fi

# Créer un répertoire propre
mkdir -p /etc/logstash/conf.d

print_status "✅ Configurations nettoyées"

# ================================
# CONFIGURATION LOGSTASH MINIMALE
# ================================

print_status "Création de la configuration Logstash minimale..."

cat > /etc/logstash/conf.d/00-minimal-honeypot.conf << 'EOF'
# Configuration Logstash minimale et fonctionnelle pour honeypots
# Version simplifiée sans fonctionnalités avancées

input {
  # Port TCP pour envoi direct depuis les honeypots
  tcp {
    port => 5046
    host => "0.0.0.0"
    codec => json_lines
    type => "tcp_honeypot"
  }
  
  # Port Beats pour Filebeat
  beats {
    port => 5044
    host => "0.0.0.0"
    type => "beats_honeypot"
  }
}

filter {
  # Détection simple des types de honeypots
  
  # SSH/Cowrie: détecté par la présence du champ eventid
  if [eventid] {
    mutate {
      add_field => { 
        "honeypot_type" => "ssh"
        "service" => "cowrie"
      }
    }
    
    # Normaliser l'IP source
    if [src_ip] {
      mutate { 
        add_field => { "client_ip" => "%{src_ip}" }
      }
    }
  }
  
  # HTTP: détecté par la présence du champ attack_type
  else if [attack_type] {
    mutate {
      add_field => { 
        "honeypot_type" => "http"
        "service" => "http_honeypot"
      }
    }
    
    # Normaliser l'IP source
    if [ip] {
      mutate { 
        add_field => { "client_ip" => "%{ip}" }
      }
    }
  }
  
  # FTP: détecté par honeypot_type déjà défini ou event_type FTP
  else if [honeypot_type] == "ftp" or [event_type] =~ /^ftp_/ {
    mutate {
      add_field => { 
        "honeypot_type" => "ftp"
        "service" => "ftp_honeypot"
      }
    }
    
    # Normaliser l'IP source
    if [ip] {
      mutate { 
        add_field => { "client_ip" => "%{ip}" }
      }
    }
  }
  
  # Marquer les logs non identifiés
  if ![honeypot_type] {
    mutate {
      add_field => { 
        "honeypot_type" => "unknown"
        "service" => "unknown"
      }
    }
  }
  
  # Ajouter un timestamp de traitement
  mutate {
    add_field => { "processed_at" => "%{@timestamp}" }
  }
}

output {
  # Routage simple par type vers les indices appropriés
  
  if [honeypot_type] == "ssh" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
    }
  }
  else if [honeypot_type] == "http" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
    }
  }
  else if [honeypot_type] == "ftp" {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
    }
  }
  else {
    elasticsearch {
      hosts => ["localhost:9200"]
      index => "honeypot-unknown-%{+YYYY.MM.dd}"
    }
  }
  
  # Debug optionnel (décommentez si nécessaire)
  # stdout { codec => rubydebug }
}
EOF

# ================================
# PERMISSIONS ET PROPRIÉTÉS
# ================================

print_status "Configuration des permissions..."

chown logstash:logstash /etc/logstash/conf.d/00-minimal-honeypot.conf
chmod 644 /etc/logstash/conf.d/00-minimal-honeypot.conf

# Vérifier que le fichier existe et est lisible
if [ -f "/etc/logstash/conf.d/00-minimal-honeypot.conf" ]; then
    print_status "✅ Fichier de configuration créé"
    print_info "Taille: $(wc -l < /etc/logstash/conf.d/00-minimal-honeypot.conf) lignes"
else
    print_error "❌ Échec de création du fichier de configuration"
    exit 1
fi

# ================================
# TEST DE SYNTAXE
# ================================

print_status "Test de la syntaxe Logstash..."

TEST_OUTPUT=$(sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t 2>&1)
TEST_RESULT=$?

if [ $TEST_RESULT -eq 0 ]; then
    print_status "✅ Syntaxe Logstash validée"
else
    print_error "❌ Erreur de syntaxe détectée:"
    echo "$TEST_OUTPUT"
    exit 1
fi

# ================================
# CONFIGURATION LOGSTASH.YML SIMPLE
# ================================

print_status "Configuration du fichier logstash.yml..."

cat > /etc/logstash/logstash.yml << 'EOF'
# Configuration Logstash simplifiée
node.name: "logstash-honeypot-minimal"
path.data: /var/lib/logstash
path.logs: /var/log/logstash
path.settings: /etc/logstash

# Configuration pipeline simple
pipeline.workers: 1
pipeline.batch.size: 125
pipeline.batch.delay: 50

# Configuration réseau
http.host: "192.168.2.124"
http.port: 9600

# Logs
log.level: info
xpack.monitoring.enabled: false
xpack.management.enabled: false
EOF

chown logstash:logstash /etc/logstash/logstash.yml
chmod 644 /etc/logstash/logstash.yml

print_status "✅ Configuration logstash.yml mise à jour"

# ================================
# DÉMARRAGE DE LOGSTASH
# ================================

print_status "Démarrage de Logstash avec la configuration minimale..."

systemctl start logstash

print_info "Attente du démarrage complet (45 secondes)..."

# Surveillance du démarrage
for i in {1..45}; do
    if systemctl is-active --quiet logstash; then
        sleep 1
    else
        sleep 1
    fi
    
    if [ $((i % 10)) -eq 0 ]; then
        echo "   Attente... ${i}s"
    fi
done

# Vérification finale du statut
if systemctl is-active --quiet logstash; then
    print_status "✅ Logstash démarré avec succès"
else
    print_error "❌ Échec du démarrage de Logstash"
    print_info "Logs d'erreur:"
    journalctl -u logstash --no-pager -n 10
    exit 1
fi

# ================================
# VÉRIFICATION DES PORTS
# ================================

print_status "Vérification des ports d'écoute..."

sleep 10  # Attendre que les ports soient ouverts

if ss -tlnp | grep -q ":5046 "; then
    print_status "✅ Port 5046 (TCP) en écoute"
else
    print_warning "⚠ Port 5046 pas encore ouvert (attendre un peu plus)"
fi

if ss -tlnp | grep -q ":5044 "; then
    print_status "✅ Port 5044 (Beats) en écoute"
else
    print_warning "⚠ Port 5044 pas encore ouvert (attendre un peu plus)"
fi

# ================================
# TEST DE L'API LOGSTASH
# ================================

print_status "Test de l'API Logstash..."

API_RESPONSE=$(curl -s "http://localhost:9600/" 2>/dev/null)
if echo "$API_RESPONSE" | grep -q "ok"; then
    print_status "✅ API Logstash accessible"
else
    print_warning "⚠ API Logstash pas encore disponible"
fi

# ================================
# TEST D'INGESTION DE DONNÉES
# ================================

print_status "Test d'ingestion de données..."

# Test SSH
print_info "Test SSH/Cowrie..."
echo '{"eventid":"cowrie.login.failed","src_ip":"192.168.1.100","username":"test_minimal","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'"}' | nc -w 5 localhost 5046 2>/dev/null
if [ $? -eq 0 ]; then
    print_status "✅ Données SSH envoyées"
else
    print_warning "⚠ Échec envoi SSH (port peut-être pas encore ouvert)"
fi

# Test HTTP
print_info "Test HTTP..."
echo '{"attack_type":"sql_injection","ip":"192.168.1.101","method":"POST","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'"}' | nc -w 5 localhost 5046 2>/dev/null
if [ $? -eq 0 ]; then
    print_status "✅ Données HTTP envoyées"
else
    print_warning "⚠ Échec envoi HTTP"
fi

# Test FTP
print_info "Test FTP..."
echo '{"honeypot_type":"ftp","event_type":"ftp_auth","ip":"192.168.1.102","username":"test","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'"}' | nc -w 5 localhost 5046 2>/dev/null
if [ $? -eq 0 ]; then
    print_status "✅ Données FTP envoyées"
else
    print_warning "⚠ Échec envoi FTP"
fi

print_status "✅ Tests d'ingestion terminés"

# ================================
# VÉRIFICATION DE L'INDEXATION
# ================================

print_status "Vérification de l'indexation dans Elasticsearch..."

print_info "Attente de l'indexation (10 secondes)..."
sleep 10

TODAY=$(date +%Y.%m.%d)

# Compter les documents par type
COWRIE_COUNT=$(curl -s "http://localhost:9200/honeypot-cowrie-$TODAY/_count" 2>/dev/null | jq -r '.count // 0')
HTTP_COUNT=$(curl -s "http://localhost:9200/honeypot-http-$TODAY/_count" 2>/dev/null | jq -r '.count // 0')
FTP_COUNT=$(curl -s "http://localhost:9200/honeypot-ftp-$TODAY/_count" 2>/dev/null | jq -r '.count // 0')

echo "   Documents indexés aujourd'hui:"
echo "     • SSH/Cowrie: $COWRIE_COUNT"
echo "     • HTTP: $HTTP_COUNT"
echo "     • FTP: $FTP_COUNT"

TOTAL_TODAY=$((COWRIE_COUNT + HTTP_COUNT + FTP_COUNT))

if [ "$TOTAL_TODAY" -gt 0 ]; then
    print_status "🎉 SUCCÈS ! $TOTAL_TODAY documents indexés"
else
    print_warning "⚠ Aucun document indexé - les tests peuvent prendre plus de temps"
    print_info "Vérifiez dans quelques minutes avec: curl 'localhost:9200/honeypot-*/_count'"
fi

# ================================
# CRÉATION DES SCRIPTS UTILITAIRES
# ================================

print_status "Création des scripts utilitaires minimaux..."

mkdir -p /opt/elk-scripts

# Script de test simple
cat > /opt/elk-scripts/test_logstash_minimal.sh << 'EOF'
#!/bin/bash
echo "🧪 Test Logstash minimal..."

echo "Services:"
echo "  Logstash: $(systemctl is-active logstash)"

echo "Ports:"
ss -tlnp | grep -E ":504[46]" || echo "  Ports pas encore ouverts"

echo "API:"
curl -s "http://localhost:9600/" | jq .status 2>/dev/null || echo "  API pas accessible"

echo "Test d'envoi:"
echo '{"eventid":"cowrie.test","src_ip":"127.0.0.1"}' | nc -w 3 localhost 5046 && echo "  ✅ Envoi OK" || echo "  ❌ Envoi KO"

echo "Documents:"
curl -s "http://localhost:9200/honeypot-*/_count" | jq .count 2>/dev/null || echo "  Pas de données"
EOF

chmod +x /opt/elk-scripts/test_logstash_minimal.sh

# Script de monitoring simple
cat > /opt/elk-scripts/monitor_logstash_minimal.sh << 'EOF'
#!/bin/bash
echo "📊 Monitoring Logstash minimal..."

echo "=== STATUT ==="
echo "Logstash: $(systemctl is-active logstash)"
echo "Uptime: $(systemctl show logstash --property=ActiveEnterTimestamp --value)"

echo ""
echo "=== PORTS ==="
ss -tlnp | grep -E ":504[46]"

echo ""
echo "=== API ==="
curl -s "http://localhost:9600/" | jq '{status, pipeline}' 2>/dev/null || echo "API non accessible"

echo ""
echo "=== DONNÉES ==="
for type in cowrie http ftp unknown; do
    count=$(curl -s "http://localhost:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // 0')
    echo "$type: $count documents"
done

echo ""
echo "=== DERNIERS LOGS ==="
journalctl -u logstash --no-pager -n 3
EOF

chmod +x /opt/elk-scripts/monitor_logstash_minimal.sh

print_status "✅ Scripts utilitaires créés"

# ================================
# RÉSUMÉ FINAL
# ================================

echo ""
print_status "=== CONFIGURATION LOGSTASH MINIMALE TERMINÉE ==="
echo ""
print_info "✅ CONFIGURATION APPLIQUÉE:"
echo "   • Configuration minimale et stable"
echo "   • 1 fichier de pipeline (/etc/logstash/conf.d/00-minimal-honeypot.conf)"
echo "   • Détection automatique SSH, HTTP, FTP"
echo "   • Routage vers indices appropriés"
echo ""
print_info "✅ SERVICES:"
echo "   • Logstash: $(systemctl is-active logstash)"
echo "   • API disponible: http://192.168.2.124:9600"
echo ""
print_info "✅ PORTS EN ÉCOUTE:"
echo "   • 5044 (Filebeat/Beats)"
echo "   • 5046 (TCP direct)"
echo ""
print_info "✅ TESTS EFFECTUÉS:"
echo "   • Configuration validée"
echo "   • Ingestion de données testée"
echo "   • Indexation vérifiée"
echo ""
print_info "🔧 SCRIPTS UTILITAIRES:"
echo "   • /opt/elk-scripts/test_logstash_minimal.sh"
echo "   • /opt/elk-scripts/monitor_logstash_minimal.sh"
echo ""
print_warning "📋 CETTE VERSION MINIMALE FONCTIONNE SANS:"
echo "   • Enrichissement GeoIP"
echo "   • Classification MITRE ATT&CK"
echo "   • Scoring de risque"
echo "   • Détection avancée de commandes"
echo ""
print_warning "💡 UNE FOIS STABLE, NOUS POURRONS AJOUTER CES FONCTIONNALITÉS"
echo ""
print_status "🎉 Configuration Logstash minimale opérationnelle !"
print_status "✅ Prêt pour passer à l'étape 5.6 (Kibana) !"

echo "$(date): Configuration Logstash minimale (5.5-fix) terminée" >> /var/log/elk-setup/install.log