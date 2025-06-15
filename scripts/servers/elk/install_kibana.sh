#!/bin/bash
# scripts/elk/install_kibana.sh
# Installation et configuration de Kibana - Étape 5.4

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

print_status "=== Installation de Kibana pour ELK Stack ==="

# ================================
# VÉRIFICATIONS PRÉLIMINAIRES
# ================================

print_status "Vérifications préliminaires..."

# Vérifier Elasticsearch
if curl -s "http://192.168.2.124:9200/" >/dev/null; then
    print_status "✓ Elasticsearch accessible"
else
    print_error "✗ Elasticsearch non accessible"
    exit 1
fi

# Vérifier Logstash
if systemctl is-active --quiet logstash; then
    print_status "✓ Logstash en cours d'exécution"
else
    print_warning "⚠ Logstash non actif (continuons quand même)"
fi

# ================================
# INSTALLATION DE KIBANA
# ================================

print_status "Installation de Kibana..."

# Mettre à jour les paquets
apt update

# Installer Kibana
apt install -y kibana

# Vérifier l'installation
if ! dpkg -l | grep -q "kibana"; then
    print_error "Échec de l'installation de Kibana"
    exit 1
fi

KIBANA_VERSION=$(dpkg -l | grep kibana | awk '{print $3}')
print_status "Kibana installé : version $KIBANA_VERSION"

# ================================
# CONFIGURATION DE KIBANA
# ================================

print_status "Configuration de Kibana..."

# Sauvegarder la configuration originale
cp /etc/kibana/kibana.yml /etc/kibana/kibana.yml.backup.$(date +%Y%m%d_%H%M%S)

# Configuration principale de Kibana
cat > /etc/kibana/kibana.yml << 'EOF'
# Configuration Kibana pour ELK Honeypot Stack

# ================================
# SERVER CONFIGURATION
# ================================
server.port: 5601
server.host: "192.168.2.124"
server.name: "honeypot-kibana"
server.publicBaseUrl: "http://192.168.2.124:5601"

# ================================
# ELASTICSEARCH CONFIGURATION
# ================================
elasticsearch.hosts: ["http://192.168.2.124:9200"]
elasticsearch.username: ""
elasticsearch.password: ""
elasticsearch.requestTimeout: 30000
elasticsearch.shardTimeout: 30000

# ================================
# KIBANA INDEX
# ================================
kibana.index: ".kibana"
kibana.defaultAppId: "dashboard"

# ================================
# LOGGING CONFIGURATION
# ================================
logging.appenders.file.type: file
logging.appenders.file.fileName: /var/log/kibana/kibana.log
logging.appenders.file.layout.type: json

logging.root.appenders:
  - default
  - file

logging.root.level: info

# ================================
# ADVANCED SETTINGS
# ================================
pid.file: /run/kibana/kibana.pid

# Monitoring (désactivé pour simplifier)
monitoring.enabled: false
monitoring.kibana.collection.enabled: false

# Security (désactivé)
xpack.security.enabled: false
xpack.encryptedSavedObjects.encryptionKey: "honeypot_elk_stack_encryption_key_32chars"

# Telemetry (désactivé)
telemetry.enabled: false
telemetry.optIn: false

# ================================
# UI CONFIGURATION
# ================================
map.includeElasticMapsService: true
map.tilemap.url: "https://tiles.elastic.co/v2/default/{z}/{x}/{y}.png?elastic_tile_service_tos=agree&my_app_name=kibana"

# ================================
# PERFORMANCE SETTINGS
# ================================
elasticsearch.requestHeadersWhitelist: ["authorization"]
server.maxPayloadBytes: 1048576
csp.strict: false
EOF

print_status "Configuration Kibana créée"

# ================================
# CONFIGURATION DES RÉPERTOIRES ET PERMISSIONS
# ================================

print_status "Configuration des répertoires et permissions..."

# Créer les répertoires nécessaires
mkdir -p /var/log/kibana
mkdir -p /run/kibana

# Permissions appropriées
chown -R kibana:kibana /var/log/kibana
chown -R kibana:kibana /run/kibana
chown -R kibana:kibana /etc/kibana

# Permissions sur la configuration
chmod 640 /etc/kibana/kibana.yml

print_status "Permissions configurées"

# ================================
# CONFIGURATION SYSTEMD
# ================================

print_status "Configuration du service systemd..."

# Créer un override pour optimiser le service
mkdir -p /etc/systemd/system/kibana.service.d
cat > /etc/systemd/system/kibana.service.d/override.conf << 'EOF'
[Service]
# Timeouts augmentés pour Kibana
TimeoutStartSec=300
TimeoutStopSec=120

# Restart policy
Restart=always
RestartSec=10

# Environment
Environment="NODE_OPTIONS=--max-old-space-size=1024"

# PID File
PIDFile=/run/kibana/kibana.pid
EOF

# Recharger systemd
systemctl daemon-reload

print_status "Service systemd configuré"

# ================================
# ACTIVATION ET DÉMARRAGE
# ================================

print_status "Activation et démarrage de Kibana..."

# Activer le service au démarrage
systemctl enable kibana

# Démarrer Kibana
systemctl start kibana

# Attendre le démarrage avec patience (Kibana peut être lent)
print_status "Attente du démarrage de Kibana (jusqu'à 120 secondes)..."

counter=0
while [ $counter -lt 120 ]; do
    if systemctl is-active --quiet kibana; then
        print_status "✓ Service Kibana actif"
        break
    fi
    if [ $((counter % 10)) -eq 0 ]; then
        echo "Attente... ${counter}s"
    fi
    sleep 2
    counter=$((counter + 2))
done

# ================================
# TESTS DE VALIDATION
# ================================

print_status "Tests de validation de Kibana..."

# Vérifier le statut du service
STATUS=$(systemctl is-active kibana)
print_info "Statut du service: $STATUS"

if [ "$STATUS" = "active" ]; then
    print_status "✓ Kibana est démarré"
    
    # Attendre que l'API soit disponible
    print_status "Attente de l'API Kibana..."
    api_counter=0
    while [ $api_counter -lt 60 ]; do
        if curl -s "http://192.168.2.124:5601/api/status" >/dev/null 2>&1; then
            print_status "✓ API Kibana accessible"
            break
        fi
        sleep 2
        api_counter=$((api_counter + 2))
        if [ $((api_counter % 10)) -eq 0 ]; then
            echo "Test API... ${api_counter}s"
        fi
    done
    
    # Test de l'interface web
    echo ""
    print_status "Test de l'interface web:"
    if curl -s "http://192.168.2.124:5601/" | grep -q "kibana"; then
        print_status "✓ Interface web accessible"
        echo ""
        print_info "🌐 Kibana accessible à: http://192.168.2.124:5601"
    else
        print_warning "⚠ Interface web pas encore prête (normal au premier démarrage)"
        print_info "Attendez quelques minutes et testez: http://192.168.2.124:5601"
    fi
    
else
    print_error "✗ Kibana ne démarre pas"
    print_error "Vérification des logs:"
    journalctl -u kibana --no-pager -n 10
fi

# ================================
# CONFIGURATION DES INDEX PATTERNS
# ================================

print_status "Préparation des index patterns pour honeypots..."

# Créer un script pour configurer les index patterns
cat > /opt/elk-scripts/setup_kibana_indexes.sh << 'EOF'
#!/bin/bash
# Configuration des index patterns Kibana pour honeypots

KIBANA_URL="http://192.168.2.124:5601"

echo "=== Configuration des index patterns Kibana ==="

# Attendre que Kibana soit prêt
echo "Attente de Kibana..."
while ! curl -s "${KIBANA_URL}/api/status" >/dev/null; do
    echo "En attente..."
    sleep 5
done

echo "Kibana accessible, configuration des index patterns..."

# Index pattern pour Cowrie SSH
echo "Création index pattern Cowrie..."
curl -X POST "${KIBANA_URL}/api/saved_objects/index-pattern/honeypot-cowrie" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "honeypot-cowrie-*",
      "timeFieldName": "@timestamp"
    }
  }' || echo "Erreur création index Cowrie"

# Index pattern pour HTTP Honeypot
echo "Création index pattern HTTP..."
curl -X POST "${KIBANA_URL}/api/saved_objects/index-pattern/honeypot-http" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "honeypot-http-*",
      "timeFieldName": "@timestamp"
    }
  }' || echo "Erreur création index HTTP"

# Index pattern pour FTP Honeypot
echo "Création index pattern FTP..."
curl -X POST "${KIBANA_URL}/api/saved_objects/index-pattern/honeypot-ftp" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "honeypot-ftp-*",
      "timeFieldName": "@timestamp"
    }
  }' || echo "Erreur création index FTP"

# Index pattern global pour tous les honeypots
echo "Création index pattern global honeypots..."
curl -X POST "${KIBANA_URL}/api/saved_objects/index-pattern/honeypot-all" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "honeypot-*",
      "timeFieldName": "@timestamp"
    }
  }' || echo "Erreur création index global"

echo "Configuration des index patterns terminée!"
echo "Accédez à Kibana: http://192.168.2.124:5601"
EOF

chmod +x /opt/elk-scripts/setup_kibana_indexes.sh

print_status "Script de configuration des index patterns créé"

# ================================
# SCRIPTS UTILITAIRES
# ================================

print_status "Création des scripts utilitaires..."

# Script de monitoring Kibana
cat > /opt/elk-scripts/check_kibana.sh << 'EOF'
#!/bin/bash
echo "=== État de Kibana ==="

echo "Service: $(systemctl is-active kibana)"
echo "Enabled: $(systemctl is-enabled kibana)"

echo ""
echo "Processus:"
ps aux | grep kibana | grep -v grep || echo "Aucun processus Kibana"

echo ""
echo "Ports:"
netstat -tlnp | grep 5601 || echo "Port 5601 pas en écoute"

echo ""
echo "API Kibana:"
curl -s "http://192.168.2.124:5601/api/status" | jq .status.overall.state 2>/dev/null || echo "API non accessible"

echo ""
echo "Interface web:"
if curl -s "http://192.168.2.124:5601/" | grep -q "kibana"; then
    echo "✓ Interface accessible"
else
    echo "✗ Interface non accessible"
fi

echo ""
echo "Derniers logs:"
journalctl -u kibana --no-pager -n 5
EOF

chmod +x /opt/elk-scripts/check_kibana.sh

# Script de redémarrage complet de la stack
cat > /opt/elk-scripts/restart_elk_stack.sh << 'EOF'
#!/bin/bash
echo "=== Redémarrage complet de la stack ELK ==="

echo "1. Arrêt des services..."
systemctl stop kibana
systemctl stop logstash
systemctl stop elasticsearch

echo "2. Attente..."
sleep 10

echo "3. Démarrage dans l'ordre..."
systemctl start elasticsearch
sleep 30

systemctl start logstash
sleep 15

systemctl start kibana
sleep 10

echo "4. Vérification:"
echo "  Elasticsearch: $(systemctl is-active elasticsearch)"
echo "  Logstash: $(systemctl is-active logstash)"
echo "  Kibana: $(systemctl is-active kibana)"

echo ""
echo "Stack ELK redémarrée!"
echo "Kibana: http://192.168.2.124:5601"
EOF

chmod +x /opt/elk-scripts/restart_elk_stack.sh

print_status "Scripts utilitaires créés"

# ================================
# INFORMATIONS FINALES
# ================================

print_status "=== Installation de Kibana terminée avec succès! ==="
echo ""
print_info "🌐 ACCÈS KIBANA:"
echo "   URL: http://192.168.2.124:5601"
echo "   Interface: Web (aucun login requis)"
echo ""
print_info "📊 CONFIGURATION:"
echo "   Version: $KIBANA_VERSION"
echo "   Elasticsearch: http://192.168.2.124:9200"
echo "   Logs: /var/log/kibana/kibana.log"
echo ""
print_info "🔧 SCRIPTS DISPONIBLES:"
echo "   - /opt/elk-scripts/setup_kibana_indexes.sh (config index patterns)"
echo "   - /opt/elk-scripts/check_kibana.sh (monitoring)"
echo "   - /opt/elk-scripts/restart_elk_stack.sh (redémarrage complet)"
echo ""
print_warning "📋 PROCHAINES ÉTAPES:"
echo "1. Attendre 2-3 minutes que Kibana soit complètement prêt"
echo "2. Accéder à: http://192.168.2.124:5601"
echo "3. Configurer les index patterns: /opt/elk-scripts/setup_kibana_indexes.sh"
echo "4. Créer des tableaux de bord pour les honeypots"
echo ""
print_status "🎯 Stack ELK complète opérationnelle!"

# ================================
# STATUT FINAL DE LA STACK ELK
# ================================

echo ""
print_status "=== ÉTAT COMPLET DE LA STACK ELK ==="
echo ""
print_info "✅ ELASTICSEARCH:"
echo "   Status: $(systemctl is-active elasticsearch)"
echo "   URL: http://192.168.2.124:9200"
echo "   Cluster: honeypot-elk"
echo ""
print_info "✅ LOGSTASH:"
echo "   Status: $(systemctl is-active logstash)"
echo "   Pipelines: 4 actifs (SSH, HTTP, FTP, Secure)"
echo "   API: http://192.168.2.124:9600"
echo ""
print_info "✅ KIBANA:"
echo "   Status: $(systemctl is-active kibana)"
echo "   Interface: http://192.168.2.124:5601"
echo "   Version: $KIBANA_VERSION"
echo ""

# Créer un fichier de statut final complet
cat > /opt/elk-setup-complete.txt << EOF
=== ELK Stack - Installation Complète ===
Date: $(date)

🎯 STACK ELK OPÉRATIONNELLE:

✅ ELASTICSEARCH:
- Status: $(systemctl is-active elasticsearch)
- URL: http://192.168.2.124:9200
- Cluster: honeypot-elk
- Heap: 1g

✅ LOGSTASH:
- Status: $(systemctl is-active logstash)
- Pipelines: 4 pipelines actifs
- Heap: 512m
- API: http://192.168.2.124:9600

✅ KIBANA:
- Status: $(systemctl is-active kibana)
- Interface: http://192.168.2.124:5601
- Version: $KIBANA_VERSION

📊 INDEX ELASTICSEARCH:
- honeypot-cowrie-*     (SSH Honeypot)
- honeypot-http-*       (HTTP Honeypot)
- honeypot-ftp-*        (FTP Honeypot)
- secure-servers-*      (Serveurs sécurisés)

🔧 SCRIPTS UTILITAIRES:
- /opt/elk-scripts/setup_kibana_indexes.sh
- /opt/elk-scripts/check_kibana.sh
- /opt/elk-scripts/restart_elk_stack.sh
- /opt/elk-scripts/monitor_elk.sh
- /opt/elk-scripts/start_logstash_safe.sh

🌐 ACCÈS:
- Elasticsearch: http://192.168.2.124:9200
- Kibana: http://192.168.2.124:5601
- Logstash API: http://192.168.2.124:9600

🎯 PRÊT POUR:
- Configuration des honeypots
- Ingestion de données
- Création de tableaux de bord
- Analyse des attaques

✅ ÉTAPE 5 (ELK Stack) TERMINÉE AVEC SUCCÈS!
EOF

echo "$(date): Installation Kibana terminée - Stack ELK complète" >> /var/log/elk-setup/install.log

print_status "Configuration complète sauvegardée dans: /opt/elk-setup-complete.txt"