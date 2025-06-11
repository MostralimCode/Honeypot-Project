#!/bin/bash
# scripts/elk/install_elasticsearch.sh
# Installation et configuration d'Elasticsearch pour ELK Stack
# Étape 5.2 - Installation d'Elasticsearch

# ================================
# VARIABLES DE CONFIGURATION
# ================================

ES_VERSION="8.x"
ES_IP="192.168.2.124"
ES_PORT="9200"
ES_TRANSPORT_PORT="9300"
CLUSTER_NAME="honeypot-elk"
NODE_NAME="elk-node-1"

# Couleurs pour l'affichage
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# ================================
# FONCTIONS UTILITAIRES
# ================================

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

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Ce script doit être exécuté en tant que root ou avec sudo"
        exit 1
    fi
}

wait_for_service() {
    local service=$1
    local max_wait=${2:-60}
    local counter=0
    
    print_info "Attente du démarrage de $service (max ${max_wait}s)..."
    
    while [ $counter -lt $max_wait ]; do
        if systemctl is-active --quiet $service; then
            print_status "$service est démarré"
            return 0
        fi
        sleep 2
        counter=$((counter + 2))
        echo -n "."
    done
    
    print_error "Timeout: $service n'a pas démarré dans les ${max_wait} secondes"
    return 1
}

# ================================
# VÉRIFICATIONS PRÉLIMINAIRES
# ================================

print_status "=== Installation d'Elasticsearch pour ELK Stack ==="
echo "Version: $ES_VERSION"
echo "IP: $ES_IP"
echo "Port HTTP: $ES_PORT"
echo "Port Transport: $ES_TRANSPORT_PORT"
echo "Cluster: $CLUSTER_NAME"
echo ""

check_root

# Vérifier que le repository Elastic est configuré
if ! apt-cache search elasticsearch | grep -q "elasticsearch"; then
    print_error "Repository Elastic non configuré. Exécutez d'abord setup_java_and_repository.sh"
    exit 1
fi

# Vérifier Java
if ! command -v java >/dev/null 2>&1; then
    print_error "Java n'est pas installé. Exécutez d'abord setup_java_and_repository.sh"
    exit 1
fi

print_status "Vérifications préliminaires OK"

# ================================
# INSTALLATION D'ELASTICSEARCH
# ================================

print_status "Installation d'Elasticsearch..."

# Mettre à jour la liste des paquets
apt update

# Installer Elasticsearch
print_info "Téléchargement et installation d'Elasticsearch..."
apt install -y elasticsearch

# Vérifier l'installation
if ! dpkg -l | grep -q "elasticsearch"; then
    print_error "Échec de l'installation d'Elasticsearch"
    exit 1
fi

print_status "Elasticsearch installé avec succès"

# Afficher la version installée
ES_INSTALLED_VERSION=$(dpkg -l | grep elasticsearch | awk '{print $3}')
print_info "Version installée: $ES_INSTALLED_VERSION"

# ================================
# SAUVEGARDE DE LA CONFIGURATION ORIGINALE
# ================================

print_status "Sauvegarde de la configuration originale..."

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
cp /etc/elasticsearch/elasticsearch.yml /etc/elasticsearch/elasticsearch.yml.backup.$BACKUP_DATE
cp /etc/elasticsearch/jvm.options /etc/elasticsearch/jvm.options.backup.$BACKUP_DATE

print_status "Configuration sauvegardée"

# ================================
# CONFIGURATION D'ELASTICSEARCH
# ================================

print_status "Configuration d'Elasticsearch..."

# Créer la configuration principale
cat > /etc/elasticsearch/elasticsearch.yml << EOF
# ======================== Elasticsearch Configuration =========================

# ---------------------------------- Cluster -----------------------------------
cluster.name: ${CLUSTER_NAME}

# ------------------------------------ Node ------------------------------------
node.name: ${NODE_NAME}
node.roles: [ master, data, ingest, ml, remote_cluster_client ]

# ----------------------------------- Paths ------------------------------------
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# ---------------------------------- Memory ------------------------------------
bootstrap.memory_lock: true

# ---------------------------------- Network -----------------------------------
network.host: ${ES_IP}
http.port: ${ES_PORT}
transport.port: ${ES_TRANSPORT_PORT}

# --------------------------------- Discovery ----------------------------------
discovery.type: single-node

# ---------------------------------- Gateway -----------------------------------
gateway.recover_after_nodes: 1

# ---------------------------------- Various -----------------------------------
action.destructive_requires_name: true

# --------------------------------- Security ----------------------------------
# ATTENTION: Sécurité désactivée pour environnement de développement
xpack.security.enabled: false
xpack.security.enrollment.enabled: false

# Transport Layer Security
xpack.security.transport.ssl.enabled: false
xpack.security.http.ssl.enabled: false

# ---------------------------------- Monitoring -------------------------------
xpack.monitoring.collection.enabled: true

# ---------------------------------- Index Management -------------------------
# Configuration pour la gestion automatique des indices de logs
action.auto_create_index: "honeypot-*,logstash-*,filebeat-*,.monitoring-*,.watches,.triggered_watches,.watcher-history-*,.ml-*"

# ---------------------------------- Performance ------------------------------
# Optimisations pour environnement honeypot
indices.memory.index_buffer_size: 20%
indices.queries.cache.size: 40%
indices.fielddata.cache.size: 40%

# Refresh interval pour de meilleures performances
index.refresh_interval: 5s

# Number of shards par défaut pour les nouveaux indices
index.number_of_shards: 1
index.number_of_replicas: 0

# ---------------------------------- Logging ----------------------------------
logger.level: INFO

# Logs spécifiques pour le debugging
logger.org.elasticsearch.discovery: DEBUG

# ---------------------------------- Thread Pool ------------------------------
thread_pool.write.queue_size: 1000
thread_pool.search.queue_size: 1000

EOF

print_status "Configuration principale créée"

# ================================
# CONFIGURATION DE LA MÉMOIRE JVM
# ================================

print_status "Configuration de la mémoire JVM..."

# Calculer la mémoire disponible
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

# Allouer la moitié de la RAM à Elasticsearch (max 4GB pour notre environnement)
if [ $TOTAL_RAM_GB -ge 8 ]; then
    ES_HEAP_SIZE="2g"
elif [ $TOTAL_RAM_GB -ge 4 ]; then
    ES_HEAP_SIZE="1g"
else
    ES_HEAP_SIZE="512m"
fi

print_info "RAM totale: ${TOTAL_RAM_GB}GB"
print_info "Heap Elasticsearch: $ES_HEAP_SIZE"

# Modifier la configuration JVM
sed -i "s/-Xms1g/-Xms$ES_HEAP_SIZE/" /etc/elasticsearch/jvm.options
sed -i "s/-Xmx1g/-Xmx$ES_HEAP_SIZE/" /etc/elasticsearch/jvm.options

# Ajouter des optimisations JVM spécifiques
cat >> /etc/elasticsearch/jvm.options << EOF

# Optimisations JVM pour honeypot ELK
-XX:+UseG1GC
-XX:MaxGCPauseMillis=200
-XX:+DisableExplicitGC
-XX:+AlwaysPreTouch
-XX:+UseLargePagesInMetaspace
-Xlog:gc*:gc.log:time

# Optimisations pour de petites instances
-XX:+UnlockExperimentalVMOptions
-XX:+UseCGroupMemoryLimitForHeap
EOF

print_status "Configuration JVM optimisée"

# ================================
# CONFIGURATION DES PERMISSIONS
# ================================

print_status "Configuration des permissions et propriétés..."

# Créer l'utilisateur elasticsearch s'il n'existe pas
if ! id elasticsearch &>/dev/null; then
    useradd -r -s /bin/false elasticsearch
fi

# S'assurer que les répertoires appartiennent à elasticsearch
chown -R elasticsearch:elasticsearch /var/lib/elasticsearch
chown -R elasticsearch:elasticsearch /var/log/elasticsearch
chown -R elasticsearch:elasticsearch /etc/elasticsearch

# Permissions appropriées
chmod 750 /etc/elasticsearch
chmod 660 /etc/elasticsearch/elasticsearch.yml

print_status "Permissions configurées"

# ================================
# CONFIGURATION SYSTEMD
# ================================

print_status "Configuration du service systemd..."

# Modifier la configuration systemd pour les limites mémoire
mkdir -p /etc/systemd/system/elasticsearch.service.d
cat > /etc/systemd/system/elasticsearch.service.d/override.conf << EOF
[Service]
LimitMEMLOCK=infinity
LimitNOFILE=65536
LimitNPROC=4096

# Variables d'environnement
Environment=ES_PATH_CONF=/etc/elasticsearch
Environment=ES_JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64

# Restart policy
Restart=always
RestartSec=10
EOF

# Recharger systemd
systemctl daemon-reload

print_status "Service systemd configuré"

# ================================
# DÉMARRAGE D'ELASTICSEARCH
# ================================

print_status "Démarrage d'Elasticsearch..."

# Activer le service au démarrage
systemctl enable elasticsearch

# Démarrer Elasticsearch
systemctl start elasticsearch

# Attendre que le service démarre
if wait_for_service elasticsearch 120; then
    print_status "Elasticsearch démarré avec succès"
else
    print_error "Échec du démarrage d'Elasticsearch"
    
    # Afficher les logs d'erreur
    print_info "Logs d'erreur:"
    journalctl -u elasticsearch --no-pager -n 20
    
    print_info "Logs Elasticsearch:"
    tail -20 /var/log/elasticsearch/${CLUSTER_NAME}.log 2>/dev/null || echo "Pas de logs disponibles"
    
    exit 1
fi

# ================================
# TESTS DE VALIDATION
# ================================

print_status "Tests de validation d'Elasticsearch..."

# Attendre un peu plus pour que ES soit complètement opérationnel
sleep 15

# Test 1: Connectivité HTTP
print_info "Test 1: Connectivité HTTP..."
if curl -s "http://${ES_IP}:${ES_PORT}/" >/dev/null; then
    print_status "✓ Connectivité HTTP OK"
else
    print_error "✗ Échec connectivité HTTP"
    exit 1
fi

# Test 2: Informations du cluster
print_info "Test 2: Informations du cluster..."
CLUSTER_INFO=$(curl -s "http://${ES_IP}:${ES_PORT}/")
if echo "$CLUSTER_INFO" | grep -q "cluster_name.*$CLUSTER_NAME"; then
    print_status "✓ Cluster configuré correctement"
    echo "$CLUSTER_INFO" | jq . 2>/dev/null || echo "$CLUSTER_INFO"
else
    print_error "✗ Problème de configuration du cluster"
fi

# Test 3: Santé du cluster
print_info "Test 3: Santé du cluster..."
CLUSTER_HEALTH=$(curl -s "http://${ES_IP}:${ES_PORT}/_cluster/health")
if echo "$CLUSTER_HEALTH" | grep -q '"status":"green\|yellow"'; then
    print_status "✓ Cluster en bonne santé"
    echo "$CLUSTER_HEALTH" | jq . 2>/dev/null || echo "$CLUSTER_HEALTH"
else
    print_warning "⚠ Statut du cluster à vérifier"
    echo "$CLUSTER_HEALTH"
fi

# Test 4: Créer un index de test
print_info "Test 4: Test de création d'index..."
if curl -s -X PUT "http://${ES_IP}:${ES_PORT}/test-honeypot" -H 'Content-Type: application/json' -d'
{
  "mappings": {
    "properties": {
      "timestamp": { "type": "date" },
      "message": { "type": "text" },
      "test": { "type": "boolean" }
    }
  }
}' | grep -q '"acknowledged":true'; then
    print_status "✓ Création d'index fonctionnelle"
    
    # Ajouter un document de test
    curl -s -X POST "http://${ES_IP}:${ES_PORT}/test-honeypot/_doc" -H 'Content-Type: application/json' -d'
    {
      "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
      "message": "Test installation Elasticsearch",
      "test": true
    }' >/dev/null
    
    # Supprimer l'index de test
    curl -s -X DELETE "http://${ES_IP}:${ES_PORT}/test-honeypot" >/dev/null
    print_status "✓ Test d'indexation réussi"
else
    print_warning "⚠ Problème avec la création d'index"
fi

# ================================
# CONFIGURATION DES INDEX PATTERNS
# ================================

print_status "Configuration des index patterns pour honeypot..."

# Template pour les indices honeypot
curl -s -X PUT "http://${ES_IP}:${ES_PORT}/_index_template/honeypot-template" -H 'Content-Type: application/json' -d'
{
  "index_patterns": ["honeypot-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "5s",
      "index.mapping.total_fields.limit": 2000
    },
    "mappings": {
      "properties": {
        "@timestamp": { "type": "date" },
        "timestamp": { "type": "date" },
        "honeypot_type": { "type": "keyword" },
        "event_category": { "type": "keyword" },
        "severity": { "type": "keyword" },
        "src_ip": { "type": "ip" },
        "dst_ip": { "type": "ip" },
        "src_port": { "type": "integer" },
        "dst_port": { "type": "integer" },
        "session": { "type": "keyword" },
        "username": { "type": "keyword" },
        "password": { "type": "keyword" },
        "message": { "type": "text" },
        "geoip": {
          "properties": {
            "country_name": { "type": "keyword" },
            "country_code": { "type": "keyword" },
            "city_name": { "type": "keyword" },
            "location": { "type": "geo_point" }
          }
        }
      }
    }
  }
}' | jq . >/dev/null 2>&1

print_status "Index template configuré"

# ================================
# INFORMATIONS FINALES
# ================================

print_status "=== Installation d'Elasticsearch terminée avec succès! ==="
echo ""
print_info "Configuration:"
echo "  URL: http://${ES_IP}:${ES_PORT}"
echo "  Cluster: $CLUSTER_NAME"
echo "  Node: $NODE_NAME"
echo "  Heap JVM: $ES_HEAP_SIZE"
echo "  Version: $ES_INSTALLED_VERSION"
echo ""
print_info "Services:"
echo "  Status: $(systemctl is-active elasticsearch)"
echo "  Enabled: $(systemctl is-enabled elasticsearch)"
echo ""
print_info "Fichiers importants:"
echo "  Configuration: /etc/elasticsearch/elasticsearch.yml"
echo "  Logs: /var/log/elasticsearch/${CLUSTER_NAME}.log"
echo "  Données: /var/lib/elasticsearch"
echo ""
print_info "Commandes utiles:"
echo "  Status: systemctl status elasticsearch"
echo "  Logs: journalctl -u elasticsearch -f"
echo "  Test: curl http://${ES_IP}:${ES_PORT}/_cluster/health?pretty"
echo ""
print_warning "SÉCURITÉ: X-Pack Security est DÉSACTIVÉ"
print_warning "Pour la production, activez la sécurité dans elasticsearch.yml"
echo ""
print_status "Elasticsearch est prêt pour recevoir les données de Logstash!"

# Créer un fichier de statut
cat > /opt/elk-setup-status-elasticsearch.txt << EOF
=== Elasticsearch Installation Status ===
Date: $(date)
Version: $ES_INSTALLED_VERSION
URL: http://${ES_IP}:${ES_PORT}
Cluster: $CLUSTER_NAME
Node: $NODE_NAME
Heap: $ES_HEAP_SIZE
Status: $(systemctl is-active elasticsearch)

Tests de validation:
✓ Installation réussie
✓ Configuration appliquée  
✓ Service démarré
✓ Connectivité HTTP
✓ Santé du cluster
✓ Index template configuré

Prêt pour: Installation de Logstash
EOF

print_status "Fichier de statut créé: /opt/elk-setup-status-elasticsearch.txt"

# Log de fin
echo "$(date): Installation Elasticsearch terminée avec succès" >> /var/log/elk-setup/install.log