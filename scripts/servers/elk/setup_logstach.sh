#!/bin/bash

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

print_status "=== Installation de Logstash ==="

# 1. Vérifier qu'Elasticsearch fonctionne
print_status "Vérification d'Elasticsearch..."
if curl -s "http://192.168.2.124:9200/" >/dev/null; then
    print_status "✓ Elasticsearch accessible"
else
    print_error "✗ Elasticsearch non accessible. Résolvez ce problème d'abord."
    exit 1
fi

# 2. Installation de Logstash
print_status "Installation de Logstash..."
apt update
apt install -y logstash

# Vérifier l'installation
if ! dpkg -l | grep -q "logstash"; then
    print_error "Échec de l'installation de Logstash"
    exit 1
fi

LOGSTASH_VERSION=$(dpkg -l | grep logstash | awk '{print $3}')
print_status "Logstash installé : version $LOGSTASH_VERSION"

# 3. Configuration JVM pour Logstash
print_status "Configuration JVM Logstash..."

# Calculer la mémoire pour Logstash (moins qu'Elasticsearch)
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

if [ $TOTAL_RAM_GB -ge 8 ]; then
    LOGSTASH_HEAP="1g"
elif [ $TOTAL_RAM_GB -ge 4 ]; then
    LOGSTASH_HEAP="512m"
else
    LOGSTASH_HEAP="256m"
fi

print_info "Heap Logstash configuré: $LOGSTASH_HEAP"

# Sauvegarder la configuration JVM originale
cp /etc/logstash/jvm.options /etc/logstash/jvm.options.backup.$(date +%Y%m%d_%H%M%S)

# Configuration JVM simplifiée pour Logstash
sed -i "s/-Xms1g/-Xms$LOGSTASH_HEAP/" /etc/logstash/jvm.options
sed -i "s/-Xmx1g/-Xmx$LOGSTASH_HEAP/" /etc/logstash/jvm.options

# 4. Configuration de base de Logstash
print_status "Configuration de base de Logstash..."

# Sauvegarder la configuration originale
cp /etc/logstash/logstash.yml /etc/logstash/logstash.yml.backup.$(date +%Y%m%d_%H%M%S)

# Configuration principale de Logstash
cat > /etc/logstash/logstash.yml << 'EOF'
# Configuration Logstash pour ELK Honeypot

# Node
node.name: logstash-honeypot

# Paths
path.data: /var/lib/logstash
path.logs: /var/log/logstash
path.settings: /etc/logstash

# Pipeline
pipeline.workers: 2
pipeline.batch.size: 125
pipeline.batch.delay: 50

# HTTP API
http.host: "192.168.2.124"
http.port: 9600

# Logging
log.level: info
slowlog.threshold.warn: 2s
slowlog.threshold.info: 1s
slowlog.threshold.debug: 500ms
slowlog.threshold.trace: 100ms

# Monitoring
monitoring.enabled: true
monitoring.elasticsearch.hosts: ["http://192.168.2.124:9200"]

# X-Pack (désactivé)
xpack.monitoring.enabled: false
EOF

print_status "Configuration de base créée"

# 5. Créer la structure des pipelines
print_status "Création de la structure des pipelines..."

# Nettoyer le répertoire conf.d
rm -rf /etc/logstash/conf.d/*

# Créer les répertoires pour organiser les pipelines
mkdir -p /etc/logstash/conf.d/{input,filter,output}
mkdir -p /etc/logstash/patterns

# 6. Configuration des permissions
print_status "Configuration des permissions..."
chown -R logstash:logstash /var/lib/logstash
chown -R logstash:logstash /var/log/logstash
chown -R logstash:logstash /etc/logstash

# 7. Ne pas démarrer automatiquement (configuration manuelle à faire)
print_status "Préparation du service (pas de démarrage automatique)..."
systemctl enable logstash

# 8. Créer un pipeline de test basique
print_status "Création d'un pipeline de test..."

cat > /etc/logstash/conf.d/01-test.conf << 'EOF'
# Pipeline de test pour vérifier Logstash
input {
  stdin { }
}

filter {
  # Pas de filtres pour le test
}

output {
  elasticsearch {
    hosts => ["192.168.2.124:9200"]
    index => "logstash-test-%{+YYYY.MM.dd}"
  }
  
  stdout {
    codec => rubydebug
  }
}
EOF

# 9. Créer des scripts utilitaires
print_status "Création des scripts utilitaires..."

# Script de test de configuration
cat > /opt/elk-scripts/test_logstash_config.sh << 'EOF'
#!/bin/bash
echo "=== Test de la configuration Logstash ==="

echo "1. Test de syntaxe des pipelines:"
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t

echo ""
echo "2. Statut du service:"
systemctl status logstash --no-pager

echo ""
echo "3. Ports Logstash:"
netstat -tlnp | grep -E "(9600|5044)" || echo "Aucun port Logstash en écoute"

echo ""
echo "4. Test connectivité Elasticsearch:"
curl -s "http://192.168.2.124:9200/" | grep cluster_name || echo "Elasticsearch non accessible"
EOF

chmod +x /opt/elk-scripts/test_logstash_config.sh

# Script de démarrage en mode debug
cat > /opt/elk-scripts/start_logstash_debug.sh << 'EOF'
#!/bin/bash
echo "=== Démarrage Logstash en mode debug ==="
echo "Ctrl+C pour arrêter"
echo ""

sudo -u logstash /usr/share/logstash/bin/logstash \
  --path.settings /etc/logstash \
  --path.data /var/lib/logstash \
  --path.logs /var/log/logstash \
  --log.level debug
EOF

chmod +x /opt/elk-scripts/start_logstash_debug.sh

# Script de monitoring Logstash
cat > /opt/elk-scripts/monitor_logstash.sh << 'EOF'
#!/bin/bash
echo "=== Monitoring Logstash ==="

echo "Statut service:"
systemctl is-active logstash 2>/dev/null || echo "Logstash arrêté"

echo ""
echo "API Logstash (si démarré):"
curl -s "http://192.168.2.124:9600/" 2>/dev/null | jq . || echo "API non accessible"

echo ""
echo "Statistiques des nœuds:"
curl -s "http://192.168.2.124:9600/_node/stats" 2>/dev/null | jq .jvm.mem || echo "Stats non disponibles"

echo ""
echo "Pipelines actifs:"
curl -s "http://192.168.2.124:9600/_node/pipelines" 2>/dev/null | jq keys || echo "Pas de pipelines"

echo ""
echo "Processus Logstash:"
ps aux | grep logstash | grep -v grep || echo "Aucun processus Logstash"
EOF

chmod +x /opt/elk-scripts/monitor_logstash.sh

# 10. Informations finales
print_status "=== Installation Logstash terminée ==="
echo ""
print_info "Version installée: $LOGSTASH_VERSION"
print_info "Heap JVM: $LOGSTASH_HEAP"
print_info "Configuration: /etc/logstash/logstash.yml"
print_info "Pipelines: /etc/logstash/conf.d/"
echo ""
print_warning "ÉTAPES MANUELLES REQUISES:"
echo "1. Tester la configuration: /opt/elk-scripts/test_logstash_config.sh"
echo "2. Configurer les pipelines spécifiques aux honeypots"
echo "3. Démarrer Logstash: systemctl start logstash"
echo ""
print_info "Scripts disponibles:"
echo "  - /opt/elk-scripts/test_logstash_config.sh"
echo "  - /opt/elk-scripts/start_logstash_debug.sh"
echo "  - /opt/elk-scripts/monitor_logstash.sh"
echo ""
print_status "Logstash prêt pour la configuration des pipelines !"

# Créer un fichier de statut
cat > /opt/elk-setup-status-logstash.txt << EOF
=== Logstash Installation Status ===
Date: $(date)
Version: $LOGSTASH_VERSION
Heap: $LOGSTASH_HEAP
API: http://192.168.2.124:9600

✓ Installation réussie
✓ Configuration de base
✓ Structure pipelines créée
✓ Scripts utilitaires créés
✓ Permissions configurées

À FAIRE:
- Tester la configuration
- Créer les pipelines honeypot
- Démarrer le service

Prêt pour: Configuration des pipelines
EOF

echo "$(date): Installation Logstash terminée" >> /var/log/elk-setup/install.log