#!/bin/bash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

print_status "=== Configuration Elasticsearch simplifiée ==="

# 1. Arrêter Elasticsearch
print_status "Arrêt d'Elasticsearch..."
systemctl stop elasticsearch

# 2. Configuration JVM minimaliste et compatible
print_status "Création d'une configuration JVM minimaliste..."

# Sauvegarder l'ancienne configuration
cp /etc/elasticsearch/jvm.options /etc/elasticsearch/jvm.options.backup.$(date +%Y%m%d_%H%M%S)

# Configuration JVM ultra-simple
cat > /etc/elasticsearch/jvm.options << 'EOF'
# Configuration JVM simplifiée pour Elasticsearch

################################################################
## IMPORTANT: JVM heap size
################################################################
-Xms1g
-Xmx1g

################################################################
## Configuration de base
################################################################

# Temporary directory
-Djava.io.tmpdir=${ES_TMPDIR}

# Heap dump en cas d'erreur
-XX:+HeapDumpOnOutOfMemoryError
-XX:+ExitOnOutOfMemoryError
-XX:HeapDumpPath=data
-XX:ErrorFile=logs/hs_err_pid%p.log

# Désactiver les logs de deprecation pour éviter le spam
-Delasticsearch.deprecation_logger=false
EOF

print_status "Configuration JVM simplifiée créée"

# 3. Configuration Elasticsearch avec la bonne IP
print_status "Configuration d'Elasticsearch avec IP 192.168.2.124..."

cat > /etc/elasticsearch/elasticsearch.yml << 'EOF'
# Configuration Elasticsearch simplifiée

# Cluster
cluster.name: honeypot-elk
node.name: elk-node-1

# Paths
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

# Memory
bootstrap.memory_lock: true

# Network - IP CORRIGÉE
network.host: 192.168.2.124
http.port: 9200

# Discovery
discovery.type: single-node

# Security - DÉSACTIVÉE
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.transport.ssl.enabled: false
xpack.security.http.ssl.enabled: false

# Index management
action.auto_create_index: "honeypot-*,logstash-*,filebeat-*,.monitoring-*"

# Performance basique
index.number_of_shards: 1
index.number_of_replicas: 0
EOF

print_status "Configuration Elasticsearch créée avec IP 192.168.2.124"

# 4. Supprimer les configurations dans jvm.options.d qui peuvent poser problème
print_status "Nettoyage des configurations JVM additionnelles..."
rm -rf /etc/elasticsearch/jvm.options.d/*

# Créer une configuration heap simple
mkdir -p /etc/elasticsearch/jvm.options.d
cat > /etc/elasticsearch/jvm.options.d/heap.options << 'EOF'
# Configuration heap simplifiée
-Xms1g
-Xmx1g
EOF

# 5. Permissions
print_status "Configuration des permissions..."
chown -R elasticsearch:elasticsearch /etc/elasticsearch
chown -R elasticsearch:elasticsearch /var/lib/elasticsearch
chown -R elasticsearch:elasticsearch /var/log/elasticsearch

# 6. Recharger et démarrer
print_status "Redémarrage d'Elasticsearch..."
systemctl daemon-reload
systemctl start elasticsearch

# 7. Attendre le démarrage avec plus de patience
print_status "Attente du démarrage (jusqu'à 120 secondes)..."
counter=0
while [ $counter -lt 120 ]; do
    if systemctl is-active --quiet elasticsearch; then
        print_status "✓ Service Elasticsearch actif"
        break
    fi
    if [ $((counter % 10)) -eq 0 ]; then
        echo "Attente... ${counter}s"
    fi
    sleep 2
    counter=$((counter + 2))
done

# 8. Vérifier le statut final
STATUS=$(systemctl is-active elasticsearch)
echo ""
print_status "Statut final: $STATUS"

if [ "$STATUS" = "active" ]; then
    print_status "✓ Elasticsearch est démarré"
    
    # Attendre que l'API soit disponible
    print_status "Attente de l'API Elasticsearch..."
    api_counter=0
    while [ $api_counter -lt 60 ]; do
        if curl -s "http://192.168.2.124:9200/" >/dev/null 2>&1; then
            print_status "✓ API Elasticsearch accessible"
            break
        fi
        sleep 2
        api_counter=$((api_counter + 2))
        if [ $((api_counter % 10)) -eq 0 ]; then
            echo "Test API... ${api_counter}s"
        fi
    done
    
    # Test final de l'API
    echo ""
    print_status "Test de l'API:"
    if curl -s "http://192.168.2.124:9200/" | grep -q "cluster_name"; then
        print_status "✓ API fonctionne correctement"
        echo ""
        echo "Informations du cluster:"
        curl -s "http://192.168.2.124:9200/" | jq . 2>/dev/null || curl -s "http://192.168.2.124:9200/"
        echo ""
        echo "Santé du cluster:"
        curl -s "http://192.168.2.124:9200/_cluster/health?pretty"
    else
        print_warning "⚠ API pas encore prête"
    fi
    
else
    print_error "✗ Elasticsearch ne démarre pas"
    print_error "Vérification des derniers logs:"
    journalctl -u elasticsearch --no-pager -n 10
fi

# 9. Créer un script de test simple
cat > /opt/elk-scripts/test_elasticsearch.sh << 'EOF'
#!/bin/bash
echo "=== Test Elasticsearch ==="

echo "1. Statut du service:"
systemctl is-active elasticsearch

echo ""
echo "2. Test API:"
curl -s "http://192.168.2.124:9200/" || echo "API non accessible"

echo ""
echo "3. Santé du cluster:"
curl -s "http://192.168.2.124:9200/_cluster/health" || echo "Cluster non accessible"

echo ""
echo "4. Processus:"
ps aux | grep elasticsearch | grep -v grep || echo "Aucun processus"

echo ""
echo "5. Port 9200:"
netstat -tlnp | grep 9200 || echo "Port 9200 pas en écoute"
EOF

chmod +x /opt/elk-scripts/test_elasticsearch.sh

print_status "=== Configuration simplifiée terminée ==="
print_status "Script de test créé: /opt/elk-scripts/test_elasticsearch.sh"
print_warning "Si des problèmes persistent, vérifiez: journalctl -u elasticsearch -f"