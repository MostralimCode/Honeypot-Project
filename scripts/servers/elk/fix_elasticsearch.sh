#!/bin/bash
# scripts/elk/fix_elasticsearch_jvm.sh
# Correction des options JVM d'Elasticsearch

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

print_status "=== Correction de la configuration JVM Elasticsearch ==="

# 1. Arrêter Elasticsearch
print_status "Arrêt d'Elasticsearch..."
systemctl stop elasticsearch

# 2. Nettoyer la configuration JVM problématique
print_status "Nettoyage de la configuration JVM..."

# Sauvegarder la configuration actuelle
cp /etc/elasticsearch/jvm.options /etc/elasticsearch/jvm.options.broken.$(date +%Y%m%d_%H%M%S)

# Créer une nouvelle configuration JVM propre
cat > /etc/elasticsearch/jvm.options << 'EOF'
## JVM configuration for Elasticsearch

################################################################
## IMPORTANT: JVM heap size
################################################################
##
## The heap size is automatically configured by Elasticsearch
## based on the available memory in your system and the roles
## each node is configured to fulfill. If specifying heap is
## required, it should be done through a file in jvm.options.d,
## which should be named with .options suffix, for example, the
## heap size can be set in /etc/elasticsearch/jvm.options.d/heap.options
## See https://www.elastic.co/guide/en/elasticsearch/reference/current/jvm-options.html
## for more details
##
################################################################

# Xms represents the initial size of total heap space
# Xmx represents the maximum size of total heap space

-Xms1g
-Xmx1g

################################################################
## Expert settings
################################################################
##
## All settings below this section are considered
## expert settings. Don't tamper with them unless
## you understand what you are doing
##
################################################################

## GC configuration
8-13:-XX:+UseConcMarkSweepGC
8-13:-XX:CMSInitiatingOccupancyFraction=75
8-13:-XX:+UseCMSInitiatingOccupancyOnly

## G1GC Configuration
# NOTE: G1 GC is only supported on JDK version 10 or later
# to use G1GC, uncomment the next two lines and update the version on the
# following three lines to your version of the JDK
14-:-XX:+UseG1GC

## JVM temporary directory
-Djava.io.tmpdir=${ES_TMPDIR}

## heap dumps

# generate a heap dump when an allocation from the Java heap fails; heap dumps
# are created in the working directory of the JVM unless an alternative path is
# specified
-XX:+HeapDumpOnOutOfMemoryError

# exit right after heap dump on out of memory error
-XX:+ExitOnOutOfMemoryError

# specify an alternative path for heap dumps; ensure the directory exists and
# has sufficient space
-XX:HeapDumpPath=data

# specify an alternative path for JVM fatal error logs
-XX:ErrorFile=logs/hs_err_pid%p.log

## JDK 8 GC logging
8:-XX:+PrintGCDetails
8:-XX:+PrintGCTimeStamps
8:-XX:+PrintGCDateStamps
8:-XX:+PrintClassHistogram
8:-XX:+PrintTenuringDistribution
8:-XX:+PrintGCApplicationStoppedTime
8:-Xloggc:logs/gc.log
8:-XX:+UseGCLogFileRotation
8:-XX:NumberOfGCLogFiles=32
8:-XX:GCLogFileSize=64m

# JDK 9+ GC logging
9-:-Xlog:gc*,gc+age=trace,safepoint:logs/gc.log:utctime,level,tags:filecount=32,filesize=64m

# Elasticsearch 5.0.0 will throw an exception on unquoted field names in JSON.
# If documents were already indexed with unquoted field names, YAML boolean
# values will cause parsing failures. See https://www.elastic.co/guide/en/elasticsearch/reference/5.0/breaking_50_mapping_changes.html#_elasticsearch_5_0_0_will_throw_an_exception_on_unquoted_field_names_in_json
#-Delasticsearch.json.allow_unquoted_field_names=true

# Disable deprecation logging to avoid log spam
# Comment out this line to enable deprecation logging
-Delasticsearch.deprecation_logger=false
EOF

# 3. Créer un fichier de configuration heap séparé
print_status "Configuration de la mémoire heap..."

# Calculer la mémoire appropriée
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))

if [ $TOTAL_RAM_GB -ge 8 ]; then
    ES_HEAP_SIZE="2g"
elif [ $TOTAL_RAM_GB -ge 4 ]; then
    ES_HEAP_SIZE="1g"
else
    ES_HEAP_SIZE="512m"
fi

# Créer le répertoire jvm.options.d s'il n'existe pas
mkdir -p /etc/elasticsearch/jvm.options.d

# Créer la configuration heap
cat > /etc/elasticsearch/jvm.options.d/heap.options << EOF
# Heap size configuration
-Xms${ES_HEAP_SIZE}
-Xmx${ES_HEAP_SIZE}
EOF

print_status "Heap configuré: $ES_HEAP_SIZE"

# 4. Vérifier la version Java et ajuster si nécessaire
print_status "Vérification de Java..."
JAVA_VERSION=$(java -version 2>&1 | head -n 1 | cut -d'"' -f2 | cut -d'.' -f1)
echo "Version Java détectée: $JAVA_VERSION"

# 5. Vérifier les permissions
print_status "Vérification des permissions..."
chown -R elasticsearch:elasticsearch /etc/elasticsearch
chown -R elasticsearch:elasticsearch /var/lib/elasticsearch
chown -R elasticsearch:elasticsearch /var/log/elasticsearch

# 6. Recharger systemd et démarrer Elasticsearch
print_status "Redémarrage d'Elasticsearch..."
systemctl daemon-reload
systemctl start elasticsearch

# 7. Attendre le démarrage
print_status "Attente du démarrage (60 secondes max)..."
counter=0
while [ $counter -lt 60 ]; do
    if systemctl is-active --quiet elasticsearch; then
        print_status "Elasticsearch démarré avec succès!"
        break
    fi
    sleep 2
    counter=$((counter + 2))
    echo -n "."
done

echo ""

# 8. Vérifier le statut
STATUS=$(systemctl is-active elasticsearch)
if [ "$STATUS" = "active" ]; then
    print_status "✓ Elasticsearch fonctionne correctement"
    
    # Attendre un peu plus pour la connectivité
    sleep 10
    
    # Test de connectivité
    if curl -s "http://192.168.2.124:9200/" >/dev/null; then
        print_status "✓ API Elasticsearch accessible"
        
        # Afficher les informations du cluster
        echo ""
        print_status "Informations du cluster:"
        curl -s "http://192.168.2.124:9200/" | jq . 2>/dev/null || curl -s "http://192.168.2.124:9200/"
        
        echo ""
        print_status "Santé du cluster:"
        curl -s "http://192.168.2.124:9200/_cluster/health?pretty"
        
    else
        print_warning "⚠ API pas encore accessible, attendez quelques minutes"
    fi
else
    print_error "✗ Elasticsearch ne démarre toujours pas"
    
    print_error "Vérification des logs d'erreur:"
    journalctl -u elasticsearch --no-pager -n 20
fi

# 9. Créer un script de diagnostic
cat > /opt/elk-scripts/diagnose_elasticsearch.sh << 'EOF'
#!/bin/bash
echo "=== Diagnostic Elasticsearch ==="
echo ""

echo "Status du service:"
systemctl status elasticsearch --no-pager -l

echo ""
echo "Derniers logs:"
journalctl -u elasticsearch --no-pager -n 10

echo ""
echo "Configuration JVM:"
cat /etc/elasticsearch/jvm.options.d/heap.options

echo ""
echo "Test connectivité:"
curl -s "http://192.168.2.124:9200/" || echo "Pas de réponse"

echo ""
echo "Processus Java:"
ps aux | grep elasticsearch | grep -v grep

echo ""
echo "Ports en écoute:"
netstat -tlnp | grep 9200
EOF

chmod +x /opt/elk-scripts/diagnose_elasticsearch.sh

print_status "Script de diagnostic créé: /opt/elk-scripts/diagnose_elasticsearch.sh"

print_status "=== Correction terminée ==="
print_warning "Si des erreurs persistent, exécutez: /opt/elk-scripts/diagnose_elasticsearch.sh"