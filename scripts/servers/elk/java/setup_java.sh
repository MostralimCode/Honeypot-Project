#!/bin/bash
# scripts/elk/setup_java_and_repository.sh
# Installation Java 17 et préparation repository Elastic

# ================================
# VARIABLES DE CONFIGURATION

ELK_IP="192.168.2.124"
HOSTNAME="elk-stack"
DOMAIN="honeypot.local"

# Couleurs pour l'affichage
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

# FONCTIONS UTILITAIRES

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

check_connectivity() {
    print_status "Vérification de la connectivité internet..."
    if ! ping -c 2 8.8.8.8 >/dev/null 2>&1; then
        print_error "Pas de connectivité internet. Vérifiez la configuration réseau."
        exit 1
    fi
    print_status "Connectivité internet OK"
}

# VÉRIFICATIONS PRÉLIMINAIRES

print_status "=== Configuration système de base pour ELK Stack ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "IP: $(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')"
echo ""

check_root
check_connectivity

# MISE À JOUR DU SYSTÈME

print_status "Mise à jour complète du système..."
apt update

# Afficher les paquets à mettre à jour
UPGRADABLE=$(apt list --upgradable 2>/dev/null | wc -l)
if [ $UPGRADABLE -gt 1 ]; then
    print_info "$((UPGRADABLE-1)) paquets à mettre à jour"
    apt upgrade -y
else
    print_status "Système déjà à jour"
fi

# INSTALLATION DES PRÉREQUIS

print_status "Installation des paquets prérequis..."

REQUIRED_PACKAGES=(
    "curl"
    "wget" 
    "gnupg"
    "apt-transport-https"
    "ca-certificates"
    "software-properties-common"
    "vim"
    "htop"
    "net-tools"
    "ufw"
    "chrony"
    "rsyslog"
    "unzip"
    "lsof"
    "jq"
)

for package in "${REQUIRED_PACKAGES[@]}"; do
    if ! dpkg -l | grep -q "^ii  $package "; then
        print_info "Installation de $package..."
        apt install -y $package
    else
        print_info "$package déjà installé"
    fi
done

print_status "Prérequis installés avec succès"

# OPTIMISATIONS SYSTÈME POUR ELK

print_status "Application des optimisations système pour ELK Stack..."

# Paramètres kernel pour Elasticsearch
print_info "Configuration des paramètres kernel..."

# Sauvegarder la configuration originale
cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d)

# Ajouter les optimisations ELK si pas déjà présentes
grep -q "vm.max_map_count" /etc/sysctl.conf || {
    echo "" >> /etc/sysctl.conf
    echo "# Optimisations pour ELK Stack" >> /etc/sysctl.conf
    echo "vm.max_map_count=262144" >> /etc/sysctl.conf
    echo "vm.swappiness=1" >> /etc/sysctl.conf
    echo "fs.file-max=65536" >> /etc/sysctl.conf
    print_status "Paramètres kernel ajoutés"
}

# Appliquer les paramètres
sysctl -p

# Vérifier les paramètres critiques
print_info "Vérification des paramètres kernel:"
echo "  vm.max_map_count = $(sysctl -n vm.max_map_count)"
echo "  vm.swappiness = $(sysctl -n vm.swappiness)"
echo "  fs.file-max = $(sysctl -n fs.file-max)"

# ================================
# CONFIGURATION DES LIMITES SYSTÈME
# ================================

print_status "Configuration des limites système..."

# Sauvegarder la configuration originale
cp /etc/security/limits.conf /etc/security/limits.conf.backup.$(date +%Y%m%d)

# Ajouter les limites pour ELK si pas déjà présentes
grep -q "elasticsearch" /etc/security/limits.conf || {
    cat >> /etc/security/limits.conf << 'EOF'

# Optimisations pour ELK Stack - Ajouté automatiquement
elasticsearch  soft  nofile   65536
elasticsearch  hard  nofile   65536
elasticsearch  soft  memlock  unlimited
elasticsearch  hard  memlock  unlimited

logstash       soft  nofile   16384
logstash       hard  nofile   16384

kibana         soft  nofile   8192
kibana         hard  nofile   8192

# Limites pour l'utilisateur elkadmin
elkadmin       soft  nofile   32768
elkadmin       hard  nofile   32768
EOF
    print_status "Limites système configurées"
}

# ================================
# INSTALLATION DE JAVA 17
# ================================

print_status "Installation de Java OpenJDK 17..."

# Vérifier si Java est déjà installé
if command -v java >/dev/null 2>&1; then
    JAVA_VERSION=$(java -version 2>&1 | head -n 1)
    print_info "Java déjà installé: $JAVA_VERSION"
    
    # Vérifier si c'est Java 17
    if java -version 2>&1 | grep -q "17\."; then
        print_status "Java 17 déjà installé et configuré"
    else
        print_warning "Version Java différente de 17 détectée"
        print_info "Installation de Java 17..."
        apt install -y openjdk-17-jdk
    fi
else
    print_info "Installation de Java 17..."
    apt install -y openjdk-17-jdk
fi

# Configuration de JAVA_HOME
print_status "Configuration de JAVA_HOME..."

JAVA_HOME_PATH="/usr/lib/jvm/java-17-openjdk-amd64"

# Ajouter JAVA_HOME au profil système si pas déjà présent
grep -q "JAVA_HOME" /etc/environment || {
    echo "JAVA_HOME=$JAVA_HOME_PATH" >> /etc/environment
    print_status "JAVA_HOME ajouté à /etc/environment"
}

# Exporter pour la session actuelle
export JAVA_HOME=$JAVA_HOME_PATH
export PATH=$PATH:$JAVA_HOME/bin

# Vérifier l'installation Java
print_status "Vérification de l'installation Java..."
java -version
javac -version 2>/dev/null || print_warning "javac non disponible (normal pour JRE)"

print_info "JAVA_HOME: $JAVA_HOME"
print_info "Java installé avec succès"

# PRÉPARATION DU REPOSITORY ELASTIC

print_status "Préparation du repository Elastic..."

# Télécharger et ajouter la clé GPG Elastic
print_info "Ajout de la clé GPG Elastic..."
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Vérifier que la clé a été ajoutée
if [ -f "/usr/share/keyrings/elasticsearch-keyring.gpg" ]; then
    print_status "Clé GPG Elastic ajoutée avec succès"
else
    print_error "Échec de l'ajout de la clé GPG Elastic"
    exit 1
fi

# Ajouter le repository Elastic 8.x
print_info "Ajout du repository Elastic 8.x..."
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | tee /etc/apt/sources.list.d/elastic-8.x.list

# Mettre à jour la liste des paquets
print_status "Mise à jour de la liste des paquets..."
apt update

# Vérifier que le repository est accessible
print_info "Vérification du repository Elastic..."
if apt-cache search elasticsearch | grep -q "elasticsearch"; then
    print_status "Repository Elastic configuré avec succès"
    
    # Afficher les versions disponibles
    print_info "Versions Elasticsearch disponibles:"
    apt-cache madison elasticsearch | head -5
else
    print_error "Problème avec le repository Elastic"
    exit 1
fi

# CONFIGURATION TEMPORELLE

print_status "Configuration de la synchronisation temporelle..."

# Configuration de chrony
systemctl enable chrony
systemctl start chrony

# Forcer la synchronisation
chrony sources -v

# Vérifier la synchronisation
if chrony tracking | grep -q "Leap status.*Normal"; then
    print_status "Synchronisation temporelle configurée"
else
    print_warning "Problème de synchronisation temporelle détecté"
fi

# Afficher l'heure actuelle
print_info "Heure système: $(date)"

# ================================
# CONFIGURATION DU PARE-FEU
# ================================

print_status "Configuration du pare-feu UFW pour ELK..."

# Réinitialiser UFW proprement
ufw --force reset

# Politiques par défaut
ufw default deny incoming
ufw default allow outgoing

# SSH depuis le réseau LAN
ufw allow from 192.168.2.0/24 to any port 22 proto tcp comment 'SSH from LAN'

# Ports ELK depuis le réseau LAN uniquement (sécurité)
ufw allow from 192.168.2.0/24 to any port 9200 proto tcp comment 'Elasticsearch HTTP'
ufw allow from 192.168.2.0/24 to any port 9300 proto tcp comment 'Elasticsearch Transport'
ufw allow from 192.168.2.0/24 to any port 5601 proto tcp comment 'Kibana Web Interface'
ufw allow from 192.168.2.0/24 to any port 5044 proto tcp comment 'Logstash Beats Input'

# Activer UFW
ufw --force enable

# Afficher le statut
print_status "Configuration UFW terminée:"
ufw status numbered

# ================================
# CRÉATION DE LA STRUCTURE DE RÉPERTOIRES
# ================================

print_status "Création de la structure de répertoires ELK..."

# Répertoires pour les configurations personnalisées
mkdir -p /opt/elk-config/{elasticsearch,logstash,kibana}
mkdir -p /opt/elk-scripts
mkdir -p /var/log/elk-setup

# Répertoires pour les données (optimisation sur /var)
mkdir -p /var/lib/elasticsearch
mkdir -p /var/lib/logstash  
mkdir -p /var/log/elasticsearch
mkdir -p /var/log/logstash
mkdir -p /var/log/kibana

# Répertoires pour les sauvegardes
mkdir -p /opt/elk-backups/{configs,data}

# Permissions appropriées
chown -R root:root /opt/elk-config
chmod -R 755 /opt/elk-config

print_status "Structure de répertoires créée"

# ================================
# SCRIPTS UTILITAIRES
# ================================

print_status "Création des scripts utilitaires..."

# Script de monitoring ELK
cat > /opt/elk-scripts/monitor_elk.sh << 'EOF'
#!/bin/bash
# Script de monitoring ELK Stack

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=== ELK Stack Status - $(date) ==="
echo ""

# Statut des services
echo "Services Status:"
for service in elasticsearch logstash kibana; do
    if systemctl is-active --quiet $service; then
        echo -e "  ${GREEN}✓${NC} $service: Running"
    else
        echo -e "  ${RED}✗${NC} $service: Stopped"
    fi
done
echo ""

# Utilisation des ressources
echo "Resource Usage:"
echo "  Memory: $(free -h | awk 'NR==2{printf "%.1f%% used (%s/%s)", $3*100/$2, $3, $2}')"
echo "  Disk /var: $(df -h /var | awk 'NR==2{printf "%s used (%s available)", $5, $4}')"
echo "  Load Average: $(uptime | awk -F'load average:' '{print $2}')"
echo ""

# Ports en écoute
echo "ELK Ports:"
for port in 9200 5601 5044; do
    if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
        echo -e "  ${GREEN}✓${NC} Port $port: Listening"
    else
        echo -e "  ${RED}✗${NC} Port $port: Not listening"
    fi
done
echo ""

# Processus Java
JAVA_PROCS=$(ps aux | grep java | grep -v grep | wc -l)
echo "Java Processes: $JAVA_PROCS"

# Test Elasticsearch (si en cours d'exécution)
if systemctl is-active --quiet elasticsearch; then
    echo ""
    echo "Elasticsearch Health:"
    curl -s -X GET "localhost:9200/_cluster/health?pretty" 2>/dev/null | grep -E "(cluster_name|status|number_of_nodes)" || echo "  Not responding"
fi
EOF

chmod +x /opt/elk-scripts/monitor_elk.sh

# Script de sauvegarde des configurations
cat > /opt/elk-scripts/backup_configs.sh << 'EOF'
#!/bin/bash
# Script de sauvegarde des configurations ELK

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/elk-backups/configs/$BACKUP_DATE"

mkdir -p "$BACKUP_DIR"

echo "=== Sauvegarde configurations ELK - $BACKUP_DATE ==="

# Sauvegarder les configurations si elles existent
[ -f /etc/elasticsearch/elasticsearch.yml ] && cp /etc/elasticsearch/elasticsearch.yml "$BACKUP_DIR/"
[ -f /etc/logstash/logstash.yml ] && cp /etc/logstash/logstash.yml "$BACKUP_DIR/"
[ -f /etc/kibana/kibana.yml ] && cp /etc/kibana/kibana.yml "$BACKUP_DIR/"
[ -d /etc/logstash/conf.d ] && cp -r /etc/logstash/conf.d "$BACKUP_DIR/"

# Sauvegarder les configurations système importantes
cp /etc/sysctl.conf "$BACKUP_DIR/"
cp /etc/security/limits.conf "$BACKUP_DIR/"

echo "Sauvegarde terminée dans: $BACKUP_DIR"
ls -la "$BACKUP_DIR"
EOF

chmod +x /opt/elk-scripts/backup_configs.sh

print_status "Scripts utilitaires créés"

# ================================
# FINALISATION ET TESTS
# ================================

print_status "Tests de validation de la configuration..."

# Test Java
print_info "Test Java:"
java -version 2>&1 | head -1

# Test connectivité repository Elastic
print_info "Test repository Elastic:"
if apt-cache search elasticsearch >/dev/null 2>&1; then
    echo "  ✓ Repository accessible"
else
    echo "  ✗ Problème repository"
fi

# Test paramètres système
print_info "Test paramètres système critiques:"
echo "  vm.max_map_count = $(sysctl -n vm.max_map_count) (requis: ≥262144)"
echo "  Mémoire disponible = $(free -h | awk 'NR==2{print $7}')"

# Test pare-feu
print_info "Test pare-feu:"
if ufw status | grep -q "Status: active"; then
    echo "  ✓ UFW activé et configuré"
else
    echo "  ✗ Problème UFW"
fi

# ================================
# CRÉATION DU FICHIER DE STATUT
# ================================

print_status "Création du fichier de statut de configuration..."

cat > /opt/elk-setup-status.txt << EOF
=== ELK Stack - Configuration système de base ===
Date de configuration: $(date)
Hostname: $(hostname)
IP: $(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')

✓ SYSTÈME
- OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)
- Kernel: $(uname -r)
- Uptime: $(uptime | awk '{print $3,$4}' | sed 's/,//')

✓ JAVA
- Version: $(java -version 2>&1 | head -n 1)
- JAVA_HOME: $JAVA_HOME

✓ REPOSITORY ELASTIC
- Clé GPG: Ajoutée
- Repository 8.x: Configuré
- Accès: $(apt-cache search elasticsearch >/dev/null 2>&1 && echo "OK" || echo "ERREUR")

✓ OPTIMISATIONS SYSTÈME
- vm.max_map_count: $(sysctl -n vm.max_map_count)
- vm.swappiness: $(sysctl -n vm.swappiness)
- Limites nofile: Configurées

✓ SÉCURITÉ
- UFW: $(ufw status | grep Status | awk '{print $2}')
- SSH: Port 22 (LAN uniquement)
- ELK Ports: 9200, 5601, 5044 (LAN uniquement)

✓ STRUCTURE
- Répertoires: Créés
- Scripts: /opt/elk-scripts/
- Backups: /opt/elk-backups/

ÉTAPES SUIVANTES:
1. Installation Elasticsearch
2. Installation Logstash  
3. Installation Kibana
4. Configuration des services
5. Tests d'intégration

SCRIPTS DISPONIBLES:
- /opt/elk-scripts/monitor_elk.sh
- /opt/elk-scripts/backup_configs.sh
EOF

# ================================
# INFORMATIONS FINALES
# ================================

print_status "=== Configuration système de base terminée avec succès! ==="
echo ""
print_info "Résumé de la configuration:"
echo "  Java 17: $(java -version 2>&1 | head -1 | awk '{print $3}' | tr -d '"')"
echo "  Repository Elastic: Configuré"
echo "  Paramètres système: Optimisés"
echo "  Pare-feu: Configuré"
echo "  Scripts: Créés"
echo ""
print_info "Fichiers importants:"
echo "  Statut: /opt/elk-setup-status.txt"
echo "  Scripts: /opt/elk-scripts/"
echo "  Logs: /var/log/elk-setup/"
echo ""
print_warning "PROCHAINES ÉTAPES:"
echo "1. Installation d'Elasticsearch"
echo "2. Installation de Logstash"
echo "3. Installation de Kibana"
echo ""
print_status "Système prêt pour l'installation de la stack ELK!"

# Log de fin
echo "$(date): Configuration système de base terminée avec succès" >> /var/log/elk-setup/install.log