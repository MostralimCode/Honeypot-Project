#!/bin/bash
# Script de résolution des problèmes Logstash identifiés

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

print_status "=== Résolution des problèmes Logstash ==="

# 1. ARRÊTER TOUS LES PROCESSUS LOGSTASH
print_status "1. Arrêt de tous les processus Logstash..."

# Arrêter le service systemd
systemctl stop logstash 2>/dev/null

# Tuer tous les processus Logstash restants
print_warning "Recherche des processus Logstash actifs..."
LOGSTASH_PIDS=$(ps aux | grep logstash | grep -v grep | awk '{print $2}')

if [ ! -z "$LOGSTASH_PIDS" ]; then
    echo "Processus trouvés: $LOGSTASH_PIDS"
    for pid in $LOGSTASH_PIDS; do
        echo "Arrêt du processus $pid..."
        kill -TERM $pid 2>/dev/null || kill -KILL $pid 2>/dev/null
    done
    sleep 5
    
    # Vérifier si des processus restent
    REMAINING=$(ps aux | grep logstash | grep -v grep | wc -l)
    if [ $REMAINING -gt 0 ]; then
        print_error "Des processus Logstash résistent, force kill..."
        pkill -9 -f logstash
    fi
else
    echo "Aucun processus Logstash trouvé"
fi

print_status "✓ Tous les processus Logstash arrêtés"

# 2. NETTOYER LES VERROUS ET DONNÉES
print_status "2. Nettoyage des verrous et données..."

# Supprimer les fichiers de verrouillage
rm -f /var/lib/logstash/.lock
rm -f /var/lib/logstash/logstash.lock
rm -rf /var/lib/logstash/queue
rm -rf /var/lib/logstash/dead_letter_queue

# Nettoyer les sincedb (positions de lecture des fichiers)
rm -f /var/lib/logstash/sincedb_*

# Nettoyer les logs anciens
rm -f /var/log/logstash/logstash-plain.log.*
rm -f /var/log/logstash/logstash-deprecation.log.*

print_status "✓ Nettoyage terminé"

# 3. RECRÉER LA STRUCTURE PROPREMENT
print_status "3. Recréation de la structure Logstash..."

# Recréer les répertoires avec bonnes permissions
mkdir -p /var/lib/logstash
mkdir -p /var/log/logstash
mkdir -p /etc/logstash/conf.d

# Permissions correctes
chown -R logstash:logstash /var/lib/logstash
chown -R logstash:logstash /var/log/logstash
chown -R logstash:logstash /etc/logstash

# Permissions spécifiques
chmod 755 /var/lib/logstash
chmod 755 /var/log/logstash
chmod 750 /etc/logstash

print_status "✓ Structure recréée"

# 4. CONFIGURATION ULTRA-MINIMALE
print_status "4. Création d'une configuration minimale fonctionnelle..."

# Supprimer toutes les configurations existantes
rm -f /etc/logstash/conf.d/*.conf

# Configuration Logstash ultra-simple
cat > /etc/logstash/logstash.yml << 'EOF'
# Configuration Logstash ultra-minimale
node.name: logstash-honeypot
path.data: /var/lib/logstash
path.logs: /var/log/logstash
path.settings: /etc/logstash
pipeline.workers: 1
pipeline.batch.size: 125
http.host: "192.168.2.124"
http.port: 9600
log.level: info
EOF

# Pipeline ultra-simple pour test
cat > /etc/logstash/conf.d/00-test-minimal.conf << 'EOF'
input {
  heartbeat {
    interval => 10
    type => "heartbeat"
  }
}

output {
  elasticsearch {
    hosts => ["192.168.2.124:9200"]
    index => "logstash-test-%{+YYYY.MM.dd}"
  }
}
EOF

# Permissions
chown logstash:logstash /etc/logstash/logstash.yml
chown logstash:logstash /etc/logstash/conf.d/00-test-minimal.conf
chmod 644 /etc/logstash/logstash.yml
chmod 644 /etc/logstash/conf.d/00-test-minimal.conf

print_status "✓ Configuration minimale créée"

# 5. TEST DE CONFIGURATION
print_status "5. Test de la configuration..."

if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✓ Configuration validée"
else
    print_error "✗ Erreur de configuration"
    exit 1
fi

# 6. VÉRIFICATIONS PRÉALABLES
print_status "6. Vérifications préalables..."

# Vérifier Elasticsearch
if curl -s "http://192.168.2.124:9200/" >/dev/null; then
    print_status "✓ Elasticsearch accessible"
else
    print_error "✗ Elasticsearch non accessible"
    exit 1
fi

# Vérifier Java
if java -version >/dev/null 2>&1; then
    print_status "✓ Java disponible"
else
    print_error "✗ Java non disponible"
    exit 1
fi

# Vérifier les permissions
if [ -w "/var/lib/logstash" ] && [ -w "/var/log/logstash" ]; then
    print_status "✓ Permissions OK"
else
    print_error "✗ Problème de permissions"
    chown -R logstash:logstash /var/lib/logstash /var/log/logstash
fi

print_status "✓ Toutes les vérifications passées"

# 7. CRÉATION D'UN SCRIPT DE TEST SÉCURISÉ
cat > /opt/elk-scripts/test_logstash_safe.sh << 'EOF'
#!/bin/bash
echo "=== Test sécurisé de Logstash ==="

echo "1. Vérification qu'aucun processus Logstash n'est actif..."
if ps aux | grep -v grep | grep -q logstash; then
    echo "❌ Processus Logstash encore actifs!"
    ps aux | grep logstash | grep -v grep
    exit 1
fi
echo "✅ Aucun processus Logstash actif"

echo ""
echo "2. Test de configuration..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    echo "✅ Configuration OK"
else
    echo "❌ Configuration invalide"
    exit 1
fi

echo ""
echo "3. Test de connectivité Elasticsearch..."
if curl -s "http://192.168.2.124:9200/" >/dev/null; then
    echo "✅ Elasticsearch accessible"
else
    echo "❌ Elasticsearch non accessible"
    exit 1
fi

echo ""
echo "4. Démarrage du service..."
systemctl start logstash

echo ""
echo "5. Attente du démarrage (30s max)..."
counter=0
while [ $counter -lt 30 ]; do
    if systemctl is-active --quiet logstash; then
        echo "✅ Logstash démarré avec succès"
        break
    fi
    echo -n "."
    sleep 2
    counter=$((counter + 2))
done

echo ""
echo "6. Vérification finale..."
echo "Service: $(systemctl is-active logstash)"
echo "API: $(curl -s http://192.168.2.124:9600/ >/dev/null 2>&1 && echo "OK" || echo "NOK")"

if systemctl is-active --quiet logstash; then
    echo ""
    echo "🎉 SUCCÈS! Logstash fonctionne"
else
    echo ""
    echo "❌ Échec - Vérifiez les logs:"
    journalctl -u logstash --no-pager -n 10
fi
EOF

chmod +x /opt/elk-scripts/test_logstash_safe.sh

print_status "=== Résolution terminée ==="
echo ""
print_warning "ÉTAPES SUIVANTES:"
echo "1. Lancer le test: /opt/elk-scripts/test_logstash_safe.sh"
echo "2. Si succès, ajouter progressivement vos pipelines"
echo "3. Surveiller: journalctl -u logstash -f"
echo ""
print_status "Logstash prêt pour un nouveau démarrage propre!"