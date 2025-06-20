#!/bin/bash
# Script de correction Logstash SIMPLIFIÉ - VM ELK (192.168.2.124)
# Version corrigée sans templates complexes

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

print_status "=== CORRECTION LOGSTASH SIMPLIFIÉE ==="

# 1. Arrêter Logstash
print_status "Arrêt de Logstash..."
systemctl stop logstash

# 2. Supprimer les configurations défaillantes
print_status "Suppression des configurations défaillantes..."
rm -f /etc/logstash/conf.d/*.conf

# 3. Créer INPUT simple
print_status "Création INPUT Beats simple..."

cat > /etc/logstash/conf.d/00-beats-input.conf << 'EOF'
input {
  beats {
    port => 5044
    host => "192.168.2.124"
  }
}
EOF

# 4. Créer FILTER simple
print_status "Création FILTER simple..."

cat > /etc/logstash/conf.d/10-honeypot-filters.conf << 'EOF'
filter {
  # Ajouter des métadonnées communes
  mutate {
    add_field => { "processed_by" => "logstash" }
  }
  
  # Traitement par type de honeypot
  if [honeypot_type] == "ssh" {
    mutate {
      add_field => { "service" => "cowrie-ssh" }
      add_field => { "category" => "ssh_honeypot" }
    }
  }
  
  if [honeypot_type] == "http" {
    mutate {
      add_field => { "service" => "http-honeypot" }
      add_field => { "category" => "web_honeypot" }
    }
  }
  
  if [honeypot_type] == "ftp" {
    mutate {
      add_field => { "service" => "ftp-honeypot" }
      add_field => { "category" => "ftp_honeypot" }
    }
  }
  
  # Parser timestamp si présent
  if [timestamp] {
    date {
      match => [ "timestamp", "ISO8601" ]
      target => "@timestamp"
    }
  }
}
EOF

# 5. Créer OUTPUT simple
print_status "Création OUTPUT simple..."

cat > /etc/logstash/conf.d/90-elasticsearch-output.conf << 'EOF'
output {
  # Output pour SSH
  if [honeypot_type] == "ssh" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
    }
  }
  # Output pour HTTP
  else if [honeypot_type] == "http" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
    }
  }
  # Output pour FTP
  else if [honeypot_type] == "ftp" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
    }
  }
  # Output pour système
  else if [honeypot_type] == "system" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-system-%{+YYYY.MM.dd}"
    }
  }
  # Fallback
  else {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-misc-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# 6. Permissions
print_status "Configuration des permissions..."
chown -R logstash:logstash /etc/logstash/conf.d/
chmod 644 /etc/logstash/conf.d/*.conf

# 7. Test de syntaxe
print_status "Test de syntaxe..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Syntaxe correcte"
else
    print_error "❌ Erreur de syntaxe"
    echo "Fichiers créés pour debug:"
    ls -la /etc/logstash/conf.d/
    exit 1
fi

# 8. Démarrer Logstash
print_status "Démarrage de Logstash..."
systemctl start logstash

# Attendre le démarrage
print_info "Attente du démarrage..."
counter=0
while [ $counter -lt 60 ]; do
    if systemctl is-active --quiet logstash; then
        print_status "✅ Logstash démarré"
        break
    fi
    sleep 2
    counter=$((counter + 2))
    if [ $((counter % 10)) -eq 0 ]; then
        echo "Attente... ${counter}s"
    fi
done

# 9. Vérifications
print_status "Vérifications..."

# Service actif
if systemctl is-active --quiet logstash; then
    print_status "✅ Service actif"
else
    print_error "❌ Service non actif"
    journalctl -u logstash --no-pager -n 10
    exit 1
fi

# Port en écoute
sleep 10
if netstat -tlnp | grep -q ":5044 "; then
    print_status "✅ Port 5044 en écoute"
else
    print_warning "⚠️ Port 5044 pas encore ouvert"
fi

# Test Elasticsearch
if curl -s "http://192.168.2.124:9200/_cluster/health" | grep -q "yellow\|green"; then
    print_status "✅ Elasticsearch accessible"
else
    print_warning "⚠️ Problème Elasticsearch"
fi

# 10. Script de test
print_status "Création du script de test..."

cat > /opt/test_logstash_honeypot.sh << 'TEST_EOF'
#!/bin/bash
echo "=== TEST LOGSTASH HONEYPOT ==="
echo ""
echo "📊 Status services:"
echo "Logstash: $(systemctl is-active logstash)"
echo "Elasticsearch: $(systemctl is-active elasticsearch)"
echo ""
echo "🔗 Ports:"
netstat -tlnp | grep -E ":5044|:9200" | head -2
echo ""
echo "📊 Indices honeypot:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v" 2>/dev/null || echo "Pas encore d'indices"
echo ""
echo "🔢 Test de comptage:"
curl -s "http://192.168.2.124:9200/honeypot-*/_count?pretty" 2>/dev/null | grep count || echo "Pas de données"
echo ""
echo "🔍 Derniers logs Logstash:"
journalctl -u logstash --no-pager -n 3 | tail -3
TEST_EOF

chmod +x /opt/test_logstash_honeypot.sh

# 11. Résumé
print_status "=== CORRECTION TERMINÉE ==="
echo ""
print_info "📁 Fichiers créés:"
echo "✅ /etc/logstash/conf.d/00-beats-input.conf"
echo "✅ /etc/logstash/conf.d/10-honeypot-filters.conf"
echo "✅ /etc/logstash/conf.d/90-elasticsearch-output.conf"
echo "✅ /opt/test_logstash_honeypot.sh"
echo ""
print_warning "🎯 PROCHAINES ÉTAPES:"
echo "1. Tester: /opt/test_logstash_honeypot.sh"
echo "2. Surveiller: journalctl -u logstash -f"
echo "3. Générer des logs de test sur VM Honeypot"
echo ""
print_status "Configuration Logstash simplifiée - Prête !"