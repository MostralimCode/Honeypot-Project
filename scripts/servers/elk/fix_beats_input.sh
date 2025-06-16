#!/bin/bash
# Correction immédiate pour l'input Beats manquant dans Logstash
# À exécuter sur VM ELK (192.168.2.124)

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

print_status "=== CORRECTION INPUT BEATS LOGSTASH ==="

# 1. Créer l'input Beats manquant
print_status "Création de l'input Beats..."

cat > /etc/logstash/conf.d/00-beats-input.conf << 'EOF'
# Input Beats pour recevoir les données de Filebeat
input {
  beats {
    port => 5044
    type => "beats"
  }
}
EOF

# 2. Créer des filtres et outputs basiques pour les honeypots
print_status "Création des pipelines honeypot..."

# Pipeline pour tous les honeypots
cat > /etc/logstash/conf.d/01-honeypot-filter.conf << 'EOF'
filter {
  if [type] == "beats" {
    # Ajouter des métadonnées communes
    mutate {
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "processed_by" => "logstash" }
    }
    
    # Parser le timestamp si présent
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
        target => "@timestamp"
      }
    }
    
    # Classification par type de honeypot
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
  }
}
EOF

# Pipeline de sortie vers Elasticsearch
cat > /etc/logstash/conf.d/99-elasticsearch-output.conf << 'EOF'
output {
  if [type] == "beats" {
    # Rediriger vers les bons indices selon le type
    if [honeypot_type] == "ssh" {
      elasticsearch {
        hosts => ["192.168.2.124:9200"]
        index => "honeypot-cowrie-%{+YYYY.MM.dd}"
      }
    } else if [honeypot_type] == "http" {
      elasticsearch {
        hosts => ["192.168.2.124:9200"]
        index => "honeypot-http-%{+YYYY.MM.dd}"
      }
    } else if [honeypot_type] == "ftp" {
      elasticsearch {
        hosts => ["192.168.2.124:9200"]
        index => "honeypot-ftp-%{+YYYY.MM.dd}"
      }
    } else {
      # Fallback pour autres types
      elasticsearch {
        hosts => ["192.168.2.124:9200"]
        index => "honeypot-general-%{+YYYY.MM.dd}"
      }
    }
  }
}
EOF

# 3. Permissions
print_status "Configuration des permissions..."
chown logstash:logstash /etc/logstash/conf.d/*.conf
chmod 644 /etc/logstash/conf.d/*.conf

# 4. Test de la configuration
print_status "Test de la nouvelle configuration..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Configuration valide"
else
    print_error "❌ Erreur dans la configuration"
    exit 1
fi

# 5. Redémarrage de Logstash
print_status "Redémarrage de Logstash..."
systemctl restart logstash

# Attendre le redémarrage
sleep 15

# 6. Vérification
print_status "Vérification du redémarrage..."

if systemctl is-active --quiet logstash; then
    print_status "✅ Logstash redémarré avec succès"
    
    # Vérifier le port 5044
    if netstat -tlnp | grep -q ":5044 "; then
        print_status "✅ Port 5044 en écoute"
    else
        print_warning "⚠️ Port 5044 pas encore en écoute"
    fi
    
    # Test API
    sleep 5
    if curl -s "http://192.168.2.124:9600/" >/dev/null; then
        print_status "✅ API Logstash accessible"
    else
        print_warning "⚠️ API Logstash pas encore prête"
    fi
    
else
    print_error "❌ Problème avec Logstash"
    journalctl -u logstash --no-pager -n 10
fi

# 7. Affichage final
print_status "=== RÉSULTAT ==="
echo ""
echo "📁 Fichiers créés:"
echo "   ✓ /etc/logstash/conf.d/00-beats-input.conf"
echo "   ✓ /etc/logstash/conf.d/01-honeypot-filter.conf"
echo "   ✓ /etc/logstash/conf.d/99-elasticsearch-output.conf"
echo ""
echo "🔧 Configuration:"
echo "   ✓ Input Beats sur port 5044"
echo "   ✓ Filtres pour SSH/HTTP/FTP"
echo "   ✓ Outputs vers indices honeypot-*"
echo ""
echo "🎯 Prochaine étape:"
echo "   Configurez Filebeat sur VM Honeypot (192.168.2.117)"
echo ""
print_status "Correction terminée - Logstash prêt à recevoir les données!"