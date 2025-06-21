#!/bin/bash
# Script pour créer une configuration FTP minimale qui fonctionne
# Basé exactement sur la structure Cowrie qui marche

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

print_status "=== Configuration FTP Pipeline - Version Minimale ==="

FTP_FILE="/etc/logstash/conf.d/30-ftp-honeypot.conf"

# Sauvegarder l'ancien fichier
if [ -f "$FTP_FILE" ]; then
    BACKUP_FILE="${FTP_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    print_warning "Sauvegarde: $BACKUP_FILE"
    cp "$FTP_FILE" "$BACKUP_FILE"
fi

print_status "Création du pipeline FTP minimal (structure Cowrie)..."

cat > "$FTP_FILE" << 'EOF'
filter {
  if [honeypot_type] == "ftp" {
    mutate {
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "service" => "ftp_honeypot" }
    }
    
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
      }
    }
    
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    if [event_type] == "auth_attempt" {
      mutate { 
        add_field => { "event_category" => "authentication_attempt" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
      }
    } else if [event_type] == "file_upload" {
      mutate { 
        add_field => { "event_category" => "file_upload" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    } else if [event_type] == "directory_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    } else if [event_type] == "file_download" {
      mutate { 
        add_field => { "event_category" => "file_download" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
      }
    }
    
    if [filename] =~ /(?i)(\.php|\.asp|\.exe|backdoor|shell)/ {
      mutate {
        add_field => { "suspicious_file" => "true" }
        add_field => { "malicious_file" => "true" }
      }
    }
  }
}

output {
  if [honeypot_type] == "ftp" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✓ Fichier FTP minimal créé"

# Permissions
chmod 644 "$FTP_FILE"
chown root:root "$FTP_FILE"

print_status "Test de syntaxe du fichier FTP minimal..."

# Test isolé
TEST_DIR="/tmp/test-ftp-minimal"
mkdir -p "$TEST_DIR"
cp "$FTP_FILE" "$TEST_DIR/"

if timeout 30 sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash --path.config "$TEST_DIR" -t; then
    print_status "✅ SUCCÈS - Pipeline FTP minimal validé !"
    SYNTAX_OK=true
else
    print_error "❌ ÉCHEC - Erreur de syntaxe persistante"
    SYNTAX_OK=false
fi

rm -rf "$TEST_DIR"

# Test complet avec tous les pipelines
if [ "$SYNTAX_OK" = true ]; then
    print_status "Test de la configuration complète..."
    
    if timeout 30 sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
        print_status "✅ Configuration complète validée !"
        echo ""
        print_status "🎯 PIPELINE FTP FONCTIONNEL !"
        echo "   Structure: Identique à Cowrie (testé et validé)"
        echo "   Fonctionnalités: Authentification, uploads, downloads, traversal"
        echo "   GeoIP: Activé"
        echo "   Détection: Fichiers suspects"
        echo ""
        print_status "📋 PROCHAINES ÉTAPES:"
        echo "   1. Démarrer Logstash: systemctl start logstash"
        echo "   2. Surveiller: journalctl -u logstash -f"
        echo "   3. Passer à l'étape 5.6 (Kibana)"
        
    else
        print_error "❌ Problème avec la configuration complète"
        print_warning "Le pipeline FTP fonctionne seul, mais conflit avec les autres"
        echo ""
        print_warning "Actions possibles:"
        echo "   1. Vérifier les autres pipelines"
        echo "   2. Démarrer avec FTP seul pour tester"
    fi
else
    print_error "❌ Le pipeline FTP minimal ne fonctionne toujours pas"
    echo ""
    print_error "Le problème est plus profond. Vérifiez:"
    echo "   1. Version Logstash: /usr/share/logstash/bin/logstash --version"
    echo "   2. Permissions: ls -la /etc/logstash/conf.d/"
    echo "   3. Syntaxe manuelle: nano $FTP_FILE"
fi

print_status "=== Configuration FTP terminée ==="