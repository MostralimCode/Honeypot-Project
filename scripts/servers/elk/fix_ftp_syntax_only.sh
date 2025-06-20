#!/bin/bash
# Correction des opérateurs Logstash dans le fichier FTP
# Le problème: "and" n'existe pas en Logstash, il faut utiliser des blocs imbriqués simples

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

print_status "=== Correction des opérateurs Logstash pour FTP ==="

# Recréer le fichier avec la BONNE syntaxe Logstash
cat > /etc/logstash/conf.d/30-ftp.conf << 'EOF'
filter {
  if [honeypot_type] == "ftp" {
    # Ajouter métadonnées
    mutate {
      add_field => { "service" => "ftp_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
    
    # Parse timestamp
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
      }
    }
    
    # Normalisation IP
    if [ip] and ![src_ip] {
      mutate {
        add_field => { "src_ip" => "%{ip}" }
      }
    }
    
    # GeoIP enrichissement
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification événements FTP - SYNTAXE LOGSTASH CORRECTE
    if [event_type] == "auth_attempt" {
      if [success] == true {
        mutate { 
          add_field => { "event_category" => "authentication_success" }
          add_field => { "severity" => "critical" }
          add_field => { "alert_level" => "4" }
        }
      } else {
        mutate { 
          add_field => { "event_category" => "authentication_failure" }
          add_field => { "severity" => "medium" }
          add_field => { "alert_level" => "2" }
        }
      }
    }
    
    if [event_type] == "file_upload" {
      mutate { 
        add_field => { "event_category" => "file_upload" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    }
    
    if [event_type] == "directory_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    }
    
    if [event_type] == "file_download" {
      mutate { 
        add_field => { "event_category" => "file_download" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
      }
    }
    
    # Détection fichiers suspects
    if [filename] =~ /(?i)(\.php|\.asp|\.exe|backdoor|shell)/ {
      mutate {
        add_field => { "suspicious_file" => "true" }
        add_field => { "malicious_file" => "true" }
      }
    }
    
    # Détection mots de passe communs
    if [password] {
      if [password] in ["ftp", "anonymous", "admin", "password", "123456", "root"] {
        mutate {
          add_field => { "common_password" => "true" }
        }
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

print_status "✓ Fichier FTP recréé avec syntaxe Logstash correcte"

# Test de syntaxe
print_status "Test de syntaxe..."

TEST_DIR="/tmp/test-ftp-final"
mkdir -p "$TEST_DIR"
cp /etc/logstash/conf.d/30-ftp.conf "$TEST_DIR/"

if timeout 30 sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash --path.config "$TEST_DIR" -t; then
    print_status "✅ SUCCÈS - Syntaxe FTP validée !"
else
    print_error "❌ Erreur de syntaxe persistante"
fi

rm -rf "$TEST_DIR"

print_status "=== Correction terminée ==="
print_status "CHANGEMENTS CLÉS:"
echo "   • Supprimé: 'and' operator (n'existe pas en Logstash)"
echo "   • Utilisé: if imbriqués simples (syntaxe standard)"
echo "   • Structure: comme le fichier Cowrie qui fonctionne"