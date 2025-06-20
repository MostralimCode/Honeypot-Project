#!/bin/bash
# Script pour corriger UNIQUEMENT la syntaxe du fichier 30-ftp.conf
# Fix des problèmes de if imbriqués et structure

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

print_status "=== Correction syntaxe fichier FTP UNIQUEMENT ==="

# Sauvegarder l'ancien fichier FTP
FTP_FILE="/etc/logstash/conf.d/30-ftp.conf"
BACKUP_FILE="/etc/logstash/conf.d/30-ftp.conf.backup.$(date +%Y%m%d_%H%M%S)"

if [ -f "$FTP_FILE" ]; then
    print_warning "Sauvegarde de l'ancien fichier FTP vers: $BACKUP_FILE"
    cp "$FTP_FILE" "$BACKUP_FILE"
else
    print_error "Fichier $FTP_FILE non trouvé"
    exit 1
fi

# Recréer le fichier FTP avec syntaxe corrigée
print_status "Recréation du fichier 30-ftp.conf avec syntaxe propre..."

cat > "$FTP_FILE" << 'EOF'
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
    
    # Classification événements FTP - STRUCTURE CORRIGÉE (pas de if imbriqués)
    if [event_type] == "auth_attempt" and [success] == true {
      mutate { 
        add_field => { "event_category" => "authentication_success" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
      }
    } else if [event_type] == "auth_attempt" and [success] == false {
      mutate { 
        add_field => { "event_category" => "authentication_failure" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
      }
    } else if [event_type] == "auth_attempt" {
      # Cas où success n'est pas défini - traiter comme échec
      mutate { 
        add_field => { "event_category" => "authentication_failure" }
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
    } else if [event_type] == "vulnerability_test" {
      mutate { 
        add_field => { "event_category" => "vulnerability_probe" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    } else if [event_type] == "command_injection" {
      mutate { 
        add_field => { "event_category" => "command_injection" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
      }
    }
    
    # Analyse des commandes FTP
    if [command] {
      if [command] in ["SITE EXEC", "SITE CHMOD", "SITE RMDIR"] {
        mutate {
          add_field => { "dangerous_command" => "true" }
          add_field => { "severity" => "high" }
        }
      }
    }
    
    # Détection fichiers suspects
    if [filename] =~ /(?i)(\.php|\.asp|\.jsp|\.exe|\.bat|\.sh|backdoor|shell|webshell)/ {
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

print_status "✓ Fichier 30-ftp.conf recréé avec syntaxe corrigée"

# Test de syntaxe du fichier FTP uniquement
print_status "Test de syntaxe du fichier FTP corrigé..."

# Créer un répertoire de test temporaire
TEST_DIR="/tmp/test-ftp-syntax"
mkdir -p "$TEST_DIR"

# Copier seulement le fichier FTP pour test isolé
cp "$FTP_FILE" "$TEST_DIR/"

# Test de syntaxe
if timeout 30 sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash --path.config "$TEST_DIR" -t; then
    print_status "✅ Fichier 30-ftp.conf - SYNTAXE VALIDÉE"
    SYNTAX_OK=true
else
    print_error "❌ Fichier 30-ftp.conf - ERREUR DE SYNTAXE"
    SYNTAX_OK=false
fi

# Nettoyer le répertoire de test
rm -rf "$TEST_DIR"

# Permissions correctes
chmod 644 "$FTP_FILE"
chown root:root "$FTP_FILE"

print_status "=== Résultat de la correction ==="

if [ "$SYNTAX_OK" = true ]; then
    print_status "🎯 SUCCÈS - Fichier FTP corrigé et validé"
    echo ""
    print_status "✅ CORRECTIONS APPLIQUÉES:"
    echo "   • Suppression des if imbriqués problématiques"
    echo "   • Structure en else if linéaire (comme Cowrie)"
    echo "   • Gestion explicite des cas [success] == true/false"
    echo "   • Syntaxe Logstash standardisée"
    echo ""
    print_status "📁 FICHIERS:"
    echo "   • Nouveau: $FTP_FILE"
    echo "   • Backup: $BACKUP_FILE"
    echo ""
    print_status "🔧 TEST COMPLET DES PIPELINES:"
    echo "   sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t"
    echo ""
    print_status "🚀 PRÊT POUR DÉMARRAGE LOGSTASH"
    
else
    print_error "❌ ÉCHEC - Problème de syntaxe persistant"
    echo ""
    print_warning "Restauration de l'ancien fichier..."
    cp "$BACKUP_FILE" "$FTP_FILE"
    echo ""
    print_error "Actions possibles:"
    echo "   1. Vérifier le contenu: cat $FTP_FILE"
    echo "   2. Éditer manuellement: nano $FTP_FILE"  
    echo "   3. Utiliser la backup: cp $BACKUP_FILE $FTP_FILE"
fi

echo ""
print_status "=== Correction du fichier FTP terminée ==="