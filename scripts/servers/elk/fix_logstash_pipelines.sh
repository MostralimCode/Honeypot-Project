#!/bin/bash
# scripts/elk/fix_logstash_pipelines.sh
# Correction automatique des pipelines Logstash

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

print_status "=== Correction des pipelines Logstash ==="

# Arrêter Logstash si en cours
print_status "Arrêt de Logstash..."
systemctl stop logstash 2>/dev/null

# Supprimer tous les pipelines problématiques
print_status "Suppression des pipelines défaillants..."
rm -f /etc/logstash/conf.d/*.conf

# ================================
# PIPELINE 1: COWRIE SSH (SIMPLIFIÉ)
# ================================

print_status "Création du pipeline Cowrie SSH (corrigé)..."

cat > /etc/logstash/conf.d/10-cowrie-ssh.conf << 'EOF'
# Pipeline Cowrie SSH - Version corrigée
input {
  file {
    path => "/var/log/cowrie/cowrie.json"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_cowrie"
    type => "cowrie"
    codec => "json"
    tags => ["honeypot", "ssh", "cowrie"]
  }
}

filter {
  if [type] == "cowrie" {
    # Parse timestamp
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    # Métadonnées de base
    mutate {
      add_field => { "honeypot_type" => "ssh" }
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "service" => "cowrie" }
    }
    
    # Classification simple des événements
    if [eventid] == "cowrie.login.success" {
      mutate { 
        add_field => { "event_category" => "authentication_success" }
        add_field => { "severity" => "high" }
      }
    }
    
    if [eventid] == "cowrie.login.failed" {
      mutate { 
        add_field => { "event_category" => "authentication_failure" }
        add_field => { "severity" => "medium" }
      }
    }
    
    if [eventid] == "cowrie.command.input" {
      mutate { 
        add_field => { "event_category" => "command_execution" }
        add_field => { "severity" => "medium" }
      }
      
      # Détecter commandes suspectes
      if [input] =~ /(?i)(wget|curl|nc|netcat|python|bash|sh)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "severity" => "high" }
        }
      }
    }
    
    if [eventid] == "cowrie.session.file_download" {
      mutate { 
        add_field => { "event_category" => "file_download" }
        add_field => { "severity" => "critical" }
      }
    }
    
    # Copier src_ip si présent
    if [src_ip] {
      mutate {
        add_field => { "source_ip" => "%{src_ip}" }
      }
    }
  }
}

output {
  if [type] == "cowrie" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✓ Pipeline Cowrie SSH créé"

# ================================
# PIPELINE 2: HTTP HONEYPOT (SIMPLIFIÉ)
# ================================

print_status "Création du pipeline HTTP Honeypot (corrigé)..."

cat > /etc/logstash/conf.d/20-http-honeypot.conf << 'EOF'
# Pipeline HTTP Honeypot - Version corrigée
input {
  file {
    path => "/var/log/honeypot/http_honeypot.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_http_honeypot"
    type => "http_honeypot"
    codec => "json"
    tags => ["honeypot", "http", "web"]
  }
}

filter {
  if [type] == "http_honeypot" {
    # Parse timestamp
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    # Métadonnées de base
    mutate {
      add_field => { "honeypot_type" => "http" }
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "service" => "http_custom" }
    }
    
    # Copier IP vers champ standard
    if [ip] {
      mutate {
        add_field => { "src_ip" => "%{ip}" }
      }
    }
    
    # Classification des attaques HTTP
    if [attack_type] == "sql_injection" {
      mutate { 
        add_field => { "event_category" => "sql_injection" }
        add_field => { "severity" => "high" }
      }
    }
    
    if [attack_type] == "xss" {
      mutate { 
        add_field => { "event_category" => "cross_site_scripting" }
        add_field => { "severity" => "medium" }
      }
    }
    
    if [attack_type] == "path_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
      }
    }
    
    if [attack_type] == "unauthorized_admin_access" {
      mutate { 
        add_field => { "event_category" => "unauthorized_access" }
        add_field => { "severity" => "critical" }
      }
    }
  }
}

output {
  if [type] == "http_honeypot" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✓ Pipeline HTTP Honeypot créé"

# ================================
# PIPELINE 3: FTP HONEYPOT (ULTRA-SIMPLIFIÉ)
# ================================

print_status "Création du pipeline FTP Honeypot (corrigé)..."

cat > /etc/logstash/conf.d/30-ftp-honeypot.conf << 'EOF'
# Pipeline FTP Honeypot - Version corrigée
input {
  file {
    path => "/root/honeypot-ftp/logs/sessions.json"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_ftp_honeypot"
    type => "ftp_honeypot"
    codec => "json"
    tags => ["honeypot", "ftp"]
  }
}

filter {
  if [type] == "ftp_honeypot" {
    # Parse timestamp
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    # Métadonnées de base
    mutate {
      add_field => { "honeypot_type" => "ftp" }
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "service" => "ftp_custom" }
    }
    
    # Copier IP vers champ standard
    if [ip] {
      mutate {
        add_field => { "src_ip" => "%{ip}" }
      }
    }
    
    # Classification simple des événements FTP
    if [event_type] == "auth_attempt" {
      if [success] == true {
        mutate { 
          add_field => { "event_category" => "authentication_success" }
          add_field => { "severity" => "high" }
        }
      } else {
        mutate { 
          add_field => { "event_category" => "authentication_failure" }
          add_field => { "severity" => "medium" }
        }
      }
    }
    
    if [event_type] == "directory_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
      }
    }
    
    if [event_type] == "brute_force_detected" {
      mutate { 
        add_field => { "event_category" => "brute_force" }
        add_field => { "severity" => "critical" }
      }
    }
  }
}

output {
  if [type] == "ftp_honeypot" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✓ Pipeline FTP Honeypot créé"

# ================================
# PIPELINE 4: SERVEURS SÉCURISÉS (SIMPLIFIÉ)
# ================================

print_status "Création du pipeline serveurs sécurisés (corrigé)..."

cat > /etc/logstash/conf.d/40-secure-servers.conf << 'EOF'
# Pipeline serveurs sécurisés - Version corrigée
input {
  file {
    path => "/var/log/auth.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_auth"
    type => "secure_server"
    tags => ["secure", "auth"]
  }
}

filter {
  if [type] == "secure_server" {
    # Parse syslog basique
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{IPORHOST:host} %{PROG:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:log_message}" }
    }
    
    # Métadonnées
    mutate {
      add_field => { "infrastructure" => "secure_server" }
      add_field => { "honeypot_type" => "secure" }
    }
    
    # Classification SSH simple
    if [program] == "sshd" {
      if [log_message] =~ /Failed password/ {
        mutate { 
          add_field => { "event_category" => "ssh_failed_login" }
          add_field => { "severity" => "medium" }
        }
      }
      
      if [log_message] =~ /Accepted password/ {
        mutate { 
          add_field => { "event_category" => "ssh_successful_login" }
          add_field => { "severity" => "low" }
        }
      }
    }
  }
}

output {
  if [type] == "secure_server" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "secure-servers-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✓ Pipeline serveurs sécurisés créé"

# ================================
# CONFIGURATION DES PERMISSIONS
# ================================

print_status "Configuration des permissions..."
chown -R logstash:logstash /etc/logstash/conf.d/
chmod 644 /etc/logstash/conf.d/*.conf

# ================================
# TEST DE LA CONFIGURATION
# ================================

print_status "Test de la configuration corrigée..."

if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✓ Configuration validée avec succès!"
    
    # Créer les répertoires de logs si nécessaire
    print_status "Création des répertoires de logs..."
    mkdir -p /var/log/cowrie
    mkdir -p /var/log/honeypot
    mkdir -p /root/honeypot-ftp/logs
    
    # Permissions
    chown -R logstash:logstash /var/lib/logstash/
    
    print_status "✓ Répertoires créés"
    
else
    print_error "✗ Erreur dans la configuration"
    print_info "Vérifiez les logs d'erreur ci-dessus"
    exit 1
fi

# ================================
# INFORMATIONS FINALES
# ================================

print_status "=== Pipelines Logstash corrigés avec succès! ==="
echo ""
print_info "Pipelines créés (versions simplifiées et fonctionnelles):"
echo "  ✓ 10-cowrie-ssh.conf       (SSH Honeypot)"
echo "  ✓ 20-http-honeypot.conf    (HTTP Honeypot)"
echo "  ✓ 30-ftp-honeypot.conf     (FTP Honeypot)"
echo "  ✓ 40-secure-servers.conf   (Serveurs sécurisés)"
echo ""
print_info "Fonctionnalités simplifiées pour éviter les erreurs:"
echo "  - GeoIP temporairement retiré (ajout possible plus tard)"
echo "  - Filtres de base fonctionnels"
echo "  - Classification des événements"
echo "  - Index Elasticsearch configurés"
echo ""
print_warning "PROCHAINES ÉTAPES:"
echo "1. Démarrer Logstash: systemctl start logstash"
echo "2. Vérifier les logs: journalctl -u logstash -f"
echo "3. Tester avec des données réelles"
echo ""
print_status "Logstash prêt à démarrer!"

# Créer un fichier de statut
cat > /opt/elk-setup-status-pipelines-fixed.txt << EOF
=== Logstash Pipelines Fixed Status ===
Date: $(date)

✓ PIPELINES CORRIGÉS:
- Cowrie SSH: Version simplifiée, fonctionnelle
- HTTP Honeypot: Version simplifiée, fonctionnelle
- FTP Honeypot: Version ultra-simplifiée, fonctionnelle  
- Serveurs sécurisés: Version simplifiée, fonctionnelle

✓ CORRECTIONS APPLIQUÉES:
- Suppression des configurations GeoIP problématiques
- Simplification des blocs mutate
- Syntaxe Ruby validée
- Permissions corrigées

✓ VALIDATION:
- Test de syntaxe: RÉUSSI
- Répertoires: Créés
- Permissions: OK

ÉTAPES SUIVANTES:
1. systemctl start logstash
2. Vérifier le démarrage
3. Ajouter GeoIP plus tard si nécessaire

Prêt pour: Démarrage de Logstash
EOF

echo "$(date): Pipelines Logstash corrigés avec succès" >> /var/log/elk-setup/install.log