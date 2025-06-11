#!/bin/bash
# scripts/elk/create_logstash_pipelines.sh
# Création des pipelines Logstash pour tous les honeypots

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

print_status "=== Création des pipelines Logstash honeypot ==="

# Supprimer le pipeline de test
rm -f /etc/logstash/conf.d/01-test.conf

# ================================
# PIPELINE 1: COWRIE SSH HONEYPOT
# ================================

print_status "Création du pipeline Cowrie SSH..."

cat > /etc/logstash/conf.d/10-cowrie-ssh.conf << 'EOF'
# Pipeline pour Cowrie SSH Honeypot
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
    
    # Ajouter des métadonnées
    mutate {
      add_field => { "honeypot_type" => "ssh" }
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "service" => "cowrie" }
    }
    
    # GeoIP sur les IPs sources
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification des événements SSH
    if [eventid] == "cowrie.login.success" {
      mutate { 
        add_field => { "event_category" => "authentication_success" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    }
    
    if [eventid] == "cowrie.login.failed" {
      mutate { 
        add_field => { "event_category" => "authentication_failure" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
      }
    }
    
    if [eventid] == "cowrie.command.input" {
      mutate { 
        add_field => { "event_category" => "command_execution" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
      }
      
      # Détecter les commandes suspectes
      if [input] =~ /(?i)(wget|curl|nc|netcat|python|perl|bash|sh|cat \/etc\/passwd|whoami|id|ps|kill)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "severity" => "high" }
          add_field => { "alert_level" => "3" }
        }
      }
    }
    
    if [eventid] == "cowrie.session.file_download" {
      mutate { 
        add_field => { "event_category" => "file_download" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
      }
    }
    
    if [eventid] == "cowrie.session.file_upload" {
      mutate { 
        add_field => { "event_category" => "file_upload" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
      }
    }
    
    # Enrichissement session
    if [session] {
      mutate {
        add_field => { "session_id" => "%{session}" }
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
# PIPELINE 2: HTTP HONEYPOT
# ================================

print_status "Création du pipeline HTTP Honeypot..."

cat > /etc/logstash/conf.d/20-http-honeypot.conf << 'EOF'
# Pipeline pour HTTP Honeypot personnalisé
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
    
    # Ajouter des métadonnées
    mutate {
      add_field => { "honeypot_type" => "http" }
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "service" => "http_custom" }
    }
    
    # GeoIP sur l'IP source
    if [ip] {
      geoip {
        source => "ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
      
      # Copier IP vers champ standard
      mutate {
        add_field => { "src_ip" => "%{ip}" }
      }
    }
    
    # Classification par type d'attaque HTTP
    if [attack_type] == "sql_injection" {
      mutate { 
        add_field => { "event_category" => "sql_injection" }
        add_field => { "alert_level" => "3" }
      }
      
      # Détecter les injections critiques
      if [data][search_term] =~ /(?i)(union|select|drop|insert|update|delete|exec|script)/ {
        mutate { 
          add_field => { "severity" => "critical" }
          add_field => { "alert_level" => "4" }
        }
      } else {
        mutate { add_field => { "severity" => "high" } }
      }
    }
    
    if [attack_type] == "xss" {
      mutate { 
        add_field => { "event_category" => "cross_site_scripting" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
      }
    }
    
    if [attack_type] == "path_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    }
    
    if [attack_type] == "unauthorized_admin_access" {
      mutate { 
        add_field => { "event_category" => "unauthorized_access" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
      }
    }
    
    if [attack_type] == "command_injection" {
      mutate { 
        add_field => { "event_category" => "command_injection" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
      }
    }
    
    # Analyser les User-Agents suspects
    if [user_agent] =~ /(?i)(sqlmap|nikto|nmap|scanner|bot|crawler)/ {
      mutate {
        add_field => { "suspicious_ua" => "true" }
        add_field => { "tool_detected" => "scanner" }
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
# PIPELINE 3: FTP HONEYPOT
# ================================

print_status "Création du pipeline FTP Honeypot..."

cat > /etc/logstash/conf.d/30-ftp-honeypot.conf << 'EOF'
# Pipeline pour FTP Honeypot personnalisé
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
    
    # Ajouter des métadonnées
    mutate {
      add_field => { "honeypot_type" => "ftp" }
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "service" => "ftp_custom" }
    }
    
    # GeoIP sur l'IP source
    if [ip] {
      geoip {
        source => "ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
      
      # Copier IP vers champ standard
      mutate {
        add_field => { "src_ip" => "%{ip}" }
      }
    }
    
    # Classification des événements FTP
    if [event_type] == "auth_attempt" {
      if [success] == true {
        mutate { 
          add_field => { "event_category" => "authentication_success" }
          add_field => { "severity" => "high" }
          add_field => { "alert_level" => "3" }
        }
      } else {
        mutate { 
          add_field => { "event_category" => "authentication_failure" }
          add_field => { "severity" => "medium" }
          add_field => { "alert_level" => "2" }
        }
      }
    }
    
    if [event_type] == "directory_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    }
    
    if [event_type] == "brute_force_detected" {
      mutate { 
        add_field => { "event_category" => "brute_force" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
      }
    }
    
    if [event_type] == "file_access" {
      mutate { 
        add_field => { "event_category" => "file_access" }
        add_field => { "alert_level" => "2" }
      }
      
      if [action] == "delete" {
        mutate { 
          add_field => { "severity" => "high" }
          add_field => { "alert_level" => "3" }
        }
      } else {
        mutate { add_field => { "severity" => "medium" } }
      }
    }
    
    if [event_type] == "command_execution" {
      mutate { 
        add_field => { "event_category" => "command_execution" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
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
# PIPELINE 4: SERVEURS SÉCURISÉS
# ================================

print_status "Création du pipeline serveurs sécurisés..."

cat > /etc/logstash/conf.d/40-secure-servers.conf << 'EOF'
# Pipeline pour serveurs sécurisés (SSH/FTP)
input {
  file {
    path => "/var/log/auth.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_auth"
    type => "secure_server"
    tags => ["secure", "auth"]
  }
  
  file {
    path => "/var/log/fail2ban.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_fail2ban"
    type => "fail2ban"
    tags => ["secure", "fail2ban"]
  }
}

filter {
  if [type] == "secure_server" {
    # Parse syslog format
    grok {
      match => { "message" => "%{SYSLOGTIMESTAMP:timestamp} %{IPORHOST:host} %{PROG:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:log_message}" }
    }
    
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
    
    mutate {
      add_field => { "infrastructure" => "secure_server" }
      add_field => { "honeypot_type" => "secure" }
    }
    
    # Classification des événements SSH
    if [program] == "sshd" {
      if [log_message] =~ /Failed password/ {
        mutate { 
          add_field => { "event_category" => "ssh_failed_login" }
          add_field => { "severity" => "medium" }
          add_field => { "alert_level" => "2" }
        }
        
        grok {
          match => { "log_message" => "Failed password for %{USERNAME:username} from %{IP:src_ip}" }
        }
      }
      
      if [log_message] =~ /Accepted password/ {
        mutate { 
          add_field => { "event_category" => "ssh_successful_login" }
          add_field => { "severity" => "low" }
          add_field => { "alert_level" => "1" }
        }
        
        grok {
          match => { "log_message" => "Accepted password for %{USERNAME:username} from %{IP:src_ip}" }
        }
      }
    }
    
    # GeoIP pour les IPs extraites
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
  }
  
  if [type] == "fail2ban" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} %{LOGLEVEL:level} %{GREEDYDATA:log_message}" }
    }
    
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    mutate {
      add_field => { "infrastructure" => "security_system" }
      add_field => { "event_category" => "fail2ban" }
      add_field => { "honeypot_type" => "security" }
    }
    
    if [log_message] =~ /Ban/ {
      mutate { 
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
      
      grok {
        match => { "log_message" => "Ban %{IP:banned_ip}" }
      }
      
      if [banned_ip] {
        mutate {
          add_field => { "src_ip" => "%{banned_ip}" }
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
  
  if [type] == "fail2ban" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "security-fail2ban-%{+YYYY.MM.dd}"
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
# CRÉATION DES RÉPERTOIRES DE LOGS
# ================================

print_status "Création des répertoires de logs honeypot..."

# Répertoires pour les logs des honeypots (simulation)
mkdir -p /var/log/cowrie
mkdir -p /var/log/honeypot
mkdir -p /root/honeypot-ftp/logs

# Permissions appropriées
chown -R logstash:logstash /var/lib/logstash/

print_status "✓ Répertoires créés"

# ================================
# TEST DE LA CONFIGURATION
# ================================

print_status "Test de la configuration des pipelines..."

# Test de syntaxe
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✓ Configuration des pipelines validée"
else
    print_error "✗ Erreur dans la configuration des pipelines"
    exit 1
fi

# ================================
# CRÉATION D'UN SCRIPT DE MONITORING
# ================================

print_status "Création du script de monitoring des pipelines..."

cat > /opt/elk-scripts/monitor_pipelines.sh << 'EOF'
#!/bin/bash
echo "=== Monitoring Pipelines Logstash ==="

echo "Fichiers de configuration:"
ls -la /etc/logstash/conf.d/

echo ""
echo "Pipelines actifs (si Logstash en cours):"
curl -s "http://192.168.2.124:9600/_node/pipelines" 2>/dev/null | jq keys || echo "Logstash non démarré"

echo ""
echo "Statistiques par pipeline:"
curl -s "http://192.168.2.124:9600/_node/stats/pipelines" 2>/dev/null | jq '.pipelines | to_entries[] | {pipeline: .key, events: .value.events}' || echo "Stats non disponibles"

echo ""
echo "Test des fichiers de logs source:"
echo "  Cowrie: $(ls -la /var/log/cowrie/ 2>/dev/null | wc -l) fichiers"
echo "  HTTP: $(ls -la /var/log/honeypot/ 2>/dev/null | wc -l) fichiers"
echo "  FTP: $(ls -la /root/honeypot-ftp/logs/ 2>/dev/null | wc -l) fichiers"
EOF

chmod +x /opt/elk-scripts/monitor_pipelines.sh

# ================================
# INFORMATIONS FINALES
# ================================

print_status "=== Pipelines Logstash créés avec succès! ==="
echo ""
print_info "Pipelines créés:"
echo "  ✓ 10-cowrie-ssh.conf       (SSH Honeypot)"
echo "  ✓ 20-http-honeypot.conf    (HTTP Honeypot)"
echo "  ✓ 30-ftp-honeypot.conf     (FTP Honeypot)"
echo "  ✓ 40-secure-servers.conf   (Serveurs sécurisés)"
echo ""
print_info "Index Elasticsearch:"
echo "  - honeypot-cowrie-YYYY.MM.dd"
echo "  - honeypot-http-YYYY.MM.dd"
echo "  - honeypot-ftp-YYYY.MM.dd"
echo "  - secure-servers-YYYY.MM.dd"
echo "  - security-fail2ban-YYYY.MM.dd"
echo ""
print_info "Scripts disponibles:"
echo "  - /opt/elk-scripts/monitor_pipelines.sh"
echo ""
print_warning "PROCHAINES ÉTAPES:"
echo "1. Démarrer Logstash: systemctl start logstash"
echo "2. Vérifier les logs: journalctl -u logstash -f"
echo "3. Tester l'ingestion de données"
echo ""
print_status "Pipelines prêts pour l'ingestion des données honeypot!"

# Créer un fichier de statut
cat > /opt/elk-setup-status-pipelines.txt << EOF
=== Logstash Pipelines Status ===
Date: $(date)

✓ PIPELINES CRÉÉS:
- Cowrie SSH: /etc/logstash/conf.d/10-cowrie-ssh.conf
- HTTP Honeypot: /etc/logstash/conf.d/20-http-honeypot.conf  
- FTP Honeypot: /etc/logstash/conf.d/30-ftp-honeypot.conf
- Serveurs sécurisés: /etc/logstash/conf.d/40-secure-servers.conf

✓ VALIDATION:
- Syntaxe: OK
- Permissions: OK
- Répertoires: Créés

ÉTAPES SUIVANTES:
1. Démarrer Logstash
2. Configurer les honeypots
3. Tester l'ingestion

Prêt pour: Démarrage de Logstash
EOF

echo "$(date): Pipelines Logstash créés avec succès" >> /var/log/elk-setup/install.log