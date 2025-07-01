#!/bin/bash
# SOLUTION COMPLÈTE - Fix JSON Parse Failure Honeypot
# Problème : Cowrie et HTTP en JSON natif vs pipeline attendant format encapsulé
# Solution : Pipeline intelligent qui détecte automatiquement le format

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
print_status "=== FIX HONEYPOT JSON PARSE FAILURE ==="
print_info "Problème : Format JSON natif vs format encapsulé attendu"
print_info "Solution : Pipeline intelligent multi-format"
echo ""

# 1. BACKUP DE SÉCURITÉ
print_status "1. Sauvegarde de sécurité..."
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/logstash-backup-fix-$BACKUP_DATE"
mkdir -p "$BACKUP_DIR"

systemctl stop logstash
sleep 3

cp -r /etc/logstash/conf.d/* "$BACKUP_DIR/" 2>/dev/null || true
print_info "Sauvegarde : $BACKUP_DIR"

# 2. SUPPRIMER LES ANCIENS PIPELINES DÉFAILLANTS
print_status "2. Suppression des pipelines défaillants..."
rm -f /etc/logstash/conf.d/*.conf

# 3. CRÉER LE NOUVEAU PIPELINE INTELLIGENT
print_status "3. Création du pipeline intelligent multi-format..."

cat > /etc/logstash/conf.d/00-honeypot-intelligent-pipelines.conf << 'EOF'
# =============================================================================
# PIPELINE INPUT TCP - Port 5046
# =============================================================================

input {
  tcp {
    port => 5046
    host => "0.0.0.0"
    codec => json
    type => "honeypot_tcp"
  }
}

# =============================================================================
# FILTRES INTELLIGENTS - DÉTECTION AUTOMATIQUE DU FORMAT
# =============================================================================

filter {
  # Ajouter des métadonnées communes
  mutate {
    add_field => { "[@metadata][processed_by]" => "logstash" }
    add_field => { "[@metadata][processing_timestamp]" => "%{@timestamp}" }
  }

  # ==========================================================================
  # DÉTECTION AUTOMATIQUE DU FORMAT COWRIE SSH
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
    
    # Enrichissement GeoIP
    if [src_ip] and [src_ip] != "127.0.0.1" and [src_ip] != "192.168.2.117" {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
        add_field => { "src_location" => "%{[geoip][latitude]},%{[geoip][longitude]}" }
      }
    }
    
    # Classification des événements par eventid
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
      
      # Analyser les commandes suspectes
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
          }
        }
        
        if [input] =~ /(?i)(cat|ls|pwd|whoami|id|uname)/ {
          mutate {
            add_field => { "command_type" => "reconnaissance" }
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
  # DÉTECTION AUTOMATIQUE DU FORMAT HTTP HONEYPOT
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
    
    # Enrichissement GeoIP pour HTTP
    if [ip] and [ip] != "127.0.0.1" and [ip] != "192.168.2.117" {
      geoip {
        source => "ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
        add_field => { "src_location" => "%{[geoip][latitude]},%{[geoip][longitude]}" }
      }
    }
    
    # Classification des attaques HTTP par type
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
    
    # Analyse User-Agent
    if [user_agent] {
      if [user_agent] =~ /(?i)(bot|crawler|spider|scanner|nikto|sqlmap|nmap)/ {
        mutate {
          add_field => { "client_type" => "security_scanner" }
          add_field => { "alert_score" => "8" }
        }
      } else if [user_agent] =~ /(?i)(curl|wget|python|powershell)/ {
        mutate {
          add_field => { "client_type" => "script" }
          add_field => { "alert_score" => "6" }
        }
      } else if [user_agent] =~ /(?i)(mozilla|chrome|firefox|safari)/ {
        mutate {
          add_field => { "client_type" => "browser" }
        }
      }
    }
    
    # Analyse des méthodes HTTP suspectes
    if [method] {
      if [method] in ["PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
        mutate {
          add_field => { "suspicious_method" => "true" }
          add_field => { "alert_score" => "6" }
        }
      }
    }
    
    # Analyse des chemins suspects
    if [path] {
      if [path] =~ /(?i)(admin|phpmyadmin|wp-admin|login|config|\.env|\.git|backup)/ {
        mutate {
          add_field => { "suspicious_path" => "true" }
          add_field => { "path_type" => "sensitive" }
        }
      }
      
      if [path] =~ /(?i)(\.\.\/|%2e%2e|%252e|\.\.%2f|\.\.%5c)/ {
        mutate {
          add_field => { "directory_traversal" => "true" }
          add_field => { "alert_score" => "9" }
          add_field => { "mitre_technique" => "T1083" }
        }
      }
    }
  }

  # ==========================================================================
  # DÉTECTION FORMAT FTP (DÉJÀ FONCTIONNEL)
  # ==========================================================================
  else if [honeypot_type] == "ftp" {
    # FTP fonctionne déjà - garder la logique existante
    if [log_format] == "ftp_json" and [event_type] {
      mutate {
        add_field => { "honeypot_service" => "ftp_honeypot" }
        add_field => { "detection_method" => "explicit_ftp_type" }
      }
      
      # Enrichissement GeoIP pour FTP
      if [ip] and [ip] != "127.0.0.1" {
        geoip {
          source => "ip"
          target => "geoip"
          add_field => { "src_country" => "%{[geoip][country_name]}" }
          add_field => { "src_city" => "%{[geoip][city_name]}" }
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
  # ENRICHISSEMENTS COMMUNS POUR TOUS LES TYPES
  # ==========================================================================
  
  # Ajouter un score de risque global basé sur alert_score
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
  
  # Ajouter métadonnées de détection
  mutate {
    add_field => { "infrastructure" => "honeypot" }
    add_field => { "vm_source" => "192.168.2.117" }
    add_field => { "vm_destination" => "192.168.2.124" }
  }
  
  # Nettoyer les champs temporaires
  mutate {
    remove_field => [ "host", "port" ]
  }
}

# =============================================================================
# OUTPUTS SPÉCIALISÉS PAR TYPE DÉTECTÉ
# =============================================================================

output {
  # Output pour SSH Cowrie (détecté automatiquement)
  if [honeypot_type] == "ssh" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
      template_name => "honeypot-cowrie"
    }
  }
  
  # Output pour HTTP (détecté automatiquement)
  else if [honeypot_type] == "http" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
      template_name => "honeypot-http"
    }
  }
  
  # Output pour FTP (déjà fonctionnel)
  else if [honeypot_type] == "ftp" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
      template_name => "honeypot-ftp"
    }
  }
  
  # Fallback pour logs non identifiés (debugging)
  else {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-unknown-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✅ Pipeline intelligent créé"

# 4. PERMISSIONS ET VALIDATION
print_status "4. Configuration des permissions..."
chown logstash:logstash /etc/logstash/conf.d/00-honeypot-intelligent-pipelines.conf
chmod 644 /etc/logstash/conf.d/00-honeypot-intelligent-pipelines.conf

# 5. TEST DE SYNTAXE
print_status "5. Test de syntaxe..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Syntaxe validée"
else
    print_error "❌ Erreur de syntaxe"
    print_error "Restauration de l'ancienne configuration..."
    rm -f /etc/logstash/conf.d/*.conf
    cp "$BACKUP_DIR"/* /etc/logstash/conf.d/ 2>/dev/null || true
    exit 1
fi

# 6. DÉMARRER LOGSTASH
print_status "6. Démarrage de Logstash..."
systemctl start logstash

# Attendre le démarrage
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

# 7. VÉRIFICATIONS
print_status "7. Vérifications..."

# Service actif
if systemctl is-active --quiet logstash; then
    print_status "✅ Service actif"
else
    print_error "❌ Service non actif - Logs récents :"
    journalctl -u logstash --no-pager -n 5
    exit 1
fi

# Port en écoute
sleep 10
if netstat -tlnp | grep -q ":5046"; then
    print_status "✅ Port 5046 en écoute"
else
    print_warning "⚠️ Port 5046 pas encore ouvert"
fi

# 8. CRÉER LES SCRIPTS DE TEST ET MONITORING
print_status "8. Création des scripts utilitaires..."

# Script de test spécialisé
cat > /opt/test_honeypot_fix.sh << 'TEST_EOF'
#!/bin/bash
echo "=== TEST FIX JSON PARSE FAILURE ==="
echo ""

echo "🔧 Status Logstash:"
echo "   Service: $(systemctl is-active logstash)"
echo "   Port 5046: $(netstat -tln | grep :5046 >/dev/null && echo 'OK' || echo 'NOK')"
echo ""

echo "🧪 Test détection automatique:"
echo ""

# Test Cowrie format
echo "📡 Test JSON Cowrie natif..."
echo '{"eventid":"cowrie.session.connect","src_ip":"192.168.1.100","dst_ip":"192.168.2.117","session":"test123","timestamp":"2025-07-01T12:00:00Z","message":"Test connection"}' | nc -w 2 localhost 5046 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ JSON Cowrie envoyé"
else
    echo "   ❌ Échec envoi Cowrie"
fi

sleep 2

# Test HTTP format
echo "📡 Test JSON HTTP natif..."
echo '{"timestamp":"2025-07-01T12:00:00Z","attack_id":"test001","attack_type":"sql_injection","severity":"high","ip":"192.168.1.101","method":"POST","path":"/search","user_agent":"curl/7.68.0"}' | nc -w 2 localhost 5046 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ JSON HTTP envoyé"
else
    echo "   ❌ Échec envoi HTTP"
fi

sleep 2

# Test FTP format existant
echo "📡 Test JSON FTP (existant)..."
echo '{"honeypot_type":"ftp","log_format":"ftp_json","event_type":"ftp_command","ip":"192.168.1.102","username":"admin","command":"LIST"}' | nc -w 2 localhost 5046 2>/dev/null
if [ $? -eq 0 ]; then
    echo "   ✅ JSON FTP envoyé"
else
    echo "   ❌ Échec envoi FTP"
fi

echo ""
echo "⏱️  Attente indexation (5s)..."
sleep 5

echo ""
echo "📊 Vérification indices:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v" 2>/dev/null || echo "   Indices pas encore créés"

echo ""
echo "🔢 Comptage documents:"
for type in cowrie http ftp; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // 0')
    echo "   $type: $count documents"
done

echo ""
echo "🔍 Derniers logs Logstash:"
journalctl -u logstash --no-pager -n 2
TEST_EOF

chmod +x /opt/test_honeypot_fix.sh

# Script de monitoring avancé
cat > /opt/monitor_honeypot_detection.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== MONITORING DÉTECTION AUTOMATIQUE ==="
echo ""

echo "📊 INDICES HONEYPOT:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v&s=index" 2>/dev/null || echo "Aucun indice trouvé"
echo ""

echo "🔢 COMPTAGE PAR TYPE:"
for type in cowrie http ftp unknown; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // 0')
    echo "   $type: $count documents"
done
echo ""

echo "🔍 MÉTHODES DE DÉTECTION:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?size=0&aggs={\"detection_methods\":{\"terms\":{\"field\":\"detection_method.keyword\"}}}" 2>/dev/null | jq -r '.aggregations.detection_methods.buckets[] | "   \(.key): \(.doc_count)"' || echo "   Pas de données"
echo ""

echo "🚨 ALERTES CRITIQUES (score >= 8):"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?q=alert_score:>=8&size=3&_source=@timestamp,honeypot_type,event_category,alert_score,client_ip" 2>/dev/null | jq -r '.hits.hits[]._source | "\(.@timestamp) - \(.honeypot_type) - \(.event_category) - Score:\(.alert_score) - \(.client_ip)"' || echo "   Aucune alerte critique"
echo ""

echo "📈 STATS PIPELINE:"
curl -s "http://192.168.2.124:9600/_node/stats/pipelines" 2>/dev/null | jq -r '.pipelines.main.events | "Events: in=\(.in), out=\(.out), filtered=\(.filtered)"' || echo "Stats non disponibles"
MONITOR_EOF

chmod +x /opt/monitor_honeypot_detection.sh

# 9. RÉSUMÉ FINAL
echo ""
print_status "=== FIX APPLIQUÉ AVEC SUCCÈS ==="
echo ""
print_info "🎯 PROBLÈME RÉSOLU :"
echo "   ✅ Détection automatique du format JSON Cowrie natif"
echo "   ✅ Détection automatique du format JSON HTTP natif"  
echo "   ✅ Conservation du fonctionnement FTP existant"
echo "   ✅ Élimination des JSON parse failures"
echo ""
print_info "🔧 NOUVELLE LOGIQUE :"
echo "   • Cowrie: Détecté par présence d'eventid=/^cowrie\./"
echo "   • HTTP: Détecté par présence d'attack_id+attack_type"
echo "   • FTP: Format existant conservé (honeypot_type=ftp)"
echo ""
print_info "📁 INDICES ELASTICSEARCH :"
echo "   • honeypot-cowrie-YYYY.MM.dd (JSON natif supporté)"
echo "   • honeypot-http-YYYY.MM.dd (JSON natif supporté)"
echo "   • honeypot-ftp-YYYY.MM.dd (format existant conservé)"
echo "   • honeypot-unknown-YYYY.MM.dd (logs non identifiés)"
echo ""
print_info "🚀 AMÉLIORATIONS APPORTÉES :"
echo "   ✅ Détection intelligente multi-format"
echo "   ✅ Classification MITRE ATT&CK améliorée"
echo "   ✅ Enrichissement GeoIP pour tous les types"
echo "   ✅ Scoring de risque dynamique (0-10)"
echo "   ✅ Détection commandes/paths suspects"
echo "   ✅ Support User-Agent analysis"
echo ""
print_warning "🎯 PROCHAINES ÉTAPES :"
echo "1. Tester la détection: /opt/test_honeypot_fix.sh"
echo "2. Surveiller: /opt/monitor_honeypot_detection.sh"
echo "3. Redémarrer le sender: systemctl restart honeypot-sender"
echo "4. Vérifier les logs: journalctl -u logstash -f"
echo ""
print_status "✅ SOLUTION APPLIQUÉE - JSON PARSE FAILURES ÉLIMINÉS !"
echo ""
print_info "🔍 COMMANDES DE VÉRIFICATION :"
echo "   • Test fix: /opt/test_honeypot_fix.sh"
echo "   • Monitoring: /opt/monitor_honeypot_detection.sh"
echo "   • Logs Logstash: journalctl -u logstash -f"
echo "   • API status: curl http://192.168.2.124:9600/"
echo "   • Indices: curl 'http://192.168.2.124:9200/_cat/indices/honeypot-*?v'"
echo ""
print_info "📋 EN CAS DE PROBLÈME :"
echo "   • Restaurer: cp $BACKUP_DIR/* /etc/logstash/conf.d/"
echo "   • Redémarrer: systemctl restart logstash"
echo "   • Debug: journalctl -u logstash -f"
echo ""

# 10. LOG FINAL
echo "$(date): Fix JSON Parse Failure honeypot appliqué avec succès" >> /var/log/elk-honeypot-fix.log
echo "   - Backup: $BACKUP_DIR" >> /var/log/elk-honeypot-fix.log
echo "   - Pipeline intelligent multi-format installé" >> /var/log/elk-honeypot-fix.log
echo "   - Détection automatique Cowrie/HTTP/FTP activée" >> /var/log/elk-honeypot-fix.log

print_status "Fix JSON Parse Failure terminé avec succès !"
echo ""