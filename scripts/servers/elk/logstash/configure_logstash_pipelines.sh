#!/bin/bash
# Script d'installation des pipelines Logstash optimisés pour logs honeypot réels
# VM ELK: 192.168.2.124
# Traite les vrais logs Cowrie/HTTP/FTP sans transformation complexe

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

print_status "=== INSTALLATION PIPELINES OPTIMISÉS POUR LOGS RÉELS ==="
echo ""

# 1. VÉRIFICATIONS
print_status "1. Vérifications préalables..."

if ! systemctl is-active --quiet elasticsearch; then
    print_error "Elasticsearch non actif"
    exit 1
fi

print_status "✅ Elasticsearch actif"

# 2. ARRÊTER LOGSTASH
print_status "2. Arrêt de Logstash..."
systemctl stop logstash
sleep 5

# 3. SAUVEGARDER
print_status "3. Sauvegarde des configurations..."
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/logstash-backups/optimized.$BACKUP_DATE"

mkdir -p "$BACKUP_DIR"
if [ -f "/etc/logstash/conf.d/00-honeypot-pipelines.conf" ]; then
    cp /etc/logstash/conf.d/00-honeypot-pipelines.conf "$BACKUP_DIR/"
    print_info "Sauvegarde : $BACKUP_DIR"
fi

# 4. CRÉER LA CONFIGURATION OPTIMISÉE
print_status "4. Création des pipelines optimisés..."

cat > /etc/logstash/conf.d/00-honeypot-pipelines.conf << 'EOF'
# =============================================================================
# PIPELINES LOGSTASH OPTIMISÉS POUR LOGS HONEYPOT RÉELS
# =============================================================================

input {
  tcp {
    port => 5046
    host => "0.0.0.0"
    codec => json
    type => "honeypot_tcp"
  }
}

filter {
  # Ajouter des métadonnées de traitement
  mutate {
    add_field => { "[@metadata][processed_by]" => "logstash_optimized" }
    add_field => { "[@metadata][processing_timestamp]" => "%{@timestamp}" }
  }

  # ==========================================================================
  # DETECTION AUTOMATIQUE DU TYPE DE HONEYPOT
  # ==========================================================================
  
  # Détecter Cowrie SSH par la présence de champs spécifiques
  if [eventid] and [src_ip] and [dst_ip] and [session] {
    mutate {
      add_field => { "honeypot_type" => "ssh" }
      add_field => { "honeypot_service" => "cowrie" }
    }
  }
  
  # Détecter HTTP par la présence de champs spécifiques
  else if [attack_id] and [attack_type] and [severity] {
    mutate {
      add_field => { "honeypot_type" => "http" }
      add_field => { "honeypot_service" => "web_honeypot" }
    }
  }
  
  # Détecter FTP par la présence de champs spécifiques
  else if [event_type] and ([event_type] =~ /ftp/ or [source_type] =~ /ftp/) {
    mutate {
      add_field => { "honeypot_type" => "ftp" }
      add_field => { "honeypot_service" => "ftp_honeypot" }
    }
  }
  
  # Fallback basé sur source_type
  else if [source_type] {
    if [source_type] =~ /cowrie/ {
      mutate {
        add_field => { "honeypot_type" => "ssh" }
        add_field => { "honeypot_service" => "cowrie" }
      }
    } else if [source_type] =~ /http/ {
      mutate {
        add_field => { "honeypot_type" => "http" }
        add_field => { "honeypot_service" => "web_honeypot" }
      }
    } else if [source_type] =~ /ftp/ {
      mutate {
        add_field => { "honeypot_type" => "ftp" }
        add_field => { "honeypot_service" => "ftp_honeypot" }
      }
    }
  }

  # ==========================================================================
  # TRAITEMENT COWRIE SSH
  # ==========================================================================
  if [honeypot_type] == "ssh" {
    # Parser le timestamp Cowrie
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
        target => "original_timestamp"
      }
    }
    
    # Enrichissement GeoIP
    if [src_ip] and [src_ip] != "127.0.0.1" {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification des événements SSH
    if [eventid] {
      if [eventid] == "cowrie.login.success" {
        mutate { 
          add_field => { "event_category" => "authentication_success" }
          add_field => { "severity_level" => "critical" }
          add_field => { "alert_score" => "10" }
          add_field => { "mitre_tactic" => "initial_access" }
        }
      } else if [eventid] == "cowrie.login.failed" {
        mutate { 
          add_field => { "event_category" => "authentication_failure" }
          add_field => { "severity_level" => "medium" }
          add_field => { "alert_score" => "5" }
          add_field => { "mitre_tactic" => "credential_access" }
        }
      } else if [eventid] == "cowrie.command.input" {
        mutate { 
          add_field => { "event_category" => "command_execution" }
          add_field => { "severity_level" => "high" }
          add_field => { "alert_score" => "8" }
          add_field => { "mitre_tactic" => "execution" }
        }
      } else if [eventid] == "cowrie.session.connect" {
        mutate { 
          add_field => { "event_category" => "connection" }
          add_field => { "severity_level" => "low" }
          add_field => { "alert_score" => "3" }
          add_field => { "mitre_tactic" => "initial_access" }
        }
      }
    }
    
    # Détection de commandes suspectes
    if [message] {
      if [message] =~ /(?i)(wget|curl|nc|netcat|nmap)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "network_tool" }
          add_field => { "alert_score" => "9" }
        }
      }
      
      if [message] =~ /(?i)(rm -rf|dd if=|mkfs|fdisk)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "destructive" }
          add_field => { "alert_score" => "10" }
        }
      }
    }
  }

  # ==========================================================================
  # TRAITEMENT HTTP HONEYPOT
  # ==========================================================================
  else if [honeypot_type] == "http" {
    # Enrichissement GeoIP pour HTTP
    if [ip] and [ip] != "127.0.0.1" {
      geoip {
        source => "ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
      
      # Alias pour standardisation
      mutate { add_field => { "client_ip" => "%{ip}" } }
    }
    
    # Classification des attaques HTTP
    if [attack_type] {
      if [attack_type] == "sql_injection" {
        mutate { 
          add_field => { "event_category" => "web_attack" }
          add_field => { "severity_level" => "critical" }
          add_field => { "alert_score" => "9" }
          add_field => { "mitre_tactic" => "initial_access" }
          add_field => { "owasp_category" => "A03_injection" }
        }
      } else if [attack_type] == "api_access" {
        mutate { 
          add_field => { "event_category" => "api_abuse" }
          add_field => { "severity_level" => "medium" }
          add_field => { "alert_score" => "5" }
          add_field => { "mitre_tactic" => "discovery" }
        }
      } else if [attack_type] == "sql_error" {
        mutate { 
          add_field => { "event_category" => "web_error" }
          add_field => { "severity_level" => "low" }
          add_field => { "alert_score" => "3" }
        }
      }
    }
    
    # Mapping de sévérité HTTP
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
      if [user_agent] =~ /(?i)(bot|crawler|spider|scanner)/ {
        mutate { 
          add_field => { "client_type" => "automated" }
          add_field => { "alert_score" => "6" }
        }
      } else if [user_agent] =~ /(?i)(curl|wget|python)/ {
        mutate { 
          add_field => { "client_type" => "script" }
          add_field => { "alert_score" => "7" }
        }
      }
    }
  }

  # ==========================================================================
  # TRAITEMENT FTP HONEYPOT
  # ==========================================================================
  else if [honeypot_type] == "ftp" {
    # Pour les logs FTP JSON
    if [event_type] and [ip] {
      mutate { add_field => { "client_ip" => "%{ip}" } }
      
      mutate { 
        add_field => { "event_category" => "ftp_session" }
        add_field => { "severity_level" => "medium" }
        add_field => { "alert_score" => "5" }
      }
    }
    
    # Pour les logs FTP texte (basé sur message)
    if [message] and [message] =~ /Auth|LOGIN|PASS/ {
      if [message] =~ /SUCCESS/ {
        mutate { 
          add_field => { "event_category" => "ftp_success" }
          add_field => { "severity_level" => "low" }
          add_field => { "alert_score" => "3" }
        }
      } else if [message] =~ /FAIL/ {
        mutate { 
          add_field => { "event_category" => "ftp_failure" }
          add_field => { "severity_level" => "medium" }
          add_field => { "alert_score" => "5" }
        }
      }
    }
    
    # Enrichissement GeoIP pour FTP
    if [client_ip] and [client_ip] != "127.0.0.1" {
      geoip {
        source => "client_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
  }

  # ==========================================================================
  # ENRICHISSEMENTS COMMUNS
  # ==========================================================================
  
  # Score de risque global
  if [alert_score] {
    if [alert_score] >= "8" {
      mutate { add_field => { "risk_level" => "critical" } }
    } else if [alert_score] >= "6" {
      mutate { add_field => { "risk_level" => "high" } }
    } else if [alert_score] >= "4" {
      mutate { add_field => { "risk_level" => "medium" } }
    } else {
      mutate { add_field => { "risk_level" => "low" } }
    }
  }
  
  # Standardiser les champs IP pour tous les types
  if [src_ip] and ![client_ip] {
    mutate { add_field => { "client_ip" => "%{src_ip}" } }
  }
  
  # Nettoyer les champs temporaires
  mutate {
    remove_field => [ "host", "port" ]
  }
}

# =============================================================================
# OUTPUTS SPÉCIALISÉS PAR TYPE - INDICES SÉPARÉS
# =============================================================================

output {
  # SSH Cowrie → honeypot-cowrie-*
  if [honeypot_type] == "ssh" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
    }
  }
  
  # HTTP → honeypot-http-*
  else if [honeypot_type] == "http" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
    }
  }
  
  # FTP → honeypot-ftp-*
  else if [honeypot_type] == "ftp" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
    }
  }
  
  # Fallback pour types non identifiés
  else {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-misc-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✅ Configuration optimisée créée"

# 5. PERMISSIONS
print_status "5. Configuration des permissions..."
chown logstash:logstash /etc/logstash/conf.d/00-honeypot-pipelines.conf
chmod 644 /etc/logstash/conf.d/00-honeypot-pipelines.conf

# 6. TEST SYNTAXE
print_status "6. Test de syntaxe..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Syntaxe validée"
else
    print_error "❌ Erreur de syntaxe"
    print_error "Restauration..."
    if [ -f "$BACKUP_DIR/00-honeypot-pipelines.conf" ]; then
        cp "$BACKUP_DIR/00-honeypot-pipelines.conf" /etc/logstash/conf.d/
    fi
    exit 1
fi

# 7. REDÉMARRER LOGSTASH
print_status "7. Redémarrage de Logstash..."
systemctl start logstash

print_info "Attente du démarrage (45s)..."
counter=0
while [ $counter -lt 45 ]; do
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

# 8. VÉRIFICATIONS
print_status "8. Vérifications..."

if systemctl is-active --quiet logstash; then
    print_status "✅ Service actif"
else
    print_error "❌ Service non actif"
    journalctl -u logstash --no-pager -n 10
    exit 1
fi

sleep 10

if netstat -tlnp | grep -q ":5046"; then
    print_status "✅ Port 5046 ouvert"
else
    print_warning "⚠️ Port 5046 pas encore ouvert"
fi

if curl -s "http://192.168.2.124:9600/" >/dev/null 2>&1; then
    print_status "✅ API Logstash accessible"
else
    print_warning "⚠️ API pas encore prête"
fi

# 9. CRÉER SCRIPTS DE TEST
print_status "9. Création des scripts de test..."

cat > /opt/test_optimized_pipelines.sh << 'TEST_EOF'
#!/bin/bash
echo "=== TEST PIPELINES OPTIMISÉS ==="
echo ""
echo "📊 Status:"
echo "   Logstash: $(systemctl is-active logstash)"
echo "   Port 5046: $(netstat -tlnp | grep -q ':5046' && echo 'OUVERT' || echo 'FERMÉ')"
echo ""
echo "🔗 Test envoi:"
echo '{"eventid": "cowrie.login.failed", "src_ip": "203.0.113.5", "dst_ip": "192.168.2.117", "session": "test123", "message": "SSH login test"}' | nc localhost 5046 2>/dev/null && echo "   ✅ Envoi SSH réussi" || echo "   ❌ Envoi SSH échoué"

echo '{"attack_id": "test123", "attack_type": "sql_injection", "severity": "high", "ip": "203.0.113.10", "method": "POST", "path": "/login"}' | nc localhost 5046 2>/dev/null && echo "   ✅ Envoi HTTP réussi" || echo "   ❌ Envoi HTTP échoué"
echo ""
echo "📊 Indices créés:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v&s=index" 2>/dev/null || echo "   Aucun indice"
echo ""
echo "🔢 Comptage par type:"
for type in cowrie http ftp misc; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // 0')
    echo "   $type: $count documents"
done
TEST_EOF

chmod +x /opt/test_optimized_pipelines.sh

cat > /opt/monitor_pipeline_activity.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== MONITORING ACTIVITÉ PIPELINES ==="
echo ""
echo "📊 Répartition par type:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?size=0" -H "Content-Type: application/json" -d '{
  "aggs": {
    "by_type": {
      "terms": {
        "field": "honeypot_type.keyword",
        "size": 10
      }
    }
  }
}' 2>/dev/null | jq -r '.aggregations.by_type.buckets[] | "\(.key): \(.doc_count)"' 2>/dev/null || echo "Erreur requête"

echo ""
echo "🕐 Dernières données par type:"
for type in ssh http ftp; do
    latest=$(curl -s "http://192.168.2.124:9200/honeypot-*/_search?q=honeypot_type:$type&size=1&sort=@timestamp:desc&_source=@timestamp,eventid,attack_type,event_type" 2>/dev/null | jq -r '.hits.hits[0]._source | "\(.["@timestamp"]) - \(.eventid // .attack_type // .event_type // "N/A")"' 2>/dev/null)
    echo "   $type: $latest"
done
MONITOR_EOF

chmod +x /opt/monitor_pipeline_activity.sh

# 10. RÉSUMÉ FINAL
echo ""
print_status "=== INSTALLATION TERMINÉE ==="
echo ""
print_info "📊 PIPELINES OPTIMISÉS:"
echo "✅ Détection automatique par champs natifs"
echo "✅ SSH Cowrie: eventid, src_ip, session → honeypot-cowrie-*"
echo "✅ HTTP: attack_id, attack_type, severity → honeypot-http-*"
echo "✅ FTP: event_type, source_type → honeypot-ftp-*"
echo ""
print_info "📁 ENRICHISSEMENTS:"
echo "✅ GeoIP sur tous les types"
echo "✅ Classification MITRE ATT&CK"
echo "✅ Scores d'alerte et niveaux de risque"
echo "✅ Détection de commandes suspectes"
echo ""
print_warning "🎯 PROCHAINES ÉTAPES:"
echo "1. Tester: /opt/test_optimized_pipelines.sh"
echo "2. Installer script sender optimisé"
echo "3. Monitoring: /opt/monitor_pipeline_activity.sh"
echo "4. Redémarrer honeypot-sender"
echo ""
print_status "Pipelines optimisés installés avec succès !"
echo ""
print_info "🔍 COMMANDES UTILES:"
echo "   • Test: /opt/test_optimized_pipelines.sh"
echo "   • Monitoring: /opt/monitor_pipeline_activity.sh"
echo "   • Logs: journalctl -u logstash -f"

echo ""
echo "$(date): Pipelines optimisés installés" >> /var/log/elk-optimized-install.log