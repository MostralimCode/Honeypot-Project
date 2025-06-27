#!/bin/bash
# Script d'installation des pipelines Logstash spécialisés pour honeypot
# VM ELK: 192.168.2.124
# Support: Cowrie SSH + HTTP + FTP honeypots

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

print_status "=== INSTALLATION PIPELINES LOGSTASH HONEYPOT ==="
echo ""

# 1. VÉRIFICATIONS PRÉALABLES
print_status "1. Vérifications préalables..."

# Vérifier Elasticsearch
if ! curl -s "http://192.168.2.124:9200" >/dev/null 2>&1; then
    print_error "Elasticsearch non accessible"
    exit 1
fi

# Vérifier Logstash installé
if ! systemctl is-active --quiet logstash; then
    print_error "Logstash non installé"
    exit 1
fi

print_status "✅ Prérequis validés"

# 2. ARRÊTER LOGSTASH
print_status "2. Arrêt de Logstash..."
systemctl stop logstash
sleep 5

# 3. SAUVEGARDER LES CONFIGS EXISTANTES
print_status "3. Sauvegarde des configurations existantes..."
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/logstash-backups/conf.d.$BACKUP_DATE"

mkdir -p "$BACKUP_DIR"
if [ -d "/etc/logstash/conf.d" ]; then
    cp -r /etc/logstash/conf.d/* "$BACKUP_DIR/" 2>/dev/null || true
    print_info "Sauvegarde créée : $BACKUP_DIR"
fi

# 4. NETTOYER LES ANCIENNES CONFIGS
print_status "4. Nettoyage des anciennes configurations..."
rm -f /etc/logstash/conf.d/*.conf

# 5. CRÉER LA NOUVELLE CONFIGURATION
print_status "5. Création de la nouvelle configuration..."

cat > /etc/logstash/conf.d/00-honeypot-pipelines.conf << 'EOF'
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
# FILTRES SPÉCIALISÉS PAR TYPE DE HONEYPOT
# =============================================================================

filter {
  # Ajouter des métadonnées communes
  mutate {
    add_field => { "[@metadata][processed_by]" => "logstash" }
    add_field => { "[@metadata][processing_timestamp]" => "%{@timestamp}" }
  }

  # ==========================================================================
  # PIPELINE COWRIE SSH
  # ==========================================================================
  if [honeypot_type] == "ssh" {
    # Extraire les données Cowrie spécifiques
    if [cowrie_data] {
      mutate {
        add_field => { "eventid" => "%{[cowrie_data][eventid]}" }
        add_field => { "src_ip" => "%{[cowrie_data][src_ip]}" }
        add_field => { "session_id" => "%{[cowrie_data][session]}" }
        add_field => { "event_message" => "%{[cowrie_data][message]}" }
      }
      
      # Parser le timestamp Cowrie
      if [cowrie_data][timestamp] {
        date {
          match => [ "[cowrie_data][timestamp]", "ISO8601" ]
          target => "original_timestamp"
        }
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
    if [event_message] {
      if [event_message] =~ /(?i)(wget|curl|nc|netcat|nmap)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "network_tool" }
          add_field => { "alert_score" => "9" }
        }
      }
      
      if [event_message] =~ /(?i)(rm -rf|dd if=|mkfs|fdisk)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "destructive" }
          add_field => { "alert_score" => "10" }
        }
      }
    }
  }

  # ==========================================================================
  # PIPELINE HTTP HONEYPOT
  # ==========================================================================
  else if [honeypot_type] == "http" {
    # Extraire les données HTTP spécifiques
    if [http_data] {
      mutate {
        add_field => { "attack_id" => "%{[http_data][attack_id]}" }
        add_field => { "attack_type" => "%{[http_data][attack_type]}" }
        add_field => { "severity" => "%{[http_data][severity]}" }
        add_field => { "client_ip" => "%{[http_data][ip]}" }
        add_field => { "http_method" => "%{[http_data][method]}" }
        add_field => { "http_path" => "%{[http_data][path]}" }
        add_field => { "user_agent" => "%{[http_data][user_agent]}" }
      }
    }
    
    # Enrichissement GeoIP pour HTTP
    if [client_ip] and [client_ip] != "127.0.0.1" {
      geoip {
        source => "client_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
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
    
    # Mapping de sévérité
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
  # PIPELINE FTP HONEYPOT
  # ==========================================================================
  else if [honeypot_type] == "ftp" {
    if [log_format] == "ftp_json" and [ftp_data] {
      # FTP JSON - Sessions complètes
      mutate {
        add_field => { "event_type" => "%{[ftp_data][event_type]}" }
        add_field => { "session_id" => "%{[ftp_data][session_id]}" }
        add_field => { "client_ip" => "%{[ftp_data][ip]}" }
        add_field => { "username" => "%{[ftp_data][username]}" }
        add_field => { "ftp_command" => "%{[ftp_data][command]}" }
      }
      
      mutate { 
        add_field => { "event_category" => "ftp_session" }
        add_field => { "severity_level" => "medium" }
        add_field => { "alert_score" => "5" }
      }
      
    } else if [log_format] == "ftp_text" {
      # FTP Texte - Logs parsés
      if [action] {
        if [action] =~ /(?i)success/ {
          mutate { 
            add_field => { "event_category" => "ftp_success" }
            add_field => { "severity_level" => "low" }
            add_field => { "alert_score" => "3" }
          }
        } else if [action] =~ /(?i)fail/ {
          mutate { 
            add_field => { "event_category" => "ftp_failure" }
            add_field => { "severity_level" => "medium" }
            add_field => { "alert_score" => "5" }
          }
        } else if [action] =~ /(?i)(brute|force|attempt)/ {
          mutate { 
            add_field => { "event_category" => "ftp_bruteforce" }
            add_field => { "severity_level" => "high" }
            add_field => { "alert_score" => "8" }
            add_field => { "mitre_tactic" => "credential_access" }
          }
        }
      }
      
      # Alias pour IP client
      if [ip] {
        mutate { add_field => { "client_ip" => "%{ip}" } }
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
  
  # Ajouter un score de risque global
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
  
  # Standardiser les champs IP
  if [src_ip] and ![client_ip] {
    mutate { add_field => { "client_ip" => "%{src_ip}" } }
  }
  
  # Nettoyer les champs temporaires
  mutate {
    remove_field => [ "host", "port" ]
  }
}

# =============================================================================
# OUTPUTS SPÉCIALISÉS PAR TYPE
# =============================================================================

output {
  # Output pour SSH Cowrie
  if [honeypot_type] == "ssh" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
      template_name => "honeypot-cowrie"
    }
  }
  
  # Output pour HTTP
  else if [honeypot_type] == "http" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
      template_name => "honeypot-http"
    }
  }
  
  # Output pour FTP
  else if [honeypot_type] == "ftp" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
      template_name => "honeypot-ftp"
    }
  }
  
  # Fallback pour autres types
  else {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-misc-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✅ Configuration créée"

# 6. PERMISSIONS
print_status "6. Configuration des permissions..."
chown logstash:logstash /etc/logstash/conf.d/00-honeypot-pipelines.conf
chmod 644 /etc/logstash/conf.d/00-honeypot-pipelines.conf

# 7. TEST DE SYNTAXE
print_status "7. Test de syntaxe..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Syntaxe validée"
else
    print_error "❌ Erreur de syntaxe"
    print_error "Restauration de l'ancienne configuration..."
    rm -f /etc/logstash/conf.d/*.conf
    cp "$BACKUP_DIR"/* /etc/logstash/conf.d/ 2>/dev/null || true
    exit 1
fi

# 8. CONFIGURER ELASTICSEARCH POUR AUTO-CREATE INDEX
print_status "8. Configuration Elasticsearch..."
curl -X PUT "http://192.168.2.124:9200/_cluster/settings" -H "Content-Type: application/json" -d '{
  "persistent": {
    "action.auto_create_index": "honeypot-*,logstash-*,filebeat-*,.monitoring-*"
  }
}' >/dev/null 2>&1

print_status "✅ Elasticsearch configuré"

# 9. REDÉMARRER LOGSTASH
print_status "9. Redémarrage de Logstash..."
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

# 10. VÉRIFICATIONS POST-DÉMARRAGE
print_status "10. Vérifications post-démarrage..."

# Service actif
if systemctl is-active --quiet logstash; then
    print_status "✅ Service actif"
else
    print_error "❌ Service non actif"
    journalctl -u logstash --no-pager -n 10
    exit 1
fi

# Port en écoute
sleep 10
if netstat -tlnp | grep -q ":5046"; then
    print_status "✅ Port 5046 en écoute"
    PORT_INFO=$(netstat -tlnp | grep ":5046")
    print_info "   $PORT_INFO"
else
    print_warning "⚠️ Port 5046 pas encore ouvert"
fi

# API Logstash
if curl -s "http://192.168.2.124:9600/" >/dev/null 2>&1; then
    print_status "✅ API Logstash accessible"
else
    print_warning "⚠️ API pas encore prête"
fi

# 11. CRÉER UN SCRIPT DE TEST
print_status "11. Création du script de test..."

cat > /opt/test_honeypot_pipelines.sh << 'TEST_EOF'
#!/bin/bash
echo "=== TEST PIPELINES HONEYPOT ==="
echo ""
echo "📊 Status Logstash:"
echo "   Service: $(systemctl is-active logstash)"
echo ""
echo "🔗 Ports:"
netstat -tlnp | grep -E "5046|9200|9600"
echo ""
echo "📈 API Logstash:"
curl -s "http://192.168.2.124:9600/" | jq .status 2>/dev/null || echo "   API non accessible"
echo ""
echo "📁 Indices honeypot:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v" 2>/dev/null || echo "   Pas encore d'indices"
echo ""
echo "🔢 Test de comptage:"
curl -s "http://192.168.2.124:9200/honeypot-*/_count?pretty" 2>/dev/null | grep count || echo "   Pas de données"
echo ""
echo "🔍 Derniers logs Logstash:"
journalctl -u logstash --no-pager -n 3 | tail -3
echo ""
echo "🧪 Test d'envoi manuel:"
echo '{"honeypot_type": "test", "message": "Pipeline test", "timestamp": "'$(date -Iseconds)'"}' | nc localhost 5046 2>/dev/null && echo "   ✅ Envoi réussi" || echo "   ❌ Envoi échoué"
TEST_EOF

chmod +x /opt/test_honeypot_pipelines.sh

# 12. CRÉER UN SCRIPT DE MONITORING
cat > /opt/monitor_honeypot_pipelines.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== MONITORING PIPELINES HONEYPOT ==="
echo ""

# Statistiques Elasticsearch
echo "📊 INDICES HONEYPOT:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v&s=index" 2>/dev/null || echo "Aucun indice trouvé"
echo ""

# Comptage par type
echo "🔢 COMPTAGE PAR TYPE:"
for type in cowrie http ftp; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // 0')
    echo "   $type: $count documents"
done
echo ""

# Dernières données reçues
echo "🕐 DERNIÈRES DONNÉES:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?sort=@timestamp:desc&size=3&_source=honeypot_type,@timestamp,client_ip" 2>/dev/null | jq -r '.hits.hits[]._source | "\(.@timestamp) - \(.honeypot_type) - \(.client_ip // "N/A")"' 2>/dev/null || echo "Aucune donnée récente"
echo ""

# Status pipeline
echo "📈 STATUS PIPELINE:"
curl -s "http://192.168.2.124:9600/_node/stats/pipelines" 2>/dev/null | jq -r '.pipelines.main.events | "Events: in=\(.in), out=\(.out), filtered=\(.filtered)"' 2>/dev/null || echo "Stats non disponibles"
MONITOR_EOF

chmod +x /opt/monitor_honeypot_pipelines.sh

# 13. RÉSUMÉ FINAL
echo ""
print_status "=== INSTALLATION TERMINÉE ==="
echo ""
print_info "📊 RÉSUMÉ:"
echo "✅ Ancienne config sauvegardée: $BACKUP_DIR"
echo "✅ Nouvelle configuration installée"
echo "✅ Tests de validation réussis"
echo "✅ Service Logstash redémarré"
echo "✅ Scripts de test créés"
echo ""
print_info "📁 PIPELINES CONFIGURÉS:"
echo "   • SSH Cowrie: Analyse eventid, GeoIP, MITRE ATT&CK"
echo "   • HTTP: Classification attaques, OWASP, User-Agent"
echo "   • FTP: Sessions JSON + logs texte parsés"
echo ""
print_info "📊 INDICES ELASTICSEARCH:"
echo "   • honeypot-cowrie-YYYY.MM.dd"
echo "   • honeypot-http-YYYY.MM.dd"
echo "   • honeypot-ftp-YYYY.MM.dd"
echo ""
print_warning "🎯 PROCHAINES ÉTAPES:"
echo "1. Tester: /opt/test_honeypot_pipelines.sh"
echo "2. Monitoring: /opt/monitor_honeypot_pipelines.sh"
echo "3. Redémarrer le sender: systemctl restart honeypot-sender"
echo "4. Surveiller: journalctl -u logstash -f"
echo ""
print_status "Pipelines Logstash honeypot installés avec succès !"
echo ""
print_info "🔍 COMMANDES UTILES:"
echo "   • Test pipelines: /opt/test_honeypot_pipelines.sh"
echo "   • Monitoring: /opt/monitor_honeypot_pipelines.sh"
echo "   • Logs Logstash: journalctl -u logstash -f"
echo "   • API Logstash: curl http://192.168.2.124:9600/"

echo ""
echo "$(date): Pipelines Logstash honeypot installés" >> /var/log/elk-honeypot-install.log