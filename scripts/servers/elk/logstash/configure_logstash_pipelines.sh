#!/bin/bash
# Script d'installation des pipelines Logstash spécialisés pour honeypot
# VM ELK: 192.168.2.124
# Support: Cowrie SSH + HTTP + FTP honeypots
# CORRIGÉ pour formats de logs réels

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
    print_error "Logstash non installé ou arrêté"
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

# 5. CRÉER LA NOUVELLE CONFIGURATION CORRIGÉE
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
# FILTRES SPÉCIALISÉS PAR TYPE DE HONEYPOT - VERSION CORRIGÉE
# =============================================================================

filter {
  # Ajouter des métadonnées communes
  mutate {
    add_field => { "[@metadata][processed_by]" => "logstash" }
    add_field => { "[@metadata][processing_timestamp]" => "%{@timestamp}" }
  }

  # ==========================================================================
  # PIPELINE COWRIE SSH - CORRIGÉ POUR DONNÉES DIRECTES
  # ==========================================================================
  if [honeypot_type] == "ssh" {
    
    # Parse du timestamp Cowrie (format: 2025-06-27T13:47:54.424222Z)
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
        target => "cowrie_timestamp"
      }
    }
    
    # Enrichissement GeoIP sur src_ip (données directes maintenant)
    if [src_ip] and [src_ip] != "127.0.0.1" and [src_ip] != "192.168.2.117" {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification basée sur eventid (direct maintenant, pas cowrie_data)
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
        }
      } else if [eventid] == "cowrie.session.closed" {
        mutate { 
          add_field => { "event_category" => "disconnection" }
          add_field => { "severity_level" => "low" }
          add_field => { "alert_score" => "1" }
        }
      } else if [eventid] == "cowrie.client.version" {
        mutate { 
          add_field => { "event_category" => "reconnaissance" }
          add_field => { "severity_level" => "low" }
          add_field => { "alert_score" => "2" }
        }
      }
    }
    
    # Analyser les commandes suspectes dans le message
    if [message] {
      if [message] =~ /(?i)(wget|curl).*http/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "download_tool" }
        }
      }
      
      if [message] =~ /(?i)(nc|netcat|nmap)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "network_tool" }
        }
      }
      
      if [message] =~ /(?i)(rm -rf|dd if=|mkfs|fdisk)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "destructive" }
        }
      }
    }
    
    # Métadonnées
    mutate {
      add_field => { "service_type" => "ssh_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
  }

  # ==========================================================================
  # PIPELINE HTTP HONEYPOT - CORRIGÉ POUR VOS DONNÉES RÉELLES
  # ==========================================================================
  else if [honeypot_type] == "http" {
    
    # Parse du timestamp HTTP (format: 2025-05-07T16:28:49.324)
    if [timestamp] {
      date {
        match => [ "timestamp", "yyyy-MM-dd'T'HH:mm:ss.SSS" ]
        target => "http_timestamp"
      }
    }
    
    # Enrichissement GeoIP sur le champ ip
    if [ip] and [ip] != "127.0.0.1" and [ip] != "192.168.2.117" {
      geoip {
        source => "ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification basée sur attack_type de vos logs
    if [attack_type] {
      if [attack_type] == "sql_injection" {
        mutate { 
          add_field => { "event_category" => "web_attack" }
          add_field => { "attack_category" => "injection" }
          add_field => { "owasp_category" => "A03_injection" }
        }
      } else if [attack_type] == "sql_error" {
        mutate { 
          add_field => { "event_category" => "web_error" }
          add_field => { "attack_category" => "information_disclosure" }
        }
      } else if [attack_type] == "api_access" {
        mutate { 
          add_field => { "event_category" => "api_access" }
          add_field => { "attack_category" => "reconnaissance" }
        }
      }
    }
    
    # Analyser les query_string
    if [query_string] {
      if [query_string] =~ /(?i)(union|select|insert|delete|drop)/ {
        mutate { 
          add_field => { "suspicious_query" => "true" }
          add_field => { "attack_vector" => "sql_injection" }
        }
      }
      
      if [query_string] =~ /(?i)(<script|javascript|onerror)/ {
        mutate { 
          add_field => { "suspicious_query" => "true" }
          add_field => { "attack_vector" => "xss" }
        }
      }
    }
    
    # Classification severity de vos logs
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
    
    mutate {
      add_field => { "service_type" => "http_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
  }

  # ==========================================================================
  # PIPELINE FTP HONEYPOT - GARDE LA LOGIQUE QUI FONCTIONNE
  # ==========================================================================
  else if [honeypot_type] == "ftp" {
    
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
        target => "ftp_timestamp"
      }
    }
    
    if [ip] and [ip] != "127.0.0.1" and [ip] != "192.168.2.117" {
      geoip {
        source => "ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    if [event_type] {
      if [event_type] == "auth_attempt" {
        if [success] == true {
          mutate { 
            add_field => { "event_category" => "authentication_success" }
            add_field => { "severity_level" => "critical" }
            add_field => { "alert_score" => "10" }
          }
        } else {
          mutate { 
            add_field => { "event_category" => "authentication_failure" }
            add_field => { "severity_level" => "medium" }
            add_field => { "alert_score" => "5" }
          }
        }
      } else if [event_type] == "file_upload" {
        mutate { 
          add_field => { "event_category" => "file_transfer" }
          add_field => { "severity_level" => "high" }
          add_field => { "alert_score" => "8" }
        }
      }
    }
    
    if [filename] {
      if [filename] =~ /(?i)(\.php|\.asp|\.exe|backdoor|shell)/ {
        mutate {
          add_field => { "suspicious_file" => "true" }
          add_field => { "malicious_file" => "true" }
        }
      }
    }
    
    mutate {
      add_field => { "service_type" => "ftp_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
  }

  # Normalisation finale
  if [honeypot_type] {
    # IP unifiée
    if [src_ip] and ![client_ip] {
      mutate { add_field => { "client_ip" => "%{src_ip}" } }
    } else if [ip] and ![client_ip] {
      mutate { add_field => { "client_ip" => "%{ip}" } }
    }
    
    # Nettoyer les champs temporaires
    mutate {
      remove_field => [ "host", "port", "@version" ]
    }
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
  
  # Fallback
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

# 8. CONFIGURER ELASTICSEARCH
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
echo "✅ Nouvelle configuration installée (corrigée pour vos logs)"
echo "✅ Tests de validation réussis"
echo "✅ Service Logstash redémarré"
echo "✅ Scripts de test créés"
echo ""
print_info "📁 CORRECTIONS APPORTÉES:"
echo "   • Cowrie: eventid direct (plus de cowrie_data)"
echo "   • HTTP: attack_type, severity, query_string pris en compte"
echo "   • Timestamps: ISO8601 + format HTTP spécifique"
echo ""
print_info "📊 INDICES ELASTICSEARCH:"
echo "   • honeypot-cowrie-YYYY.MM.dd"
echo "   • honeypot-http-YYYY.MM.dd"
echo "   • honeypot-ftp-YYYY.MM.dd"
echo ""
print_warning "🎯 PROCHAINES ÉTAPES:"
echo "1. Tester: /opt/test_honeypot_pipelines.sh"
echo "2. Monitoring: /opt/monitor_honeypot_pipelines.sh"
echo "3. Installer le nouveau sender honeypot"
echo "4. Surveiller: journalctl -u logstash -f"
echo ""
print_status "Pipelines Logstash corrigés installés avec succès !"
echo ""
print_info "🔍 COMMANDES UTILES:"
echo "   • Test pipelines: /opt/test_honeypot_pipelines.sh"
echo "   • Monitoring: /opt/monitor_honeypot_pipelines.sh"
echo "   • Logs Logstash: journalctl -u logstash -f"
echo "   • API Logstash: curl http://192.168.2.124:9600/"

echo ""
echo "$(date): Pipelines Logstash honeypot corrigés installés" >> /var/log/elk-honeypot-install.log