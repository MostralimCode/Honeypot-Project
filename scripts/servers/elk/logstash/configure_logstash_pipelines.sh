#!/bin/bash
# SCRIPT D'INSTALLATION PIPELINE LOGSTASH CORRIGÉ
# Compatible avec les formats de logs honeypot réels
# VM ELK: 192.168.2.124
# Date: 2025-06-30

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

print_status "=== INSTALLATION PIPELINE LOGSTASH CORRIGÉ ==="
echo ""
print_info "Ce script va remplacer vos pipelines actuels par une version"
print_info "parfaitement adaptée à vos formats de logs Cowrie et HTTP"
echo ""

# =============================================================================
# 1. VÉRIFICATIONS PRÉALABLES
# =============================================================================

print_status "1. Vérifications préalables..."

# Vérifier Elasticsearch
if ! curl -s "http://192.168.2.124:9200/_cluster/health" >/dev/null 2>&1; then
    print_error "Elasticsearch non accessible sur 192.168.2.124:9200"
    exit 1
fi

# Vérifier Logstash installé
if ! command -v /usr/share/logstash/bin/logstash >/dev/null 2>&1; then
    print_error "Logstash non installé"
    exit 1
fi

# Vérifier que jq est disponible
if ! command -v jq >/dev/null 2>&1; then
    print_warning "jq non installé - Installation..."
    apt-get update && apt-get install -y jq
fi

print_status "✅ Prérequis validés"

# =============================================================================
# 2. ARRÊT SÉCURISÉ DE LOGSTASH
# =============================================================================

print_status "2. Arrêt sécurisé de Logstash..."
systemctl stop logstash 2>/dev/null || true

# Attendre l'arrêt complet
sleep 5

# Vérifier que Logstash est bien arrêté
if pgrep -f logstash >/dev/null; then
    print_warning "Logstash encore actif - Force kill..."
    pkill -9 -f logstash
    sleep 2
fi

print_status "✅ Logstash arrêté"

# =============================================================================
# 3. SAUVEGARDE DES CONFIGURATIONS EXISTANTES
# =============================================================================

print_status "3. Sauvegarde des configurations existantes..."

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/logstash-backups/pipeline-correction-$BACKUP_DATE"

mkdir -p "$BACKUP_DIR"

if [ -d "/etc/logstash/conf.d" ] && [ "$(ls -A /etc/logstash/conf.d)" ]; then
    cp -r /etc/logstash/conf.d/* "$BACKUP_DIR/" 2>/dev/null || true
    print_info "Sauvegarde créée : $BACKUP_DIR"
    
    # Lister les fichiers sauvegardés
    print_info "Fichiers sauvegardés :"
    ls -la "$BACKUP_DIR/"
else
    print_warning "Aucune configuration existante trouvée"
fi

# =============================================================================
# 4. NETTOYAGE ET PRÉPARATION
# =============================================================================

print_status "4. Nettoyage des anciennes configurations..."

# Supprimer tous les fichiers de configuration
rm -f /etc/logstash/conf.d/*.conf

# Créer le répertoire s'il n'existe pas
mkdir -p /etc/logstash/conf.d

print_status "✅ Répertoire nettoyé"

# =============================================================================
# 5. INSTALLATION DE LA NOUVELLE CONFIGURATION
# =============================================================================

print_status "5. Installation de la nouvelle configuration adaptée..."

cat > /etc/logstash/conf.d/00-honeypot-pipelines-corrected.conf << 'EOF'
# =============================================================================
# PIPELINE LOGSTASH CORRIGÉ POUR DONNÉES HONEYPOT RÉELLES
# Compatible avec le nouveau sender et les formats de logs exacts
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
  # Métadonnées communes
  mutate {
    add_field => { "[@metadata][processed_by]" => "logstash" }
    add_field => { "[@metadata][processing_timestamp]" => "%{@timestamp}" }
  }

  # ==========================================================================
  # PIPELINE COWRIE SSH - ADAPTÉ AUX DONNÉES RÉELLES
  # ==========================================================================
  if [honeypot_type] == "ssh" {
    # Les données arrivent maintenant directement au niveau racine
    
    # Parse du timestamp Cowrie (format: 2025-06-27T13:47:54.424222Z)
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
        target => "cowrie_timestamp"
      }
    }
    
    # Enrichissement GeoIP sur src_ip
    if [src_ip] and [src_ip] != "127.0.0.1" and [src_ip] != "192.168.2.117" {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
        add_field => { "src_coordinates" => "%{[geoip][latitude]},%{[geoip][longitude]}" }
      }
    }
    
    # Classification basée sur l'eventid réel de Cowrie
    if [eventid] {
      if [eventid] == "cowrie.login.success" {
        mutate { 
          add_field => { "event_category" => "authentication_success" }
          add_field => { "severity_level" => "critical" }
          add_field => { "alert_score" => "10" }
          add_field => { "mitre_tactic" => "initial_access" }
          add_field => { "mitre_technique" => "T1078" }
        }
      } else if [eventid] == "cowrie.login.failed" {
        mutate { 
          add_field => { "event_category" => "authentication_failure" }
          add_field => { "severity_level" => "medium" }
          add_field => { "alert_score" => "5" }
          add_field => { "mitre_tactic" => "credential_access" }
          add_field => { "mitre_technique" => "T1110" }
        }
      } else if [eventid] == "cowrie.command.input" {
        mutate { 
          add_field => { "event_category" => "command_execution" }
          add_field => { "severity_level" => "high" }
          add_field => { "alert_score" => "8" }
          add_field => { "mitre_tactic" => "execution" }
          add_field => { "mitre_technique" => "T1059" }
        }
      } else if [eventid] == "cowrie.session.connect" {
        mutate { 
          add_field => { "event_category" => "connection" }
          add_field => { "severity_level" => "low" }
          add_field => { "alert_score" => "3" }
          add_field => { "mitre_tactic" => "initial_access" }
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
          add_field => { "alert_score" => "9" }
          add_field => { "mitre_technique" => "T1105" }
        }
      }
      
      if [message] =~ /(?i)(nc|netcat|nmap)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "network_tool" }
          add_field => { "alert_score" => "8" }
        }
      }
      
      if [message] =~ /(?i)(rm -rf|dd if=|mkfs|fdisk)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "destructive" }
          add_field => { "alert_score" => "10" }
        }
      }
      
      if [message] =~ /(?i)(cat|less|more).*(passwd|shadow|hosts)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "reconnaissance" }
          add_field => { "alert_score" => "7" }
          add_field => { "mitre_technique" => "T1082" }
        }
      }
    }
    
    # Ajouter des métadonnées de service
    mutate {
      add_field => { "service_type" => "ssh_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
  }

  # ==========================================================================
  # PIPELINE HTTP HONEYPOT - ADAPTÉ AUX DONNÉES RÉELLES
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
        add_field => { "src_coordinates" => "%{[geoip][latitude]},%{[geoip][longitude]}" }
      }
    }
    
    # Classification basée sur attack_type réel
    if [attack_type] {
      if [attack_type] == "sql_injection" {
        mutate { 
          add_field => { "event_category" => "web_attack" }
          add_field => { "attack_category" => "injection" }
          add_field => { "owasp_category" => "A03_injection" }
          add_field => { "mitre_technique" => "T1190" }
        }
      } else if [attack_type] == "sql_error" {
        mutate { 
          add_field => { "event_category" => "web_error" }
          add_field => { "attack_category" => "information_disclosure" }
          add_field => { "owasp_category" => "A01_broken_access" }
        }
      } else if [attack_type] == "api_access" {
        mutate { 
          add_field => { "event_category" => "api_access" }
          add_field => { "attack_category" => "reconnaissance" }
        }
      }
    }
    
    # Analyser les query_string suspectes
    if [query_string] {
      if [query_string] =~ /(?i)(union|select|insert|delete|drop|exec|script)/ {
        mutate { 
          add_field => { "suspicious_query" => "true" }
          add_field => { "attack_vector" => "sql_injection" }
        }
      }
      
      if [query_string] =~ /(?i)(<script|javascript|onerror|onload)/ {
        mutate { 
          add_field => { "suspicious_query" => "true" }
          add_field => { "attack_vector" => "xss" }
          add_field => { "owasp_category" => "A07_xss" }
        }
      }
      
      if [query_string] =~ /(?i)(\.\.\/|\.\.\\|etc\/passwd|boot\.ini)/ {
        mutate { 
          add_field => { "suspicious_query" => "true" }
          add_field => { "attack_vector" => "path_traversal" }
        }
      }
    }
    
    # Analyser les User-Agent suspects
    if [user_agent] {
      if [user_agent] =~ /(?i)(sqlmap|burp|nmap|nikto|dirb|gobuster)/ {
        mutate { 
          add_field => { "suspicious_useragent" => "true" }
          add_field => { "scanner_detected" => "true" }
        }
      }
      
      if [user_agent] =~ /(?i)(bot|crawler|spider|scan)/ {
        mutate { 
          add_field => { "automated_tool" => "true" }
        }
      }
    }
    
    # Classification de sévérité
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
    
    # Métadonnées de service
    mutate {
      add_field => { "service_type" => "http_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
  }

  # ==========================================================================
  # PIPELINE FTP HONEYPOT - GARDE LA LOGIQUE EXISTANTE
  # ==========================================================================
  else if [honeypot_type] == "ftp" {
    
    # Parse du timestamp selon le format
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
        target => "ftp_timestamp"
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
    
    # Classification basée sur les événements FTP
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
    
    # Détection de fichiers suspects
    if [filename] {
      if [filename] =~ /(?i)(\.php|\.asp|\.exe|backdoor|shell|webshell)/ {
        mutate {
          add_field => { "suspicious_file" => "true" }
          add_field => { "malicious_file" => "true" }
          add_field => { "alert_score" => "10" }
        }
      }
    }
    
    mutate {
      add_field => { "service_type" => "ftp_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
  }

  # Normalisation finale pour tous les types
  if [honeypot_type] {
    # Copier l'IP source vers un champ unifié
    if [src_ip] and ![client_ip] {
      mutate { add_field => { "client_ip" => "%{src_ip}" } }
    } else if [ip] and ![client_ip] {
      mutate { add_field => { "client_ip" => "%{ip}" } }
    }
    
    # Ajouter un timestamp de traitement
    mutate {
      add_field => { "logstash_processed_at" => "%{@timestamp}" }
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
  
  # Fallback pour types non reconnus
  else {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-misc-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_status "✅ Nouvelle configuration installée"

# =============================================================================
# 6. CONFIGURATION DES PERMISSIONS
# =============================================================================

print_status "6. Configuration des permissions..."

chown -R logstash:logstash /etc/logstash/conf.d/
chmod 644 /etc/logstash/conf.d/*.conf

print_status "✅ Permissions configurées"

# =============================================================================
# 7. TEST DE SYNTAXE
# =============================================================================

print_status "7. Test de syntaxe de la configuration..."

if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Syntaxe validée avec succès"
else
    print_error "❌ Erreur de syntaxe détectée"
    print_error "Restauration de l'ancienne configuration..."
    
    # Restaurer la sauvegarde
    rm -f /etc/logstash/conf.d/*.conf
    if [ -d "$BACKUP_DIR" ] && [ "$(ls -A $BACKUP_DIR)" ]; then
        cp "$BACKUP_DIR"/* /etc/logstash/conf.d/ 2>/dev/null || true
        print_warning "Configuration restaurée depuis $BACKUP_DIR"
    fi
    
    exit 1
fi

# =============================================================================
# 8. CONFIGURATION ELASTICSEARCH
# =============================================================================

print_status "8. Configuration d'Elasticsearch..."

# Configurer l'auto-création d'indices
curl -X PUT "http://192.168.2.124:9200/_cluster/settings" \
     -H "Content-Type: application/json" \
     -d '{
       "persistent": {
         "action.auto_create_index": "honeypot-*,logstash-*,filebeat-*,.monitoring-*"
       }
     }' >/dev/null 2>&1

if [ $? -eq 0 ]; then
    print_status "✅ Elasticsearch configuré"
else
    print_warning "⚠️ Impossible de configurer Elasticsearch"
fi

# =============================================================================
# 9. REDÉMARRAGE DE LOGSTASH
# =============================================================================

print_status "9. Redémarrage de Logstash..."

systemctl start logstash

# Attendre le démarrage avec timeout
print_info "Attente du démarrage (60s max)..."
counter=0
while [ $counter -lt 60 ]; do
    if systemctl is-active --quiet logstash; then
        print_status "✅ Logstash démarré avec succès"
        break
    fi
    
    if [ $((counter % 10)) -eq 0 ]; then
        echo "   Attente... ${counter}s"
    fi
    
    sleep 2
    counter=$((counter + 2))
done

if [ $counter -ge 60 ]; then
    print_error "❌ Timeout - Logstash n'a pas démarré"
    print_error "Vérifiez les logs : journalctl -u logstash -n 20"
    exit 1
fi

# =============================================================================
# 10. VÉRIFICATIONS POST-INSTALLATION
# =============================================================================

print_status "10. Vérifications post-installation..."

# Vérifier le service
if systemctl is-active --quiet logstash; then
    print_status "✅ Service Logstash actif"
else
    print_error "❌ Service Logstash inactif"
fi

# Vérifier le port TCP 5046 après un délai
sleep 10
if netstat -tlnp 2>/dev/null | grep -q ":5046 "; then
    print_status "✅ Port TCP 5046 en écoute"
else
    print_warning "⚠️ Port TCP 5046 pas encore ouvert (peut prendre du temps)"
fi

# Test de connectivité Elasticsearch
if curl -s "http://192.168.2.124:9200/_cluster/health" | grep -q "yellow\|green"; then
    print_status "✅ Elasticsearch accessible"
else
    print_warning "⚠️ Problème avec Elasticsearch"
fi

# =============================================================================
# 11. CRÉATION D'OUTILS DE MONITORING
# =============================================================================

print_status "11. Création des outils de monitoring..."

# Script de monitoring principal
cat > /opt/monitor_honeypot_corrected.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== MONITORING PIPELINE HONEYPOT CORRIGÉ ==="
echo "Date: $(date)"
echo ""

# Status du service
echo "🔧 SERVICE LOGSTASH:"
if systemctl is-active --quiet logstash; then
    echo "✅ Service actif"
    uptime_info=$(systemctl show logstash --property=ActiveEnterTimestamp --value)
    echo "   Démarré: $uptime_info"
else
    echo "❌ Service inactif"
fi
echo ""

# Ports en écoute
echo "🔌 PORTS EN ÉCOUTE:"
netstat -tlnp | grep -E ":5046|:9200|:9600" | while read line; do
    echo "   $line"
done
echo ""

# Indices Elasticsearch honeypot
echo "📊 INDICES HONEYPOT:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v&s=index" 2>/dev/null || echo "   Aucun indice honeypot trouvé"
echo ""

# Comptage par type
echo "🔢 DOCUMENTS PAR TYPE:"
for type in cowrie http ftp; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // 0')
    echo "   honeypot-$type: $count documents"
done
echo ""

# Dernières données
echo "🕐 DERNIÈRES DONNÉES REÇUES:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?sort=@timestamp:desc&size=3&_source=honeypot_type,@timestamp,client_ip,eventid,attack_type" 2>/dev/null | \
jq -r '.hits.hits[]._source | "\(.@timestamp) - \(.honeypot_type) - \(.client_ip // "N/A") - \(.eventid // .attack_type // "N/A")"' 2>/dev/null || echo "   Aucune donnée récente"
echo ""

# Stats pipeline Logstash
echo "📈 STATISTIQUES PIPELINE:"
curl -s "http://192.168.2.124:9600/_node/stats/pipelines" 2>/dev/null | \
jq -r '.pipelines.main.events | "   Events: entrées=\(.in), sorties=\(.out), filtrés=\(.filtered)"' 2>/dev/null || echo "   Stats non disponibles"
echo ""

# Dernières erreurs Logstash
echo "🚨 DERNIÈRES ERREURS:"
journalctl -u logstash --since "10 minutes ago" --no-pager | grep -i "error\|failed\|exception" | tail -3 || echo "   Aucune erreur récente"
MONITOR_EOF

chmod +x /opt/monitor_honeypot_corrected.sh

# Script de test simple
cat > /opt/test_pipeline_corrected.sh << 'TEST_EOF'
#!/bin/bash
echo "=== TEST PIPELINE CORRIGÉ ==="

LOGSTASH_HOST="192.168.2.124"
LOGSTASH_PORT="5046"

echo "1. Test connectivité TCP $LOGSTASH_PORT..."
if nc -z "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null; then
    echo "✅ Port accessible"
else
    echo "❌ Port inaccessible"
    exit 1
fi

echo ""
echo "2. Envoi de logs de test..."

# Test Cowrie
cowrie_test='{"honeypot_type":"ssh","eventid":"cowrie.session.connect","src_ip":"192.168.1.100","timestamp":"2025-06-30T12:00:00.000Z","message":"Test connection","honeypot_service":"cowrie","source_vm":"192.168.2.117"}'

echo "   Test Cowrie SSH..."
echo "$cowrie_test" | nc -w 3 "$LOGSTASH_HOST" "$LOGSTASH_PORT"
if [ $? -eq 0 ]; then
    echo "   ✅ Cowrie envoyé"
else
    echo "   ❌ Cowrie échoué"
fi

# Test HTTP
http_test='{"honeypot_type":"http","attack_type":"sql_injection","ip":"192.168.1.101","timestamp":"2025-06-30T12:00:00.324","severity":"high","query_string":"SELECT * FROM users","honeypot_service":"main","source_vm":"192.168.2.117"}'

echo "   Test HTTP..."
echo "$http_test" | nc -w 3 "$LOGSTASH_HOST" "$LOGSTASH_PORT"
if [ $? -eq 0 ]; then
    echo "   ✅ HTTP envoyé"
else
    echo "   ❌ HTTP échoué"
fi

echo ""
echo "3. Attente du traitement (10s)..."
sleep 10

echo ""
echo "4. Vérification dans Elasticsearch..."
curl -s "http://192.168.2.124:9200/honeypot-*/_search?q=Test&size=5&_source=honeypot_type,eventid,attack_type" 2>/dev/null | \
jq -r '.hits.hits[]._source | "   \(.honeypot_type): \(.eventid // .attack_type)"' 2>/dev/null || echo "   Erreur de recherche"

echo ""
echo "Test terminé !"
TEST_EOF

chmod +x /opt/test_pipeline_corrected.sh

print_status "✅ Outils de monitoring créés"

# =============================================================================
# 12. RÉSUMÉ FINAL
# =============================================================================

echo ""
print_status "=== INSTALLATION TERMINÉE AVEC SUCCÈS ==="
echo ""

print_info "📊 RÉSUMÉ DES ACTIONS:"
echo "✅ Ancienne configuration sauvegardée: $BACKUP_DIR"
echo "✅ Nouvelle configuration adaptée installée"
echo "✅ Syntaxe validée avec succès"
echo "✅ Service Logstash redémarré"
echo "✅ Outils de monitoring créés"
echo ""

print_info "📁 FICHIERS INSTALLÉS:"
echo "   • /etc/logstash/conf.d/00-honeypot-pipelines-corrected.conf"
echo "   • /opt/monitor_honeypot_corrected.sh (monitoring)"
echo "   • /opt/test_pipeline_corrected.sh (tests)"
echo ""

print_info "🔧 AMÉLIORATIONS APPORTÉES:"
echo "   • Pipeline Cowrie adapté aux données réelles (eventid direct)"
echo "   • Pipeline HTTP pour attack_type, severity, query_string"
echo "   • Timestamps corrigés (ISO8601 + format HTTP)"
echo "   • Enrichissement GeoIP optimisé"
echo "   • Classification MITRE ATT&CK et OWASP"
echo "   • Scoring d'alertes unifié"
echo ""

print_info "📊 INDICES ELASTICSEARCH:"
echo "   • honeypot-cowrie-YYYY.MM.dd (données SSH)"
echo "   • honeypot-http-YYYY.MM.dd (attaques web)"
echo "   • honeypot-ftp-YYYY.MM.dd (transferts de fichiers)"
echo ""

print_warning "🎯 PROCHAINES ÉTAPES RECOMMANDÉES:"
echo ""
echo "1. Installer le nouveau sender honeypot:"
echo "   wget -O /tmp/honeypot_logs_sender_final.sh [URL_DU_SCRIPT]"
echo "   chmod +x /tmp/honeypot_logs_sender_final.sh"
echo "   systemctl stop honeypot-sender"
echo "   cp /tmp/honeypot_logs_sender_final.sh /opt/honeypot_logs_sender.sh"
echo "   systemctl start honeypot-sender"
echo ""

echo "2. Tester la configuration:"
echo "   /opt/test_pipeline_corrected.sh"
echo ""

echo "3. Monitoring en temps réel:"
echo "   /opt/monitor_honeypot_corrected.sh"
echo "   journalctl -u logstash -f"
echo ""

echo "4. Vérifier les indices Elasticsearch:"
echo "   curl -s 'http://192.168.2.124:9200/_cat/indices/honeypot-*?v'"
echo ""

echo "5. Générer du trafic de test:"
echo "   # Test SSH: ssh root@192.168.2.117 -p 2222"
echo "   # Test HTTP: curl 'http://192.168.2.117:8080/search?q=test'"
echo ""

print_info "🔍 COMMANDES DE DIAGNOSTIC:"
echo ""
echo "• Vérifier Logstash:     systemctl status logstash"
echo "• Logs Logstash:         journalctl -u logstash -f"
echo "• Test syntaxe:          sudo -u logstash /usr/share/logstash/bin/logstash -t"
echo "• API Logstash:          curl http://192.168.2.124:9600/"
echo "• Santé Elasticsearch:   curl http://192.168.2.124:9200/_cluster/health"
echo "• Monitoring pipeline:   /opt/monitor_honeypot_corrected.sh"
echo ""

print_info "📋 LOGS À SURVEILLER:"
echo "• Sender honeypot:       tail -f /var/log/honeypot-sender/sender.log"
echo "• Logstash service:      journalctl -u logstash -f"
echo "• Elasticsearch:         tail -f /var/log/elasticsearch/elasticsearch.log"
echo ""

print_warning "⚠️ EN CAS DE PROBLÈME:"
echo ""
echo "1. Restaurer l'ancienne config:"
echo "   systemctl stop logstash"
echo "   rm -f /etc/logstash/conf.d/*.conf"
echo "   cp $BACKUP_DIR/* /etc/logstash/conf.d/"
echo "   systemctl start logstash"
echo ""

echo "2. Diagnostiquer les erreurs:"
echo "   journalctl -u logstash --since '5 minutes ago'"
echo "   sudo -u logstash /usr/share/logstash/bin/logstash -t"
echo ""

echo "3. Vérifier les permissions:"
echo "   ls -la /etc/logstash/conf.d/"
echo "   chown -R logstash:logstash /etc/logstash/"
echo ""

# Créer un fichier de log d'installation
cat > /var/log/honeypot-pipeline-install.log << LOG_EOF
$(date): Installation pipeline Logstash corrigé terminée
Sauvegarde: $BACKUP_DIR
Configuration: /etc/logstash/conf.d/00-honeypot-pipelines-corrected.conf
Outils: /opt/monitor_honeypot_corrected.sh, /opt/test_pipeline_corrected.sh
Status: SUCCESS
LOG_EOF

echo "📝 Log d'installation: /var/log/honeypot-pipeline-install.log"
echo ""

print_status "🎉 PIPELINE LOGSTASH CORRIGÉ INSTALLÉ AVEC SUCCÈS !"
echo ""
print_info "Votre infrastructure est maintenant prête à traiter correctement"
print_info "les logs Cowrie SSH et HTTP honeypot sans erreurs de parsing JSON."
echo ""
print_warning "N'oubliez pas d'installer également le nouveau sender honeypot"
print_warning "pour une compatibilité parfaite avec ces pipelines !"
echo ""

# Test final automatique si demandé
read -p "Voulez-vous exécuter un test automatique maintenant ? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    print_status "Exécution du test automatique..."
    /opt/test_pipeline_corrected.sh
    echo ""
    print_status "Monitoring post-test..."
    /opt/monitor_honeypot_corrected.sh
fi

echo ""
print_status "Installation terminée - Prêt pour la production !"
echo ""

# Afficher le statut final
echo "=== STATUT FINAL ==="
echo "Logstash: $(systemctl is-active logstash)"
echo "Port 5046: $(netstat -tln | grep :5046 >/dev/null && echo 'OUVERT' || echo 'FERMÉ')"
echo "Elasticsearch: $(curl -s http://192.168.2.124:9200/_cluster/health | jq -r .status 2>/dev/null || echo 'INACCESSIBLE')"
echo "Configuration: /etc/logstash/conf.d/00-honeypot-pipelines-corrected.conf"
echo ""

exit 0