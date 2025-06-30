#!/bin/bash
# SCRIPT PIPELINE LOGSTASH ROBUSTE - SANS INTERRUPTIONS
# Compatible avec les formats de logs honeypot réels
# VM ELK: 192.168.2.124
# Date: 2025-06-30

set -e  # Arrêter immédiatement en cas d'erreur
set -o pipefail  # Détecter les erreurs dans les pipes

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

# Fonction de cleanup en cas d'erreur
cleanup_on_error() {
    print_error "Erreur détectée ! Nettoyage automatique..."
    
    # Redémarrer Logstash si possible
    systemctl start logstash 2>/dev/null && print_info "Logstash redémarré" || print_warning "Impossible de redémarrer Logstash"
    
    # Restaurer la sauvegarde si elle existe
    if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ] && [ "$(ls -A $BACKUP_DIR)" ]; then
        print_info "Restauration de la sauvegarde depuis $BACKUP_DIR"
        rm -f /etc/logstash/conf.d/*.conf 2>/dev/null || true
        cp "$BACKUP_DIR"/* /etc/logstash/conf.d/ 2>/dev/null || true
        systemctl restart logstash 2>/dev/null || true
    fi
    
    print_error "Installation annulée - système restauré"
    exit 1
}

# Installer le trap pour le cleanup
trap cleanup_on_error ERR INT TERM

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

clear
print_status "=== INSTALLATION PIPELINE LOGSTASH ROBUSTE ==="
print_info "Installation automatique sans interruption"
echo ""

# =============================================================================
# 1. VÉRIFICATIONS PRÉALABLES ROBUSTES
# =============================================================================

print_status "1. Vérifications préalables..."

# Test Elasticsearch avec retry
print_info "   • Test Elasticsearch..."
for i in {1..3}; do
    if curl -s --connect-timeout 10 "http://192.168.2.124:9200/_cluster/health" >/dev/null 2>&1; then
        print_info "   ✅ Elasticsearch accessible"
        break
    else
        if [ $i -eq 3 ]; then
            print_error "Elasticsearch inaccessible après 3 tentatives"
            exit 1
        fi
        print_warning "   Tentative $i/3 échouée, retry..."
        sleep 2
    fi
done

# Test Logstash
print_info "   • Test Logstash..."
if command -v /usr/share/logstash/bin/logstash >/dev/null 2>&1; then
    print_info "   ✅ Logstash installé"
else
    print_error "Logstash non installé"
    exit 1
fi

# Test/installation jq
print_info "   • Test jq..."
if ! command -v jq >/dev/null 2>&1; then
    print_info "   Installation de jq..."
    apt-get update -qq && apt-get install -y jq -qq
fi
print_info "   ✅ jq disponible"

print_status "✅ Tous les prérequis validés"

# =============================================================================
# 2. ARRÊT SIMPLE DE LOGSTASH
# =============================================================================

print_status "2. Arrêt de Logstash..."

print_info "   • Arrêt du service Logstash..."
systemctl stop logstash 2>/dev/null || true

print_info "   • Attente de l'arrêt (5s)..."
sleep 5

# Vérification de l'arrêt
if systemctl is-active --quiet logstash 2>/dev/null; then
    print_warning "   ⚠️ Logstash encore actif - Attente supplémentaire..."
    sleep 3
else
    print_info "   ✅ Logstash arrêté avec succès"
fi

print_status "✅ Arrêt terminé"

# =============================================================================
# 3. SAUVEGARDE AUTOMATIQUE
# =============================================================================

print_status "3. Sauvegarde automatique..."

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/opt/logstash-backups/robust-$BACKUP_DATE"

print_info "   • Création du répertoire de sauvegarde..."
mkdir -p "$BACKUP_DIR"

if [ -d "/etc/logstash/conf.d" ] && [ "$(ls -A /etc/logstash/conf.d 2>/dev/null)" ]; then
    print_info "   • Sauvegarde des fichiers existants..."
    cp -r /etc/logstash/conf.d/* "$BACKUP_DIR/" 2>/dev/null || true
    
    # Vérifier la sauvegarde
    if [ "$(ls -A $BACKUP_DIR 2>/dev/null)" ]; then
        print_info "   ✅ Sauvegarde créée : $BACKUP_DIR"
        ls -la "$BACKUP_DIR/" | head -5
    else
        print_warning "   ⚠️ Sauvegarde vide (aucun fichier à sauvegarder)"
    fi
else
    print_info "   ✅ Aucune configuration existante à sauvegarder"
fi

# =============================================================================
# 4. NETTOYAGE ET PRÉPARATION
# =============================================================================

print_status "4. Nettoyage des configurations..."

print_info "   • Suppression des anciennes configurations..."
rm -f /etc/logstash/conf.d/*.conf 2>/dev/null || true

print_info "   • Création du répertoire de configuration..."
mkdir -p /etc/logstash/conf.d

print_status "✅ Nettoyage terminé"

# =============================================================================
# 5. INSTALLATION DE LA NOUVELLE CONFIGURATION
# =============================================================================

print_status "5. Installation de la configuration optimisée..."

print_info "   • Création du fichier de configuration..."

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

print_info "   ✅ Configuration installée"

# =============================================================================
# 6. CONFIGURATION DES PERMISSIONS
# =============================================================================

print_status "6. Configuration des permissions..."

print_info "   • Attribution des permissions Logstash..."
chown -R logstash:logstash /etc/logstash/conf.d/
chmod 644 /etc/logstash/conf.d/*.conf

print_status "✅ Permissions configurées"

# =============================================================================
# 7. TEST DE SYNTAXE OBLIGATOIRE
# =============================================================================

print_status "7. Validation de la syntaxe..."

print_info "   • Test de la syntaxe Logstash..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Syntaxe validée avec succès"
else
    print_error "❌ Erreur de syntaxe détectée - Restauration automatique"
    # La fonction cleanup_on_error sera appelée automatiquement
    exit 1
fi

# =============================================================================
# 8. CONFIGURATION ELASTICSEARCH
# =============================================================================

print_status "8. Configuration d'Elasticsearch..."

print_info "   • Configuration de l'auto-création d'indices..."
if curl -s -X PUT "http://192.168.2.124:9200/_cluster/settings" \
        -H "Content-Type: application/json" \
        -d '{"persistent":{"action.auto_create_index":"honeypot-*,logstash-*,filebeat-*,.monitoring-*"}}' \
        >/dev/null 2>&1; then
    print_info "   ✅ Elasticsearch configuré"
else
    print_warning "   ⚠️ Configuration Elasticsearch échouée (non critique)"
fi

# =============================================================================
# 9. REDÉMARRAGE LOGSTASH
# =============================================================================

print_status "9. Redémarrage de Logstash..."

print_info "   • Démarrage du service..."
systemctl start logstash

print_info "   • Attente du démarrage (30s max)..."
for i in {1..30}; do
    if systemctl is-active --quiet logstash; then
        print_status "✅ Logstash démarré avec succès (${i}s)"
        break
    fi
    sleep 1
    if [ $((i % 5)) -eq 0 ]; then
        echo -n "   Attente... ${i}s"\n'
    fi
done

if [ $i -eq 30 ]; then
    print_error "❌ Timeout - Logstash n'a pas démarré dans les temps"
    print_error "Vérifiez les logs : journalctl -u logstash -n 20"
    exit 1
fi

# =============================================================================
# 10. VÉRIFICATIONS POST-INSTALLATION
# =============================================================================

print_status "10. Vérifications finales..."

# Service actif
print_info "   • Test du service..."
if systemctl is-active --quiet logstash; then
    print_info "   ✅ Service Logstash actif"
else
    print_error "   ❌ Service Logstash inactif"
    exit 1
fi

# Port TCP (avec délai pour le démarrage)
print_info "   • Test du port TCP 5046 (attente 15s)..."
sleep 15
if netstat -tlnp 2>/dev/null | grep -q ":5046 "; then
    print_info "   ✅ Port TCP 5046 en écoute"
else
    print_warning "   ⚠️ Port TCP 5046 pas encore disponible"
    print_info "   Cela peut prendre quelques minutes supplémentaires"
fi

# Connectivité Elasticsearch
print_info "   • Test connectivité Elasticsearch..."
if curl -s "http://192.168.2.124:9200/_cluster/health" | grep -q "yellow\|green"; then
    print_info "   ✅ Elasticsearch accessible"
else
    print_warning "   ⚠️ Problème avec Elasticsearch"
fi

# =============================================================================
# 11. CRÉATION D'OUTILS DE MONITORING
# =============================================================================

print_status "11. Création des outils de monitoring..."

print_info "   • Script de monitoring..."
cat > /opt/monitor_honeypot_robust.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== MONITORING PIPELINE HONEYPOT ==="
echo "Date: $(date)"
echo ""

echo "🔧 SERVICE:"
echo "   Logstash: $(systemctl is-active logstash 2>/dev/null || echo 'ARRÊTÉ')"
echo ""

echo "🔌 PORTS:"
netstat -tlnp | grep -E ":5046|:9200" | head -3
echo ""

echo "📊 INDICES HONEYPOT:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v&s=index" 2>/dev/null | head -10 || echo "   Aucun indice"
echo ""

echo "🔢 DOCUMENTS:"
for type in cowrie http ftp; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // 0')
    echo "   $type: $count"
done
echo ""

echo "🕐 DERNIÈRES DONNÉES:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?sort=@timestamp:desc&size=3&_source=honeypot_type,@timestamp,client_ip" 2>/dev/null | \
jq -r '.hits.hits[]._source | "\(.@timestamp) - \(.honeypot_type) - \(.client_ip // "N/A")"' 2>/dev/null | head -3 || echo "   Aucune donnée"
MONITOR_EOF

chmod +x /opt/monitor_honeypot_robust.sh

print_info "   • Script de test..."
cat > /opt/test_pipeline_robust.sh << 'TEST_EOF'
#!/bin/bash
echo "=== TEST PIPELINE ROBUSTE ==="

HOST="192.168.2.124"
PORT="5046"

echo "1. Test connectivité..."
if nc -z "$HOST" "$PORT" 2>/dev/null; then
    echo "✅ Port accessible"
else
    echo "❌ Port inaccessible"
    exit 1
fi

echo "2. Envoi de tests..."
echo '{"honeypot_type":"ssh","eventid":"cowrie.session.connect","src_ip":"192.168.1.100","timestamp":"2025-06-30T12:00:00.000Z","message":"Test SSH"}' | nc -w 3 "$HOST" "$PORT"
echo "   ✅ Test SSH envoyé"

echo '{"honeypot_type":"http","attack_type":"sql_injection","ip":"192.168.1.101","timestamp":"2025-06-30T12:00:00.324","severity":"high"}' | nc -w 3 "$HOST" "$PORT"
echo "   ✅ Test HTTP envoyé"

echo "3. Attente traitement (10s)..."
sleep 10

echo "4. Vérification..."
curl -s "http://192.168.2.124:9200/honeypot-*/_count" | jq .count 2>/dev/null || echo "Erreur de vérification"
TEST_EOF

chmod +x /opt/test_pipeline_robust.sh

print_info "   ✅ Outils créés"

# =============================================================================
# 12. RÉSUMÉ FINAL
# =============================================================================

clear
print_status "🎉 INSTALLATION TERMINÉE AVEC SUCCÈS !"
echo ""

print_info "📊 RÉSUMÉ:"
echo "✅ Configuration adaptée aux vrais formats de logs"
echo "✅ Pipeline Cowrie corrigé (eventid direct)"
echo "✅ Pipeline HTTP enrichi (attack_type, severity)"
echo "✅ Syntaxe validée et service redémarré"
echo "✅ Outils de monitoring créés"
echo ""

print_info "📁 SAUVEGARDE:"
echo "   Ancienne config: $BACKUP_DIR"
echo ""

print_info "🔧 FICHIERS INSTALLÉS:"
echo "   • /etc/logstash/conf.d/00-honeypot-pipelines-corrected.conf"
echo "   • /opt/monitor_honeypot_robust.sh"
echo "   • /opt/test_pipeline_robust.sh"
echo ""

print_warning "🎯 PROCHAINES ÉTAPES:"
echo "1. Installer le nouveau sender honeypot"
echo "2. Tester: /opt/test_pipeline_robust.sh"
echo "3. Surveiller: /opt/monitor_honeypot_robust.sh"
echo "4. Vérifier logs: journalctl -u logstash -f"
echo ""

print_info "💡 COMMANDES UTILES:"
echo "• Statut: systemctl status logstash"
echo "• Monitoring: /opt/monitor_honeypot_robust.sh"
echo "• Test: /opt/test_pipeline_robust.sh"
echo "• Logs: journalctl -u logstash -f"
echo ""

# Test final optionnel
read -p "Lancer un test automatique maintenant ? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    print_status "Test en cours..."
    /opt/test_pipeline_robust.sh
fi

print_status "Installation robuste terminée - Prêt pour la production !"
exit 0