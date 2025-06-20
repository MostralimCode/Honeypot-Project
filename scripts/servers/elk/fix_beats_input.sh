#!/bin/bash
# Script de correction Logstash - VM ELK (192.168.2.124)
# Corrige les configurations pour recevoir les données des honeypots

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

print_status "=== CORRECTION CONFIGURATION LOGSTASH ==="

# 1. Vérifier qu'on est sur la bonne VM
CURRENT_IP=$(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')
if [ "$CURRENT_IP" != "192.168.2.124" ]; then
    print_error "Ce script doit être exécuté sur la VM ELK (192.168.2.124)"
    print_error "IP actuelle: $CURRENT_IP"
    exit 1
fi

# 2. Arrêter Logstash
print_status "Arrêt de Logstash..."
systemctl stop logstash

# 3. Sauvegarder les configurations existantes
print_status "Sauvegarde des configurations existantes..."
BACKUP_DIR="/etc/logstash/conf.d.backup.$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp /etc/logstash/conf.d/*.conf "$BACKUP_DIR/" 2>/dev/null || true
print_info "Sauvegarde créée : $BACKUP_DIR"

# 4. Supprimer les anciennes configurations
print_status "Suppression des anciennes configurations..."
rm -f /etc/logstash/conf.d/*.conf

# 5. Créer la nouvelle configuration INPUT
print_status "Création de l'input Beats corrigé..."

cat > /etc/logstash/conf.d/00-beats-input.conf << 'EOF'
# Input Beats pour recevoir les données de Filebeat depuis VM Honeypot
input {
  beats {
    port => 5044
    host => "192.168.2.124"
    type => "beats"
  }
}
EOF

# 6. Créer la configuration FILTER
print_status "Création des filtres honeypot corrigés..."

cat > /etc/logstash/conf.d/10-honeypot-filters.conf << 'EOF'
# Filtres pour traiter les données des honeypots
filter {
  # Ajouter des métadonnées communes pour tous les événements Beats
  if [@metadata][beat] {
    mutate {
      add_field => { "processed_by" => "logstash" }
      add_field => { "ingestion_timestamp" => "%{@timestamp}" }
    }
  }

  # Traitement spécialisé par type de honeypot
  if [honeypot_type] == "ssh" {
    mutate {
      add_field => { 
        "service_category" => "ssh_honeypot"
        "protocol" => "ssh"
        "honeypot_name" => "cowrie"
      }
    }
    
    # Parser les événements Cowrie spécifiques
    if [eventid] {
      if [eventid] =~ /login/ {
        mutate { add_field => { "event_category" => "authentication" } }
      }
      if [eventid] =~ /command/ {
        mutate { add_field => { "event_category" => "command_execution" } }
      }
      if [eventid] =~ /session/ {
        mutate { add_field => { "event_category" => "session_management" } }
      }
    }
  }
  
  else if [honeypot_type] == "http" {
    mutate {
      add_field => { 
        "service_category" => "web_honeypot"
        "protocol" => "http"
        "honeypot_name" => "http_custom"
      }
    }
    
    # Classifier les attaques HTTP
    if [attack_type] {
      mutate { add_field => { "event_category" => "%{attack_type}" } }
      
      if [attack_type] == "sql_injection" {
        mutate { add_field => { "threat_level" => "high" } }
      }
      else if [attack_type] == "xss" {
        mutate { add_field => { "threat_level" => "medium" } }
      }
      else {
        mutate { add_field => { "threat_level" => "low" } }
      }
    }
  }
  
  else if [honeypot_type] == "ftp" {
    mutate {
      add_field => { 
        "service_category" => "ftp_honeypot"
        "protocol" => "ftp"
        "honeypot_name" => "ftp_custom"
      }
    }
    
    # Classifier les événements FTP
    if [event_type] {
      if [event_type] =~ /auth/ {
        mutate { add_field => { "event_category" => "authentication" } }
      }
      else if [event_type] =~ /command/ {
        mutate { add_field => { "event_category" => "command_execution" } }
      }
      else if [event_type] =~ /transfer/ {
        mutate { add_field => { "event_category" => "file_transfer" } }
      }
      else {
        mutate { add_field => { "event_category" => "session" } }
      }
    }
  }
  
  else if [honeypot_type] == "system" {
    mutate {
      add_field => { 
        "service_category" => "system_logs"
        "honeypot_name" => "system"
      }
    }
  }
  
  # Traitement du timestamp si présent
  if [timestamp] {
    date {
      match => [ "timestamp", "ISO8601", "yyyy-MM-dd'T'HH:mm:ss.SSSZ", "yyyy-MM-dd'T'HH:mm:ssZ" ]
      target => "@timestamp"
    }
  }
  
  # Géolocalisation des IPs (si présente)
  if [src_ip] {
    geoip {
      source => "src_ip"
      target => "geoip_src"
    }
  }
  
  if [ip] and [ip] != [src_ip] {
    geoip {
      source => "ip"
      target => "geoip_client"
    }
  }
  
  # Nettoyage des champs vides
  if [message] == "" {
    mutate { remove_field => [ "message" ] }
  }
}
EOF

# 7. Créer la configuration OUTPUT
print_status "Création des outputs Elasticsearch corrigés..."

cat > /etc/logstash/conf.d/90-elasticsearch-output.conf << 'EOF'
# Outputs vers Elasticsearch avec indices spécialisés
output {
  # Output pour honeypot SSH (Cowrie)
  if [honeypot_type] == "ssh" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
      template_name => "honeypot-cowrie"
      template_pattern => "honeypot-cowrie-*"
      template => {
        "index_patterns" => ["honeypot-cowrie-*"],
        "settings" => {
          "number_of_shards" => 1,
          "number_of_replicas" => 0,
          "index.refresh_interval" => "5s"
        },
        "mappings" => {
          "properties" => {
            "@timestamp" => { "type" => "date" },
            "timestamp" => { "type" => "date" },
            "src_ip" => { "type" => "ip" },
            "username" => { "type" => "keyword" },
            "password" => { "type" => "keyword" },
            "eventid" => { "type" => "keyword" },
            "honeypot_type" => { "type" => "keyword" },
            "service_category" => { "type" => "keyword" },
            "event_category" => { "type" => "keyword" }
          }
        }
      }
    }
  }
  
  # Output pour honeypot HTTP
  else if [honeypot_type] == "http" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
      template_name => "honeypot-http"
      template_pattern => "honeypot-http-*"
      template => {
        "index_patterns" => ["honeypot-http-*"],
        "settings" => {
          "number_of_shards" => 1,
          "number_of_replicas" => 0,
          "index.refresh_interval" => "5s"
        },
        "mappings" => {
          "properties" => {
            "@timestamp" => { "type" => "date" },
            "timestamp" => { "type" => "date" },
            "ip" => { "type" => "ip" },
            "method" => { "type" => "keyword" },
            "path" => { "type" => "keyword" },
            "attack_type" => { "type" => "keyword" },
            "honeypot_type" => { "type" => "keyword" },
            "service_category" => { "type" => "keyword" },
            "threat_level" => { "type" => "keyword" }
          }
        }
      }
    }
  }
  
  # Output pour honeypot FTP
  else if [honeypot_type] == "ftp" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
      template_name => "honeypot-ftp"
      template_pattern => "honeypot-ftp-*"
      template => {
        "index_patterns" => ["honeypot-ftp-*"],
        "settings" => {
          "number_of_shards" => 1,
          "number_of_replicas" => 0,
          "index.refresh_interval" => "5s"
        },
        "mappings" => {
          "properties" => {
            "@timestamp" => { "type" => "date" },
            "timestamp" => { "type" => "date" },
            "ip" => { "type" => "ip" },
            "username" => { "type" => "keyword" },
            "event_type" => { "type" => "keyword" },
            "honeypot_type" => { "type" => "keyword" },
            "service_category" => { "type" => "keyword" }
          }
        }
      }
    }
  }
  
  # Output pour logs système
  else if [honeypot_type] == "system" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-system-%{+YYYY.MM.dd}"
    }
  }
  
  # Fallback pour types non reconnus
  else {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-misc-%{+YYYY.MM.dd}"
    }
  }
  
  # Output de debug (optionnel - commentez si pas nécessaire)
  # stdout { 
  #   codec => rubydebug { metadata => true }
  # }
}
EOF

# 8. Vérifier les permissions
print_status "Configuration des permissions..."
chown -R logstash:logstash /etc/logstash/conf.d/
chmod 644 /etc/logstash/conf.d/*.conf

# 9. Test de la configuration
print_status "Test de la configuration Logstash..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Configuration valide"
else
    print_error "❌ Configuration invalide"
    print_error "Restauration des anciennes configurations..."
    rm -f /etc/logstash/conf.d/*.conf
    cp "$BACKUP_DIR"/*.conf /etc/logstash/conf.d/ 2>/dev/null || true
    exit 1
fi

# 10. Redémarrer Logstash
print_status "Redémarrage de Logstash..."
systemctl start logstash
systemctl enable logstash

# Attendre le démarrage
print_info "Attente du démarrage de Logstash..."
counter=0
while [ $counter -lt 60 ]; do
    if systemctl is-active --quiet logstash; then
        print_status "✅ Logstash démarré"
        break
    fi
    sleep 2
    counter=$((counter + 2))
    if [ $((counter % 10)) -eq 0 ]; then
        echo "Attente... ${counter}s"
    fi
done

# 11. Vérifications finales
print_status "Vérifications finales..."

# Vérifier le service
if systemctl is-active --quiet logstash; then
    print_status "✅ Service Logstash actif"
else
    print_error "❌ Service Logstash non actif"
    journalctl -u logstash --no-pager -n 10
    exit 1
fi

# Vérifier le port 5044
sleep 10
if netstat -tlnp | grep -q ":5044 "; then
    print_status "✅ Port 5044 en écoute"
else
    print_warning "⚠️ Port 5044 pas encore en écoute"
fi

# Vérifier Elasticsearch
if curl -s "http://192.168.2.124:9200/_cluster/health" | grep -q "yellow\|green"; then
    print_status "✅ Elasticsearch accessible"
else
    print_warning "⚠️ Problème avec Elasticsearch"
fi

# 12. Créer un script de monitoring
print_status "Création du script de monitoring..."

cat > /opt/monitor_logstash_elk.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== MONITORING LOGSTASH ELK ==="
echo ""
echo "📊 Services ELK:"
echo "Elasticsearch: $(systemctl is-active elasticsearch)"
echo "Logstash: $(systemctl is-active logstash)"
echo "Kibana: $(systemctl is-active kibana)"
echo ""
echo "🔗 Ports:"
echo "Port 9200 (ES): $(netstat -tlnp | grep ':9200' | wc -l) connexions"
echo "Port 5044 (Logstash): $(netstat -tlnp | grep ':5044' | wc -l) connexions"
echo "Port 5601 (Kibana): $(netstat -tlnp | grep ':5601' | wc -l) connexions"
echo ""
echo "📊 Indices Honeypot:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v" 2>/dev/null | head -10 || echo "Pas d'indices honeypot"
echo ""
echo "🔢 Nombre de documents:"
for index in cowrie http ftp system; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$index-*/_count" 2>/dev/null | jq -r '.count // 0' 2>/dev/null || echo "0")
    echo "$index: $count documents"
done
echo ""
echo "🔍 Derniers logs Logstash:"
journalctl -u logstash --no-pager -n 3 | tail -3
MONITOR_EOF

chmod +x /opt/monitor_logstash_elk.sh

# 13. Résumé final
print_status "=== CORRECTION LOGSTASH TERMINÉE ==="
echo ""
print_info "📊 RÉSUMÉ:"
echo "✅ Configurations Logstash corrigées"
echo "✅ Input Beats configuré (port 5044)"
echo "✅ Filtres honeypot optimisés"
echo "✅ Outputs Elasticsearch avec templates"
echo "✅ Service redémarré et vérifié"
echo "✅ Script de monitoring créé: /opt/monitor_logstash_elk.sh"
echo ""
print_info "📁 FICHIERS:"
echo "Input: /etc/logstash/conf.d/00-beats-input.conf"
echo "Filtres: /etc/logstash/conf.d/10-honeypot-filters.conf"
echo "Outputs: /etc/logstash/conf.d/90-elasticsearch-output.conf"
echo "Sauvegarde: $BACKUP_DIR"
echo "Monitoring: /opt/monitor_logstash_elk.sh"
echo ""
print_warning "🎯 PROCHAINES ÉTAPES:"
echo "1. Attendre 2-3 minutes pour stabilisation"
echo "2. Générer des logs de test sur VM Honeypot"
echo "3. Vérifier l'ingestion: /opt/monitor_logstash_elk.sh"
echo "4. Surveiller: journalctl -u logstash -f"
echo ""
print_status "Logstash configuré - Prêt à recevoir les données des honeypots !"