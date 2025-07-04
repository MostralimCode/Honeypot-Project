#!/bin/bash
# Développement des pipelines Logstash pour chaque type de log - Étape 5.5
# À exécuter sur la VM ELK (192.168.2.124)

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

# Vérifier que nous sommes sur la bonne VM
VM_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
if [ "$VM_IP" != "192.168.2.124" ]; then
    print_error "Ce script doit être exécuté sur la VM ELK (192.168.2.124)"
    exit 1
fi

print_status "=== Développement des pipelines Logstash - Étape 5.5 ==="
echo ""

# ================================
# VÉRIFICATIONS PRÉLIMINAIRES
# ================================

print_status "Vérifications préliminaires..."

# Vérifier Elasticsearch
if ! curl -s "http://192.168.2.124:9200/_cluster/health" | grep -q "yellow\|green"; then
    print_error "Elasticsearch non accessible"
    exit 1
fi

# Arrêter Logstash pour configuration
systemctl stop logstash
sleep 5

print_status "✅ Prêt pour la configuration des pipelines"

# ================================
# SAUVEGARDE DES CONFIGURATIONS EXISTANTES
# ================================

print_status "Sauvegarde des configurations existantes..."

BACKUP_DIR="/opt/elk-backups/logstash-$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

if [ -d "/etc/logstash/conf.d" ]; then
    cp -r /etc/logstash/conf.d/* "$BACKUP_DIR/" 2>/dev/null || true
    print_info "Backup créé: $BACKUP_DIR"
fi

# Nettoyer les anciennes configurations
rm -f /etc/logstash/conf.d/*.conf

# ================================
# PIPELINE 1: INPUT - RÉCEPTION DES DONNÉES
# ================================

print_status "Configuration du pipeline d'entrée..."

cat > /etc/logstash/conf.d/00-input.conf << 'EOF'
# Pipeline d'entrée pour les honeypots
# Reçoit les données de Filebeat et TCP direct

input {
  # Filebeat depuis les honeypots (port standard)
  beats {
    port => 5044
    host => "0.0.0.0"
    type => "beats"
  }
  
  # TCP direct pour tests et envois manuels
  tcp {
    port => 5046
    host => "0.0.0.0"
    codec => json_lines
    type => "tcp_direct"
  }
}
EOF

# ================================
# PIPELINE 2: FILTRES COWRIE SSH
# ================================

print_status "Configuration du pipeline Cowrie SSH..."

cat > /etc/logstash/conf.d/10-cowrie-filter.conf << 'EOF'
# Pipeline de traitement pour Cowrie SSH Honeypot
# Détection basée sur la présence du champ 'eventid' avec pattern cowrie.*

filter {
  # Détection des logs Cowrie (eventid commence par "cowrie.")
  if [eventid] =~ /^cowrie\./ {
    
    # Marquer comme honeypot SSH
    mutate {
      add_field => { 
        "honeypot_type" => "ssh"
        "service" => "cowrie"
        "infrastructure" => "honeypot"
      }
    }
    
    # Parse du timestamp Cowrie si présent
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601", "yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'" ]
        target => "@timestamp"
      }
    }
    
    # Normalisation de l'IP source
    if [src_ip] {
      mutate { 
        add_field => { "client_ip" => "%{src_ip}" }
        add_field => { "source_ip" => "%{src_ip}" }
      }
    }
    
    # Classification des événements SSH par criticité
    if [eventid] == "cowrie.login.success" {
      mutate { 
        add_field => { 
          "alert_level" => "high"
          "severity" => "high"
          "attack_success" => "true"
          "event_category" => "authentication"
        }
      }
    }
    
    if [eventid] == "cowrie.login.failed" {
      mutate { 
        add_field => { 
          "alert_level" => "medium"
          "severity" => "medium" 
          "attack_success" => "false"
          "event_category" => "authentication"
        }
      }
    }
    
    if [eventid] == "cowrie.command.input" {
      mutate { 
        add_field => { 
          "alert_level" => "high"
          "severity" => "high"
          "event_category" => "command_execution"
        }
      }
      
      # Détection de commandes suspectes
      if [input] =~ /(?i)(wget|curl|nc|netcat|nmap|masscan)/ {
        mutate { 
          add_field => { 
            "suspicious_command" => "true"
            "command_type" => "network_tool"
            "alert_level" => "critical"
          }
        }
      }
      
      if [input] =~ /(?i)(rm -rf|dd if=|mkfs|fdisk)/ {
        mutate { 
          add_field => { 
            "suspicious_command" => "true"
            "command_type" => "destructive"
            "alert_level" => "critical"
          }
        }
      }
      
      if [input] =~ /(?i)(cat /etc/passwd|cat /etc/shadow|ls /root)/ {
        mutate { 
          add_field => { 
            "suspicious_command" => "true"
            "command_type" => "reconnaissance"
            "alert_level" => "high"
          }
        }
      }
    }
    
    if [eventid] == "cowrie.session.connect" {
      mutate { 
        add_field => { 
          "alert_level" => "info"
          "severity" => "info"
          "event_category" => "connection"
        }
      }
    }
    
    if [eventid] == "cowrie.session.file_download" {
      mutate { 
        add_field => { 
          "alert_level" => "high"
          "severity" => "high"
          "event_category" => "file_transfer"
          "suspicious_activity" => "true"
        }
      }
    }
    
    # Enrichissement géographique IP
    if [client_ip] {
      geoip {
        source => "client_ip"
        target => "geoip"
        add_field => { "geo_enabled" => "true" }
      }
    }
    
    # Ajout de métadonnées temporelles
    mutate {
      add_field => { 
        "processed_at" => "%{@timestamp}"
        "log_source" => "cowrie_honeypot"
      }
    }
  }
}
EOF

# ================================
# PIPELINE 3: FILTRES HTTP HONEYPOT
# ================================

print_status "Configuration du pipeline HTTP Honeypot..."

cat > /etc/logstash/conf.d/20-http-filter.conf << 'EOF'
# Pipeline de traitement pour HTTP Honeypot
# Détection basée sur la présence des champs 'attack_type' et 'attack_id'

filter {
  # Détection des logs HTTP Honeypot
  if [attack_type] and ([attack_id] or [honeypot_type] == "http") {
    
    # Marquer comme honeypot HTTP
    mutate {
      add_field => { 
        "honeypot_type" => "http"
        "service" => "http_honeypot"
        "infrastructure" => "honeypot"
      }
    }
    
    # Normalisation de l'IP source
    if [ip] {
      mutate { 
        add_field => { "client_ip" => "%{ip}" }
        add_field => { "source_ip" => "%{ip}" }
      }
    }
    
    # Classification des attaques HTTP par type et sévérité
    if [attack_type] == "sql_injection" {
      mutate { 
        add_field => { 
          "alert_level" => "high"
          "severity" => "high"
          "attack_category" => "injection"
          "owasp_category" => "A03_injection"
        }
      }
    }
    
    if [attack_type] == "xss" {
      mutate { 
        add_field => { 
          "alert_level" => "medium"
          "severity" => "medium"
          "attack_category" => "injection"
          "owasp_category" => "A07_xss"
        }
      }
    }
    
    if [attack_type] == "path_traversal" {
      mutate { 
        add_field => { 
          "alert_level" =>