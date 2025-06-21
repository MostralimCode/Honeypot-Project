#!/bin/bash
# Déploiement de Logstash en production après validation

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
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

print_status "=== Déploiement Logstash en production ==="

# 1. VÉRIFICATION FINALE
print_status "1. Vérification finale avant déploiement..."

# Vérifier qu'Elasticsearch fonctionne
if ! curl -s "http://192.168.2.124:9200/" >/dev/null; then
    print_error "Elasticsearch non accessible"
    exit 1
fi

# Vérifier qu'aucun Logstash n'est en cours
if systemctl is-active --quiet logstash; then
    print_warning "Logstash déjà actif, arrêt..."
    systemctl stop logstash
    sleep 5
fi

print_status "✓ Vérifications OK"

# 2. CONFIGURATION FINALE AVEC PIPELINES HONEYPOT
print_status "2. Déploiement des pipelines honeypot..."

# Supprimer le pipeline de test
rm -f /etc/logstash/conf.d/00-test-minimal.conf

# Pipeline 1: Input Beats (OBLIGATOIRE pour recevoir Filebeat)
cat > /etc/logstash/conf.d/00-beats-input.conf << 'EOF'
# Input Beats pour recevoir les données de Filebeat depuis les honeypots
input {
  beats {
    port => 5044
    type => "beats"
    host => "192.168.2.124"
  }
}
EOF

# Pipeline 2: Cowrie SSH Honeypot (simplifié)
cat > /etc/logstash/conf.d/10-cowrie.conf << 'EOF'
# Pipeline Cowrie SSH Honeypot
filter {
  if [honeypot_type] == "ssh" {
    mutate {
      add_field => { "service" => "cowrie" }
      add_field => { "infrastructure" => "honeypot" }
    }
    
    # Parse timestamp si présent
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
      }
    }
    
    # Classification événements SSH
    if [eventid] == "cowrie.login.success" {
      mutate { 
        add_field => { "event_category" => "authentication_success" }
        add_field => { "severity" => "high" }
      }
    }
    
    if [eventid] == "cowrie.login.failed" {
      mutate { 
        add_field => { "event_category" => "authentication_failure" }
        add_field => { "severity" => "medium" }
      }
    }
    
    if [eventid] == "cowrie.command.input" {
      mutate { 
        add_field => { "event_category" => "command_execution" }
        add_field => { "severity" => "medium" }
      }
    }
  }
}

output {
  if [honeypot_type] == "ssh" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# Pipeline 3: HTTP Honeypot (simplifié)
cat > /etc/logstash/conf.d/20-http.conf << 'EOF'
# Pipeline HTTP Honeypot
filter {
  if [honeypot_type] == "http" {
    mutate {
      add_field => { "service" => "http_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
    
    # Parse timestamp
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
      }
    }
    
    # Classification attaques HTTP
    if [attack_type] == "sql_injection" {
      mutate { 
        add_field => { "event_category" => "sql_injection" }
        add_field => { "severity" => "high" }
      }
    }
    
    if [attack_type] == "xss" {
      mutate { 
        add_field => { "event_category" => "cross_site_scripting" }
        add_field => { "severity" => "medium" }
      }
    }
    
    if [attack_type] == "path_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
      }
    }
  }
}

output {
  if [honeypot_type] == "http" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# Pipeline 4: FTP Honeypot (simplifié)
cat > /etc/logstash/conf.d/30-ftp.conf << 'EOF'
# Pipeline FTP Honeypot
filter {
  if [honeypot_type] == "ftp" {
    mutate {
      add_field => { "service" => "ftp_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
    
    # Parse timestamp
    if [timestamp] {
      date {
        match => [ "timestamp", "ISO8601" ]
      }
    }
    
    # Classification événements FTP
    if [event_type] == "auth_attempt" {
      if [success] == true {
        mutate { 
          add_field => { "event_category" => "authentication_success" }
          add_field => { "severity" => "high" }
        }
      } else {
        mutate { 
          add_field => { "event_category" => "authentication_failure" }
          add_field => { "severity" => "medium" }
        }
      }
    }
  }
}

output {
  if [honeypot_type] == "ftp" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# Pipeline 5: Serveurs sécurisés (simplifié)
cat > /etc/logstash/conf.d/40-secure.conf << 'EOF'
# Pipeline serveurs sécurisés
filter {
  if [honeypot_type] == "system" {
    mutate {
      add_field => { "infrastructure" => "secure_server" }
    }
    
    # Parse syslog simple
    if [message] {
      grok {
        match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{IPORHOST:host} %{PROG:program}(?:\[%{POSINT:pid}\])?: %{GREEDYDATA:log_message}" }
      }
    }
  }
}

output {
  if [honeypot_type] == "system" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "secure-servers-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# Output par défaut pour tous les autres logs
cat > /etc/logstash/conf.d/99-default.conf << 'EOF'
# Output par défaut pour logs non classifiés
output {
  if ![honeypot_type] {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "logstash-misc-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# Permissions
chown -R logstash:logstash /etc/logstash/conf.d/
chmod 644 /etc/logstash/conf.d/*.conf

print_status "✓ Pipelines honeypot déployés"

# 3. TEST FINAL DE CONFIGURATION
print_status "3. Test final de configuration..."

if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✓ Configuration finale validée"
else
    print_error "✗ Erreur dans la configuration finale"
    exit 1
fi

# 4. DÉMARRAGE PRODUCTION
print_status "4. Démarrage en mode production..."

# Démarrer le service
systemctl start logstash

# Attendre le démarrage
print_info "Attente du démarrage (60 secondes max)..."
counter=0
while [ $counter -lt 60 ]; do
    if systemctl is-active --quiet logstash; then
        print_status "✓ Service Logstash actif"
        break
    fi
    if [ $((counter % 10)) -eq 0 ]; then
        echo "Attente... ${counter}s"
    fi
    sleep 2
    counter=$((counter + 2))
done

# 5. VÉRIFICATIONS POST-DÉMARRAGE
print_status "5. Vérifications post-démarrage..."

# Statut du service
STATUS=$(systemctl is-active logstash)
echo "Service status: $STATUS"

if [ "$STATUS" = "active" ]; then
    print_status "✓ Logstash en cours d'exécution"
    
    # Test API Logstash
    print_info "Test de l'API Logstash..."
    sleep 10  # Laisser le temps à l'API de se lancer
    
    api_counter=0
    while [ $api_counter -lt 30 ]; do
        if curl -s "http://192.168.2.124:9600/" >/dev/null 2>&1; then
            print_status "✓ API Logstash accessible"
            break
        fi
        sleep 2
        api_counter=$((api_counter + 2))
        if [ $((api_counter % 10)) -eq 0 ]; then
            echo "Test API... ${api_counter}s"
        fi
    done
    
    # Test port Beats
    print_info "Test du port Beats..."
    if netstat -tlnp | grep -q ":5044 "; then
        print_status "✓ Port 5044 (Beats) en écoute"
    else
        print_warning "⚠ Port 5044 pas encore en écoute (normal au démarrage)"
    fi
    
    # Afficher info API
    echo ""
    print_info "Informations Logstash:"
    curl -s "http://192.168.2.124:9600/" | jq . 2>/dev/null || echo "API pas encore prête"
    
else
    print_error "✗ Logstash ne démarre pas"
    print_error "Logs d'erreur:"
    journalctl -u logstash --no-pager -n 10
    exit 1
fi

# 6. GÉNÉRATION DES DONNÉES DE TEST
print_status "6. Génération de données de test..."

# Créer des répertoires de logs test si nécessaires
mkdir -p /home/cowrie/cowrie/var/log/cowrie
mkdir -p /var/log/honeypot
mkdir -p /root/honeypot-ftp/logs

# Données de test Cowrie
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","eventid":"cowrie.login.failed","src_ip":"203.0.113.100","username":"admin","password":"123456","protocol":"ssh","honeypot_type":"ssh"}' > /home/cowrie/cowrie/var/log/cowrie/test.json

# Données de test HTTP
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","ip":"203.0.113.101","attack_type":"sql_injection","honeypot_type":"http"}' > /var/log/honeypot/test.log

# Données de test FTP
echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","event_type":"auth_attempt","success":false,"honeypot_type":"ftp"}' > /root/honeypot-ftp/logs/test.json

print_status "✓ Données de test créées"

# 7. SCRIPT DE MONITORING
cat > /opt/elk-scripts/monitor_logstash_production.sh << 'EOF'
#!/bin/bash
echo "=== Logstash Production Monitor ==="

echo "1. Service Status:"
echo "   Status: $(systemctl is-active logstash)"
echo "   Uptime: $(systemctl show logstash --property=ActiveEnterTimestamp --value)"

echo ""
echo "2. Ports:"
netstat -tlnp | grep -E "(9600|5044)" || echo "   Aucun port Logstash"

echo ""
echo "3. API Status:"
curl -s "http://192.168.2.124:9600/" | jq .status 2>/dev/null || echo "   API non accessible"

echo ""
echo "4. Pipelines:"
curl -s "http://192.168.2.124:9600/_node/pipelines" | jq keys 2>/dev/null || echo "   Pas de pipelines"

echo ""
echo "5. Stats événements:"
curl -s "http://192.168.2.124:9600/_node/stats/pipelines" | jq '.pipelines.main.events' 2>/dev/null || echo "   Stats non disponibles"

echo ""
echo "6. Derniers logs:"
journalctl -u logstash --no-pager -n 3

echo ""
echo "7. Indices Elasticsearch créés:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v" 2>/dev/null || echo "   Pas encore d'indices honeypot"
EOF

chmod +x /opt/elk-scripts/monitor_logstash_production.sh

print_status "=== Déploiement terminé avec succès! ==="
echo ""
print_info "🎯 LOGSTASH EN PRODUCTION:"
echo "   Service: $(systemctl is-active logstash)"
echo "   API: http://192.168.2.124:9600"
echo "   Port Beats: 5044"
echo ""
print_info "📊 PIPELINES ACTIFS:"
echo "   ✓ Input Beats (port 5044)"
echo "   ✓ Cowrie SSH → honeypot-cowrie-*"
echo "   ✓ HTTP Honeypot → honeypot-http-*"
echo "   ✓ FTP Honeypot → honeypot-ftp-*"
echo "   ✓ Serveurs sécurisés → secure-servers-*"
echo ""
print_info "🔧 MONITORING:"
echo "   Script: /opt/elk-scripts/monitor_logstash_production.sh"
echo "   Logs: journalctl -u logstash -f"
echo "   API: curl http://192.168.2.124:9600/"
echo ""
print_warning "📋 PROCHAINES ÉTAPES:"
echo "1. Configurer Filebeat sur les honeypots pour envoyer vers ce Logstash"
echo "2. Installer et configurer Kibana"
echo "3. Surveiller l'ingestion: /opt/elk-scripts/monitor_logstash_production.sh"
echo ""
print_status "🚀 ELK Stack prêt pour recevoir les données des honeypots!"