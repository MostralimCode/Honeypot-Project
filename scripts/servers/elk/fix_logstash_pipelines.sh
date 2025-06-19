#!/bin/bash
# Correction des erreurs de syntaxe dans les pipelines Logstash

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
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

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

print_status "=== Correction des erreurs de syntaxe Logstash ==="

# Arrêter Logstash
systemctl stop logstash 2>/dev/null

# Supprimer tous les pipelines défaillants
print_status "Suppression des pipelines avec erreurs..."
rm -f /etc/logstash/conf.d/*.conf

# PIPELINE 1: INPUT BEATS (OBLIGATOIRE)
print_status "Création de l'input Beats corrigé..."
cat > /etc/logstash/conf.d/00-beats-input.conf << 'EOF'
input {
  beats {
    port => 5044
    host => "192.168.2.124"
  }
}
EOF

# PIPELINE 2: COWRIE (SYNTAXE CORRIGÉE)
print_status "Création du pipeline Cowrie corrigé..."
cat > /etc/logstash/conf.d/10-cowrie.conf << 'EOF'
filter {
  if [honeypot_type] == "ssh" {
    mutate {
      add_field => { "service" => "cowrie" }
      add_field => { "infrastructure" => "honeypot" }
    }
    
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

# PIPELINE 3: HTTP (SYNTAXE CORRIGÉE)
print_status "Création du pipeline HTTP corrigé..."
cat > /etc/logstash/conf.d/20-http.conf << 'EOF'
filter {
  if [honeypot_type] == "http" {
    mutate {
      add_field => { "service" => "http_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
    
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

# PIPELINE 4: FTP (SYNTAXE CORRIGÉE - C'ÉTAIT LÀ LE PROBLÈME)
print_status "Création du pipeline FTP corrigé..."
cat > /etc/logstash/conf.d/30-ftp.conf << 'EOF'
filter {
  if [honeypot_type] == "ftp" {
    mutate {
      add_field => { "service" => "ftp_honeypot" }
      add_field => { "infrastructure" => "honeypot" }
    }
    
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

# PIPELINE 5: SERVEURS SÉCURISÉS (SYNTAXE CORRIGÉE)
print_status "Création du pipeline serveurs sécurisés corrigé..."
cat > /etc/logstash/conf.d/40-secure.conf << 'EOF'
filter {
  if [honeypot_type] == "system" {
    mutate {
      add_field => { "infrastructure" => "secure_server" }
    }
    
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

# PIPELINE 6: OUTPUT PAR DÉFAUT
print_status "Création de l'output par défaut..."
cat > /etc/logstash/conf.d/99-default.conf << 'EOF'
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

print_status "Pipelines corrigés créés"

# TEST DE SYNTAXE
print_status "Test de syntaxe des pipelines corrigés..."

if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ SUCCÈS! Syntaxe correcte"
else
    print_error "❌ Erreur de syntaxe persistante"
    echo ""
    print_warning "Affichage des fichiers créés pour debug:"
    ls -la /etc/logstash/conf.d/
    exit 1
fi

# DÉMARRAGE
print_status "Démarrage de Logstash avec la configuration corrigée..."

systemctl start logstash

# Attendre le démarrage
counter=0
while [ $counter -lt 30 ]; do
    if systemctl is-active --quiet logstash; then
        print_status "✅ Logstash démarré avec succès"
        break
    fi
    sleep 2
    counter=$((counter + 2))
    if [ $((counter % 10)) -eq 0 ]; then
        echo "Attente... ${counter}s"
    fi
done

# Vérifications finales
print_status "Vérifications finales..."

echo "Service: $(systemctl is-active logstash)"

if systemctl is-active --quiet logstash; then
    # Test API
    sleep 10
    if curl -s "http://192.168.2.124:9600/" >/dev/null 2>&1; then
        print_status "✅ API Logstash accessible"
    else
        print_warning "⚠ API pas encore prête"
    fi
    
    # Test port Beats
    if netstat -tlnp | grep -q ":5044 "; then
        print_status "✅ Port 5044 (Beats) en écoute"
    else
        print_warning "⚠ Port 5044 pas encore ouvert"
    fi
else
    print_error "❌ Logstash ne démarre pas"
    print_error "Logs d'erreur:"
    journalctl -u logstash --no-pager -n 10
fi

print_status "=== Correction terminée ==="
echo ""
print_warning "Si Logstash fonctionne maintenant:"
echo "1. Surveillez: journalctl -u logstash -f"
echo "2. Testez API: curl http://192.168.2.124:9600/"
echo "3. Vérifiez port: netstat -tlnp | grep 5044"