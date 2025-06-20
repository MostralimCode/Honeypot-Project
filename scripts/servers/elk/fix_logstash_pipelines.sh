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
systemctl stop logstash 2>/dev/null || true
sleep 3

# Supprimer tous les pipelines défaillants
print_status "Suppression des pipelines avec erreurs..."
rm -f /etc/logstash/conf.d/*.conf

# ================================
# PIPELINE 0: INPUT BEATS (OBLIGATOIRE ET CORRECT)
# ================================

print_status "Création de l'input Beats corrigé..."
cat > /etc/logstash/conf.d/00-beats-input.conf << 'EOF'
input {
  beats {
    port => 5044
    host => "192.168.2.124"
  }
}
EOF

# ================================
# PIPELINE 1: COWRIE SSH (SYNTAXE CORRIGÉE)
# ================================

print_status "Création du pipeline Cowrie SSH corrigé..."
cat > /etc/logstash/conf.d/10-cowrie.conf << 'EOF'
filter {
  if [honeypot_type] == "ssh" {
    # Ajouter métadonnées
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
    
    # GeoIP enrichissement
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification des événements
    if [eventid] == "cowrie.login.success" {
      mutate { 
        add_field => { "event_category" => "authentication_success" }
        add_field => { "severity" => "critical" }
        add_field => { "alert_level" => "4" }
      }
    } else if [eventid] == "cowrie.login.failed" {
      mutate { 
        add_field => { "event_category" => "authentication_failure" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
      }
    } else if [eventid] == "cowrie.command.input" {
      mutate { 
        add_field => { "event_category" => "command_execution" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
      
      # Détection commandes suspectes
      if [input] =~ /(?i)(wget|curl|nc|netcat)/ {
        mutate { 
          add_field => { "suspicious_command" => "true" }
          add_field => { "command_type" => "network_tool" }
        }
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

# ================================
# PIPELINE 2: HTTP HONEYPOT (SYNTAXE CORRIGÉE)
# ================================

print_status "Création du pipeline HTTP corrigé..."
cat > /etc/logstash/conf.d/20-http.conf << 'EOF'
filter {
  if [honeypot_type] == "http" {
    # Ajouter métadonnées
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
    
    # Normalisation IP
    if [ip] and ![src_ip] {
      mutate {
        add_field => { "src_ip" => "%{ip}" }
      }
    }
    
    # GeoIP enrichissement
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification attaques HTTP
    if [attack_type] == "sql_injection" {
      mutate { 
        add_field => { "event_category" => "sql_injection" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    } else if [attack_type] == "xss" {
      mutate { 
        add_field => { "event_category" => "cross_site_scripting" }
        add_field => { "severity" => "medium" }
        add_field => { "alert_level" => "2" }
      }
    } else if [attack_type] == "path_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    }
    
    # Détection User-Agent suspects
    if [user_agent] =~ /(?i)(sqlmap|nikto|nmap|burp)/ {
      mutate {
        add_field => { "scanner_detected" => "true" }
        add_field => { "tool_detected" => "security_scanner" }
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

# ================================
# PIPELINE 3: FTP HONEYPOT (SYNTAXE CORRIGÉE - C'ÉTAIT LÀ LE PROBLÈME)
# ================================

print_status "Création du pipeline FTP corrigé..."
cat > /etc/logstash/conf.d/30-ftp.conf << 'EOF'
filter {
  if [honeypot_type] == "ftp" {
    # Ajouter métadonnées
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
    
    # Normalisation IP
    if [ip] and ![src_ip] {
      mutate {
        add_field => { "src_ip" => "%{ip}" }
      }
    }
    
    # GeoIP enrichissement
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
        add_field => { "src_city" => "%{[geoip][city_name]}" }
      }
    }
    
    # Classification événements FTP
    if [event_type] == "auth_attempt" {
      if [success] == true {
        mutate { 
          add_field => { "event_category" => "authentication_success" }
          add_field => { "severity" => "critical" }
          add_field => { "alert_level" => "4" }
        }
      } else {
        mutate { 
          add_field => { "event_category" => "authentication_failure" }
          add_field => { "severity" => "medium" }
          add_field => { "alert_level" => "2" }
        }
      }
    } else if [event_type] == "file_upload" {
      mutate { 
        add_field => { "event_category" => "file_upload" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    } else if [event_type] == "directory_traversal" {
      mutate { 
        add_field => { "event_category" => "directory_traversal" }
        add_field => { "severity" => "high" }
        add_field => { "alert_level" => "3" }
      }
    }
    
    # Détection fichiers suspects
    if [filename] =~ /(?i)(\.php|\.asp|\.exe|backdoor|shell)/ {
      mutate {
        add_field => { "suspicious_file" => "true" }
        add_field => { "malicious_file" => "true" }
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

# ================================
# PIPELINE 4: SERVEURS SÉCURISÉS (SYNTAXE CORRIGÉE)
# ================================

print_status "Création du pipeline serveurs sécurisés corrigé..."
cat > /etc/logstash/conf.d/40-secure.conf << 'EOF'
filter {
  if [honeypot_type] == "system" or [infrastructure] == "secure_server" {
    # Ajouter métadonnées
    mutate {
      add_field => { "infrastructure" => "secure_server" }
      add_field => { "service" => "system" }
    }
    
    # Parse syslog simple
    if [message] {
      grok {
        match => { "message" => "%{SYSLOGTIMESTAMP:syslog_timestamp} %{IPORHOST:host} %{PROG:program}(?:\\[%{POSINT:pid}\\])?: %{GREEDYDATA:log_message}" }
      }
    }
    
    # Classification événements système
    if [program] == "sshd" {
      if [log_message] =~ /Failed password/ {
        mutate {
          add_field => { "event_category" => "authentication_failure" }
          add_field => { "severity" => "medium" }
          add_field => { "service_type" => "ssh" }
        }
        
        # Extraire l'IP
        grok {
          match => { "log_message" => "Failed password for %{USERNAME:username} from %{IPORHOST:src_ip}" }
        }
      } else if [log_message] =~ /Accepted password/ {
        mutate {
          add_field => { "event_category" => "authentication_success" }
          add_field => { "severity" => "low" }
          add_field => { "service_type" => "ssh" }
        }
      }
    }
    
    # GeoIP sur IP extraite
    if [src_ip] {
      geoip {
        source => "src_ip"
        target => "geoip"
        add_field => { "src_country" => "%{[geoip][country_name]}" }
      }
    }
  }
}

output {
  if [infrastructure] == "secure_server" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "secure-servers-%{+YYYY.MM.dd}"
    }
  }
}
EOF

# ================================
# VALIDATION DE LA SYNTAXE
# ================================

print_status "Validation de la syntaxe des pipelines corrigés..."

# Test de configuration avec timeout
timeout 30 sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t

if [ $? -eq 0 ]; then
    print_status "✅ Configuration des pipelines validée avec succès"
else
    print_error "❌ Erreur de syntaxe détectée"
    print_error "Vérification ligne par ligne..."
    
    # Tester chaque fichier individuellement
    for conf_file in /etc/logstash/conf.d/*.conf; do
        echo "Test de: $(basename $conf_file)"
        
        # Créer un répertoire temporaire pour test isolé
        TEST_DIR="/tmp/logstash-test"
        mkdir -p "$TEST_DIR"
        cp "$conf_file" "$TEST_DIR/"
        
        # Test isolé
        if timeout 10 sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash --path.config "$TEST_DIR" -t 2>/dev/null; then
            echo "  ✓ $(basename $conf_file) - OK"
        else
            echo "  ✗ $(basename $conf_file) - ERREUR"
            print_error "Fichier problématique: $conf_file"
        fi
        
        rm -rf "$TEST_DIR"
    done
    
    exit 1
fi

# ================================
# PERMISSIONS ET FINALISATION
# ================================

print_status "Configuration des permissions..."

# Permissions correctes
chown -R logstash:logstash /var/lib/logstash
chmod 755 /etc/logstash/conf.d
chmod 644 /etc/logstash/conf.d/*.conf

# ================================
# SCRIPT DE MONITORING SIMPLE
# ================================

print_status "Création du script de monitoring..."

cat > /opt/elk-scripts/check_logstash.sh << 'EOF'
#!/bin/bash
echo "=== Check Logstash Simple ==="

echo "1. Service Status:"
echo "   Logstash: $(systemctl is-active logstash)"

echo ""
echo "2. Configuration Files:"
ls -la /etc/logstash/conf.d/

echo ""
echo "3. Syntax Test:"
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t 2>/dev/null; then
    echo "   ✓ Configuration valide"
else
    echo "   ✗ Erreur de configuration"
fi

echo ""
echo "4. Logstash API (si démarré):"
curl -s "http://192.168.2.124:9600/" 2>/dev/null | jq .status || echo "   API non accessible"

echo ""
echo "5. Ports:"
netstat -tlnp | grep -E "(9600|5044)" || echo "   Aucun port Logstash ouvert"

echo ""
echo "6. Derniers logs:"
journalctl -u logstash --no-pager -n 3 2>/dev/null || echo "   Pas de logs récents"
EOF

chmod +x /opt/elk-scripts/check_logstash.sh

# ================================
# SCRIPT DE DÉMARRAGE SÉCURISÉ
# ================================

cat > /opt/elk-scripts/start_logstash_safe.sh << 'EOF'
#!/bin/bash
echo "=== Démarrage sécurisé Logstash ==="

# 1. Vérifier Elasticsearch
echo "1. Test Elasticsearch..."
if curl -s http://192.168.2.124:9200 >/dev/null; then
    echo "   ✓ Elasticsearch accessible"
else
    echo "   ✗ Elasticsearch non accessible"
    exit 1
fi

# 2. Test configuration
echo "2. Test configuration..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    echo "   ✓ Configuration valide"
else
    echo "   ✗ Configuration invalide"
    exit 1
fi

# 3. Démarrer Logstash
echo "3. Démarrage Logstash..."
systemctl start logstash

# 4. Attendre et vérifier
echo "4. Vérification du démarrage..."
sleep 15

if systemctl is-active logstash >/dev/null; then
    echo "   ✓ Logstash démarré avec succès"
    echo ""
    echo "Informations:"
    echo "   API: http://192.168.2.124:9600"
    echo "   Logs: journalctl -u logstash -f"
    echo "   Check: /opt/elk-scripts/check_logstash.sh"
else
    echo "   ✗ Échec du démarrage"
    echo ""
    echo "Logs d'erreur:"
    journalctl -u logstash --no-pager -n 10
fi
EOF

chmod +x /opt/elk-scripts/start_logstash_safe.sh

print_status "=== Correction terminée avec succès! ==="
echo ""
print_status "🎯 PIPELINES CORRIGÉS:"
echo "   ✓ 00-beats-input.conf (Input Beats port 5044)"
echo "   ✓ 10-cowrie.conf (SSH Honeypot)"
echo "   ✓ 20-http.conf (HTTP Honeypot)"
echo "   ✓ 30-ftp.conf (FTP Honeypot)"
echo "   ✓ 40-secure.conf (Serveurs sécurisés)"
echo ""
print_status "🔧 SCRIPTS DISPONIBLES:"
echo "   • /opt/elk-scripts/check_logstash.sh (vérification)"
echo "   • /opt/elk-scripts/start_logstash_safe.sh (démarrage sécurisé)"
echo ""
print_warning "📋 PROCHAINES ÉTAPES:"
echo "1. Démarrer Logstash: /opt/elk-scripts/start_logstash_safe.sh"
echo "2. Vérifier le statut: /opt/elk-scripts/check_logstash.sh"
echo "3. Surveiller les logs: journalctl -u logstash -f"
echo ""
print_status "Configuration garantie sans erreur de syntaxe!"

# Créer un statut final
cat > /opt/elk-setup-status-fixed.txt << EOF
=== Logstash Pipelines - Configuration Corrigée ===
Date: $(date)

✅ CORRECTION EFFECTUÉE:
- Suppression de tous les anciens pipelines
- Recréation avec syntaxe validée
- Test de configuration réussi

✅ PIPELINES FONCTIONNELS:
- Input Beats: /etc/logstash/conf.d/00-beats-input.conf
- Cowrie SSH: /etc/logstash/conf.d/10-cowrie.conf
- HTTP Honeypot: /etc/logstash/conf.d/20-http.conf
- FTP Honeypot: /etc/logstash/conf.d/30-ftp.conf
- Serveurs sécurisés: /etc/logstash/conf.d/40-secure.conf

✅ VALIDATION:
- Syntaxe: ✓ VALIDÉE
- Permissions: ✓ CORRECTES
- Scripts: ✓ CRÉÉS

🚀 PRÊT POUR DÉMARRAGE
Commande: /opt/elk-scripts/start_logstash_safe.sh
EOF

echo "$(date): Pipelines Logstash corrigés avec succès" >> /var/log/elk-setup/install.log