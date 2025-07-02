#!/bin/bash
# SOLUTION DE CONTOURNEMENT D'URGENCE
# Objectif: Avoir les logs Cowrie/HTTP/FTP dans Kibana MAINTENANT

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }

if [ "$EUID" -ne 0 ]; then
    echo "Ce script doit être exécuté en tant que root"
    exit 1
fi

echo ""
print_status "=== SOLUTION CONTOURNEMENT D'URGENCE ==="
print_warning "Les erreurs JSON vont rester mais les données vont passer !"
echo ""

# 1. ARRÊTER LOGSTASH
systemctl stop logstash
sleep 3

# 2. BACKUP ACTUEL
cp /etc/logstash/conf.d/*.conf /tmp/ 2>/dev/null

# 3. CRÉER CONFIG SIMPLIFIÉE QUI MARCHE
print_status "Création de la config simplifiée d'urgence..."

cat > /etc/logstash/conf.d/00-emergency-honeypot.conf << 'EOF'
# CONFIG D'URGENCE - IGNORE LES ERREURS JSON MAIS TRAITE LES DONNÉES

input {
  tcp {
    port => 5046
    host => "0.0.0.0"
    codec => json_lines
    type => "honeypot_tcp"
  }
}

filter {
  # Supprimer les tags d'erreur pour éviter les échecs
  if [tags] {
    mutate {
      remove_tag => ["_jsonparsefailure"]
    }
  }

  # DÉTECTION COWRIE SSH
  if [eventid] =~ /^cowrie\./ {
    mutate {
      add_field => { "honeypot_type" => "ssh" }
      add_field => { "service" => "cowrie" }
    }
    
    if [src_ip] {
      mutate { add_field => { "client_ip" => "%{src_ip}" } }
    }
    
    # Classification simple
    if [eventid] == "cowrie.login.success" {
      mutate { add_field => { "alert_level" => "HIGH" } }
    }
    if [eventid] == "cowrie.command.input" {
      mutate { add_field => { "alert_level" => "MEDIUM" } }
    }
  }

  # DÉTECTION HTTP
  else if [attack_id] and [attack_type] {
    mutate {
      add_field => { "honeypot_type" => "http" }
      add_field => { "service" => "http_honeypot" }
    }
    
    if [ip] {
      mutate { add_field => { "client_ip" => "%{ip}" } }
    }
    
    # Classification simple
    if [attack_type] == "sql_injection" {
      mutate { add_field => { "alert_level" => "HIGH" } }
    }
  }

  # DÉTECTION FTP (garde existant)
  else if [honeypot_type] == "ftp" {
    mutate {
      add_field => { "service" => "ftp_honeypot" }
    }
    
    if [ip] {
      mutate { add_field => { "client_ip" => "%{ip}" } }
    }
  }

  # Ajouter timestamp si manquant
  if ![honeypot_type] {
    mutate {
      add_field => { "honeypot_type" => "unknown" }
    }
  }
}

output {
  # Tout dans un seul indice pour simplicité
  elasticsearch {
    hosts => ["192.168.2.124:9200"]
    index => "honeypot-all-%{+YYYY.MM.dd}"
  }
  
  # Debug - voir ce qui passe
  stdout {
    codec => rubydebug {
      metadata => false
    }
  }
}
EOF

# 4. SUPPRIMER AUTRES CONFIGS
rm -f /etc/logstash/conf.d/00-honeypot-*.conf 2>/dev/null

# 5. PERMISSIONS
chown logstash:logstash /etc/logstash/conf.d/00-emergency-honeypot.conf
chmod 644 /etc/logstash/conf.d/00-emergency-honeypot.conf

# 6. DÉMARRER IMMÉDIATEMENT
print_status "Démarrage Logstash en mode urgence..."
systemctl start logstash

# 7. ATTENDRE ET VÉRIFIER
sleep 15

if systemctl is-active --quiet logstash; then
    print_status "✅ Logstash redémarré"
    
    # Test immédiat
    print_status "Test d'envoi immédiat..."
    
    # Test Cowrie
    echo '{"eventid":"cowrie.session.connect","src_ip":"192.168.1.100","timestamp":"2025-07-02T10:00:00Z"}' | nc -w 2 localhost 5046
    
    # Test HTTP
    echo '{"attack_id":"test001","attack_type":"sql_injection","ip":"192.168.1.101","timestamp":"2025-07-02T10:00:00Z"}' | nc -w 2 localhost 5046
    
    # Test FTP
    echo '{"honeypot_type":"ftp","ip":"192.168.1.102","timestamp":"2025-07-02T10:00:00Z"}' | nc -w 2 localhost 5046
    
    sleep 5
    
    # Vérifier l'indice
    COUNT=$(curl -s "http://192.168.2.124:9200/honeypot-all-*/_count" 2>/dev/null | jq -r '.count // 0')
    
    if [ "$COUNT" -gt 0 ]; then
        print_status "🎉 SUCCÈS ! $COUNT documents indexés"
        print_status "👉 Allez dans Kibana créer l'index pattern: honeypot-all-*"
    else
        print_warning "Pas encore de données, mais la config est active"
    fi
    
else
    echo "❌ Problème démarrage"
    journalctl -u logstash --no-pager -n 5
fi

echo ""
print_status "=== CONTOURNEMENT APPLIQUÉ ==="
print_warning "📋 ACTIONS POUR KIBANA :"
echo "1. Aller dans Kibana > Stack Management > Index Patterns"
echo "2. Créer pattern: honeypot-all-*"
echo "3. Timestamp field: @timestamp"
echo "4. Créer des visualisations avec:"
echo "   - honeypot_type (ssh/http/ftp)"
echo "   - client_ip"
echo "   - alert_level"
echo "   - eventid (pour Cowrie)"
echo "   - attack_type (pour HTTP)"
echo ""
print_warning "⚠️ Les erreurs JSON vont persister dans les logs Logstash"
print_warning "⚠️ Mais vos données vont arriver dans Kibana !"
echo ""
print_status "🚀 SOLUTION TEMPORAIRE ACTIVE - PROJET PEUT CONTINUER !"
echo "📊 Redémarrez votre sender: systemctl restart honeypot-sender"