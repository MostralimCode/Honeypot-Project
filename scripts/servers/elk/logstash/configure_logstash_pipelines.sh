#!/bin/bash

echo "=== CONFIGURATION LOGSTASH SIMPLE ==="
echo "Objectif: Préserver la structure JSON originale du sender"
echo ""

# 1. ARRÊTER LOGSTASH
echo "🛑 ARRÊT DE LOGSTASH..."
systemctl stop logstash
sleep 10

# 2. SAUVEGARDER LA CONFIGURATION ACTUELLE
echo "💾 SAUVEGARDE CONFIGURATION..."
BACKUP_DIR="/tmp/logstash_backup_simple_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"
cp -r /etc/logstash/conf.d/* "$BACKUP_DIR/" 2>/dev/null
echo "Sauvegarde: $BACKUP_DIR"

# 3. CONFIGURATION ULTRA-SIMPLE
echo "🔧 CRÉATION CONFIGURATION SIMPLE..."

# INPUT - Juste recevoir le JSON tel quel
cat > /etc/logstash/conf.d/00-input.conf << 'INPUT_EOF'
input {
  tcp {
    port => 5046
    mode => "server"
    codec => json {
      charset => "UTF-8"
    }
  }
}
INPUT_EOF

# FILTER - Minimal, juste pour router vers les bons indices
cat > /etc/logstash/conf.d/10-filter.conf << 'FILTER_EOF'
filter {
  # Nettoyer seulement les caractères de contrôle problématiques
  if [message] {
    mutate {
      gsub => [ "message", "[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]", "" ]
    }
  }
  
  # Normaliser le timestamp seulement si présent
  if [timestamp] {
    date {
      match => [ "timestamp", "ISO8601" ]
      target => "@timestamp"
      tag_on_failure => [ "_dateparsefailure" ]
    }
  }
  
  # Définir l'index selon honeypot_type (comme pour FTP qui fonctionne)
  if [honeypot_type] == "ssh" or [honeypot_type] == "cowrie" {
    mutate { add_field => { "[@metadata][target_index]" => "cowrie" } }
  } else if [honeypot_type] == "http" {
    mutate { add_field => { "[@metadata][target_index]" => "http" } }
  } else if [honeypot_type] == "ftp" {
    mutate { add_field => { "[@metadata][target_index]" => "ftp" } }
  } else {
    mutate { add_field => { "[@metadata][target_index]" => "unknown" } }
  }
}
FILTER_EOF

# OUTPUT - Simple comme pour FTP
cat > /etc/logstash/conf.d/90-output.conf << 'OUTPUT_EOF'
output {
  elasticsearch {
    hosts => ["192.168.2.124:9200"]
    index => "honeypot-%{[@metadata][target_index]}-%{+YYYY.MM.dd}"
  }
  
  # Debug pour voir ce qui pose problème
  stdout { 
    codec => json_lines 
  }
}
OUTPUT_EOF

# 4. SUPPRIMER TOUS LES TEMPLATES COMPLEXES
echo "🧹 NETTOYAGE TEMPLATES..."
rm -f /etc/logstash/templates/*.json 2>/dev/null
rm -rf /etc/logstash/templates 2>/dev/null

# 5. PERMISSIONS
echo "🔐 PERMISSIONS..."
chown -R logstash:logstash /etc/logstash/conf.d/
chmod 644 /etc/logstash/conf.d/*.conf

# 6. TEST DE SYNTAXE
echo "🧪 TEST SYNTAXE..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    echo "✅ Syntaxe correcte"
else
    echo "❌ Erreur syntaxe - Restauration"
    rm -f /etc/logstash/conf.d/*.conf
    cp "$BACKUP_DIR"/* /etc/logstash/conf.d/
    exit 1
fi

# 7. REDÉMARRAGE
echo "🚀 REDÉMARRAGE LOGSTASH..."
systemctl start logstash
sleep 30

# Vérification
if systemctl is-active --quiet logstash; then
    echo "✅ Logstash actif"
else
    echo "❌ Problème démarrage"
    journalctl -u logstash -n 10 --no-pager
    exit 1
fi

# 8. TEST AVEC CHAQUE TYPE DE HONEYPOT
echo "🧪 TESTS PAR TYPE..."

# Test SSH/Cowrie (comme votre sender l'envoie)
ssh_test='{
  "honeypot_type": "ssh",
  "honeypot_service": "cowrie",
  "source_vm": "192.168.2.117",
  "timestamp": "'$(date -Iseconds)'",
  "log_format": "cowrie_json",
  "test": true,
  "eventid": "cowrie.session.connect",
  "src_ip": "192.168.1.100",
  "session": "test123",
  "message": "Test SSH Cowrie"
}'

echo "Test SSH/Cowrie..."
echo "$ssh_test" | nc -w 5 192.168.2.124 5046

# Test HTTP (comme votre sender l'envoie)
http_test='{
  "honeypot_type": "http",
  "honeypot_service": "http_main",
  "source_vm": "192.168.2.117",
  "timestamp": "'$(date -Iseconds)'",
  "log_format": "http_json",
  "test": true,
  "ip": "192.168.1.101",
  "method": "GET",
  "path": "/admin",
  "attack_type": "admin_access",
  "message": "Test HTTP Honeypot"
}'

echo "Test HTTP..."
echo "$http_test" | nc -w 5 192.168.2.124 5046

# Test FTP (pour confirmer que ça marche toujours)
ftp_test='{
  "honeypot_type": "ftp",
  "honeypot_service": "ftp_auth",
  "source_vm": "192.168.2.117",
  "timestamp": "'$(date -Iseconds)'",
  "log_format": "ftp_text",
  "test": true,
  "ip": "192.168.1.102",
  "action": "login_attempt",
  "username": "admin",
  "message": "Test FTP Honeypot"
}'

echo "Test FTP..."
echo "$ftp_test" | nc -w 5 192.168.2.124 5046

# 9. ATTENDRE ET VÉRIFIER LES RÉSULTATS
echo "⏳ Attente traitement (30s)..."
sleep 30

echo ""
echo "📊 RÉSULTATS:"
echo "Indices créés:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v&s=index" 2>/dev/null || echo "Erreur requête Elasticsearch"

echo ""
echo "Comptage par type:"
for type in cowrie http ftp; do
    count=$(curl -s "http://192.168.2.124:9200/honeypot-$type-*/_count" 2>/dev/null | jq -r '.count // "0"' 2>/dev/null || echo "0")
    echo "  honeypot-$type: $count documents"
done

echo ""
echo "📋 DERNIERS DOCUMENTS:"
curl -s "http://192.168.2.124:9200/honeypot-*/_search?sort=@timestamp:desc&size=3&_source=honeypot_type,test,@timestamp" 2>/dev/null | jq -r '.hits.hits[]._source | "\(.@timestamp) - \(.honeypot_type) - test:\(.test)"' 2>/dev/null || echo "Pas de données récentes"

echo ""
echo "=== CONFIGURATION SIMPLE TERMINÉE ==="
echo ""
echo "🎯 SI LES TESTS FONCTIONNENT:"
echo "• Redémarrer honeypot-sender: systemctl restart honeypot-sender"
echo "• Surveiller: journalctl -u logstash -f"
echo ""
echo "🎯 SI PROBLÈME PERSISTE:"
echo "• Vérifier logs: journalctl -u logstash -n 50"
echo "• Restaurer: cp $BACKUP_DIR/* /etc/logstash/conf.d/ && systemctl restart logstash"