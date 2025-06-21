#!/bin/bash
# Script de contournement - Ingestion directe des logs honeypot
# À exécuter sur la VM ELK (192.168.2.124)

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
    print_error "Ce script doit être exécuté en tant que root sur la VM ELK"
    exit 1
fi

print_status "=== SOLUTION DE CONTOURNEMENT - INGESTION DIRECTE ==="

# 1. Créer pipeline d'ingestion directe des fichiers
print_status "Création d'un pipeline d'ingestion directe..."

cat > /etc/logstash/conf.d/00-file-input.conf << 'EOF'
input {
  # Input direct pour logs Cowrie SSH
  file {
    path => "/mnt/honeypot-logs/cowrie/*.json*"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_cowrie"
    codec => "json"
    tags => ["cowrie", "ssh", "honeypot"]
    add_field => { 
      "honeypot_type" => "ssh"
      "source_vm" => "192.168.2.117"
      "service" => "cowrie-ssh"
    }
  }
  
  # Input direct pour logs HTTP
  file {
    path => "/mnt/honeypot-logs/http/*.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_http"
    tags => ["http", "honeypot"]
    add_field => { 
      "honeypot_type" => "http"
      "source_vm" => "192.168.2.117"
      "service" => "http-honeypot"
    }
  }
  
  # Input direct pour logs FTP
  file {
    path => "/mnt/honeypot-logs/ftp/*.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_ftp"
    tags => ["ftp", "honeypot"]
    add_field => { 
      "honeypot_type" => "ftp"
      "source_vm" => "192.168.2.117"
      "service" => "ftp-honeypot"
    }
  }
  
  # Input direct pour logs FTP JSON
  file {
    path => "/mnt/honeypot-logs/ftp/*.json"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_ftp_json"
    codec => "json"
    tags => ["ftp", "honeypot", "json"]
    add_field => { 
      "honeypot_type" => "ftp"
      "source_vm" => "192.168.2.117"
      "service" => "ftp-honeypot"
    }
  }
}
EOF

# 2. Créer le répertoire de montage
print_status "Création du répertoire de montage..."
mkdir -p /mnt/honeypot-logs/{cowrie,http,ftp}
chown -R logstash:logstash /mnt/honeypot-logs

# 3. Script de synchronisation des logs
print_status "Création du script de synchronisation..."

cat > /opt/sync_honeypot_logs.sh << 'SYNC_EOF'
#!/bin/bash
# Script de synchronisation des logs depuis VM Honeypot
# À exécuter toutes les minutes via cron

LOG_DIR="/mnt/honeypot-logs"
HONEYPOT_IP="192.168.2.117"

# Fonction de sync sécurisée
sync_logs() {
    local source_path="$1"
    local dest_path="$2"
    local log_type="$3"
    
    echo "$(date): Sync $log_type depuis $source_path vers $dest_path"
    
    # Utiliser rsync avec SSH
    rsync -avz --progress \
          -e "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5" \
          "root@${HONEYPOT_IP}:${source_path}" \
          "${dest_path}/" \
          2>/dev/null || echo "Erreur sync $log_type"
}

# Synchroniser Cowrie
sync_logs "/home/cowrie/cowrie/var/log/cowrie/*.json*" "$LOG_DIR/cowrie" "Cowrie"

# Synchroniser HTTP
sync_logs "/var/log/honeypot/*.log" "$LOG_DIR/http" "HTTP"

# Synchroniser FTP
sync_logs "/root/honeypot-ftp/logs/*" "$LOG_DIR/ftp" "FTP"

# Ajuster les permissions
chown -R logstash:logstash "$LOG_DIR"
chmod -R 644 "$LOG_DIR"/*/*

echo "$(date): Synchronisation terminée"
SYNC_EOF

chmod +x /opt/sync_honeypot_logs.sh

# 4. Configurer cron pour sync automatique
print_status "Configuration de la synchronisation automatique..."
echo "*/2 * * * * /opt/sync_honeypot_logs.sh >> /var/log/honeypot-sync.log 2>&1" | crontab -

# 5. Test de connectivité SSH vers VM Honeypot
print_status "Test de connectivité SSH vers VM Honeypot..."
if ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no root@192.168.2.117 "echo 'Connexion OK'" 2>/dev/null; then
    print_status "✅ Connexion SSH vers VM Honeypot: OK"
else
    print_warning "⚠️ Impossible de se connecter en SSH à 192.168.2.117"
    print_info "Vérifiez les clés SSH ou utilisez la synchronisation manuelle"
fi

# 6. Première synchronisation manuelle
print_status "Première synchronisation des logs..."
/opt/sync_honeypot_logs.sh

# 7. Redémarrer Logstash avec la nouvelle configuration
print_status "Redémarrage de Logstash..."
systemctl restart logstash

# Attendre le démarrage
sleep 15

# 8. Vérification
print_status "Vérification de l'ingestion..."

if systemctl is-active --quiet logstash; then
    print_status "✅ Logstash actif"
    
    # Vérifier les indices
    sleep 10
    INDEX_COUNT=$(curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*" 2>/dev/null | wc -l)
    if [ "$INDEX_COUNT" -gt 0 ]; then
        print_status "✅ Indices honeypot créés: $INDEX_COUNT"
        curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v"
    else
        print_warning "⚠️ Aucun indice honeypot trouvé encore"
    fi
else
    print_error "❌ Problème avec Logstash"
    journalctl -u logstash --no-pager -n 10
fi

# 9. Script de monitoring
cat > /opt/monitor_direct_ingestion.sh << 'MONITOR_EOF'
#!/bin/bash
echo "=== MONITORING INGESTION DIRECTE ==="
echo ""
echo "📊 Status Logstash:"
systemctl is-active logstash
echo ""
echo "📁 Logs synchronisés:"
find /mnt/honeypot-logs -type f | wc -l | sed 's/^/Fichiers total: /'
echo ""
echo "📈 Indices Elasticsearch:"
curl -s "http://192.168.2.124:9200/_cat/indices/honeypot-*?v" 2>/dev/null || echo "Pas d'indices encore"
echo ""
echo "🔢 Nombre de documents:"
curl -s "http://192.168.2.124:9200/honeypot-*/_count?pretty" 2>/dev/null | grep '"count"' || echo "Pas de données"
echo ""
echo "🔍 Dernière synchronisation:"
tail -5 /var/log/honeypot-sync.log 2>/dev/null || echo "Pas de logs de sync"
MONITOR_EOF

chmod +x /opt/monitor_direct_ingestion.sh

# 10. Résumé
print_status "=== CONTOURNEMENT INSTALLÉ ==="
echo ""
print_info "📁 COMPOSANTS CRÉÉS:"
echo "✅ Pipeline Logstash: /etc/logstash/conf.d/00-file-input.conf"
echo "✅ Script de sync: /opt/sync_honeypot_logs.sh"
echo "✅ Monitoring: /opt/monitor_direct_ingestion.sh"
echo "✅ Cron job: sync toutes les 2 minutes"
echo ""
print_warning "🎯 COMMANDES UTILES:"
echo "# Synchronisation manuelle:"
echo "/opt/sync_honeypot_logs.sh"
echo ""
echo "# Monitoring:"
echo "/opt/monitor_direct_ingestion.sh"
echo ""
echo "# Logs Logstash:"
echo "journalctl -u logstash -f"
echo ""
echo "# Kibana:"
echo "http://192.168.2.124:5601"
echo ""
print_status "Solution de contournement active ! Vos logs devraient apparaître dans Elasticsearch."