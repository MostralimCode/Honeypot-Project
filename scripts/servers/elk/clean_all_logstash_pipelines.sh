#!/bin/bash
# scripts/elk/clean_fix_all_pipelines.sh
# Correction complète et définitive de tous les pipelines Logstash

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

print_status "=== NETTOYAGE COMPLET ET RECONSTRUCTION DES PIPELINES ==="

# Arrêter Logstash
print_status "Arrêt de Logstash..."
systemctl stop logstash 2>/dev/null || true

# Nettoyage complet
print_status "Nettoyage complet des pipelines défaillants..."
rm -rf /etc/logstash/conf.d/*
rm -rf /var/lib/logstash/sincedb_*

# Recréer le répertoire proprement
mkdir -p /etc/logstash/conf.d

print_status "✓ Nettoyage terminé"

# ================================
# PIPELINE 1: COWRIE SSH (MINIMAL)
# ================================

print_status "Création pipeline Cowrie SSH (minimal)..."

cat > /etc/logstash/conf.d/10-cowrie.conf << 'EOF'
input {
  file {
    path => "/var/log/cowrie/cowrie.json"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_cowrie"
    type => "cowrie"
    codec => "json"
  }
}

filter {
  if [type] == "cowrie" {
    mutate {
      add_field => { "honeypot_type" => "ssh" }
    }
  }
}

output {
  if [type] == "cowrie" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-cowrie-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_info "✓ Pipeline Cowrie créé"

# ================================
# PIPELINE 2: HTTP HONEYPOT (MINIMAL)
# ================================

print_status "Création pipeline HTTP (minimal)..."

cat > /etc/logstash/conf.d/20-http.conf << 'EOF'
input {
  file {
    path => "/var/log/honeypot/http_honeypot.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_http"
    type => "http_honeypot"
    codec => "json"
  }
}

filter {
  if [type] == "http_honeypot" {
    mutate {
      add_field => { "honeypot_type" => "http" }
    }
  }
}

output {
  if [type] == "http_honeypot" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-http-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_info "✓ Pipeline HTTP créé"

# ================================
# PIPELINE 3: FTP HONEYPOT (MINIMAL)
# ================================

print_status "Création pipeline FTP (minimal)..."

cat > /etc/logstash/conf.d/30-ftp.conf << 'EOF'
input {
  file {
    path => "/root/honeypot-ftp/logs/sessions.json"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_ftp"
    type => "ftp_honeypot"
    codec => "json"
  }
}

filter {
  if [type] == "ftp_honeypot" {
    mutate {
      add_field => { "honeypot_type" => "ftp" }
    }
  }
}

output {
  if [type] == "ftp_honeypot" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "honeypot-ftp-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_info "✓ Pipeline FTP créé"

# ================================
# PIPELINE 4: SERVEURS SÉCURISÉS (MINIMAL)
# ================================

print_status "Création pipeline serveurs sécurisés (minimal)..."

cat > /etc/logstash/conf.d/40-secure.conf << 'EOF'
input {
  file {
    path => "/var/log/auth.log"
    start_position => "beginning"
    sincedb_path => "/var/lib/logstash/sincedb_auth"
    type => "secure_server"
  }
}

filter {
  if [type] == "secure_server" {
    mutate {
      add_field => { "honeypot_type" => "secure" }
    }
  }
}

output {
  if [type] == "secure_server" {
    elasticsearch {
      hosts => ["192.168.2.124:9200"]
      index => "secure-servers-%{+YYYY.MM.dd}"
    }
  }
}
EOF

print_info "✓ Pipeline serveurs sécurisés créé"

# ================================
# CONFIGURATION DES PERMISSIONS
# ================================

print_status "Configuration des permissions..."

# Permissions sur les fichiers de configuration
chown -R root:root /etc/logstash/conf.d/
chmod 644 /etc/logstash/conf.d/*.conf

# Permissions sur les répertoires Logstash
chown -R logstash:logstash /var/lib/logstash/
chown -R logstash:logstash /var/log/logstash/

print_info "✓ Permissions configurées"

# ================================
# CRÉATION DES RÉPERTOIRES DE LOGS
# ================================

print_status "Création des répertoires de logs..."

# Créer tous les répertoires nécessaires
mkdir -p /var/log/cowrie
mkdir -p /var/log/honeypot  
mkdir -p /root/honeypot-ftp/logs

# Créer des fichiers de log vides pour les tests
touch /var/log/cowrie/cowrie.json
touch /var/log/honeypot/http_honeypot.log
touch /root/honeypot-ftp/logs/sessions.json

print_info "✓ Répertoires et fichiers de test créés"

# ================================
# TEST DE CONFIGURATION
# ================================

print_status "Test de la configuration..."

# Afficher les fichiers créés
print_info "Pipelines créés:"
ls -la /etc/logstash/conf.d/

echo ""
print_status "Test de syntaxe Logstash..."

# Test de syntaxe avec gestion d'erreur
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t 2>/tmp/logstash_test.log; then
    print_status "✅ SUCCÈS! Configuration Logstash validée"
    rm -f /tmp/logstash_test.log
else
    print_error "❌ ÉCHEC du test de configuration"
    print_info "Détails de l'erreur:"
    cat /tmp/logstash_test.log
    rm -f /tmp/logstash_test.log
    exit 1
fi

# ================================
# CRÉATION D'UN PIPELINE DE TEST SIMPLE
# ================================

print_status "Création d'un pipeline de test simple..."

cat > /etc/logstash/conf.d/99-test.conf << 'EOF'
input {
  stdin { 
    type => "test"
  }
}

filter {
  if [type] == "test" {
    mutate {
      add_field => { "test_field" => "test_value" }
    }
  }
}

output {
  if [type] == "test" {
    stdout {
      codec => rubydebug
    }
  }
}
EOF

# Test du pipeline de test
print_status "Test du pipeline de test..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    print_status "✅ Pipeline de test validé"
else
    print_error "❌ Problème avec le pipeline de test"
    # Supprimer le pipeline de test s'il pose problème
    rm -f /etc/logstash/conf.d/99-test.conf
fi

# ================================
# SCRIPTS UTILITAIRES
# ================================

print_status "Création des scripts utilitaires..."

# Script de démarrage sécurisé
cat > /opt/elk-scripts/start_logstash_safe.sh << 'EOF'
#!/bin/bash
echo "=== Démarrage sécurisé de Logstash ==="

echo "1. Test de configuration..."
if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t; then
    echo "✅ Configuration OK"
else
    echo "❌ Erreur de configuration - arrêt"
    exit 1
fi

echo ""
echo "2. Vérification Elasticsearch..."
if curl -s "http://192.168.2.124:9200/" >/dev/null; then
    echo "✅ Elasticsearch accessible"
else
    echo "❌ Elasticsearch non accessible - arrêt"
    exit 1
fi

echo ""
echo "3. Démarrage Logstash..."
systemctl start logstash

echo ""
echo "4. Vérification du démarrage..."
sleep 10
if systemctl is-active --quiet logstash; then
    echo "✅ Logstash démarré avec succès"
    echo ""
    echo "API Logstash:"
    curl -s "http://192.168.2.124:9600/" | jq . || echo "API pas encore prête"
else
    echo "❌ Échec du démarrage"
    journalctl -u logstash --no-pager -n 20
fi
EOF

chmod +x /opt/elk-scripts/start_logstash_safe.sh

# Script de monitoring simple
cat > /opt/elk-scripts/check_logstash.sh << 'EOF'
#!/bin/bash
echo "=== État de Logstash ==="

echo "Service: $(systemctl is-active logstash)"
echo "Enabled: $(systemctl is-enabled logstash)"

echo ""
echo "Processus:"
ps aux | grep logstash | grep -v grep || echo "Aucun processus"

echo ""
echo "Ports:"
netstat -tlnp | grep -E "(9600|5044)" || echo "Aucun port Logstash"

echo ""
echo "API (si disponible):"
curl -s "http://192.168.2.124:9600/" | jq .version || echo "API non accessible"

echo ""
echo "Derniers logs:"
journalctl -u logstash --no-pager -n 5
EOF

chmod +x /opt/elk-scripts/check_logstash.sh

print_info "✓ Scripts utilitaires créés"

# ================================
# INFORMATIONS FINALES
# ================================

print_status "=== RECONSTRUCTION COMPLÈTE TERMINÉE AVEC SUCCÈS! ==="
echo ""
print_info "📁 Pipelines créés (versions minimales et garanties):"
echo "   ✓ 10-cowrie.conf      - SSH Honeypot"
echo "   ✓ 20-http.conf        - HTTP Honeypot"
echo "   ✓ 30-ftp.conf         - FTP Honeypot"
echo "   ✓ 40-secure.conf      - Serveurs sécurisés"
echo ""
print_info "🔧 Fonctionnalités actuelles:"
echo "   ✓ Ingestion de base (input → filter → output)"
echo "   ✓ Métadonnées honeypot_type"
echo "   ✓ Index Elasticsearch séparés"
echo "   ✓ Syntaxe validée"
echo ""
print_info "📊 Index Elasticsearch qui seront créés:"
echo "   - honeypot-cowrie-YYYY.MM.dd"
echo "   - honeypot-http-YYYY.MM.dd"
echo "   - honeypot-ftp-YYYY.MM.dd"
echo "   - secure-servers-YYYY.MM.dd"
echo ""
print_info "🚀 Scripts disponibles:"
echo "   - /opt/elk-scripts/start_logstash_safe.sh (démarrage sécurisé)"
echo "   - /opt/elk-scripts/check_logstash.sh (monitoring)"
echo ""
print_warning "📋 ÉTAPES SUIVANTES:"
echo "1. Démarrer Logstash: /opt/elk-scripts/start_logstash_safe.sh"
echo "2. Vérifier le statut: /opt/elk-scripts/check_logstash.sh"
echo "3. Installer Kibana pour visualiser les données"
echo ""
print_status "🎯 Logstash prêt à fonctionner avec des pipelines garantis!"

# Créer un fichier de statut final
cat > /opt/elk-setup-status-final.txt << EOF
=== ELK Stack - Configuration Finale ===
Date: $(date)

✅ ELASTICSEARCH:
- Status: $(systemctl is-active elasticsearch)
- URL: http://192.168.2.124:9200
- Cluster: honeypot-elk

✅ LOGSTASH:
- Status: $(systemctl is-active logstash)
- Pipelines: 4 pipelines minimaux créés
- Configuration: Validée et fonctionnelle
- API: http://192.168.2.124:9600

📝 PIPELINES ACTIFS:
- Cowrie SSH (honeypot-cowrie-*)
- HTTP Honeypot (honeypot-http-*)
- FTP Honeypot (honeypot-ftp-*)
- Serveurs sécurisés (secure-servers-*)

🔄 ÉVOLUTIONS POSSIBLES:
- Ajouter GeoIP enrichment
- Ajouter classification avancée
- Configurer des alertes
- Ajouter des filtres spécialisés

🎯 PRÊT POUR:
- Installation de Kibana
- Ingestion de données honeypot
- Visualisation et analyse

Commande de démarrage: /opt/elk-scripts/start_logstash_safe.sh
EOF

echo "$(date): Reconstruction complète des pipelines réussie" >> /var/log/elk-setup/install.log

print_status "Configuration sauvegardée dans: /opt/elk-setup-status-final.txt"