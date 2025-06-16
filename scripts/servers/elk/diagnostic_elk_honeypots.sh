#!/bin/bash
# Script de diagnostic complet pour identifier pourquoi les données honeypot n'arrivent pas dans Elasticsearch
# À exécuter sur les VMs concernées

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

echo "=== DIAGNOSTIC COMPLET ELK - HONEYPOTS ==="
echo "Date: $(date)"
echo ""

# ================================
# PARTIE 1: DIAGNOSTIC VM ELK (192.168.2.124)
# ================================

if [[ $(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p') == "192.168.2.124" ]]; then
    print_status "=== DIAGNOSTIC VM ELK (192.168.2.124) ==="
    
    # 1. Vérifier les services ELK
    print_info "1. État des services ELK:"
    for service in elasticsearch logstash kibana; do
        if systemctl is-active --quiet $service; then
            echo "  ✓ $service: ACTIF"
        else
            echo "  ✗ $service: ARRÊTÉ"
        fi
    done
    
    # 2. Vérifier les APIs
    print_info "2. Test des APIs:"
    
    # Elasticsearch
    if curl -s "http://192.168.2.124:9200/" | grep -q "cluster_name"; then
        echo "  ✓ Elasticsearch API: OK"
        # Lister les indices existants
        echo "     Indices actuels:"
        curl -s "http://192.168.2.124:9200/_cat/indices?v" | head -10
    else
        echo "  ✗ Elasticsearch API: ERREUR"
    fi
    
    # Logstash
    if curl -s "http://192.168.2.124:9600/" | grep -q "version"; then
        echo "  ✓ Logstash API: OK"
    else
        echo "  ✗ Logstash API: ERREUR"
    fi
    
    # 3. Vérifier les pipelines Logstash
    print_info "3. Pipelines Logstash:"
    if [ -d "/etc/logstash/conf.d" ]; then
        echo "     Fichiers de configuration:"
        ls -la /etc/logstash/conf.d/
        
        # Test syntaxe
        echo "     Test syntaxe:"
        if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t 2>/dev/null; then
            echo "  ✓ Syntaxe pipelines: OK"
        else
            echo "  ✗ Syntaxe pipelines: ERREUR"
        fi
    else
        echo "  ✗ Répertoire pipelines manquant"
    fi
    
    # 4. Vérifier les ports d'écoute
    print_info "4. Ports d'écoute ELK:"
    for port in 9200 5601 5044 9600; do
        if netstat -tlnp 2>/dev/null | grep -q ":$port "; then
            echo "  ✓ Port $port: EN ÉCOUTE"
        else
            echo "  ✗ Port $port: FERMÉ"
        fi
    done
    
    # 5. Vérifier l'input Beats dans Logstash
    print_info "5. Configuration input Beats:"
    if grep -r "input.*beats" /etc/logstash/conf.d/ 2>/dev/null; then
        echo "  ✓ Input Beats configuré"
    else
        echo "  ✗ Input Beats manquant"
        print_warning "     SOLUTION: Créer l'input Beats"
    fi
    
    # 6. Logs récents
    print_info "6. Logs récents Logstash:"
    journalctl -u logstash --no-pager -n 5 2>/dev/null | grep -v "^--"
    
    echo ""

# ================================
# PARTIE 2: DIAGNOSTIC VM HONEYPOT (192.168.2.117)
# ================================

elif [[ $(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p') == "192.168.2.117" ]]; then
    print_status "=== DIAGNOSTIC VM HONEYPOT (192.168.2.117) ==="
    
    # 1. Vérifier Filebeat
    print_info "1. État de Filebeat:"
    if systemctl is-active --quiet filebeat; then
        echo "  ✓ Filebeat: ACTIF"
    else
        echo "  ✗ Filebeat: ARRÊTÉ"
        print_warning "     SOLUTION: systemctl start filebeat"
    fi
    
    # 2. Vérifier la configuration Filebeat
    print_info "2. Configuration Filebeat:"
    if [ -f "/etc/filebeat/filebeat.yml" ]; then
        echo "  ✓ Configuration existe"
        
        # Test syntaxe
        if filebeat test config 2>/dev/null; then
            echo "  ✓ Syntaxe: OK"
        else
            echo "  ✗ Syntaxe: ERREUR"
        fi
        
        # Test output
        if filebeat test output 2>/dev/null; then
            echo "  ✓ Connexion Logstash: OK"
        else
            echo "  ✗ Connexion Logstash: ERREUR"
        fi
    else
        echo "  ✗ Configuration manquante"
    fi
    
    # 3. Vérifier les fichiers de logs source
    print_info "3. Fichiers de logs surveillés:"
    
    # Cowrie SSH
    COWRIE_LOG="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
    if [ -f "$COWRIE_LOG" ]; then
        SIZE=$(wc -l < "$COWRIE_LOG" 2>/dev/null || echo "0")
        echo "  ✓ Cowrie SSH: $SIZE lignes ($COWRIE_LOG)"
    else
        echo "  ✗ Cowrie SSH: fichier manquant"
        print_warning "     Vérifier: ls -la /home/cowrie/cowrie/var/log/cowrie/"
    fi
    
    # HTTP Honeypot
    HTTP_LOG="/var/log/honeypot/http_honeypot.log"
    if [ -f "$HTTP_LOG" ]; then
        SIZE=$(wc -l < "$HTTP_LOG" 2>/dev/null || echo "0")
        echo "  ✓ HTTP Honeypot: $SIZE lignes ($HTTP_LOG)"
    else
        echo "  ✗ HTTP Honeypot: fichier manquant"
        print_warning "     Créer: mkdir -p /var/log/honeypot && touch $HTTP_LOG"
    fi
    
    # FTP Honeypot
    FTP_LOG="/root/honeypot-ftp/logs/sessions.json"
    if [ -f "$FTP_LOG" ]; then
        SIZE=$(wc -l < "$FTP_LOG" 2>/dev/null || echo "0")
        echo "  ✓ FTP Honeypot: $SIZE lignes ($FTP_LOG)"
    else
        echo "  ✗ FTP Honeypot: fichier manquant"
        print_warning "     Créer: mkdir -p /root/honeypot-ftp/logs && touch $FTP_LOG"
    fi
    
    # 4. Vérifier la connectivité vers ELK
    print_info "4. Connectivité vers ELK:"
    if ping -c 2 192.168.2.124 >/dev/null 2>&1; then
        echo "  ✓ Ping VM ELK: OK"
    else
        echo "  ✗ Ping VM ELK: ERREUR"
    fi
    
    if nc -z 192.168.2.124 5044 2>/dev/null; then
        echo "  ✓ Port Logstash 5044: ACCESSIBLE"
    else
        echo "  ✗ Port Logstash 5044: FERMÉ"
        print_warning "     Vérifier input Beats sur VM ELK"
    fi
    
    # 5. Logs Filebeat récents
    print_info "5. Logs Filebeat récents:"
    journalctl -u filebeat --no-pager -n 5 2>/dev/null | grep -v "^--"
    
    echo ""

else
    print_error "Ce script doit être exécuté sur VM ELK (192.168.2.124) ou VM Honeypot (192.168.2.117)"
    echo "IP actuelle: $(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')"
fi

# ================================
# PARTIE 3: SOLUTIONS RAPIDES
# ================================

print_status "=== SOLUTIONS RAPIDES ==="

if [[ $(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p') == "192.168.2.124" ]]; then
    echo "Sur VM ELK - Actions à effectuer:"
    echo ""
    echo "1. Si input Beats manque dans Logstash:"
    echo "   cat > /etc/logstash/conf.d/00-beats-input.conf << 'EOF'"
    echo "   input {"
    echo "     beats {"
    echo "       port => 5044"
    echo "     }"
    echo "   }"
    echo "   EOF"
    echo "   systemctl restart logstash"
    echo ""
    echo "2. Si pipelines manquent:"
    echo "   Exécuter: bash fix_logstash_pipelines.sh"
    echo ""
    echo "3. Vérifier les logs en temps réel:"
    echo "   journalctl -u logstash -f"

elif [[ $(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p') == "192.168.2.117" ]]; then
    echo "Sur VM Honeypot - Actions à effectuer:"
    echo ""
    echo "1. Si Filebeat arrêté:"
    echo "   systemctl start filebeat"
    echo "   systemctl enable filebeat"
    echo ""
    echo "2. Si fichiers de logs manquent:"
    echo "   mkdir -p /var/log/honeypot /root/honeypot-ftp/logs"
    echo "   touch /var/log/honeypot/http_honeypot.log"
    echo "   touch /root/honeypot-ftp/logs/sessions.json"
    echo ""
    echo "3. Générer des logs de test:"
    echo "   echo '{\"timestamp\":\"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'\",\"test\":\"true\"}' >> /var/log/honeypot/http_honeypot.log"
    echo ""
    echo "4. Vérifier les logs Filebeat:"
    echo "   journalctl -u filebeat -f"
fi

echo ""
print_info "Commandes de diagnostic rapide:"
echo "  - Indices Elasticsearch: curl -s 'http://192.168.2.124:9200/_cat/indices?v'"
echo "  - Santé cluster: curl -s 'http://192.168.2.124:9200/_cluster/health?pretty'"
echo "  - Stats Logstash: curl -s 'http://192.168.2.124:9600/_node/stats/pipelines?pretty'"
echo ""
print_status "Diagnostic terminé - Analysez les erreurs ci-dessus"