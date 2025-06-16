#!/bin/bash
# Diagnostic complet pour identifier pourquoi les données n'arrivent pas
# À exécuter sur VM ELK et VM Honeypot

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[+] $1${NC}"; }
print_warning() { echo -e "${YELLOW}[!] $1${NC}"; }
print_error() { echo -e "${RED}[-] $1${NC}"; }
print_info() { echo -e "${BLUE}[i] $1${NC}"; }

CURRENT_IP=$(ip route get 1 | sed -n 's/^.*src \([0-9.]*\) .*$/\1/p')

echo "=== DIAGNOSTIC COMPLET PIPELINE ELK-HONEYPOTS ==="
echo "Date: $(date)"
echo "IP: $CURRENT_IP"
echo ""

# ================================
# DIAGNOSTIC VM ELK (192.168.2.124)
# ================================

if [[ "$CURRENT_IP" == "192.168.2.124" ]]; then
    print_status "=== DIAGNOSTIC APPROFONDI VM ELK ==="
    
    # 1. Services ELK
    print_info "1. État des services ELK:"
    for service in elasticsearch logstash kibana; do
        STATUS=$(systemctl is-active $service)
        if [ "$STATUS" = "active" ]; then
            echo "  ✓ $service: $STATUS"
        else
            echo "  ✗ $service: $STATUS"
        fi
    done
    
    # 2. Ports d'écoute détaillés
    print_info "2. Ports d'écoute détaillés:"
    echo "Port 9200 (Elasticsearch):"
    netstat -tlnp 2>/dev/null | grep :9200 || echo "  ✗ Port 9200 fermé"
    echo "Port 5044 (Logstash Beats):"
    netstat -tlnp 2>/dev/null | grep :5044 || echo "  ✗ Port 5044 fermé"
    echo "Port 9600 (Logstash API):"
    netstat -tlnp 2>/dev/null | grep :9600 || echo "  ✗ Port 9600 fermé"
    
    # 3. Configuration Logstash détaillée
    print_info "3. Configuration Logstash:"
    echo "Fichiers de configuration:"
    ls -la /etc/logstash/conf.d/
    echo ""
    echo "Test syntaxe Logstash:"
    if sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t 2>/dev/null; then
        echo "  ✓ Syntaxe OK"
    else
        echo "  ✗ Erreur syntaxe"
        sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
    fi
    
    # 4. API Logstash
    print_info "4. API Logstash:"
    if curl -s "http://192.168.2.124:9600/" >/dev/null; then
        echo "  ✓ API accessible"
        echo "Pipelines actifs:"
        curl -s "http://192.168.2.124:9600/_node/pipelines" | jq 'keys' 2>/dev/null || echo "  Pas de pipelines"
        echo ""
        echo "Statistiques input:"
        curl -s "http://192.168.2.124:9600/_node/stats/pipelines" | jq '.pipelines.main.plugins.inputs' 2>/dev/null || echo "  Pas de stats input"
    else
        echo "  ✗ API non accessible"
    fi
    
    # 5. Logs Logstash récents
    print_info "5. Logs Logstash récents:"
    journalctl -u logstash --no-pager -n 10 | grep -E "(ERROR|WARN|beats|5044)" || echo "  Pas d'erreurs visibles"
    
    # 6. Test Elasticsearch
    print_info "6. Test Elasticsearch:"
    if curl -s "http://192.168.2.124:9200/" | grep -q "cluster_name"; then
        echo "  ✓ Elasticsearch accessible"
        echo "Santé cluster:"
        curl -s "http://192.168.2.124:9200/_cluster/health" | jq '.status' 2>/dev/null || echo "  Status inconnu"
        echo "Indices existants:"
        curl -s "http://192.168.2.124:9200/_cat/indices" 2>/dev/null | head -5 || echo "  Pas d'indices"
    else
        echo "  ✗ Elasticsearch non accessible"
    fi
    
    # 7. Pare-feu et connectivité
    print_info "7. Pare-feu et connectivité:"
    if command -v ufw >/dev/null 2>&1; then
        echo "UFW status:"
        ufw status | grep -E "(5044|9200)" || echo "  Pas de règles ELK"
    fi
    
    echo "Test connectivité vers VM Honeypot:"
    if ping -c 2 192.168.2.117 >/dev/null 2>&1; then
        echo "  ✓ VM Honeypot accessible"
    else
        echo "  ✗ VM Honeypot non accessible"
    fi
    
    # 8. Créer un test de réception manuelle
    print_info "8. Test de réception manuelle:"
    echo "Test avec netcat sur port 5044:"
    timeout 5 bash -c 'echo "test" | nc -w 1 192.168.2.124 5044' 2>/dev/null && echo "  ✓ Port 5044 répond" || echo "  ✗ Port 5044 ne répond pas"

# ================================
# DIAGNOSTIC VM HONEYPOT (192.168.2.117)
# ================================

elif [[ "$CURRENT_IP" == "192.168.2.117" ]]; then
    print_status "=== DIAGNOSTIC APPROFONDI VM HONEYPOT ==="
    
    # 1. État Filebeat
    print_info "1. État Filebeat détaillé:"
    systemctl status filebeat --no-pager -l | head -10
    
    # 2. Configuration Filebeat
    print_info "2. Validation configuration Filebeat:"
    if filebeat test config 2>/dev/null; then
        echo "  ✓ Configuration valide"
    else
        echo "  ✗ Configuration invalide"
        filebeat test config
    fi
    
    # 3. Test output Filebeat
    print_info "3. Test output Filebeat:"
    if filebeat test output 2>/dev/null; then
        echo "  ✓ Connexion Logstash OK"
    else
        echo "  ✗ Connexion Logstash échec"
        filebeat test output
    fi
    
    # 4. Connectivité réseau vers ELK
    print_info "4. Tests connectivité ELK:"
    echo "Ping VM ELK:"
    if ping -c 2 192.168.2.124 >/dev/null 2>&1; then
        echo "  ✓ VM ELK accessible"
    else
        echo "  ✗ VM ELK non accessible"
    fi
    
    echo "Port 5044 (Logstash):"
    if nc -z 192.168.2.124 5044 2>/dev/null; then
        echo "  ✓ Port 5044 accessible"
    else
        echo "  ✗ Port 5044 fermé"
    fi
    
    echo "Port 9200 (Elasticsearch):"
    if nc -z 192.168.2.124 9200 2>/dev/null; then
        echo "  ✓ Port 9200 accessible"
    else
        echo "  ✗ Port 9200 fermé"
    fi
    
    # 5. Logs Filebeat détaillés
    print_info "5. Logs Filebeat détaillés:"
    journalctl -u filebeat --no-pager -n 15 | grep -E "(ERROR|connection|refused|timeout)" || echo "  Pas d'erreurs de connexion"
    
    # 6. Vérification des fichiers de logs source
    print_info "6. Fichiers de logs source:"
    
    logs_to_check=(
        "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
        "/var/log/honeypot/http_honeypot.log"
        "/root/honeypot-ftp/logs/sessions.json"
    )
    
    for log_file in "${logs_to_check[@]}"; do
        if [ -f "$log_file" ]; then
            SIZE=$(wc -l < "$log_file" 2>/dev/null || echo "0")
            RECENT=$(tail -1 "$log_file" 2>/dev/null | jq -r '.timestamp // .message' 2>/dev/null | head -c 30 || echo "Format non-JSON")
            echo "  ✓ $log_file: $SIZE lignes, dernier: $RECENT..."
        else
            echo "  ✗ $log_file: MANQUANT"
        fi
    done
    
    # 7. Test manuel d'envoi
    print_info "7. Test manuel d'envoi vers Logstash:"
    echo "Test avec netcat:"
    echo '{"test": "manual", "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'"}' | timeout 5 nc 192.168.2.124 5044 2>/dev/null && echo "  ✓ Envoi réussi" || echo "  ✗ Envoi échoué"
    
    # 8. Pare-feu local
    print_info "8. Pare-feu local:"
    if command -v ufw >/dev/null 2>&1; then
        echo "UFW status:"
        ufw status | head -5
    fi
    
    echo "iptables OUTPUT:"
    iptables -L OUTPUT -n | head -5 2>/dev/null || echo "  Pas d'accès iptables"

else
    print_error "Ce script doit être exécuté sur VM ELK (192.168.2.124) ou VM Honeypot (192.168.2.117)"
    print_error "IP actuelle: $CURRENT_IP"
fi

# ================================
# RECOMMANDATIONS
# ================================

print_status "=== ÉTAPES DE RÉSOLUTION ==="

if [[ "$CURRENT_IP" == "192.168.2.124" ]]; then
    echo "Sur VM ELK - Actions recommandées:"
    echo "1. Si port 5044 fermé:"
    echo "   systemctl restart logstash"
    echo ""
    echo "2. Si erreurs Logstash:"
    echo "   journalctl -u logstash -f"
    echo ""
    echo "3. Test manuel de réception:"
    echo "   nc -l 5044  # Dans un terminal"
    echo "   # Puis testez depuis VM Honeypot"
    
elif [[ "$CURRENT_IP" == "192.168.2.117" ]]; then
    echo "Sur VM Honeypot - Actions recommandées:"
    echo "1. Si connexion Logstash échoue:"
    echo "   systemctl restart filebeat"
    echo ""
    echo "2. Si logs vides, générer des données:"
    echo "   echo '{\"test\":\"data\",\"timestamp\":\"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'\"}' >> /var/log/honeypot/http_honeypot.log"
    echo ""
    echo "3. Test connexion manuelle:"
    echo "   echo 'test' | nc 192.168.2.124 5044"
fi

print_status "Exécutez ce diagnostic sur les DEUX VMs pour identifier le problème!"