#!/bin/bash
# Configuration des indices Elasticsearch - Étape 5.4
# À exécuter sur la VM ELK (192.168.2.124)

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
    print_error "Ce script doit être exécuté en tant que root sur la VM ELK (192.168.2.124)"
    exit 1
fi

# Vérifier que nous sommes sur la bonne VM
VM_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
if [ "$VM_IP" != "192.168.2.124" ]; then
    print_error "Ce script doit être exécuté sur la VM ELK (192.168.2.124)"
    exit 1
fi

print_status "=== Configuration des indices Elasticsearch - Étape 5.4 ==="
echo ""

# Variables
ES_URL="http://192.168.2.124:9200"

# ================================
# VÉRIFICATIONS PRÉLIMINAIRES
# ================================

print_status "Vérifications préliminaires..."

# Vérifier qu'Elasticsearch fonctionne
if ! curl -s "$ES_URL/_cluster/health" | grep -q "yellow\|green"; then
    print_error "Elasticsearch n'est pas accessible ou n'est pas en bon état"
    print_error "Vérifiez le service: systemctl status elasticsearch"
    exit 1
fi

ES_CLUSTER_STATUS=$(curl -s "$ES_URL/_cluster/health" | jq -r '.status')
print_status "✅ Elasticsearch opérationnel (status: $ES_CLUSTER_STATUS)"

# ================================
# SUPPRESSION DES INDICES EXISTANTS (OPTIONNEL)
# ================================

print_warning "Nettoyage des indices existants (si nécessaire)..."
curl -X DELETE "$ES_URL/honeypot-*" 2>/dev/null || true
curl -X DELETE "$ES_URL/.kibana*" 2>/dev/null || true
print_info "Anciens indices supprimés"

# ================================
# CONFIGURATION DES TEMPLATES D'INDICES
# ================================

print_status "Configuration des templates d'indices pour les honeypots..."

# Template pour les logs SSH/Cowrie
print_info "Création du template honeypot-cowrie..."
cat > /tmp/cowrie_template.json << 'EOF'
{
  "index_patterns": ["honeypot-cowrie-*"],
  "priority": 100,
  "template": {
    "settings": {
      "index": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
        "max_result_window": 50000
      }
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "eventid": {
          "type": "keyword"
        },
        "src_ip": {
          "type": "ip"
        },
        "dst_ip": {
          "type": "ip"
        },
        "src_port": {
          "type": "integer"
        },
        "dst_port": {
          "type": "integer"
        },
        "session": {
          "type": "keyword"
        },
        "username": {
          "type": "keyword"
        },
        "password": {
          "type": "keyword"
        },
        "input": {
          "type": "text",
          "analyzer": "standard"
        },
        "message": {
          "type": "text"
        },
        "honeypot_type": {
          "type": "keyword"
        },
        "severity": {
          "type": "keyword"
        },
        "geoip": {
          "properties": {
            "location": {
              "type": "geo_point"
            },
            "country_name": {
              "type": "keyword"
            },
            "city_name": {
              "type": "keyword"
            },
            "continent_code": {
              "type": "keyword"
            }
          }
        }
      }
    }
  }
}
EOF

curl -X PUT "$ES_URL/_index_template/honeypot-cowrie" \
  -H "Content-Type: application/json" \
  -d @/tmp/cowrie_template.json

if [ $? -eq 0 ]; then
    print_status "✅ Template honeypot-cowrie créé"
else
    print_error "❌ Erreur création template cowrie"
fi

# Template pour les logs HTTP
print_info "Création du template honeypot-http..."
cat > /tmp/http_template.json << 'EOF'
{
  "index_patterns": ["honeypot-http-*"],
  "priority": 100,
  "template": {
    "settings": {
      "index": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
        "max_result_window": 50000
      }
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "attack_id": {
          "type": "keyword"
        },
        "attack_type": {
          "type": "keyword"
        },
        "ip": {
          "type": "ip"
        },
        "user_agent": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "method": {
          "type": "keyword"
        },
        "url": {
          "type": "text",
          "fields": {
            "keyword": {
              "type": "keyword",
              "ignore_above": 256
            }
          }
        },
        "payload": {
          "type": "text"
        },
        "severity": {
          "type": "keyword"
        },
        "honeypot_type": {
          "type": "keyword"
        },
        "referer": {
          "type": "text"
        },
        "headers": {
          "type": "object"
        },
        "geoip": {
          "properties": {
            "location": {
              "type": "geo_point"
            },
            "country_name": {
              "type": "keyword"
            },
            "city_name": {
              "type": "keyword"
            }
          }
        }
      }
    }
  }
}
EOF

curl -X PUT "$ES_URL/_index_template/honeypot-http" \
  -H "Content-Type: application/json" \
  -d @/tmp/http_template.json

if [ $? -eq 0 ]; then
    print_status "✅ Template honeypot-http créé"
else
    print_error "❌ Erreur création template http"
fi

# Template pour les logs FTP
print_info "Création du template honeypot-ftp..."
cat > /tmp/ftp_template.json << 'EOF'
{
  "index_patterns": ["honeypot-ftp-*"],
  "priority": 100,
  "template": {
    "settings": {
      "index": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "refresh_interval": "5s",
        "max_result_window": 50000
      }
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "event_type": {
          "type": "keyword"
        },
        "ip": {
          "type": "ip"
        },
        "username": {
          "type": "keyword"
        },
        "command": {
          "type": "keyword"
        },
        "args": {
          "type": "text"
        },
        "filename": {
          "type": "keyword"
        },
        "success": {
          "type": "boolean"
        },
        "honeypot_type": {
          "type": "keyword"
        },
        "severity": {
          "type": "keyword"
        },
        "session_id": {
          "type": "keyword"
        },
        "geoip": {
          "properties": {
            "location": {
              "type": "geo_point"
            },
            "country_name": {
              "type": "keyword"
            },
            "city_name": {
              "type": "keyword"
            }
          }
        }
      }
    }
  }
}
EOF

curl -X PUT "$ES_URL/_index_template/honeypot-ftp" \
  -H "Content-Type: application/json" \
  -d @/tmp/ftp_template.json

if [ $? -eq 0 ]; then
    print_status "✅ Template honeypot-ftp créé"
else
    print_error "❌ Erreur création template ftp"
fi

# ================================
# CRÉATION DES INDICES INITIAUX
# ================================

print_status "Création des indices initiaux..."

TODAY=$(date +%Y.%m.%d)

# Créer les indices avec les templates
curl -X PUT "$ES_URL/honeypot-cowrie-$TODAY" \
  -H "Content-Type: application/json" \
  -d '{"settings":{"index":{"number_of_shards":1,"number_of_replicas":0}}}'

curl -X PUT "$ES_URL/honeypot-http-$TODAY" \
  -H "Content-Type: application/json" \
  -d '{"settings":{"index":{"number_of_shards":1,"number_of_replicas":0}}}'

curl -X PUT "$ES_URL/honeypot-ftp-$TODAY" \
  -H "Content-Type: application/json" \
  -d '{"settings":{"index":{"number_of_shards":1,"number_of_replicas":0}}}'

print_status "✅ Indices initiaux créés pour $TODAY"

# ================================
# CONFIGURATION DES ALIAS
# ================================

print_status "Configuration des alias pour les indices..."

# Alias pour faciliter les requêtes
curl -X POST "$ES_URL/_aliases" \
  -H "Content-Type: application/json" \
  -d '{
    "actions": [
      {
        "add": {
          "index": "honeypot-cowrie-*",
          "alias": "honeypot-ssh"
        }
      },
      {
        "add": {
          "index": "honeypot-http-*",
          "alias": "honeypot-web"
        }
      },
      {
        "add": {
          "index": "honeypot-ftp-*",
          "alias": "honeypot-file"
        }
      },
      {
        "add": {
          "index": "honeypot-*",
          "alias": "honeypot-all"
        }
      }
    ]
  }'

print_status "✅ Alias configurés"

# ================================
# VÉRIFICATIONS
# ================================

print_status "Vérifications de la configuration..."

# Lister les templates créés
print_info "Templates d'indices:"
curl -s "$ES_URL/_index_template" | jq -r 'keys[]' | grep honeypot || echo "Aucun template honeypot"

# Lister les indices créés
print_info "Indices créés:"
curl -s "$ES_URL/_cat/indices/honeypot-*?v"

# Vérifier les alias
print_info "Alias configurés:"
curl -s "$ES_URL/_cat/aliases/honeypot-*?v"

# ================================
# TEST D'INSERTION DE DONNÉES
# ================================

print_status "Test d'insertion de données de démonstration..."

# Test Cowrie
curl -X POST "$ES_URL/honeypot-cowrie-$TODAY/_doc" \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
    "eventid": "cowrie.session.connect",
    "src_ip": "192.168.1.100",
    "dst_port": 22,
    "session": "test123",
    "honeypot_type": "ssh",
    "message": "Test de connexion SSH"
  }'

# Test HTTP
curl -X POST "$ES_URL/honeypot-http-$TODAY/_doc" \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
    "attack_id": "test001",
    "attack_type": "sql_injection",
    "ip": "192.168.1.101",
    "method": "POST",
    "url": "/login",
    "payload": "admin OR 1=1",
    "honeypot_type": "http",
    "severity": "high"
  }'

# Test FTP
curl -X POST "$ES_URL/honeypot-ftp-$TODAY/_doc" \
  -H "Content-Type: application/json" \
  -d '{
    "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
    "event_type": "ftp_auth",
    "ip": "192.168.1.102",
    "username": "admin",
    "command": "USER",
    "success": false,
    "honeypot_type": "ftp",
    "severity": "medium"
  }'

print_status "✅ Données de test insérées"

# Attendre l'indexation
sleep 3

# Vérifier l'indexation
print_info "Vérification de l'indexation..."
COWRIE_COUNT=$(curl -s "$ES_URL/honeypot-cowrie-*/_count" | jq -r '.count')
HTTP_COUNT=$(curl -s "$ES_URL/honeypot-http-*/_count" | jq -r '.count')
FTP_COUNT=$(curl -s "$ES_URL/honeypot-ftp-*/_count" | jq -r '.count')

echo "   • Cowrie: $COWRIE_COUNT documents"
echo "   • HTTP: $HTTP_COUNT documents"
echo "   • FTP: $FTP_COUNT documents"

# ================================
# SCRIPT DE MONITORING
# ================================

print_status "Création du script de monitoring des indices..."

cat > /opt/elk-scripts/monitor_indices.sh << 'EOF'
#!/bin/bash
echo "=== MONITORING DES INDICES HONEYPOT ==="
echo ""

ES_URL="http://192.168.2.124:9200"

echo "📊 ÉTAT DU CLUSTER:"
curl -s "$ES_URL/_cluster/health?pretty" | jq '{status, number_of_nodes, active_primary_shards, active_shards}'

echo ""
echo "📈 INDICES HONEYPOT:"
curl -s "$ES_URL/_cat/indices/honeypot-*?v&s=index"

echo ""
echo "🔢 NOMBRE DE DOCUMENTS:"
for type in cowrie http ftp; do
    count=$(curl -s "$ES_URL/honeypot-$type-*/_count" | jq -r '.count')
    echo "   • $type: $count documents"
done

total=$(curl -s "$ES_URL/honeypot-*/_count" | jq -r '.count')
echo "   • TOTAL: $total documents"

echo ""
echo "📝 ALIAS CONFIGURÉS:"
curl -s "$ES_URL/_cat/aliases/honeypot-*?v"

echo ""
echo "🔍 DERNIERS ÉVÉNEMENTS (par type):"
echo ""
echo "SSH/Cowrie:"
curl -s "$ES_URL/honeypot-cowrie-*/_search?size=2&sort=@timestamp:desc&_source=@timestamp,eventid,src_ip" | jq -r '.hits.hits[]._source | "\(.["@timestamp"]) - \(.eventid) - \(.src_ip)"' 2>/dev/null || echo "Aucun événement"

echo ""
echo "HTTP:"
curl -s "$ES_URL/honeypot-http-*/_search?size=2&sort=@timestamp:desc&_source=@timestamp,attack_type,ip" | jq -r '.hits.hits[]._source | "\(.["@timestamp"]) - \(.attack_type) - \(.ip)"' 2>/dev/null || echo "Aucun événement"

echo ""
echo "FTP:"
curl -s "$ES_URL/honeypot-ftp-*/_search?size=2&sort=@timestamp:desc&_source=@timestamp,event_type,ip" | jq -r '.hits.hits[]._source | "\(.["@timestamp"]) - \(.event_type) - \(.ip)"' 2>/dev/null || echo "Aucun événement"
EOF

chmod +x /opt/elk-scripts/monitor_indices.sh

# ================================
# NETTOYAGE
# ================================

rm -f /tmp/*_template.json

# ================================
# RÉSUMÉ
# ================================

echo ""
print_status "=== ÉTAPE 5.4 TERMINÉE AVEC SUCCÈS ==="
echo ""
print_info "✅ TEMPLATES D'INDICES:"
echo "   • honeypot-cowrie-* (SSH/Cowrie)"
echo "   • honeypot-http-* (HTTP attacks)"
echo "   • honeypot-ftp-* (FTP interactions)"
echo ""
print_info "✅ INDICES INITIAUX:"
echo "   • honeypot-cowrie-$TODAY"
echo "   • honeypot-http-$TODAY"
echo "   • honeypot-ftp-$TODAY"
echo ""
print_info "✅ ALIAS CONFIGURÉS:"
echo "   • honeypot-ssh → honeypot-cowrie-*"
echo "   • honeypot-web → honeypot-http-*"
echo "   • honeypot-file → honeypot-ftp-*"
echo "   • honeypot-all → honeypot-*"
echo ""
print_info "✅ DONNÉES DE TEST:"
echo "   • $COWRIE_COUNT documents Cowrie"
echo "   • $HTTP_COUNT documents HTTP"
echo "   • $FTP_COUNT documents FTP"
echo ""
print_warning "🚀 PROCHAINE ÉTAPE :"
echo "5.5 Développement des pipelines Logstash"
echo ""
print_info "🔧 SCRIPT DE MONITORING :"
echo "/opt/elk-scripts/monitor_indices.sh"
echo ""
print_info "🌐 ELASTICSEARCH :"
echo "http://192.168.2.124:9200"

echo "$(date): Configuration indices Elasticsearch (5.4) terminée" >> /var/log/elk-setup/install.log