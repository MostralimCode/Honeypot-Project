#!/bin/bash
# scripts/elk/configure_elasticsearch_indices.sh
# Configuration des indices Elasticsearch pour les honeypots
# Étape 5.4 du projet

# Variables
ES_HOST="192.168.2.124"
ES_PORT="9200"
ES_URL="http://${ES_HOST}:${ES_PORT}"

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

# Vérification Elasticsearch
check_elasticsearch() {
    print_status "Vérification de la connexion à Elasticsearch..."
    
    if curl -s "$ES_URL" >/dev/null 2>&1; then
        print_status "✓ Elasticsearch accessible sur $ES_URL"
        
        # Afficher la version
        ES_VERSION=$(curl -s "$ES_URL" | jq -r '.version.number' 2>/dev/null)
        print_info "Version Elasticsearch: $ES_VERSION"
        
        # Afficher le statut du cluster
        CLUSTER_STATUS=$(curl -s "$ES_URL/_cluster/health" | jq -r '.status' 2>/dev/null)
        print_info "Statut cluster: $CLUSTER_STATUS"
        
    else
        print_error "✗ Elasticsearch non accessible sur $ES_URL"
        print_error "Vérifiez que le service est démarré et accessible"
        exit 1
    fi
}

# Fonction pour créer un template d'index
create_index_template() {
    local template_name=$1
    local index_pattern=$2
    local template_config=$3
    
    print_status "Création du template '$template_name' pour '$index_pattern'..."
    
    response=$(curl -s -w "%{http_code}" -X PUT "$ES_URL/_index_template/$template_name" \
        -H "Content-Type: application/json" \
        -d "$template_config")
    
    http_code="${response: -3}"
    
    if [ "$http_code" = "200" ]; then
        print_status "✓ Template '$template_name' créé avec succès"
    else
        print_error "✗ Échec création template '$template_name' (Code: $http_code)"
        echo "$response" | head -c -3
    fi
}

print_status "=== Configuration des indices Elasticsearch pour Honeypots ==="
echo ""

# Vérifier Elasticsearch
check_elasticsearch

echo ""
print_status "=== Création des templates d'indices ==="

# ================================
# TEMPLATE 1: HONEYPOT COWRIE (SSH)
# ================================

print_status "Configuration template Cowrie SSH..."

COWRIE_TEMPLATE='{
  "index_patterns": ["honeypot-cowrie-*"],
  "priority": 500,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "5s",
      "index.lifecycle.name": "honeypot-policy",
      "index.codec": "best_compression"
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "timestamp": {
          "type": "date"
        },
        "eventid": {
          "type": "keyword"
        },
        "src_ip": {
          "type": "ip"
        },
        "src_port": {
          "type": "integer"
        },
        "dst_ip": {
          "type": "ip"
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
          "type": "text",
          "analyzer": "standard"
        },
        "input": {
          "type": "text",
          "analyzer": "standard"
        },
        "command": {
          "type": "text",
          "analyzer": "standard"
        },
        "protocol": {
          "type": "keyword"
        },
        "version": {
          "type": "keyword"
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
        "alert_level": {
          "type": "integer"
        },
        "event_category": {
          "type": "keyword"
        },
        "suspicious_command": {
          "type": "boolean"
        },
        "session_id": {
          "type": "keyword"
        },
        "filename": {
          "type": "keyword"
        },
        "size": {
          "type": "long"
        },
        "url": {
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
            "region_name": {
              "type": "keyword"
            }
          }
        }
      }
    }
  }
}'

create_index_template "honeypot-cowrie" "honeypot-cowrie-*" "$COWRIE_TEMPLATE"

# ================================
# TEMPLATE 2: HONEYPOT HTTP
# ================================

print_status "Configuration template HTTP Honeypot..."

HTTP_TEMPLATE='{
  "index_patterns": ["honeypot-http-*"],
  "priority": 500,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "5s",
      "index.lifecycle.name": "honeypot-policy",
      "index.codec": "best_compression"
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "timestamp": {
          "type": "date"
        },
        "ip": {
          "type": "ip"
        },
        "src_ip": {
          "type": "ip"
        },
        "user_agent": {
          "type": "text",
          "analyzer": "standard"
        },
        "method": {
          "type": "keyword"
        },
        "url": {
          "type": "keyword"
        },
        "path": {
          "type": "keyword"
        },
        "query_string": {
          "type": "text"
        },
        "status_code": {
          "type": "integer"
        },
        "response_size": {
          "type": "integer"
        },
        "referer": {
          "type": "keyword"
        },
        "attack_type": {
          "type": "keyword"
        },
        "attack_category": {
          "type": "keyword"
        },
        "payload": {
          "type": "text",
          "analyzer": "standard"
        },
        "honeypot_type": {
          "type": "keyword"
        },
        "honeypot_service": {
          "type": "keyword"
        },
        "severity": {
          "type": "keyword"
        },
        "alert_level": {
          "type": "integer"
        },
        "event_category": {
          "type": "keyword"
        },
        "vulnerable_endpoint": {
          "type": "keyword"
        },
        "sql_injection_detected": {
          "type": "boolean"
        },
        "xss_detected": {
          "type": "boolean"
        },
        "path_traversal_detected": {
          "type": "boolean"
        },
        "file_upload_detected": {
          "type": "boolean"
        },
        "session_id": {
          "type": "keyword"
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
            },
            "region_name": {
              "type": "keyword"
            }
          }
        }
      }
    }
  }
}'

create_index_template "honeypot-http" "honeypot-http-*" "$HTTP_TEMPLATE"

# ================================
# TEMPLATE 3: HONEYPOT FTP
# ================================

print_status "Configuration template FTP Honeypot..."

FTP_TEMPLATE='{
  "index_patterns": ["honeypot-ftp-*"],
  "priority": 500,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "5s",
      "index.lifecycle.name": "honeypot-policy",
      "index.codec": "best_compression"
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "timestamp": {
          "type": "date"
        },
        "src_ip": {
          "type": "ip"
        },
        "src_port": {
          "type": "integer"
        },
        "dst_port": {
          "type": "integer"
        },
        "session_id": {
          "type": "keyword"
        },
        "username": {
          "type": "keyword"
        },
        "password": {
          "type": "text",
          "analyzer": "standard"
        },
        "command": {
          "type": "keyword"
        },
        "command_arg": {
          "type": "text"
        },
        "response": {
          "type": "text"
        },
        "event_type": {
          "type": "keyword"
        },
        "success": {
          "type": "boolean"
        },
        "filename": {
          "type": "keyword"
        },
        "filesize": {
          "type": "long"
        },
        "transfer_type": {
          "type": "keyword"
        },
        "honeypot_type": {
          "type": "keyword"
        },
        "severity": {
          "type": "keyword"
        },
        "alert_level": {
          "type": "integer"
        },
        "event_category": {
          "type": "keyword"
        },
        "auth_method": {
          "type": "keyword"
        },
        "vulnerability_exploited": {
          "type": "keyword"
        },
        "malicious_file": {
          "type": "boolean"
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
            "region_name": {
              "type": "keyword"
            }
          }
        }
      }
    }
  }
}'

create_index_template "honeypot-ftp" "honeypot-ftp-*" "$FTP_TEMPLATE"

# ================================
# TEMPLATE 4: SERVEURS SÉCURISÉS
# ================================

print_status "Configuration template serveurs sécurisés..."

SECURE_TEMPLATE='{
  "index_patterns": ["secure-servers-*"],
  "priority": 500,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "10s",
      "index.lifecycle.name": "secure-policy"
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "timestamp": {
          "type": "date"
        },
        "host": {
          "type": "keyword"
        },
        "program": {
          "type": "keyword"
        },
        "pid": {
          "type": "integer"
        },
        "message": {
          "type": "text"
        },
        "src_ip": {
          "type": "ip"
        },
        "auth_result": {
          "type": "keyword"
        },
        "username": {
          "type": "keyword"
        },
        "service": {
          "type": "keyword"
        },
        "infrastructure": {
          "type": "keyword"
        },
        "severity": {
          "type": "keyword"
        },
        "event_type": {
          "type": "keyword"
        }
      }
    }
  }
}'

create_index_template "secure-servers" "secure-servers-*" "$SECURE_TEMPLATE"

# ================================
# POLITIQUE ILM (INDEX LIFECYCLE MANAGEMENT)
# ================================

print_status "Configuration des politiques ILM..."

# Politique pour les honeypots (conservation plus longue)
HONEYPOT_ILM_POLICY='{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_size": "1GB",
            "max_age": "7d"
          },
          "set_priority": {
            "priority": 100
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "set_priority": {
            "priority": 50
          },
          "allocate": {
            "number_of_replicas": 0
          }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "set_priority": {
            "priority": 0
          }
        }
      },
      "delete": {
        "min_age": "90d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'

response=$(curl -s -w "%{http_code}" -X PUT "$ES_URL/_ilm/policy/honeypot-policy" \
    -H "Content-Type: application/json" \
    -d "$HONEYPOT_ILM_POLICY")

http_code="${response: -3}"
if [ "$http_code" = "200" ]; then
    print_status "✓ Politique ILM honeypot-policy créée"
else
    print_warning "⚠ Politique ILM honeypot-policy: $http_code"
fi

# Politique pour serveurs sécurisés (conservation standard)
SECURE_ILM_POLICY='{
  "policy": {
    "phases": {
      "hot": {
        "min_age": "0ms",
        "actions": {
          "rollover": {
            "max_size": "500MB",
            "max_age": "3d"
          }
        }
      },
      "warm": {
        "min_age": "3d",
        "actions": {
          "allocate": {
            "number_of_replicas": 0
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'

response=$(curl -s -w "%{http_code}" -X PUT "$ES_URL/_ilm/policy/secure-policy" \
    -H "Content-Type: application/json" \
    -d "$SECURE_ILM_POLICY")

http_code="${response: -3}"
if [ "$http_code" = "200" ]; then
    print_status "✓ Politique ILM secure-policy créée"
else
    print_warning "⚠ Politique ILM secure-policy: $http_code"
fi

# ================================
# CRÉATION D'INDICES INITIAUX
# ================================

print_status "Création des premiers indices pour tester les templates..."

today=$(date +%Y.%m.%d)

# Créer des indices de test pour valider les templates
for index_type in cowrie http ftp; do
    index_name="honeypot-${index_type}-${today}"
    
    response=$(curl -s -w "%{http_code}" -X PUT "$ES_URL/$index_name" \
        -H "Content-Type: application/json" \
        -d '{"settings": {"number_of_shards": 1, "number_of_replicas": 0}}')
    
    http_code="${response: -3}"
    if [ "$http_code" = "200" ]; then
        print_status "✓ Index $index_name créé"
    else
        print_warning "⚠ Index $index_name: $http_code"
    fi
done

# Index pour serveurs sécurisés
response=$(curl -s -w "%{http_code}" -X PUT "$ES_URL/secure-servers-${today}" \
    -H "Content-Type: application/json" \
    -d '{"settings": {"number_of_shards": 1, "number_of_replicas": 0}}')

http_code="${response: -3}"
if [ "$http_code" = "200" ]; then
    print_status "✓ Index secure-servers-${today} créé"
else
    print_warning "⚠ Index secure-servers-${today}: $http_code"
fi

# ================================
# VÉRIFICATIONS ET RÉSUMÉ
# ================================

print_status "Vérification des templates créés..."

templates=$(curl -s "$ES_URL/_index_template" | jq -r '.index_templates[].name' | grep -E "(honeypot|secure)" | sort)

print_info "Templates d'indices configurés:"
for template in $templates; do
    echo "  ✓ $template"
done

echo ""
print_status "Vérification des indices créés..."

indices=$(curl -s "$ES_URL/_cat/indices/honeypot-*,secure-*?h=index" | sort)

print_info "Indices disponibles:"
for index in $indices; do
    echo "  ✓ $index"
done

echo ""
print_status "Vérification des politiques ILM..."

policies=$(curl -s "$ES_URL/_ilm/policy" | jq -r 'keys[]' | grep -E "(honeypot|secure)" | sort)

print_info "Politiques ILM configurées:"
for policy in $policies; do
    echo "  ✓ $policy"
done

echo ""
print_status "=== Configuration des indices Elasticsearch terminée! ==="
echo ""
print_info "📊 RÉSUMÉ DE LA CONFIGURATION:"
echo "   ✓ Templates d'indices: honeypot-cowrie, honeypot-http, honeypot-ftp, secure-servers"
echo "   ✓ Politiques ILM: honeypot-policy (90j), secure-policy (30j)"
echo "   ✓ Mappings optimisés pour chaque type de honeypot"
echo "   ✓ Configuration géoIP et enrichissement prête"
echo ""
print_info "🔧 CARACTÉRISTIQUES:"
echo "   • Shards: 1 par index (optimisé single-node)"
echo "   • Replicas: 0 (environnement développement)"
echo "   • Compression: best_compression"
echo "   • Refresh: 5s (honeypots), 10s (serveurs)"
echo ""
print_warning "📋 PROCHAINES ÉTAPES:"
echo "1. Configurer les pipelines Logstash (étape 5.5)"
echo "2. Vérifier l'ingestion des données"
echo "3. Créer les tableaux de bord Kibana"
echo ""
print_info "🔍 COMMANDES UTILES:"
echo "   Lister indices: curl $ES_URL/_cat/indices?v"
echo "   Voir templates: curl $ES_URL/_index_template"
echo "   Stats cluster: curl $ES_URL/_cluster/health?pretty"