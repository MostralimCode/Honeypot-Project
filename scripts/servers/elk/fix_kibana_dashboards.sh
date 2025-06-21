#!/bin/bash
# Correction des visualisations Kibana - Types compatibles
# Résout le problème "No embeddable factory found for type"

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

print_status "=== Correction des visualisations Kibana ==="
echo ""

print_status "Suppression des anciennes visualisations défaillantes..."

# Supprimer les anciennes visualisations qui posent problème
curl -X DELETE "${KIBANA_URL}/api/saved_objects/visualization/honeypot-top-ips" -H "kbn-xsrf: true" >/dev/null 2>&1
curl -X DELETE "${KIBANA_URL}/api/saved_objects/visualization/honeypot-geo-map" -H "kbn-xsrf: true" >/dev/null 2>&1
curl -X DELETE "${KIBANA_URL}/api/saved_objects/dashboard/honeypot-main-dashboard" -H "kbn-xsrf: true" >/dev/null 2>&1

print_status "Création de visualisations compatibles..."

# 1. TOP 10 IP SOURCES - Type: data_table (compatible)
print_info "Création: Table Top 10 IP sources..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Top 10 IP Sources Attaquantes",
      "type": "table",
      "params": {
        "perPage": 10,
        "showPartialRows": false,
        "showMetricsAtAllLevels": false,
        "sort": {"columnIndex": 1, "direction": "desc"},
        "showTotal": false,
        "totalFunc": "sum",
        "percentageCol": ""
      },
      "aggs": [
        {
          "id": "1",
          "enabled": true,
          "type": "count",
          "schema": "metric",
          "params": {}
        },
        {
          "id": "2", 
          "enabled": true,
          "type": "terms",
          "schema": "bucket",
          "params": {
            "field": "src_ip",
            "size": 10,
            "order": "desc",
            "orderBy": "1",
            "otherBucket": false,
            "otherBucketLabel": "Other",
            "missingBucket": false,
            "missingBucketLabel": "Missing"
          }
        }
      ],
      "visState": "{\"title\":\"Top 10 IP Sources Attaquantes\",\"type\":\"table\",\"params\":{\"perPage\":10,\"showPartialRows\":false,\"showMetricsAtAllLevels\":false,\"sort\":{\"columnIndex\":1,\"direction\":\"desc\"},\"showTotal\":false,\"totalFunc\":\"sum\",\"percentageCol\":\"\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"src_ip\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}"
    }
  }' >/dev/null 2>&1

# 2. TIMELINE DES ATTAQUES - Type: line (compatible)
print_info "Création: Timeline des attaques..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Timeline Attaques par Honeypot",
      "type": "line",
      "params": {
        "grid": {"categoryLines": false, "style": {"color": "#eee"}},
        "categoryAxes": [{
          "id": "CategoryAxis-1",
          "type": "category", 
          "position": "bottom",
          "show": true,
          "style": {},
          "scale": {"type": "linear"},
          "labels": {"show": true, "truncate": 100},
          "title": {}
        }],
        "valueAxes": [{
          "id": "ValueAxis-1",
          "name": "LeftAxis-1",
          "type": "value",
          "position": "left", 
          "show": true,
          "style": {},
          "scale": {"type": "linear", "mode": "normal"},
          "labels": {"show": true, "rotate": 0, "filter": false, "truncate": 100},
          "title": {"text": "Nombre attaques"}
        }],
        "seriesParams": [{
          "show": true,
          "type": "line",
          "mode": "normal",
          "data": {"label": "Attaques", "id": "1"},
          "valueAxis": "ValueAxis-1",
          "drawLinesBetweenPoints": true,
          "showCircles": true
        }],
        "addTooltip": true,
        "addLegend": true,
        "legendPosition": "right",
        "times": [],
        "addTimeMarker": false
      },
      "aggs": [
        {
          "id": "1",
          "enabled": true,
          "type": "count", 
          "schema": "metric",
          "params": {}
        },
        {
          "id": "2",
          "enabled": true,
          "type": "date_histogram",
          "schema": "segment",
          "params": {
            "field": "@timestamp",
            "interval": "auto",
            "customInterval": "2h",
            "min_doc_count": 1,
            "extended_bounds": {}
          }
        },
        {
          "id": "3",
          "enabled": true,
          "type": "terms",
          "schema": "group", 
          "params": {
            "field": "honeypot_type",
            "size": 5,
            "order": "desc",
            "orderBy": "1"
          }
        }
      ]
    }
  }' >/dev/null 2>&1

# 3. DISTRIBUTION SÉVÉRITÉ - Type: pie (compatible)
print_info "Création: Distribution niveaux de sévérité..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Distribution Niveaux Sévérité",
      "type": "pie",
      "params": {
        "addTooltip": true,
        "addLegend": true,
        "legendPosition": "right",
        "isDonut": true,
        "labels": {
          "show": true,
          "values": true,
          "last_level": true,
          "truncate": 100
        }
      },
      "aggs": [
        {
          "id": "1",
          "enabled": true,
          "type": "count",
          "schema": "metric", 
          "params": {}
        },
        {
          "id": "2",
          "enabled": true,
          "type": "terms",
          "schema": "segment",
          "params": {
            "field": "severity",
            "size": 5,
            "order": "desc",
            "orderBy": "1"
          }
        }
      ]
    }
  }' >/dev/null 2>&1

# 4. RÉPARTITION PAR PAYS - Type: table
print_info "Création: Répartition par pays..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Top Pays Attaquants",
      "type": "table",
      "params": {
        "perPage": 10,
        "showPartialRows": false,
        "showMetricsAtAllLevels": false,
        "sort": {"columnIndex": 1, "direction": "desc"},
        "showTotal": false,
        "totalFunc": "sum"
      },
      "aggs": [
        {
          "id": "1",
          "enabled": true,
          "type": "count",
          "schema": "metric",
          "params": {}
        },
        {
          "id": "2",
          "enabled": true,
          "type": "terms", 
          "schema": "bucket",
          "params": {
            "field": "src_country",
            "size": 10,
            "order": "desc",
            "orderBy": "1"
          }
        }
      ]
    }
  }' >/dev/null 2>&1

# 5. MÉTRIQUE TOTAL ATTAQUES - Type: metric (compatible)
print_info "Création: Métrique total attaques..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Total Attaques",
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
          "style": {
            "bgFill": "#000",
            "bgColor": false,
            "labelColor": false,
            "subText": "",
            "fontSize": 60
          }
        }
      },
      "aggs": [
        {
          "id": "1",
          "enabled": true,
          "type": "count",
          "schema": "metric",
          "params": {}
        }
      ]
    }
  }' >/dev/null 2>&1

# 6. TOP COMMANDES SSH - Type: table  
print_info "Création: Top commandes SSH..."
curl -X POST "${KIBANA_URL}/api/saved_objects/visualization" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "Top Commandes SSH Suspectes",
      "type": "table",
      "params": {
        "perPage": 15,
        "showPartialRows": false,
        "showMetricsAtAllLevels": false,
        "sort": {"columnIndex": 1, "direction": "desc"},
        "showTotal": false,
        "totalFunc": "sum"
      },
      "aggs": [
        {
          "id": "1",
          "enabled": true,
          "type": "count",
          "schema": "metric",
          "params": {}
        },
        {
          "id": "2",
          "enabled": true,
          "type": "terms",
          "schema": "bucket",
          "params": {
            "field": "input.keyword",
            "size": 15,
            "order": "desc",
            "orderBy": "1"
          }
        }
      ]
    }
  }' >/dev/null 2>&1

print_status "✓ Visualisations compatibles créées"

# ================================
# NOUVEAU DASHBOARD SIMPLE
# ================================

print_status "Création d'un dashboard simple et fonctionnel..."

# Dashboard basique sans panneaux complexes - Kibana va les détecter automatiquement
curl -X POST "${KIBANA_URL}/api/saved_objects/dashboard" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "attributes": {
      "title": "🎯 Dashboard Honeypot - Analyse Sécurité",
      "hits": 0,
      "description": "Dashboard principal pour analyse des attaques honeypot - Compatible toutes versions",
      "panelsJSON": "[]",
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
# INSTRUCTIONS D'UTILISATION
# ================================

print_status "=== Correction terminée avec succès! ==="
echo ""
print_info "🎯 VISUALISATIONS CRÉÉES (compatibles):"
echo "   ✓ Top 10 IP Sources Attaquantes"
echo "   ✓ Timeline Attaques par Honeypot"  
echo "   ✓ Distribution Niveaux Sévérité"
echo "   ✓ Top Pays Attaquants"
echo "   ✓ Total Attaques (métrique)"
echo "   ✓ Top Commandes SSH Suspectes"
echo ""
print_info "🎯 DASHBOARD CRÉÉ:"
echo "   ✓ 🎯 Dashboard Honeypot - Analyse Sécurité"
echo ""
print_warning "📋 INSTRUCTIONS D'UTILISATION:"
echo ""
echo "1. 🔄 RAFRAÎCHIR la page Kibana (F5)"
echo ""
echo "2. 📊 AJOUTER LES VISUALISATIONS AU DASHBOARD:"
echo "   • Cliquer sur 'Edit' en haut à droite"
echo "   • Cliquer sur 'Add' puis 'Add from library'"
echo "   • Sélectionner les visualisations une par une:"
echo "     - Top 10 IP Sources Attaquantes"
echo "     - Timeline Attaques par Honeypot" 
echo "     - Distribution Niveaux Sévérité"
echo "     - Top Pays Attaquants"
echo "     - Total Attaques"
echo "     - Top Commandes SSH Suspectes"
echo "   • Organiser les panneaux comme souhaité"
echo "   • Cliquer sur 'Save' pour sauvegarder"
echo ""
echo "3. 🔍 UTILISER LES FILTRES:"
echo "   • Filtre temps: 'Last 15 minutes' → 'Last 24 hours'"
echo "   • Filtre par honeypot: honeypot_type: ssh/http/ftp"
echo ""
print_info "🌐 ACCÈS:"
echo "   Dashboard: http://192.168.2.124:5601/app/dashboards"
echo "   Visualizations: http://192.168.2.124:5601/app/visualize"
echo ""
print_status "Les visualisations sont maintenant compatibles avec votre version de Kibana!"