#!/bin/bash

# Configuration des alertes Elasticsearch pour honeypot
ELK_HOST="192.168.2.124:9200"

echo "🚨 Configuration des alertes ELK Honeypot..."

# 1. Alerte attaque par force brute (plus de 10 tentatives en 5 minutes)
curl -X PUT "http://${ELK_HOST}/_watcher/watch/brute_force_alert" \
  -H 'Content-Type: application/json' \
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
                {
                  "range": {
                    "@timestamp": {
                      "gte": "now-5m"
                    }
                  }
                },
                {
                  "terms": {
                    "event_type": ["auth_attempt", "brute_force_detected"]
                  }
                }
              ]
            }
          },
          "aggs": {
            "attacks_by_ip": {
              "terms": {
                "field": "ip.keyword",
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
      "ctx.payload.aggregations.attacks_by_ip.buckets.length": {
        "gt": 0
      }
    }
  },
  "actions": {
    "log_alert": {
      "logging": {
        "level": "warn",
        "text": "🚨 ATTAQUE FORCE BRUTE DÉTECTÉE: {{ctx.payload.aggregations.attacks_by_ip.buckets.0.key}} avec {{ctx.payload.aggregations.attacks_by_ip.buckets.0.doc_count}} tentatives"
      }
    }
  }
}'

echo "✅ Alerte force brute configurée"