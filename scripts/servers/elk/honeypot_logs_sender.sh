#!/bin/bash
# Script d'envoi automatique des logs honeypot vers Logstash TCP - VERSION CORRIGÉE
# VM Honeypot: 192.168.2.117 → VM ELK: 192.168.2.124:5046

LOGSTASH_HOST="192.168.2.124"
LOGSTASH_PORT="5046"
LOG_DIR="/var/log/honeypot-sender"
POSITION_FILE="$LOG_DIR/positions.txt"

# Créer le répertoire de logs
mkdir -p "$LOG_DIR"

# Fonction d'envoi sécurisée
send_log() {
    local log_entry="$1"
    
    # Vérifier que c'est du JSON valide avant envoi
    if echo "$log_entry" | jq . >/dev/null 2>&1; then
        echo "$log_entry" | nc -w 2 "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S'): SUCCESS - Sent log for $(echo "$log_entry" | jq -r '.honeypot_type // "unknown"')" >> "$LOG_DIR/sent.log"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S'): NETWORK_ERROR - Failed to send" >> "$LOG_DIR/failed.log"
        fi
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S'): JSON_ERROR - Invalid JSON: $log_entry" >> "$LOG_DIR/failed.log"
    fi
}

# Fonction de nettoyage de chaîne pour JSON
clean_string() {
    local input="$1"
    # Échapper les caractères spéciaux JSON et supprimer les caractères de contrôle
    echo "$input" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g' | tr -d '\000-\010\013\014\016-\037'
}

# Fonction de lecture avec position
read_from_position() {
    local file="$1"
    local position_key="$2"
    
    if [ ! -f "$file" ]; then
        return
    fi
    
    # Récupérer la dernière position
    local last_pos=$(grep "^$position_key:" "$POSITION_FILE" 2>/dev/null | cut -d: -f2)
    if [ -z "$last_pos" ]; then
        last_pos=0
    fi
    
    # Lire depuis la position
    local current_lines=$(wc -l < "$file" 2>/dev/null || echo "0")
    
    if [ "$current_lines" -gt "$last_pos" ]; then
        tail -n +$((last_pos + 1)) "$file" | head -n $((current_lines - last_pos))
        
        # Mettre à jour la position
        grep -v "^$position_key:" "$POSITION_FILE" 2>/dev/null > "$POSITION_FILE.tmp" || touch "$POSITION_FILE.tmp"
        echo "$position_key:$current_lines" >> "$POSITION_FILE.tmp"
        mv "$POSITION_FILE.tmp" "$POSITION_FILE"
    fi
}

# CONFIGURATION DES SOURCES DE LOGS
declare -A LOG_SOURCES=(
    # Cowrie SSH
    ["/home/cowrie/cowrie/var/log/cowrie/cowrie.json"]="ssh:cowrie:json"
    
    # HTTP Honeypot
    ["/var/log/honeypot/http_honeypot.log"]="http:main:json"
    ["/var/log/honeypot/api_access.log"]="http:api:json"
    ["/var/log/honeypot/sql_injection.log"]="http:sql:json"
    ["/var/log/honeypot/critical_alerts.log"]="http:critical:json"
    ["/var/log/honeypot/sql_error.log"]="http:error:json"
    
    # FTP Honeypot
    ["/root/honeypot-ftp/logs/sessions.json"]="ftp:sessions:json"
    ["/root/honeypot-ftp/logs/auth_attempts.log"]="ftp:auth:text"
    ["/root/honeypot-ftp/logs/commands.log"]="ftp:commands:text"
    ["/root/honeypot-ftp/logs/security_events.log"]="ftp:security:text"
    ["/root/honeypot-ftp/logs/transfers.log"]="ftp:transfers:text"
)

echo "$(date '+%Y-%m-%d %H:%M:%S'): Starting honeypot log sender" >> "$LOG_DIR/sender.log"

# Test de connectivité initial
if ! nc -z "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S'): ERROR - Cannot connect to Logstash at $LOGSTASH_HOST:$LOGSTASH_PORT" >> "$LOG_DIR/sender.log"
    sleep 30
fi

# Boucle principale
while true; do
    for log_file in "${!LOG_SOURCES[@]}"; do
        if [ -f "$log_file" ] && [ -r "$log_file" ]; then
            IFS=':' read -r honeypot_type service log_format <<< "${LOG_SOURCES[$log_file]}"
            position_key=$(echo "$log_file" | sed 's/[^a-zA-Z0-9]/_/g')
            
            # Lire les nouvelles lignes
            read_from_position "$log_file" "$position_key" | while IFS= read -r line; do
                if [ -n "$line" ] && [ "$line" != "null" ]; then
                    current_timestamp=$(date -Iseconds)
                    
                    if [ "$log_format" = "json" ]; then
                        # Vérifier si c'est déjà du JSON valide
                        if echo "$line" | jq . >/dev/null 2>&1; then
                            # JSON valide, ajouter métadonnées
                            enhanced_log=$(echo "$line" | jq --arg ht "$honeypot_type" --arg svc "$service" --arg vm "192.168.2.117" --arg ts "$current_timestamp" '. + {
                                honeypot_type: $ht,
                                honeypot_service: $svc,
                                source_vm: $vm,
                                processed_timestamp: $ts,
                                log_format: "json"
                            }')
                            
                            if [ $? -eq 0 ] && [ -n "$enhanced_log" ]; then
                                send_log "$enhanced_log"
                            else
                                echo "$(date '+%Y-%m-%d %H:%M:%S'): JQ_ERROR - Failed to enhance JSON from $log_file" >> "$LOG_DIR/failed.log"
                            fi
                        else
                            # JSON invalide ou malformé, encapsuler en sécurité
                            clean_message=$(clean_string "$line")
                            fallback_json="{
                                \"honeypot_type\": \"$honeypot_type\",
                                \"honeypot_service\": \"$service\",
                                \"source_vm\": \"192.168.2.117\",
                                \"log_format\": \"json_fallback\",
                                \"raw_message\": \"$clean_message\",
                                \"timestamp\": \"$current_timestamp\",
                                \"processing_note\": \"Original JSON was malformed\"
                            }"
                            
                            # Compacter le JSON
                            compact_json=$(echo "$fallback_json" | jq -c .)
                            if [ $? -eq 0 ]; then
                                send_log "$compact_json"
                            else
                                echo "$(date '+%Y-%m-%d %H:%M:%S'): FALLBACK_ERROR - Could not create fallback JSON for: $line" >> "$LOG_DIR/failed.log"
                            fi
                        fi
                    else
                        # Pour les logs texte, créer un JSON propre
                        clean_message=$(clean_string "$line")
                        text_json="{
                            \"honeypot_type\": \"$honeypot_type\",
                            \"honeypot_service\": \"$service\",
                            \"source_vm\": \"192.168.2.117\",
                            \"log_format\": \"text\",
                            \"message\": \"$clean_message\",
                            \"timestamp\": \"$current_timestamp\"
                        }"
                        
                        # Compacter le JSON
                        compact_json=$(echo "$text_json" | jq -c .)
                        if [ $? -eq 0 ]; then
                            send_log "$compact_json"
                        else
                            echo "$(date '+%Y-%m-%d %H:%M:%S'): TEXT_JSON_ERROR - Could not create JSON for text log: $line" >> "$LOG_DIR/failed.log"
                        fi
                    fi
                fi
            done
        elif [ ! -f "$log_file" ]; then
            # Log au démarrage seulement
            if [ ! -f "$LOG_DIR/.missing_logged" ]; then
                echo "$(date '+%Y-%m-%d %H:%M:%S'): WARNING - Log file missing: $log_file" >> "$LOG_DIR/sender.log"
                touch "$LOG_DIR/.missing_logged"
            fi
        fi
    done
    
    # Nettoyage périodique des logs (garder 7 jours)
    find "$LOG_DIR" -name "*.log" -mtime +7 -delete 2>/dev/null
    
    # Attendre avant la prochaine vérification
    sleep 5
done