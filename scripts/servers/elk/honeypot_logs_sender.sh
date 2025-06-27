#!/bin/bash
# Script d'envoi automatique des logs honeypot vers Logstash TCP - VERSION ADAPTÉE
# VM Honeypot: 192.168.2.117 → VM ELK: 192.168.2.124:5046
# Traite spécifiquement chaque format de log

LOGSTASH_HOST="192.168.2.124"
LOGSTASH_PORT="5046"
LOG_DIR="/var/log/honeypot-sender"
POSITION_FILE="$LOG_DIR/positions.txt"

# Créer le répertoire de logs
mkdir -p "$LOG_DIR"

# Fonction d'envoi sécurisée
send_log() {
    local log_entry="$1"
    local source_info="$2"
    
    # Vérifier que ce n'est pas juste une accolade
    if [ "$log_entry" = "{" ] || [ "$log_entry" = "}" ] || [ ${#log_entry} -lt 10 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'): REJECTED - Too short: $log_entry" >> "$LOG_DIR/rejected.log"
        return
    fi
    
    # Vérifier que c'est du JSON valide avant envoi
    if echo "$log_entry" | jq . >/dev/null 2>&1; then
        echo "$log_entry" | nc -w 2 "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S'): SUCCESS - $source_info" >> "$LOG_DIR/sent.log"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S'): NETWORK_ERROR - $source_info" >> "$LOG_DIR/failed.log"
        fi
    else
        echo "$(date '+%Y-%m-%d %H:%M:%S'): JSON_ERROR - $source_info - $log_entry" >> "$LOG_DIR/failed.log"
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

# Traitement spécialisé pour les logs FTP texte
process_ftp_text() {
    local line="$1"
    local service="$2"
    local current_timestamp="$3"
    
    # Format FTP: 2025-05-05 16:56:52 - INFO - Auth SUCCESS - 127.0.0.1 - admin
    if [[ "$line" =~ ^([0-9-]+\ [0-9:]+)\ -\ ([A-Z]+)\ -\ (.+)\ -\ ([0-9.]+)\ -\ (.+)$ ]]; then
        local log_date="${BASH_REMATCH[1]}"
        local log_level="${BASH_REMATCH[2]}"
        local log_action="${BASH_REMATCH[3]}"
        local log_ip="${BASH_REMATCH[4]}"
        local log_user="${BASH_REMATCH[5]}"
        
        local json_log="{
            \"honeypot_type\": \"ftp\",
            \"honeypot_service\": \"$service\",
            \"source_vm\": \"192.168.2.117\",
            \"log_format\": \"ftp_text\",
            \"timestamp\": \"$current_timestamp\",
            \"original_timestamp\": \"$log_date\",
            \"level\": \"$log_level\",
            \"action\": \"$log_action\",
            \"ip\": \"$log_ip\",
            \"username\": \"$log_user\",
            \"message\": \"$(clean_string "$line")\"
        }"
        
        compact_json=$(echo "$json_log" | jq -c .)
        if [ $? -eq 0 ]; then
            send_log "$compact_json" "FTP_TEXT[$service]"
        fi
    else
        # Format non reconnu, encapsuler simplement
        local fallback_json="{
            \"honeypot_type\": \"ftp\",
            \"honeypot_service\": \"$service\",
            \"source_vm\": \"192.168.2.117\",
            \"log_format\": \"ftp_text_fallback\",
            \"timestamp\": \"$current_timestamp\",
            \"message\": \"$(clean_string "$line")\"
        }"
        
        compact_json=$(echo "$fallback_json" | jq -c .)
        if [ $? -eq 0 ]; then
            send_log "$compact_json" "FTP_TEXT_FALLBACK[$service]"
        fi
    fi
}

# CONFIGURATION DES SOURCES DE LOGS AVEC TYPES SPÉCIALISÉS
declare -A LOG_SOURCES=(
    # Cowrie SSH - JSON spécialisé
    ["/home/cowrie/cowrie/var/log/cowrie/cowrie.json"]="ssh:cowrie:cowrie_json"
    ["/home/cowrie/cowrie/var/log/cowrie/cowrie.json.1"]="ssh:cowrie:cowrie_json"
    
    # HTTP Honeypot - JSON spécialisé
    ["/var/log/honeypot/http_honeypot.log"]="http:main:http_json"
    ["/var/log/honeypot/api_access.log"]="http:api:http_json"
    ["/var/log/honeypot/sql_injection.log"]="http:sql:http_json"
    ["/var/log/honeypot/critical_alerts.log"]="http:critical:http_json"
    ["/var/log/honeypot/sql_error.log"]="http:error:http_json"
    
    # FTP Honeypot - Mixte JSON et texte
    ["/root/honeypot-ftp/logs/sessions.json"]="ftp:sessions:ftp_json"
    ["/root/honeypot-ftp/logs/auth_attempts.log"]="ftp:auth:ftp_text"
    ["/root/honeypot-ftp/logs/commands.log"]="ftp:commands:ftp_text"
    ["/root/honeypot-ftp/logs/security_events.log"]="ftp:security:ftp_text"
    ["/root/honeypot-ftp/logs/transfers.log"]="ftp:transfers:ftp_text"
)

echo "$(date '+%Y-%m-%d %H:%M:%S'): Starting specialized honeypot log sender" >> "$LOG_DIR/sender.log"

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
                    
                    case "$log_format" in
                        "cowrie_json")
                            # Traitement spécialisé Cowrie
                            if echo "$line" | jq . >/dev/null 2>&1; then
                                enhanced_log=$(echo "$line" | jq --arg ht "$honeypot_type" --arg svc "$service" --arg vm "192.168.2.117" --arg ts "$current_timestamp" '{
                                    honeypot_type: $ht,
                                    honeypot_service: $svc,
                                    source_vm: $vm,
                                    processed_timestamp: $ts,
                                    log_format: "cowrie",
                                    cowrie_data: {
                                        eventid: .eventid,
                                        timestamp: .timestamp,
                                        src_ip: .src_ip,
                                        session: .session,
                                        message: .message
                                    },
                                    original_log: .
                                }')
                                
                                if [ $? -eq 0 ] && [ -n "$enhanced_log" ]; then
                                    send_log "$enhanced_log" "COWRIE[$service]"
                                fi
                            fi
                            ;;
                            
                        "http_json")
                            # Traitement spécialisé HTTP
                            if echo "$line" | jq . >/dev/null 2>&1; then
                                enhanced_log=$(echo "$line" | jq --arg ht "$honeypot_type" --arg svc "$service" --arg vm "192.168.2.117" --arg ts "$current_timestamp" '{
                                    honeypot_type: $ht,
                                    honeypot_service: $svc,
                                    source_vm: $vm,
                                    processed_timestamp: $ts,
                                    log_format: "http",
                                    http_data: {
                                        attack_id: .attack_id,
                                        attack_type: .attack_type,
                                        severity: .severity,
                                        ip: .ip,
                                        method: .method,
                                        path: .path,
                                        user_agent: .user_agent
                                    },
                                    original_log: .
                                }')
                                
                                if [ $? -eq 0 ] && [ -n "$enhanced_log" ]; then
                                    send_log "$enhanced_log" "HTTP[$service]"
                                fi
                            fi
                            ;;
                            
                        "ftp_json")
                            # Traitement spécialisé FTP JSON
                            if echo "$line" | jq . >/dev/null 2>&1; then
                                enhanced_log=$(echo "$line" | jq --arg ht "$honeypot_type" --arg svc "$service" --arg vm "192.168.2.117" --arg ts "$current_timestamp" '{
                                    honeypot_type: $ht,
                                    honeypot_service: $svc,
                                    source_vm: $vm,
                                    processed_timestamp: $ts,
                                    log_format: "ftp_json",
                                    ftp_data: {
                                        event_type: .event_type,
                                        session_id: .session_id,
                                        ip: .ip,
                                        username: .username,
                                        command: .command
                                    },
                                    original_log: .
                                }')
                                
                                if [ $? -eq 0 ] && [ -n "$enhanced_log" ]; then
                                    send_log "$enhanced_log" "FTP_JSON[$service]"
                                fi
                            fi
                            ;;
                            
                        "ftp_text")
                            # Traitement spécialisé FTP texte
                            process_ftp_text "$line" "$service" "$current_timestamp"
                            ;;
                            
                        *)
                            # Fallback pour autres formats
                            clean_message=$(clean_string "$line")
                            fallback_json="{
                                \"honeypot_type\": \"$honeypot_type\",
                                \"honeypot_service\": \"$service\",
                                \"source_vm\": \"192.168.2.117\",
                                \"log_format\": \"unknown\",
                                \"message\": \"$clean_message\",
                                \"timestamp\": \"$current_timestamp\"
                            }"
                            
                            compact_json=$(echo "$fallback_json" | jq -c .)
                            if [ $? -eq 0 ]; then
                                send_log "$compact_json" "FALLBACK[$service]"
                            fi
                            ;;
                    esac
                fi
            done
        fi
    done
    
    # Nettoyage périodique des logs (garder 7 jours)
    find "$LOG_DIR" -name "*.log" -mtime +7 -delete 2>/dev/null
    
    # Attendre avant la prochaine vérification
    sleep 5
done