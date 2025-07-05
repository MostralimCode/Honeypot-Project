#!/bin/bash
# Script d'envoi spécialisé par fichier - OPTIMISÉ SELON L'ACTIVITÉ RÉELLE
# VM Honeypot: 192.168.2.117 → VM ELK: 192.168.2.124:5046
# Traitement adapté à chaque format et fréquence optimisée

LOGSTASH_HOST="192.168.2.124"
LOGSTASH_PORT="5046"
LOG_DIR="/var/log/honeypot-sender"
POSITION_FILE="$LOG_DIR/positions.txt"

# Créer le répertoire de logs
mkdir -p "$LOG_DIR"

# Fonction d'envoi avec validation stricte
send_log() {
    local log_entry="$1"
    local source_info="$2"
    local log_type="$3"
    
    # Filtrer les lignes vides ou trop courtes
    if [ -z "$log_entry" ] || [ ${#log_entry} -lt 5 ]; then
        return
    fi
    
    # Vérifier que c'est du JSON valide
    if echo "$log_entry" | jq . >/dev/null 2>&1; then
        # JSON valide - envoyer directement
        echo "$log_entry" | nc -w 2 "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null
        if [ $? -eq 0 ]; then
            echo "$(date '+%Y-%m-%d %H:%M:%S'): SUCCESS [$log_type] - $source_info" >> "$LOG_DIR/sent.log"
        else
            echo "$(date '+%Y-%m-%d %H:%M:%S'): NETWORK_ERROR [$log_type] - $source_info" >> "$LOG_DIR/failed.log"
        fi
    else
        # Si pas JSON, créer un JSON approprié selon le type
        case "$log_type" in
            "ftp_text")
                create_ftp_text_json "$log_entry" "$source_info"
                ;;
            "cowrie_text")
                create_cowrie_text_json "$log_entry" "$source_info"
                ;;
            *)
                create_generic_text_json "$log_entry" "$source_info" "$log_type"
                ;;
        esac
    fi
}

# Traitement spécialisé FTP texte
create_ftp_text_json() {
    local line="$1"
    local source="$2"
    
    # Parser le format FTP: DATE - LEVEL - ACTION - IP - USER
    if [[ "$line" =~ ^([0-9-]+\ [0-9:]+)\ -\ ([A-Z]+)\ -\ (.+)\ -\ ([0-9.]+)\ -\ (.+)$ ]]; then
        local log_date="${BASH_REMATCH[1]}"
        local log_level="${BASH_REMATCH[2]}"
        local log_action="${BASH_REMATCH[3]}"
        local log_ip="${BASH_REMATCH[4]}"
        local log_user="${BASH_REMATCH[5]}"
        
        local json_log=$(jq -n \
            --arg ts "$(date -Iseconds)" \
            --arg date "$log_date" \
            --arg level "$log_level" \
            --arg action "$log_action" \
            --arg ip "$log_ip" \
            --arg user "$log_user" \
            --arg src "$source" \
            '{
                honeypot_type: "ftp",
                honeypot_service: $src,
                timestamp: $ts,
                original_timestamp: $date,
                level: $level,
                action: $action,
                ip: $ip,
                username: $user,
                log_format: "ftp_text"
            }')
    else
        # Format non reconnu FTP
        local json_log=$(jq -n \
            --arg ts "$(date -Iseconds)" \
            --arg msg "$line" \
            --arg src "$source" \
            '{
                honeypot_type: "ftp",
                honeypot_service: $src,
                timestamp: $ts,
                message: $msg,
                log_format: "ftp_text_raw"
            }')
    fi
    
    echo "$json_log" | nc -w 2 "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'): SUCCESS [FTP_TEXT] - $source" >> "$LOG_DIR/sent.log"
    fi
}

# Traitement spécialisé Cowrie texte
create_cowrie_text_json() {
    local line="$1"
    local source="$2"
    
    local json_log=$(jq -n \
        --arg ts "$(date -Iseconds)" \
        --arg msg "$line" \
        --arg src "$source" \
        '{
            honeypot_type: "ssh",
            honeypot_service: "cowrie",
            timestamp: $ts,
            message: $msg,
            log_format: "cowrie_text"
        }')
    
    echo "$json_log" | nc -w 2 "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'): SUCCESS [COWRIE_TEXT] - $source" >> "$LOG_DIR/sent.log"
    fi
}

# Traitement générique pour autres formats texte
create_generic_text_json() {
    local line="$1"
    local source="$2"
    local type="$3"
    
    local json_log=$(jq -n \
        --arg ts "$(date -Iseconds)" \
        --arg msg "$line" \
        --arg src "$source" \
        --arg tp "$type" \
        '{
            timestamp: $ts,
            message: $msg,
            source_type: $src,
            log_format: $tp
        }')
    
    echo "$json_log" | nc -w 2 "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'): SUCCESS [GENERIC] - $source" >> "$LOG_DIR/sent.log"
    fi
}

# Fonction de lecture avec position (inchangée)
read_from_position() {
    local file="$1"
    local position_key="$2"
    
    if [ ! -f "$file" ]; then
        return
    fi
    
    local last_pos=$(grep "^$position_key:" "$POSITION_FILE" 2>/dev/null | cut -d: -f2)
    if [ -z "$last_pos" ]; then
        last_pos=0
    fi
    
    local current_lines=$(wc -l < "$file" 2>/dev/null || echo "0")
    
    if [ "$current_lines" -gt "$last_pos" ]; then
        tail -n +$((last_pos + 1)) "$file" | head -n $((current_lines - last_pos))
        
        grep -v "^$position_key:" "$POSITION_FILE" 2>/dev/null > "$POSITION_FILE.tmp" || touch "$POSITION_FILE.tmp"
        echo "$position_key:$current_lines" >> "$POSITION_FILE.tmp"
        mv "$POSITION_FILE.tmp" "$POSITION_FILE"
    fi
}

# CONFIGURATION SPÉCIALISÉE PAR FICHIER
declare -A LOG_SOURCES=(
    # === COWRIE SSH (Faible activité - 79 lignes) ===
    ["/home/cowrie/cowrie/var/log/cowrie/cowrie.json.1"]="cowrie_ssh_json:10"
    ["/home/cowrie/cowrie/var/log/cowrie/cowrie.log.1"]="cowrie_ssh_text:20"
    
    # === HTTP HONEYPOT (Activité modérée - 145 lignes) ===
    ["/var/log/honeypot/http_honeypot.log"]="http_main:3"
    ["/var/log/honeypot/api_access.log"]="http_api:5"
    ["/var/log/honeypot/sql_injection.log"]="http_sql:2"
    ["/var/log/honeypot/critical_alerts.log"]="http_critical:2"
    ["/var/log/honeypot/sql_error.log"]="http_error:5"
    
    # === FTP HONEYPOT (Haute activité - 300k+ lignes) ===
    ["/root/honeypot-ftp/logs/sessions.json"]="ftp_sessions:1"
    ["/root/honeypot-ftp/logs/auth_attempts.log"]="ftp_auth:2"
    ["/root/honeypot-ftp/logs/commands.log"]="ftp_commands:3"
    ["/root/honeypot-ftp/logs/security_events.log"]="ftp_security:2"
    ["/root/honeypot-ftp/logs/transfers.log"]="ftp_transfers:5"
)

echo "$(date '+%Y-%m-%d %H:%M:%S'): Starting specialized honeypot log sender" >> "$LOG_DIR/sender.log"

# Test de connectivité initial
if ! nc -z "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null; then
    echo "$(date '+%Y-%m-%d %H:%M:%S'): ERROR - Cannot connect to Logstash" >> "$LOG_DIR/sender.log"
    sleep 10
fi

# Variables pour rotation des vérifications
file_index=0
total_files=${#LOG_SOURCES[@]}

# Boucle principale optimisée
while true; do
    file_processed=0
    
    for log_file in "${!LOG_SOURCES[@]}"; do
        if [ -f "$log_file" ] && [ -r "$log_file" ]; then
            # Parse source_type et fréquence
            IFS=':' read -r source_type frequency <<< "${LOG_SOURCES[$log_file]}"
            position_key=$(echo "$log_file" | sed 's/[^a-zA-Z0-9]/_/g')
            
            # Vérifier seulement certains fichiers à chaque cycle (rotation)
            if [ $((file_index % frequency)) -eq 0 ]; then
                # Lire et traiter les nouvelles lignes
                read_from_position "$log_file" "$position_key" | while IFS= read -r line; do
                    if [ -n "$line" ] && [ "$line" != "null" ]; then
                        # Déterminer le type de traitement
                        case "$source_type" in
                            cowrie_ssh_json)
                                send_log "$line" "$source_type" "json"
                                ;;
                            cowrie_ssh_text)
                                send_log "$line" "$source_type" "cowrie_text"
                                ;;
                            http_*)
                                send_log "$line" "$source_type" "json"
                                ;;
                            ftp_sessions)
                                send_log "$line" "$source_type" "json"
                                ;;
                            ftp_auth|ftp_commands|ftp_security|ftp_transfers)
                                send_log "$line" "$source_type" "ftp_text"
                                ;;
                            *)
                                send_log "$line" "$source_type" "generic"
                                ;;
                        esac
                    fi
                done
                file_processed=$((file_processed + 1))
            fi
        fi
    done
    
    # Incrémenter l'index pour la rotation
    file_index=$((file_index + 1))
    
    # Log de monitoring périodique
    if [ $((file_index % 100)) -eq 0 ]; then
        echo "$(date '+%Y-%m-%d %H:%M:%S'): Processed cycle $file_index, files checked: $file_processed" >> "$LOG_DIR/sender.log"
    fi
    
    # Nettoyage périodique (chaque 1000 cycles)
    if [ $((file_index % 1000)) -eq 0 ]; then
        find "$LOG_DIR" -name "*.log" -mtime +3 -delete 2>/dev/null
    fi
    
    # Attente optimisée selon l'activité
    if [ $file_processed -gt 5 ]; then
        sleep 1  # Activité élevée
    elif [ $file_processed -gt 0 ]; then
        sleep 2  # Activité modérée
    else
        sleep 3  # Activité faible
    fi
done