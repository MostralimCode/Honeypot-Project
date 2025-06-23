#!/bin/bash
# Script d'envoi automatique des logs honeypot vers Logstash TCP
# VM Honeypot: 192.168.2.117 → VM ELK: 192.168.2.124:5046

LOGSTASH_HOST="192.168.2.124"
LOGSTASH_PORT="5046"
LOG_DIR="/var/log/honeypot-sender"
POSITION_FILE="$LOG_DIR/positions.txt"

# Créer le répertoire de logs
mkdir -p "$LOG_DIR"

# Fonction d'envoi
send_log() {
    local log_entry="$1"
    echo "$log_entry" | nc -w 2 "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "$(date): Sent - $log_entry" >> "$LOG_DIR/sent.log"
    else
        echo "$(date): Failed - $log_entry" >> "$LOG_DIR/failed.log"
    fi
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

echo "$(date): Starting honeypot log sender" >> "$LOG_DIR/sender.log"

# Boucle principale
while true; do
    for log_file in "${!LOG_SOURCES[@]}"; do
        if [ -f "$log_file" ]; then
            IFS=':' read -r honeypot_type service log_format <<< "${LOG_SOURCES[$log_file]}"
            position_key=$(echo "$log_file" | sed 's/[^a-zA-Z0-9]/_/g')
            
            # Lire les nouvelles lignes
            read_from_position "$log_file" "$position_key" | while IFS= read -r line; do
                if [ -n "$line" ]; then
                    if [ "$log_format" = "json" ]; then
                        # Pour les logs JSON, ajouter des métadonnées
                        enhanced_log=$(echo "$line" | jq --arg ht "$honeypot_type" --arg svc "$service" --arg vm "192.168.2.117" '. + {honeypot_type: $ht, honeypot_service: $svc, source_vm: $vm}' 2>/dev/null)
                        
                        if [ $? -eq 0 ] && [ -n "$enhanced_log" ]; then
                            send_log "$enhanced_log"
                        else
                            # Si jq échoue, créer un JSON simple
                            simple_json="{\"honeypot_type\":\"$honeypot_type\",\"honeypot_service\":\"$service\",\"source_vm\":\"192.168.2.117\",\"message\":$(echo "$line" | jq -R .),\"timestamp\":\"$(date -Iseconds)\"}"
                            send_log "$simple_json"
                        fi
                    else
                        # Pour les logs texte, créer un JSON
                        text_json="{\"honeypot_type\":\"$honeypot_type\",\"honeypot_service\":\"$service\",\"source_vm\":\"192.168.2.117\",\"log_format\":\"text\",\"message\":$(echo "$line" | jq -R .),\"timestamp\":\"$(date -Iseconds)\"}"
                        send_log "$text_json"
                    fi
                fi
            done
        fi
    done
    
    # Attendre avant la prochaine vérification
    sleep 5
done