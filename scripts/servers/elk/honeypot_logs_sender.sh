#!/bin/bash
# SCRIPT SENDER FINAL - Honeypot Logs vers Logstash TCP
# VM Honeypot: 192.168.2.117 → VM ELK: 192.168.2.124:5046
# Version: Optimisée pour éviter les JSON parse failures
# Date: 2025-06-30

# =============================================================================
# CONFIGURATION
# =============================================================================

LOGSTASH_HOST="192.168.2.124"
LOGSTASH_PORT="5046"
LOG_DIR="/var/log/honeypot-sender"
POSITION_FILE="$LOG_DIR/positions.txt"
LOOP_INTERVAL=2

# Créer le répertoire de logs
mkdir -p "$LOG_DIR"
touch "$POSITION_FILE"

# =============================================================================
# FONCTIONS UTILITAIRES
# =============================================================================

# Fonction de logging
log_message() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$LOG_DIR/sender.log"
}

# Fonction d'envoi TCP sécurisée
send_to_logstash() {
    local json_data="$1"
    local source_label="$2"
    
    # Vérifier que c'est du JSON valide avant envoi
    if echo "$json_data" | jq . >/dev/null 2>&1; then
        # Envoyer via TCP avec timeout
        echo "$json_data" | nc -w 3 "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null
        local result=$?
        
        if [ $result -eq 0 ]; then
            log_message "SUCCESS" "$source_label"
            return 0
        else
            log_message "NETWORK_ERROR" "$source_label (code: $result)"
            return 1
        fi
    else
        log_message "JSON_ERROR" "$source_label - Invalid JSON: $json_data"
        return 1
    fi
}

# Fonction de nettoyage pour JSON
clean_for_json() {
    local input="$1"
    # Échapper les caractères spéciaux et supprimer les caractères de contrôle
    echo "$input" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g; s/\r/\\r/g; s/\n/\\n/g' | tr -d '\000-\010\013\014\016-\037'
}

# Fonction de lecture avec position (optimisée)
read_new_lines() {
    local file="$1"
    local position_key="$2"
    
    if [ ! -f "$file" ] || [ ! -r "$file" ]; then
        return
    fi
    
    # Récupérer la dernière position
    local last_pos=$(grep "^$position_key:" "$POSITION_FILE" 2>/dev/null | cut -d: -f2-)
    if [ -z "$last_pos" ]; then
        last_pos=0
    fi
    
    # Calculer les nouvelles lignes
    local current_lines=$(wc -l < "$file" 2>/dev/null || echo "0")
    
    if [ "$current_lines" -gt "$last_pos" ]; then
        # Lire les nouvelles lignes
        tail -n +$((last_pos + 1)) "$file" | head -n $((current_lines - last_pos))
        
        # Mettre à jour la position atomiquement
        local temp_file="$POSITION_FILE.tmp.$$"
        grep -v "^$position_key:" "$POSITION_FILE" 2>/dev/null > "$temp_file" || touch "$temp_file"
        echo "$position_key:$current_lines" >> "$temp_file"
        mv "$temp_file" "$POSITION_FILE"
    fi
}

# =============================================================================
# PROCESSEURS SPÉCIALISÉS PAR TYPE DE HONEYPOT
# =============================================================================

# Processeur Cowrie SSH - JSON Direct Enrichi
process_cowrie_log() {
    local line="$1"
    local service="$2"
    
    # Vérifier que c'est du JSON valide
    if echo "$line" | jq . >/dev/null 2>&1; then
        # SOLUTION: Enrichir le JSON original directement sans sur-encapsulation
        local enriched_json=$(echo "$line" | jq --arg ht "ssh" --arg svc "$service" --arg vm "192.168.2.117" --arg ts "$(date -Iseconds)" '. + {
            honeypot_type: $ht,
            honeypot_service: $svc,
            source_vm: $vm,
            processed_timestamp: $ts
        }')
        
        if [ $? -eq 0 ] && [ -n "$enriched_json" ]; then
            send_to_logstash "$enriched_json" "COWRIE[$service]"
        fi
    else
        log_message "WARN" "COWRIE[$service] - Ligne non-JSON ignorée: $(echo "$line" | head -c 100)"
    fi
}

# Processeur HTTP Honeypot - JSON Direct Enrichi  
process_http_log() {
    local line="$1"
    local service="$2"
    
    # Vérifier que c'est du JSON valide
    if echo "$line" | jq . >/dev/null 2>&1; then
        # SOLUTION: Enrichir le JSON original directement
        local enriched_json=$(echo "$line" | jq --arg ht "http" --arg svc "$service" --arg vm "192.168.2.117" --arg ts "$(date -Iseconds)" '. + {
            honeypot_type: $ht,
            honeypot_service: $svc,
            source_vm: $vm,
            processed_timestamp: $ts
        }')
        
        if [ $? -eq 0 ] && [ -n "$enriched_json" ]; then
            send_to_logstash "$enriched_json" "HTTP[$service]"
        fi
    else
        log_message "WARN" "HTTP[$service] - Ligne non-JSON ignorée: $(echo "$line" | head -c 100)"
    fi
}

# Processeur FTP JSON
process_ftp_json() {
    local line="$1"
    local service="$2"
    
    if echo "$line" | jq . >/dev/null 2>&1; then
        local enriched_json=$(echo "$line" | jq --arg ht "ftp" --arg svc "$service" --arg vm "192.168.2.117" --arg ts "$(date -Iseconds)" '. + {
            honeypot_type: $ht,
            honeypot_service: $svc,
            source_vm: $vm,
            processed_timestamp: $ts,
            log_format: "ftp_json"
        }')
        
        if [ $? -eq 0 ] && [ -n "$enriched_json" ]; then
            send_to_logstash "$enriched_json" "FTP_JSON[$service]"
        fi
    fi
}

# Processeur FTP Texte (garde la logique existante qui fonctionne)
process_ftp_text() {
    local line="$1"
    local service="$2"
    local current_timestamp="$3"
    
    # Format: 2025-05-05 16:56:52 - INFO - Auth SUCCESS - 127.0.0.1 - admin
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
            \"message\": \"$(clean_for_json "$line")\"
        }"
        
        local compact_json=$(echo "$json_log" | jq -c .)
        if [ $? -eq 0 ]; then
            send_to_logstash "$compact_json" "FTP_TEXT[$service]"
        fi
    else
        # Format non reconnu, encapsuler simplement
        local fallback_json="{
            \"honeypot_type\": \"ftp\",
            \"honeypot_service\": \"$service\",
            \"source_vm\": \"192.168.2.117\",
            \"log_format\": \"ftp_text_fallback\",
            \"timestamp\": \"$current_timestamp\",
            \"message\": \"$(clean_for_json "$line")\"
        }"
        
        local compact_json=$(echo "$fallback_json" | jq -c .)
        if [ $? -eq 0 ]; then
            send_to_logstash "$compact_json" "FTP_TEXT_FALLBACK[$service]"
        fi
    fi
}

# =============================================================================
# CONFIGURATION DES SOURCES DE LOGS OPTIMISÉE
# =============================================================================

declare -A LOG_SOURCES=(
    # Cowrie SSH - Traitement JSON direct
    ["/home/cowrie/cowrie/var/log/cowrie/cowrie.json"]="ssh:cowrie:cowrie_json"
    ["/home/cowrie/cowrie/var/log/cowrie/cowrie.json.1"]="ssh:cowrie:cowrie_json"
    ["/home/cowrie/cowrie/var/log/cowrie/cowrie.json.2"]="ssh:cowrie:cowrie_json"
    
    # HTTP Honeypot - Traitement JSON direct
    ["/var/log/honeypot/http_honeypot.log"]="http:main:http_json"
    ["/var/log/honeypot/api_access.log"]="http:api:http_json"
    ["/var/log/honeypot/sql_injection.log"]="http:sql:http_json"
    ["/var/log/honeypot/critical_alerts.log"]="http:critical:http_json"
    ["/var/log/honeypot/sql_error.log"]="http:error:http_json"
    
    # FTP Honeypot - Mixte (garde ce qui fonctionne)
    ["/root/honeypot-ftp/logs/sessions.json"]="ftp:sessions:ftp_json"
    ["/root/honeypot-ftp/logs/auth_attempts.log"]="ftp:auth:ftp_text"
    ["/root/honeypot-ftp/logs/commands.log"]="ftp:commands:ftp_text"
    ["/root/honeypot-ftp/logs/security_events.log"]="ftp:security:ftp_text"
    ["/root/honeypot-ftp/logs/transfers.log"]="ftp:transfers:ftp_text"
)

# =============================================================================
# FONCTION PRINCIPALE
# =============================================================================

main_loop() {
    log_message "INFO" "Démarrage du sender honeypot optimisé"
    
    # Test de connectivité initial
    if ! nc -z "$LOGSTASH_HOST" "$LOGSTASH_PORT" 2>/dev/null; then
        log_message "ERROR" "Impossible de se connecter à Logstash $LOGSTASH_HOST:$LOGSTASH_PORT"
        sleep 30
        return 1
    fi
    
    log_message "INFO" "Connexion Logstash OK - Démarrage du traitement"
    
    # Boucle principale optimisée
    while true; do
        local files_processed=0
        
        for log_file in "${!LOG_SOURCES[@]}"; do
            if [ -f "$log_file" ] && [ -r "$log_file" ]; then
                # Parser la configuration
                IFS=':' read -r honeypot_type service log_format <<< "${LOG_SOURCES[$log_file]}"
                
                # Créer une clé de position unique
                local position_key=$(echo "$log_file" | sed 's/[^a-zA-Z0-9]/_/g')
                
                # Traiter les nouvelles lignes
                read_new_lines "$log_file" "$position_key" | while IFS= read -r line; do
                    if [ -n "$line" ] && [ "$line" != "null" ]; then
                        local current_timestamp=$(date -Iseconds)
                        
                        # Router vers le bon processeur
                        case "$log_format" in
                            "cowrie_json")
                                process_cowrie_log "$line" "$service"
                                ;;
                            "http_json")
                                process_http_log "$line" "$service"
                                ;;
                            "ftp_json")
                                process_ftp_json "$line" "$service"
                                ;;
                            "ftp_text")
                                process_ftp_text "$line" "$service" "$current_timestamp"
                                ;;
                            *)
                                log_message "WARN" "Format inconnu: $log_format pour $log_file"
                                ;;
                        esac
                        
                        files_processed=$((files_processed + 1))
                    fi
                done
            fi
        done
        
        # Pause entre les cycles
        sleep $LOOP_INTERVAL
        
        # Log de statut périodique (toutes les 5 minutes)
        if [ $(($(date +%s) % 300)) -lt $LOOP_INTERVAL ]; then
            log_message "INFO" "Sender actif - Fichiers traités: $files_processed"
        fi
    done
}

# =============================================================================
# GESTION DES SIGNAUX ET DÉMARRAGE
# =============================================================================

# Gestion de l'arrêt propre
cleanup() {
    log_message "INFO" "Arrêt du sender honeypot"
    exit 0
}

trap cleanup SIGTERM SIGINT

# Vérification des prérequis
if ! command -v jq >/dev/null 2>&1; then
    echo "ERREUR: jq n'est pas installé"
    exit 1
fi

if ! command -v nc >/dev/null 2>&1; then
    echo "ERREUR: netcat n'est pas installé"  
    exit 1
fi

# Démarrage
echo "$(date): Démarrage du honeypot sender final"
log_message "START" "Honeypot Logs Sender Final - Version 2025-06-30"

# Boucle principale avec reprise automatique
while true; do
    main_loop
    log_message "WARN" "Boucle principale interrompue - Redémarrage dans 10s"
    sleep 10
done