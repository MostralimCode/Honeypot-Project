#!/bin/bash

echo "=== CORRECTION D'URGENCE HONEYPOT-SENDER ==="
echo "Date: $(date)"
echo ""

# 1. ARRÊT COMPLET ET NETTOYAGE
echo "🛑 ARRÊT COMPLET DU SYSTÈME..."
systemctl stop honeypot-sender 2>/dev/null
pkill -f "honeypot.*sender" 2>/dev/null
pkill -f "sender.*honeypot" 2>/dev/null
pkill -f "/opt/honeypot_logs_sender.sh" 2>/dev/null
sleep 3

# 2. DIAGNOSTIC ROTATION LOGS
echo "🔄 DIAGNOSTIC ROTATION LOGS..."
cowrie_main="/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
cowrie_rotated="/home/cowrie/cowrie/var/log/cowrie/cowrie.json.1"

echo "Fichier principal Cowrie:"
if [ -f "$cowrie_main" ]; then
    ls -la "$cowrie_main"
    wc -l "$cowrie_main"
else
    echo "❌ Fichier principal manquant"
fi

echo "Fichier rotaté Cowrie:"
if [ -f "$cowrie_rotated" ]; then
    ls -la "$cowrie_rotated"
    wc -l "$cowrie_rotated"
else
    echo "ℹ️ Pas de fichier rotaté"
fi

# 3. RESET COMPLET DES POSITIONS
echo "🔄 RESET COMPLET DES POSITIONS..."
mkdir -p /var/log/honeypot-sender
rm -f /var/log/honeypot-sender/positions.txt
rm -f /var/log/honeypot-sender/positions.txt.*
touch /var/log/honeypot-sender/positions.txt

# 4. VÉRIFIER LES PERMISSIONS
echo "🔐 VÉRIFICATION PERMISSIONS..."
chmod 755 /var/log/honeypot-sender
chmod 644 /var/log/honeypot-sender/positions.txt

# Permissions Cowrie
if [ -f "$cowrie_main" ]; then
    chmod 644 "$cowrie_main" 2>/dev/null || echo "⚠️ Impossible de modifier permissions Cowrie"
fi

# Permissions HTTP logs
chmod 644 /var/log/honeypot/*.log 2>/dev/null || echo "⚠️ Logs HTTP non accessibles"

# Permissions FTP logs
chmod 644 /root/honeypot-ftp/logs/*.log 2>/dev/null || echo "⚠️ Logs FTP non accessibles"
chmod 644 /root/honeypot-ftp/logs/*.json 2>/dev/null || echo "⚠️ Logs FTP JSON non accessibles"

# 5. CRÉER UN SCRIPT SENDER SIMPLIFIÉ POUR TEST
echo "🧪 CRÉATION SCRIPT TEST SIMPLIFIÉ..."
cat > /tmp/sender_simple.sh << 'SIMPLE_EOF'
#!/bin/bash

LOGSTASH_HOST="192.168.2.124"
LOGSTASH_PORT="5046"

echo "$(date): Début test sender simplifié"

# Test direct avec fichiers qui fonctionnaient
send_test_log() {
    local file="$1"
    local type="$2"
    
    if [ -f "$file" ] && [ -s "$file" ]; then
        echo "Test envoi: $file"
        
        # Prendre les 2 dernières lignes
        tail -2 "$file" | while IFS= read -r line; do
            if [ -n "$line" ]; then
                # Créer un JSON simple
                test_json="{\"timestamp\":\"$(date -Iseconds)\",\"type\":\"$type\",\"test\":true,\"data\":\"$line\"}"
                
                # Envoyer
                echo "$test_json" | nc -w 5 "$LOGSTASH_HOST" "$LOGSTASH_PORT"
                result=$?
                
                if [ $result -eq 0 ]; then
                    echo "$(date): SUCCESS $type" >> /tmp/sender_test.log
                else
                    echo "$(date): FAILED $type (code: $result)" >> /tmp/sender_test.log
                fi
            fi
        done
    else
        echo "$(date): SKIP $type - fichier vide ou inexistant" >> /tmp/sender_test.log
    fi
}

# Tests avec chaque type de fichier
send_test_log "/var/log/honeypot/http_honeypot.log" "HTTP"
send_test_log "/root/honeypot-ftp/logs/auth_attempts.log" "FTP_AUTH"
send_test_log "/home/cowrie/cowrie/var/log/cowrie/cowrie.json" "COWRIE_MAIN"
send_test_log "/home/cowrie/cowrie/var/log/cowrie/cowrie.json.1" "COWRIE_ROTATED"

echo "$(date): Fin test sender simplifié"
SIMPLE_EOF

chmod +x /tmp/sender_simple.sh

# 6. EXÉCUTION DU TEST SIMPLIFIÉ
echo "▶️ EXÉCUTION TEST SIMPLIFIÉ..."
/tmp/sender_simple.sh

# Afficher les résultats
echo ""
echo "📊 RÉSULTATS TEST SIMPLIFIÉ:"
if [ -f /tmp/sender_test.log ]; then
    cat /tmp/sender_test.log
fi

# 7. GÉNÉRER DE NOUVEAUX LOGS POUR TEST
echo ""
echo "🎯 GÉNÉRATION DE NOUVEAUX LOGS..."

# Test SSH Cowrie
echo "Test connexion SSH Cowrie..."
timeout 10 bash -c 'echo "test" | nc 192.168.2.117 2222' &>/dev/null &

# Test HTTP
echo "Test requête HTTP..."
curl -s "http://192.168.2.117:8080/test" &>/dev/null &

# Attendre génération
sleep 5

# Vérifier nouveaux contenus
echo "📈 NOUVEAU CONTENU GÉNÉRÉ:"
if [ -f "$cowrie_main" ]; then
    new_lines=$(wc -l < "$cowrie_main" 2>/dev/null || echo "0")
    echo "Cowrie principal: $new_lines lignes"
fi

http_lines=$(wc -l < "/var/log/honeypot/http_honeypot.log" 2>/dev/null || echo "0")
echo "HTTP honeypot: $http_lines lignes"

# 8. CRÉATION D'UN SERVICE SYSTEMD CORRIGÉ
echo ""
echo "🔧 CRÉATION SERVICE SYSTEMD CORRIGÉ..."
cat > /etc/systemd/system/honeypot-sender.service << 'SERVICE_EOF'
[Unit]
Description=Honeypot Logs Sender to Logstash
After=network.target logstash.service cowrie.service
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt
ExecStart=/opt/honeypot_logs_sender.sh
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

# Variables d'environnement
Environment="LOGSTASH_HOST=192.168.2.124"
Environment="LOGSTASH_PORT=5046"

# Sécurité
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
SERVICE_EOF

# 9. COPIER LE SCRIPT PRINCIPAL AU BON ENDROIT
echo "📁 COPIE SCRIPT PRINCIPAL..."
if [ -f "/root/honeypot_logs_sender.sh" ]; then
    cp /root/honeypot_logs_sender.sh /opt/honeypot_logs_sender.sh
elif [ -f "/opt/honeypot_logs_sender.sh" ]; then
    echo "✅ Script déjà en place"
else
    echo "❌ Script principal non trouvé !"
    echo "Veuillez copier votre script vers /opt/honeypot_logs_sender.sh"
fi

chmod +x /opt/honeypot_logs_sender.sh

# 10. RECHARGER SYSTEMD
systemctl daemon-reload
systemctl enable honeypot-sender

# 11. PROPOSER LE REDÉMARRAGE
echo ""
echo "🎯 ACTIONS RECOMMANDÉES:"
echo ""
echo "1. Redémarrer les services dans l'ordre:"
echo "   systemctl restart cowrie"
echo "   systemctl restart logstash"  
echo "   systemctl start honeypot-sender"
echo ""
echo "2. Surveiller en temps réel:"
echo "   journalctl -u honeypot-sender -f"
echo ""
echo "3. Vérifier les logs de test:"
echo "   cat /tmp/sender_test.log"
echo ""

# 12. REDÉMARRAGE AUTOMATIQUE SI DEMANDÉ
read -p "Voulez-vous redémarrer automatiquement tous les services? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🚀 REDÉMARRAGE AUTOMATIQUE..."
    
    echo "Redémarrage Cowrie..."
    systemctl restart cowrie
    sleep 10
    
    echo "Redémarrage Logstash..."
    systemctl restart logstash
    sleep 20
    
    echo "Démarrage honeypot-sender..."
    systemctl start honeypot-sender
    sleep 5
    
    # Vérification
    if systemctl is-active --quiet honeypot-sender; then
        echo "✅ honeypot-sender démarré"
        echo "📊 Status: $(systemctl is-active honeypot-sender)"
        
        # Test final
        echo "🧪 Test final dans 30 secondes..."
        sleep 30
        /tmp/sender_simple.sh
        
        echo ""
        echo "📋 RÉSULTATS FINAUX:"
        tail -5 /tmp/sender_test.log
        
    else
        echo "❌ Échec redémarrage honeypot-sender"
        echo "🔍 Logs d'erreur:"
        journalctl -u honeypot-sender -n 10 --no-pager
    fi
else
    echo "ℹ️ Redémarrage manuel requis"
fi

echo ""
echo "=== CORRECTION D'URGENCE TERMINÉE ==="
echo ""
echo "🔍 COMMANDES DE VÉRIFICATION:"
echo "• Status: systemctl status honeypot-sender"
echo "• Logs: journalctl -u honeypot-sender -f"
echo "• Test: /tmp/sender_simple.sh"