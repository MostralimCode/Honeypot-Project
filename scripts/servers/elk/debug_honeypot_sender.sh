#!/bin/bash

echo "=== DIAGNOSTIC HONEYPOT-SENDER ==="
echo "Date: $(date)"
echo ""

# 1. Vérifier la connectivité réseau
echo "🌐 TEST CONNECTIVITÉ RÉSEAU:"
echo "Ping vers ELK Server (192.168.2.124):"
ping -c 3 192.168.2.124
echo ""

# 2. Vérifier les ports Logstash
echo "🔌 PORTS LOGSTASH SUR ELK SERVER:"
echo "Port 5046 (honeypot-sender):"
nc -zv 192.168.2.124 5046 2>&1
echo "Port 5044 (filebeat):"
nc -zv 192.168.2.124 5044 2>&1
echo ""

# 3. Vérifier le service honeypot-sender
echo "📊 SERVICE HONEYPOT-SENDER:"
if systemctl is-active --quiet honeypot-sender 2>/dev/null; then
    echo "✅ Service actif"
    echo "Status: $(systemctl is-active honeypot-sender)"
    echo "Uptime: $(systemctl show honeypot-sender --property=ActiveEnterTimestamp --value)"
else
    echo "❌ Service inactif ou n'existe pas"
fi
echo ""

# 4. Vérifier les processus en cours
echo "🔍 PROCESSUS SENDER:"
ps aux | grep -E "(honeypot.*sender|sender.*honeypot)" | grep -v grep || echo "Aucun processus sender trouvé"
echo ""

# 5. Vérifier les logs de position
echo "📁 FICHIERS DE POSITION:"
if [ -f "/var/log/honeypot-sender/positions.txt" ]; then
    echo "Fichier positions.txt existe:"
    cat /var/log/honeypot-sender/positions.txt | head -10
else
    echo "❌ Fichier positions.txt manquant"
fi
echo ""

# 6. Vérifier les logs d'erreur
echo "🚨 DERNIÈRES ERREURS:"
if [ -f "/var/log/honeypot-sender/failed.log" ]; then
    echo "Dernières erreurs (10 dernières lignes):"
    tail -10 /var/log/honeypot-sender/failed.log
else
    echo "Aucun fichier d'erreur trouvé"
fi
echo ""

# 7. Vérifier les logs de succès
echo "✅ DERNIERS SUCCÈS:"
if [ -f "/var/log/honeypot-sender/sent.log" ]; then
    echo "Derniers envois réussis (5 dernières lignes):"
    tail -5 /var/log/honeypot-sender/sent.log
else
    echo "Aucun log de succès trouvé"
fi
echo ""

# 8. Vérifier les fichiers sources
echo "📂 FICHIERS SOURCES DISPONIBLES:"
log_files=(
    "/home/cowrie/cowrie/var/log/cowrie/cowrie.json"
    "/var/log/honeypot/http_honeypot.log"
    "/root/honeypot-ftp/logs/sessions.json"
    "/root/honeypot-ftp/logs/auth_attempts.log"
)

for file in "${log_files[@]}"; do
    if [ -f "$file" ]; then
        size=$(stat -c%s "$file" 2>/dev/null || echo "0")
        lines=$(wc -l < "$file" 2>/dev/null || echo "0")
        echo "✅ $file: $size bytes, $lines lignes"
    else
        echo "❌ $file: Fichier manquant"
    fi
done
echo ""

# 9. Test de connectivité manuelle
echo "🧪 TEST ENVOI MANUEL:"
echo "Test d'envoi d'un message de test vers Logstash..."
test_json='{"test":"honeypot-debug","timestamp":"'$(date -Iseconds)'","message":"Test connectivité"}'
echo "$test_json" | nc -w 5 192.168.2.124 5046 2>&1
if [ $? -eq 0 ]; then
    echo "✅ Envoi test réussi"
else
    echo "❌ Envoi test échoué"
fi
echo ""

# 10. Recommandations
echo "🎯 RECOMMANDATIONS:"
echo "1. Si port 5046 fermé → Redémarrer Logstash"
echo "2. Si connectivité réseau OK mais pas d'envoi → Redémarrer honeypot-sender"
echo "3. Si fichiers sources vides → Vérifier les honeypots"
echo "4. Si erreurs JSON → Vérifier le script sender"
echo ""

echo "=== FIN DIAGNOSTIC ==="