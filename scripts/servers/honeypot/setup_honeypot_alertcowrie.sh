#!/bin/bash


LOGFILE="/home/cowrie/cowrie/var/log/cowrie/cowrie.log"
EMAIL="honeypotesgi@pm.me"

# Recherche des nouvelles connexions réussies dans les dernières minutes
LOGINS=$(grep -i "login attempt" "$LOGFILE" | tail -n 5)

if [ ! -z "$LOGINS" ]; then
    echo "Activité détectée sur le honeypot Cowrie:" | mail -s "ALERTE Honeypot: Tentative de connexion" "$EMAIL" -a "From: honeypot@honeypot.arpa" <<EOF

Les tentatives de connexion suivantes ont été enregistrées :

$LOGINS

Vérifiez les journaux pour plus de détails.
EOF
fi