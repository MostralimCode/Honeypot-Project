#!/bin/bash
# Script de configuration du pare-feu pour honeypot

echo "[+] Configuration du pare-feu pour le honeypot..."

# Réinitialiser les règles existantes
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Définir les politiques par défaut
iptables -P INPUT DROP      # Bloquer tout le trafic entrant par défaut
iptables -P FORWARD DROP    # Bloquer tout le trafic de transfert par défaut
iptables -P OUTPUT ACCEPT   # Autoriser le trafic sortant (limitations sera faite apres)

echo "[+] Politiques par défaut configurées"

# Autoriser le trafic local (loopback)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

echo "[+] Trafic loopback autorisé"

# Autoriser les connexions établies et associées
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

echo "[+] Connexions établies autorisées"

# Autoriser les services honeypot (entrée)
# SSH - Port standard pour attirer les attaquants
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# FTP - Ports standard et passif
iptables -A INPUT -p tcp --dport 21 -j ACCEPT
iptables -A INPUT -p tcp --dport 40000:40100 -j ACCEPT  # Plage pour FTP passif

# HTTP et HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

echo "[+] Ports des services honeypot ouverts"

# Limiter les connexions sortantes (important pour l'isolation)
# Ces règles permettent les fonctionnalités essentielles tout en limitant la capacité des attaquants à utiliser le honeypot comme tremplin

# Autoriser DNS (nécessaire pour les mises à jour)
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Autoriser NTP (synchronisation de l'heure)
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT

# Autoriser les requêtes HTTP/HTTPS (pour mises à jour et téléchargements)
iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT

# Autoriser les connexions au serveur de logs centralisé (à adapter à nos serveurs de logs plus taard)
iptables -A OUTPUT -p tcp -d 192.168.2.120 --dport 5601 -j ACCEPT  # Kibana
iptables -A OUTPUT -p tcp -d 192.168.2.120 --dport 9200 -j ACCEPT  # Elasticsearch
iptables -A OUTPUT -p tcp -d 192.168.2.120 --dport 5044 -j ACCEPT  # Logstash

echo "[+] Connexions sortantes restreintes configurées"

# Limiter le taux de connexions sortantes pour prévenir les attaques DDoS
iptables -A OUTPUT -p tcp -m limit --limit 20/minute --limit-burst 5 -j ACCEPT
iptables -A OUTPUT -p udp -m limit --limit 20/minute --limit-burst 5 -j ACCEPT
iptables -A OUTPUT -p icmp -m limit --limit 20/minute --limit-burst 5 -j ACCEPT

# Bloquer tout le reste du trafic sortant
iptables -A OUTPUT -j DROP

echo "[+] Limitation du taux de connexions sortantes appliquée"

# Journalisation des paquets rejetés (utile pour l'analyse)
iptables -A INPUT -j LOG --log-prefix "FIREWALL:INPUT:DROP: " --log-level 6
iptables -A OUTPUT -j LOG --log-prefix "FIREWALL:OUTPUT:DROP: " --log-level 6

echo "[+] Journalisation des paquets rejetés configurée"

# Sauvegarder les règles pour qu'elles persistent après redémarrage
if [ -d /etc/iptables ]; then
    iptables-save > /etc/iptables/rules.v4
    echo "[+] Règles iptables sauvegardées dans /etc/iptables/rules.v4"
else
    mkdir -p /etc/iptables
    iptables-save > /etc/iptables/rules.v4
    echo "[+] Répertoire /etc/iptables créé et règles sauvegardées"
fi

echo "[+] Configuration du pare-feu terminée avec succès"