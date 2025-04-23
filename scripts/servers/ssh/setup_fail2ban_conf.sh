#!/bin/bash

# Script d'installation et de configuration de Fail2ban

# Variables de configuration
SSH_PORT=2222
JAIL_BANTIME=3600
JAIL_FINDTIME=600
JAIL_MAXRETRY=3
JAIL_AGGRESSIVE_BANTIME=86400
JAIL_AGGRESSIVE_FINDTIME=300
JAIL_AGGRESSIVE_MAXRETRY=2
JAIL_RECIDIVE_BANTIME=604800
JAIL_RECIDIVE_FINDTIME=86400
JAIL_RECIDIVE_MAXRETRY=3
LAN_NETWORK="192.168.2.0/24"

# Couleurs pour la lisibilité
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 

# Fonctions
function print_status() {
    echo -e "${GREEN}[+] $1${NC}"
}

function print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

function print_error() {
    echo -e "${RED}[-] $1${NC}"
}

function check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Ce script doit être exécuté en tant que root"
        exit 1
    fi
}

# 1. Vérifications préliminaires
check_root

print_status "Début de l'installation et de la configuration de Fail2ban"

# 2. Installation de Fail2ban
print_status "Installation de Fail2ban..."
apt update
apt install -y fail2ban

# Arrêt du service pendant la configuration
systemctl stop fail2ban

# 3. Configuration de base de Fail2ban
print_status "Configuration de base de Fail2ban..."

# Sauvegarde de la configuration originale
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.conf.bak.$(date +%Y%m%d)

# Création du fichier jail.local
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# "bantime" est la durée pendant laquelle une adresse IP sera bannie (en secondes)
bantime = ${JAIL_BANTIME}

# Temps (en secondes) pendant lequel Fail2ban recherche des tentatives répétées
findtime = ${JAIL_FINDTIME}

# Nombre d'échecs autorisés avant de bannir une adresse IP
maxretry = ${JAIL_MAXRETRY}

# Action à prendre lorsqu'une adresse IP dépasse le seuil
banaction = iptables-multiport

# Ignorer les adresses IP locales
ignoreip = 127.0.0.1/8 ${LAN_NETWORK}

# Encodage des fichiers de journalisation
logencoding = utf-8

# Action par défaut (bannir uniquement)
action = %(action_)s

# Mode de détection
backend = auto

# Comportement au démarrage
startstate = enabled

#
# JAILS
#

[sshd]
enabled = true
port = ${SSH_PORT}
filter = sshd
logpath = /var/log/auth.log
maxretry = ${JAIL_MAXRETRY}
bantime = ${JAIL_BANTIME}

# Configuration plus stricte pour SSH
[sshd-aggressive]
enabled = true
port = ${SSH_PORT}
filter = sshd-aggressive
logpath = /var/log/auth.log
maxretry = ${JAIL_AGGRESSIVE_MAXRETRY}
bantime = ${JAIL_AGGRESSIVE_BANTIME}  # 24 heures
findtime = ${JAIL_AGGRESSIVE_FINDTIME}   # 5 minutes

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = iptables-allports
bantime = ${JAIL_RECIDIVE_BANTIME}  # 7 jours
findtime = ${JAIL_RECIDIVE_FINDTIME}  # 1 jour
maxretry = ${JAIL_RECIDIVE_MAXRETRY}
EOF

# 4. Création du filtre personnalisé sshd-aggressive
print_status "Création du filtre personnalisé sshd-aggressive..."

cat > /etc/fail2ban/filter.d/sshd-aggressive.conf <<EOF
# Configuration personnalisée pour un filtre SSH agressif
# Basé sur le filtre SSH standard mais avec une détection plus stricte

[INCLUDES]
# Lire les définitions du filtre sshd standard
before = sshd.conf

[Definition]
# Nous héritons déjà toutes les regex du filtre sshd standard
# Ajoutons quelques patterns supplémentaires pour une détection plus stricte
allowipv6 = auto

failregex =     ^%(__prefix_line)s(?:error: PAM: )?Authentication failure for .* from <HOST>\s*$
                ^%(__prefix_line)s(?:error: PAM: )?User not known to the underlying authentication module for .* from <HOST>\s*$
                ^%(__prefix_line)sConnection closed by authenticating user .* <HOST> port.*$
                ^%(__prefix_line)sConnection closed by invalid user .* <HOST> port.*$
                ^%(__prefix_line)sInvaliduser .* from <HOST>\s*$
                ^%(__prefix_line)sUser .* from <HOST># not allowed because not listed in AllowUsers\s*$

ignoreregex = 
EOF

# 5. Vérification de la configuration
print_status "Vérification de la configuration Fail2ban..."
fail2ban-client -t

if [ $? -ne 0 ]; then
    print_error "La vérification de la configuration Fail2ban a échoué. Veuillez vérifier manuellement."
    exit 1
fi

# 6. Activation et démarrage du service
print_status "Activation et démarrage du service Fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban

# Attente pour que le service démarre complètement
sleep 3

# Vérification du statut
systemctl status fail2ban

# 7. Vérification des jails actifs
print_status "Vérification des jails Fail2ban actifs..."
fail2ban-client status

# 8. Tests des filtres (optionnel)
print_status "Test du filtre sshd..."
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf --print-all-matched

print_status "Test du filtre sshd-aggressive..."
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd-aggressive.conf --print-all-matched

# 9. Informations finales
print_status "Configuration de Fail2ban terminée avec succès!"
print_status "Protection standard SSH: $JAIL_MAXRETRY tentatives en $JAIL_FINDTIME secondes = bannissement de $JAIL_BANTIME secondes"
print_status "Protection agressive SSH: $JAIL_AGGRESSIVE_MAXRETRY tentatives en $JAIL_AGGRESSIVE_FINDTIME secondes = bannissement de $JAIL_AGGRESSIVE_BANTIME secondes"
print_status "Protection récidive: $JAIL_RECIDIVE_MAXRETRY bannissements en $JAIL_RECIDIVE_FINDTIME secondes = bannissement de $JAIL_RECIDIVE_BANTIME secondes"

print_warning "Commandes utiles:"
print_warning "  - Vérifier le statut: sudo fail2ban-client status"
print_warning "  - Vérifier jail SSH: sudo fail2ban-client status sshd"
print_warning "  - Débannir une IP: sudo fail2ban-client set sshd unbanip IP_ADDRESS"

exit 0