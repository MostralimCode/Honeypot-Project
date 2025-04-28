#!/bin/bash

# Script d'installation et de configuration de Fail2ban pour serveur FTP sécurisé

# Variables de configuration
SSH_PORT=2222
FTP_PORT=21
FTP_PASV_MIN=40000
FTP_PASV_MAX=40100
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

# 3. Vérification des logs nécessaires
print_status "Vérification des fichiers journaux..."

# Création des fichiers journaux s'ils n'existent pas
touch /var/log/auth.log
touch /var/log/vsftpd.log

# Attribution des permissions appropriées
chmod 644 /var/log/auth.log
chmod 644 /var/log/vsftpd.log

# 4. Configuration du fichier fail2ban.conf
print_status "Configuration du fichier fail2ban.conf..."

# Sauvegarde du fichier original
cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.conf.bak

# Modifier le fichier de configuration principal
sed -i 's/^loglevel = INFO/loglevel = INFO/' /etc/fail2ban/fail2ban.conf
sed -i 's/^logtarget = \/var\/log\/fail2ban.log/logtarget = \/var\/log\/fail2ban.log/' /etc/fail2ban/fail2ban.conf
sed -i 's/^#dbfile = \/var\/lib\/fail2ban\/fail2ban.sqlite3/dbfile = \/var\/lib\/fail2ban\/fail2ban.sqlite3/' /etc/fail2ban/fail2ban.conf
sed -i 's/^#dbpurgeage = 86400/dbpurgeage = 86400/' /etc/fail2ban/fail2ban.conf
sed -i 's/^#allowipv6 = auto/allowipv6 = auto/' /etc/fail2ban/fail2ban.conf

# 5. Configuration de base de Fail2ban
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

[vsftpd]
enabled = true
port = ${FTP_PORT}
filter = vsftpd
logpath = /var/log/vsftpd.log
maxretry = ${JAIL_MAXRETRY}
bantime = ${JAIL_BANTIME}
findtime = ${JAIL_FINDTIME}

[vsftpd-aggressive]
enabled = true
port = ${FTP_PORT}
filter = vsftpd-aggressive
logpath = /var/log/vsftpd.log
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

# 6. Création du filtre personnalisé vsftpd-aggressive
print_status "Création du filtre personnalisé vsftpd-aggressive..."

cat > /etc/fail2ban/filter.d/vsftpd-aggressive.conf <<EOF
# Configuration personnalisée pour un filtre FTP agressif
# Basé sur le filtre vsftpd standard mais avec une détection plus stricte

[INCLUDES]
# Lire les définitions du filtre vsftpd standard
before = vsftpd.conf

[Definition]
# Nous héritons déjà toutes les regex du filtre vsftpd standard
# Ajoutons quelques patterns supplémentaires pour une détection plus stricte
allowipv6 = auto

failregex = ^%(__prefix_line)s.*?FAIL LOGIN: Client "<HOST>"$
            ^%(__prefix_line)s.*?FAIL UPLOAD: Client "<HOST>".*$
            ^%(__prefix_line)s.*?SECURITY VIOLATION: *?client "<HOST>".*$
            ^%(__prefix_line)s.*?Connection refused \(Permission denied\).*$
            ^%(__prefix_line)s.*?Client "<HOST>" is not allowed to login.*$
            ^%(__prefix_line)s.*?530 Login incorrect\.\s*$
            ^%(__prefix_line)s.*?FTP command: Client "<HOST>", "(USER|PASS|MKD|STOR|DELE)".*$

ignoreregex = 
EOF

# 7. Vérification des filtres vsftpd existants
print_status "Vérification du filtre vsftpd standard..."

# Si le filtre vsftpd standard n'existe pas, le créer
if [ ! -f /etc/fail2ban/filter.d/vsftpd.conf ]; then
    print_warning "Filtre vsftpd standard non trouvé, création..."
    cat > /etc/fail2ban/filter.d/vsftpd.conf <<EOF
[Definition]
failregex = ^%(__prefix_line)s.*?FAIL LOGIN: Client "<HOST>"$
            ^%(__prefix_line)s.*?Client "<HOST>" is not allowed to login.*$
            ^%(__prefix_line)s.*?incorrect password from.* <HOST>.*$
ignoreregex =
EOF
fi

# 8. Vérification de la configuration
print_status "Vérification de la configuration Fail2ban..."
fail2ban-client -t

if [ $? -ne 0 ]; then
    print_error "La vérification de la configuration Fail2ban a échoué. Veuillez vérifier manuellement."
    exit 1
fi

# 9. Activation et démarrage du service
print_status "Activation et démarrage du service Fail2ban..."
systemctl enable fail2ban
systemctl start fail2ban

# Attente pour que le service démarre complètement
sleep 3

# Vérification du statut
systemctl status fail2ban

# 10. Vérification des jails actifs
print_status "Vérification des jails Fail2ban actifs..."
fail2ban-client status

# 11. Configuration de la persistance après redémarrage
print_status "Configuration de la persistance après redémarrage..."

# Création d'un script pour nettoyer les fichiers socket
cat > /usr/local/bin/fail2ban-cleanup.sh <<EOF
#!/bin/bash
# Script de nettoyage des fichiers socket de Fail2ban
rm -f /var/run/fail2ban/fail2ban.sock
EOF
chmod +x /usr/local/bin/fail2ban-cleanup.sh

# Création d'un service oneshot pour nettoyer les sockets avant démarrage
cat > /etc/systemd/system/fail2ban-cleanup.service <<EOF
[Unit]
Description=Fail2ban Socket Cleanup
Before=fail2ban.service
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/fail2ban-cleanup.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

# Activation du service de nettoyage
systemctl daemon-reload
systemctl enable fail2ban-cleanup.service

# 12. Informations finales
print_status "Configuration de Fail2ban terminée avec succès!"
print_status "Protection standard SSH: $JAIL_MAXRETRY tentatives en $JAIL_FINDTIME secondes = bannissement de $JAIL_BANTIME secondes"
print_status "Protection standard FTP: $JAIL_MAXRETRY tentatives en $JAIL_FINDTIME secondes = bannissement de $JAIL_BANTIME secondes"
print_status "Protection agressive FTP: $JAIL_AGGRESSIVE_MAXRETRY tentatives en $JAIL_AGGRESSIVE_FINDTIME secondes = bannissement de $JAIL_AGGRESSIVE_BANTIME secondes"
print_status "Protection récidive: $JAIL_RECIDIVE_MAXRETRY bannissements en $JAIL_RECIDIVE_FINDTIME secondes = bannissement de $JAIL_RECIDIVE_BANTIME secondes"

print_warning "Commandes utiles:"
print_warning "  - Vérifier le statut: sudo fail2ban-client status"
print_warning "  - Vérifier jail SSH: sudo fail2ban-client status sshd"
print_warning "  - Vérifier jail FTP: sudo fail2ban-client status vsftpd"
print_warning "  - Débannir une IP: sudo fail2ban-client set [jail] unbanip [IP_ADDRESS]"

exit 0