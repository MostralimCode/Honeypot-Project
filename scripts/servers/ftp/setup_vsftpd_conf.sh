#!/bin/bash

# Script d'installation et de configuration de vsftpd sécurisé

# Variables de configuration
FTP_USER="ftpuser"
FTP_ADMIN="ftpadmin"
FTP_IP="192.168.2.116"
FTP_PASV_MIN=40000
FTP_PASV_MAX=40100
FTP_DATA_DIR="/srv/ftp"

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

print_status "Début de l'installation et de la configuration du serveur FTP sécurisé"

# 2. Installation des paquets nécessaires
print_status "Installation de vsftpd et des outils nécessaires..."
apt update
apt install -y vsftpd openssl acl ufw

# 3. Sauvegarde de la configuration par défaut
print_status "Sauvegarde de la configuration vsftpd d'origine..."
cp /etc/vsftpd.conf /etc/vsftpd.conf.bak.$(date +%Y%m%d)

# 4. Configuration sécurisée de vsftpd
print_status "Configuration sécurisée de vsftpd..."

cat > /etc/vsftpd.conf <<EOF
# Configuration sécurisée de vsftpd
# Projet Honeypot - Serveur FTP sécurisé

# Paramètres de base
listen=YES
listen_ipv6=NO
listen_port=21

# Désactivation de l'accès anonyme
anonymous_enable=NO
anon_upload_enable=NO
anon_mkdir_write_enable=NO

# Activation des utilisateurs locaux
local_enable=YES
write_enable=YES
local_umask=022

# Restrictions d'accès
chroot_local_user=YES
allow_writeable_chroot=NO
secure_chroot_dir=/var/run/vsftpd/empty
hide_ids=YES

# Bannières et messages
ftpd_banner=Serveur FTP sécurisé - Accès restreint
dirmessage_enable=YES

# Journalisation
xferlog_enable=YES
xferlog_std_format=YES
log_ftp_protocol=YES
syslog_enable=YES
dual_log_enable=YES
vsftpd_log_file=/var/log/vsftpd.log

# Configuration SSL/TLS
ssl_enable=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO
ssl_ciphers=HIGH
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
force_local_data_ssl=YES
force_local_logins_ssl=YES

# Configuration du mode passif
pasv_enable=YES
pasv_min_port=${FTP_PASV_MIN}
pasv_max_port=${FTP_PASV_MAX}
pasv_address=${FTP_IP}

# Restrictions diverses
tcp_wrappers=YES
pam_service_name=vsftpd
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO

# Limitations
max_clients=10
max_per_ip=3
local_max_rate=3072000

# Configuration par utilisateur
user_config_dir=/etc/vsftpd/users
EOF

# 5. Création du certificat SSL
print_status "Création du certificat SSL..."

mkdir -p /etc/ssl/private
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem \
    -subj "/C=FR/ST=Paris/L=Paris/O=Honeypot Project/OU=Security/CN=ftp-secure.honeypot.local/emailAddress=admin@honeypot.local"

chmod 600 /etc/ssl/private/vsftpd.pem

# 6. Création des répertoires nécessaires
print_status "Création des répertoires nécessaires..."

# Répertoire chroot
mkdir -p /var/run/vsftpd/empty

# Structure principale des répertoires FTP
mkdir -p ${FTP_DATA_DIR}
mkdir -p ${FTP_DATA_DIR}/upload
mkdir -p ${FTP_DATA_DIR}/download
mkdir -p ${FTP_DATA_DIR}/shared

# Répertoire de configuration par utilisateur
mkdir -p /etc/vsftpd/users

# 7. Création des groupes d'utilisateurs
print_status "Création des groupes d'utilisateurs..."

groupadd ftpusers
groupadd ftpadmins

# 8. Configuration des utilisateurs
print_status "Création et configuration des utilisateurs FTP..."

# Utilisateur standard
adduser --home ${FTP_DATA_DIR}/${FTP_USER} --shell /bin/false --disabled-password --gecos "" ${FTP_USER}
echo "${FTP_USER}:GY9w68na2pAX4e" | chpasswd  
usermod -g ftpusers ${FTP_USER}

# Utilisateur administrateur
adduser --home ${FTP_DATA_DIR}/${FTP_ADMIN} --shell /bin/false --disabled-password --gecos "" ${FTP_ADMIN}
echo "${FTP_ADMIN}:L53dZwK2k22Mun" | chpasswd  
usermod -g ftpadmins ${FTP_ADMIN}

# 9. Configuration des répertoires utilisateurs
print_status "Configuration des répertoires utilisateurs..."

# Répertoires personnels
mkdir -p ${FTP_DATA_DIR}/${FTP_USER}
mkdir -p ${FTP_DATA_DIR}/${FTP_ADMIN}

# Attribution des propriétés et permissions
chown -R ${FTP_USER}:ftpusers ${FTP_DATA_DIR}/${FTP_USER}
chown -R ${FTP_ADMIN}:ftpadmins ${FTP_DATA_DIR}/${FTP_ADMIN}
chmod 750 ${FTP_DATA_DIR}/${FTP_USER}
chmod 750 ${FTP_DATA_DIR}/${FTP_ADMIN}

# Permissions sur les répertoires partagés
chown ${FTP_ADMIN}:ftpadmins ${FTP_DATA_DIR}/upload ${FTP_DATA_DIR}/download ${FTP_DATA_DIR}/shared
chmod 770 ${FTP_DATA_DIR}/upload ${FTP_DATA_DIR}/shared
chmod 750 ${FTP_DATA_DIR}/download

# Mise en place des ACLs
apt install -y acl
setfacl -m g:ftpusers:rx ${FTP_DATA_DIR}/download
setfacl -m g:ftpusers:rwx ${FTP_DATA_DIR}/upload
setfacl -m g:ftpusers:rx ${FTP_DATA_DIR}/shared

# 10. Configuration des restrictions par utilisateur
print_status "Configuration des restrictions par utilisateur..."

# Configuration pour l'utilisateur standard
cat > /etc/vsftpd/users/${FTP_USER} <<EOF
local_root=${FTP_DATA_DIR}/${FTP_USER}
write_enable=YES
download_enable=YES
dirlist_enable=YES
cmds_allowed=ABOR,CWD,LIST,MDTM,NLST,PASS,PASV,PORT,PWD,QUIT,RETR,SIZE,STOR,TYPE,USER,ACCT,APPE,CDUP,HELP,MODE,NOOP,REIN,STAT,STOU,STRU,SYST
EOF

# Configuration pour l'administrateur FTP
cat > /etc/vsftpd/users/${FTP_ADMIN} <<EOF
local_root=${FTP_DATA_DIR}
write_enable=YES
download_enable=YES
dirlist_enable=YES
cmds_denied=
EOF

# 11. Mise à jour de la liste des utilisateurs autorisés
print_status "Mise à jour de la liste des utilisateurs autorisés..."

echo "${FTP_USER}" > /etc/vsftpd.userlist
echo "${FTP_ADMIN}" >> /etc/vsftpd.userlist

# 12. Ajout de contenu de test
print_status "Création de fichiers de test..."

echo "Ceci est un fichier de téléchargement de test." > ${FTP_DATA_DIR}/download/test_download.txt
echo "Ceci est un fichier partagé de test." > ${FTP_DATA_DIR}/shared/test_shared.txt

chown ${FTP_ADMIN}:ftpadmins ${FTP_DATA_DIR}/download/test_download.txt ${FTP_DATA_DIR}/shared/test_shared.txt
chmod 644 ${FTP_DATA_DIR}/download/test_download.txt ${FTP_DATA_DIR}/shared/test_shared.txt

# 13. Configuration de la rotation des logs
print_status "Configuration de la rotation des logs..."

cat > /etc/logrotate.d/vsftpd <<EOF
/var/log/vsftpd.log {
    weekly
    rotate 12
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    postrotate
        service vsftpd restart > /dev/null
    endscript
}
EOF

# 14. Configuration du pare-feu
print_status "Configuration du pare-feu..."

ufw allow from 192.168.2.0/24 to any port 21 proto tcp comment 'FTP control from LAN'
ufw allow from 192.168.2.0/24 to any port ${FTP_PASV_MIN}:${FTP_PASV_MAX} proto tcp comment 'FTP passive from LAN'


# 15. Redémarrage et activation du service
print_status "Redémarrage et activation du service vsftpd..."

systemctl enable vsftpd
systemctl restart vsftpd

# 16. Vérification du service
print_status "Vérification du service vsftpd..."

systemctl status vsftpd

print_status "==================================="
print_status "Installation terminée avec succès !"
print_status "==================================="
print_status "Serveur FTP sécurisé configuré avec :"
print_status "- Adresse IP : ${FTP_IP}"
print_status "- Utilisateur standard : ${FTP_USER}"
print_status "- Utilisateur admin : ${FTP_ADMIN}"
print_status "- Chiffrement SSL/TLS activé"
print_status "- Mode passif configuré sur les ports ${FTP_PASV_MIN}-${FTP_PASV_MAX}"
print_status ""
print_status "Vous pouvez maintenant vous connecter via un client FTP compatible SSL/TLS"
print_status "comme FileZilla en utilisant les identifiants configurés."
print_status ""
print_warning "IMPORTANT: Veuillez modifier les mots de passe par défaut !"
print_warning "Pour l'utilisateur standard: passwd ${FTP_USER}"
print_warning "Pour l'administrateur: passwd ${FTP_ADMIN}"

exit 0