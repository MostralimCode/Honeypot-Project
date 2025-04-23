#!/bin/bash

# Script d'installation et de configuration sécurisée d'OpenSSH

# Variables de configuration
SSH_PORT=2222
SSH_LISTEN_ADDRESS="192.168.2.115"
SSH_ALLOWED_USER="admin"

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

print_status "Début de la configuration sécurisée d'OpenSSH"

# 2. Installation des paquets nécessaires
print_status "Installation d'OpenSSH et des paquets utilitaires..."
apt update
apt install -y openssh-server vim sudo nano wget curl htop

# 3. Sauvegarde de la configuration SSH d'origine
print_status "Sauvegarde de la configuration SSH d'origine..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d)

# 4. Configuration d'OpenSSH
print_status "Configuration sécurisée d'OpenSSH..."

cat > /etc/ssh/sshd_config <<EOF
# Configuration sécurisée d'OpenSSH pour le projet Honeypot
# Date de configuration: $(date +%Y-%m-%d)

# Paramètres d'écoute
Port ${SSH_PORT}
ListenAddress ${SSH_LISTEN_ADDRESS}

# Paramètres de protocole et de clés
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Paramètres d'authentification
PermitRootLogin no
MaxAuthTries 3
MaxSessions 2
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
AuthenticationMethods publickey,password

# Restrictions utilisateurs
AllowUsers ${SSH_ALLOWED_USER}

# Paramètres de sécurité des sessions
ClientAliveInterval 300
ClientAliveCountMax 2
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
TCPKeepAlive yes

# Bannière de connexion
Banner /etc/ssh/banner.txt

# Journalisation
SyslogFacility AUTH
LogLevel VERBOSE

# Configurations cryptographiques
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Divers
UsePAM yes
PrintMotd no
PrintLastLog yes
AcceptEnv LANG LC_*
Subsystem sftp internal-sftp
EOF

# 5. Création de la bannière SSH
print_status "Création de la bannière SSH..."

cat > /etc/ssh/banner.txt <<EOF
**************************************************************************
ATTENTION : Accès Restreint - Serveur Sécurisé
Ce système est réservé aux utilisateurs autorisés uniquement.
Toutes les activités sont enregistrées et peuvent être surveillées.
Les accès non autorisés sont strictement interdits.
**************************************************************************
EOF

# 6. Vérification de la syntaxe de la configuration
print_status "Vérification de la syntaxe de la configuration SSH..."
sshd -t

if [ $? -ne 0 ]; then
    print_error "La vérification de la configuration SSH a échoué. Annulation des modifications..."
    cp /etc/ssh/sshd_config.bak.$(date +%Y%m%d) /etc/ssh/sshd_config
    exit 1
fi

# 7. Redémarrage du service SSH
print_status "Redémarrage du service SSH..."
systemctl restart ssh
systemctl status ssh

# 8. Vérification de l'écoute sur le nouveau port
print_status "Vérification de l'écoute SSH sur le port ${SSH_PORT}..."
ss -tuln | grep ${SSH_PORT}

if [ $? -ne 0 ]; then
    print_warning "Le service SSH ne semble pas écouter sur le port ${SSH_PORT}. Veuillez vérifier manuellement."
else
    print_status "Le service SSH écoute correctement sur le port ${SSH_PORT}"
fi

# 9. Informations finales
print_status "Configuration d'OpenSSH terminée avec succès!"
print_status "Le serveur SSH est maintenant configuré pour écouter sur le port ${SSH_PORT}"
print_status "Utilisateur autorisé: ${SSH_ALLOWED_USER}"
print_warning "N'oubliez pas de configurer le pare-feu et Fail2ban pour protéger davantage votre serveur SSH"
print_warning "Pour vous connecter: ssh -p ${SSH_PORT} ${SSH_ALLOWED_USER}@${SSH_LISTEN_ADDRESS}"

exit 0