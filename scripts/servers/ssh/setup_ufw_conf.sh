#!/bin/bash

# Script d'installation et de configuration d'UFW

# Variables de configuration
SSH_PORT=2222
LAN_NETWORK="192.168.2.0/24"
SERVER_IP="192.168.2.115"


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

print_status "Début de l'installation et de la configuration d'UFW"

# 2. Installation d'UFW
print_status "Installation d'UFW..."
apt update
apt install -y ufw

# 3. Réinitialisation d'UFW (supprime toutes les règles existantes)
print_status "Réinitialisation des règles UFW..."
ufw --force reset

# 4. Configuration des politiques par défaut
print_status "Configuration des politiques par défaut..."
ufw default deny incoming
ufw default allow outgoing

# 5. Configuration des règles spécifiques
print_status "Configuration des règles pour le serveur SSH..."

# Autoriser SSH depuis le réseau LAN uniquement
print_status "Autorisation des connexions SSH (port ${SSH_PORT}) depuis le réseau LAN (${LAN_NETWORK})..."
ufw allow from ${LAN_NETWORK} to any port ${SSH_PORT} proto tcp comment 'SSH from LAN only'

# 6. Activation d'UFW
print_warning "Activation d'UFW. Cela peut interrompre les connexions existantes si elles ne sont pas autorisées."
print_warning "Assurez-vous d'avoir configuré la règle pour autoriser votre connexion actuelle."
print_warning "Appuyez sur Entrée pour continuer ou Ctrl+C pour annuler..."
read

# Activer UFW sans demande de confirmation
print_status "Activation d'UFW..."
ufw --force enable

# 7. Vérification de la configuration
print_status "Vérification de la configuration UFW..."
ufw status verbose
ufw status numbered

# 8. Sauvegarder la configuration
print_status "Sauvegarde de la configuration UFW..."
mkdir -p /root/firewall-backups
ufw status verbose > /root/firewall-backups/ufw-config-$(date +%Y%m%d).txt
print_status "Configuration sauvegardée dans /root/firewall-backups/ufw-config-$(date +%Y%m%d).txt"

# 9. Informations finales
print_status "Configuration d'UFW terminée avec succès!"
print_status "Seules les connexions SSH depuis le réseau ${LAN_NETWORK} vers le port ${SSH_PORT} sont autorisées."
print_warning "Commandes utiles:"
print_warning "  - Vérifier le statut: sudo ufw status verbose"
print_warning "  - Ajouter une règle: sudo ufw allow ..."
print_warning "  - Supprimer une règle: sudo ufw delete [numéro]"
print_warning "  - Désactiver UFW: sudo ufw disable"

exit 0