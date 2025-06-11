#!/bin/bash
# scripts/elk/setup_elk_vm.sh
# Création de la VM ELK Stack sur Proxmox
# Auteurs: AMINE OUACHA & YANIS BETTA

# ================================
# CONFIGURATION DE LA VM ELK
# ================================

# Variables de configuration
VM_ID=204
VM_NAME="elk-stack"
ISO_STORAGE="local"
ISO_FILE="debian-12.9.0-amd64-netinst.iso"
DISK_SIZE="60G"  # Augmenté pour les logs et indices
BRIDGE="vmbr1"   # Réseau LAN honeypot
RAM=8192         # 8GB requis pour ELK Stack
CORES=4          # 4 cœurs pour de bonnes performances

# Stockage
DISK_STORAGE="local-lvm"
EFI_STORAGE="local"

# Réseau
ELK_IP="192.168.2.124"  # IP statique pour ELK

# Couleurs pour l'affichage
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Fonctions utilitaires
print_status() {
    echo -e "${GREEN}[+] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

print_error() {
    echo -e "${RED}[-] $1${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Ce script doit être exécuté en tant que root sur l'hyperviseur Proxmox"
        exit 1
    fi
}

check_vm_exists() {
    if qm status $VM_ID >/dev/null 2>&1; then
        print_warning "La VM avec l'ID $VM_ID existe déjà"
        read -p "Voulez-vous la supprimer et recréer ? (y/N): " confirm
        if [[ $confirm =~ ^[Yy]$ ]]; then
            print_status "Suppression de la VM existante..."
            qm stop $VM_ID 2>/dev/null || true
            sleep 5
            qm destroy $VM_ID --purge
        else
            print_error "Abandon de la création"
            exit 1
        fi
    fi
}

# ================================
# DÉBUT DU SCRIPT
# ================================

print_status "=== Création de la VM ELK Stack ==="
echo "Configuration:"
echo "  - ID VM: $VM_ID"
echo "  - Nom: $VM_NAME"
echo "  - RAM: ${RAM}MB"
echo "  - CPU: $CORES cœurs"
echo "  - Disque: $DISK_SIZE"
echo "  - IP prévue: $ELK_IP"
echo ""

# Vérifications préliminaires
check_root
check_vm_exists

# Vérifier que l'ISO existe
if [ ! -f "/var/lib/vz/template/iso/$ISO_FILE" ]; then
    print_error "L'ISO $ISO_FILE n'existe pas dans /var/lib/vz/template/iso/"
    print_warning "Téléchargez d'abord l'ISO Debian 12 depuis:"
    print_warning "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/"
    exit 1
fi

# Vérifier les ressources disponibles
print_status "Vérification des ressources disponibles..."
AVAILABLE_RAM=$(free -m | awk 'NR==2{printf "%.0f", $7}')
if [ $AVAILABLE_RAM -lt $RAM ]; then
    print_warning "RAM disponible: ${AVAILABLE_RAM}MB, requis: ${RAM}MB"
    read -p "Continuer quand même ? (y/N): " confirm
    [[ ! $confirm =~ ^[Yy]$ ]] && exit 1
fi

# ================================
# CRÉATION DE LA VM
# ================================

print_status "Création de la VM $VM_NAME avec l'ID $VM_ID..."

qm create $VM_ID \
    --name $VM_NAME \
    --memory $RAM \
    --cores $CORES \
    --sockets 1 \
    --cpu host \
    --net0 virtio,bridge=$BRIDGE \
    --scsihw virtio-scsi-pci \
    --ostype l26 \
    --agent enabled=1,fstrim_cloned_disks=1 \
    --description "ELK Stack pour projet Honeypot - Elasticsearch, Logstash, Kibana"

if [ $? -ne 0 ]; then
    print_error "Échec de la création de la VM"
    exit 1
fi

print_status "VM créée avec succès"

# ================================
# CONFIGURATION DU STOCKAGE
# ================================

print_status "Configuration du stockage..."

# Ajout du disque principal
print_status "Ajout du disque principal ($DISK_SIZE)..."
qm set $VM_ID --scsi0 $DISK_STORAGE:vm-$VM_ID-disk-0,size=$DISK_SIZE,cache=writeback,discard=on

# Configuration UEFI
print_status "Configuration UEFI..."
qm set $VM_ID --bios ovmf
qm set $VM_ID --efidisk0 $EFI_STORAGE:1,format=raw,efitype=4m,size=1M

# Montage de l'ISO
print_status "Montage de l'image ISO..."
qm set $VM_ID --ide2 $ISO_STORAGE:iso/$ISO_FILE,media=cdrom

# Configuration de l'ordre de boot
qm set $VM_ID --boot order=scsi0\;ide2

# ================================
# OPTIMISATIONS POUR ELK
# ================================

print_status "Application des optimisations pour ELK Stack..."

# Options avancées pour de meilleures performances
qm set $VM_ID --balloon 0  # Désactiver le ballooning pour ELK
qm set $VM_ID --numa 1     # Activer NUMA pour de meilleures performances

# Configuration des options de l'hyperviseur
qm set $VM_ID --args "-cpu host,+x2apic"

print_status "Optimisations appliquées"

# ================================
# CONFIGURATION RÉSEAU
# ================================

print_status "Informations réseau pour la configuration post-installation:"
echo "  IP à configurer: $ELK_IP"
echo "  Masque: 255.255.255.0 (/24)"
echo "  Passerelle: 192.168.2.1"
echo "  DNS: 1.1.1.1, 8.8.8.8"
echo ""

# ================================
# DÉMARRAGE DE LA VM
# ================================

print_status "Démarrage de la VM pour l'installation..."
qm start $VM_ID

if [ $? -eq 0 ]; then
    print_status "VM démarrée avec succès!"
    echo ""
    print_status "=== Étapes suivantes ==="
    echo "1. Accédez à la console de la VM via Proxmox"
    echo "2. Procédez à l'installation de Debian 12"
    echo "3. Configuration réseau recommandée:"
    echo "   - IP statique: $ELK_IP"
    echo "   - Hostname: elk-stack"
    echo "   - Domain: honeypot.local"
    echo "4. Partitionnement recommandé:"
    echo "   - / (root): 15GB"
    echo "   - /var: 40GB (pour les logs et données ELK)"
    echo "   - swap: 2GB"
    echo "5. Sélectionnez 'SSH server' et 'Standard system utilities'"
    echo ""
    print_warning "Une fois l'installation terminée, exécutez:"
    print_warning "   scripts/elk/post_install_elk.sh"
    echo ""
    print_status "Commande pour accéder à la console:"
    echo "   qm monitor $VM_ID"
    echo "   Ou via l'interface web Proxmox"
else
    print_error "Échec du démarrage de la VM"
    exit 1
fi

# ================================
# AFFICHAGE DES INFORMATIONS
# ================================

echo ""
print_status "=== Résumé de la VM créée ==="
echo "ID: $VM_ID"
echo "Nom: $VM_NAME"
echo "RAM: ${RAM}MB"
echo "CPU: $CORES cœurs"
echo "Disque: $DISK_SIZE"
echo "Réseau: $BRIDGE"
echo "IP prévue: $ELK_IP"
echo "État: $(qm status $VM_ID | awk '{print $2}')"
echo ""

# Sauvegarder la configuration dans un fichier
CONFIG_FILE="/tmp/elk_vm_config.txt"
cat > $CONFIG_FILE << EOF
=== Configuration VM ELK Stack ===
Date de création: $(date)
ID VM: $VM_ID
Nom: $VM_NAME
RAM: ${RAM}MB
CPU: $CORES cœurs
Disque: $DISK_SIZE
IP: $ELK_IP
Réseau: $BRIDGE

Ports à ouvrir après installation:
- 9200 (Elasticsearch)
- 5601 (Kibana)
- 5044 (Logstash Beats input)

Étapes suivantes:
1. Installation Debian 12
2. Configuration réseau statique
3. Installation stack ELK
4. Configuration des honeypots
EOF

print_status "Configuration sauvegardée dans: $CONFIG_FILE"

print_status "=== Création de la VM ELK terminée avec succès! ==="