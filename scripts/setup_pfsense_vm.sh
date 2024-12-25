#!/bin/bash

# Variables
PROXMOX_HOST="192.168.1.10"     # Adresse IP de Proxmox
PROXMOX_USER="root@pam"         # Utilisateur de Proxmox
PROXMOX_PASSWORD="your_password" # Mot de passe Proxmox
VM_ID=101                       # ID unique de la VM
VM_NAME="pfsense-firewall"      # Nom de la VM
ISO_PATH="/var/lib/vz/template/iso/pfSense-CE-2.7.2-RELEASE-amd64.iso" # Chemin vers l'ISO
STORAGE="local-lvm"             # Stockage pour le disque de la VM
BRIDGE_WAN="vmbr0"              # Interface WAN (externe)
BRIDGE_LAN="vmbr1"              # Interface LAN (interne)

# Créer une VM sur Proxmox
echo "Création de la VM pour pfSense..."
qm create $VM_ID \
  --name $VM_NAME \
  --memory 2048 \
  --cores 1 \
  --net0 virtio,bridge=$BRIDGE_WAN \
  --net1 virtio,bridge=$BRIDGE_LAN \
  --scsihw virtio-scsi-pci \
  --ide2 $STORAGE:iso/$ISO_PATH,media=cdrom \
  --boot order=ide2 \
  --ostype other \
  --agent 1

# Ajouter un disque à la VM
qm set $VM_ID --scsi0 $STORAGE:10

# Démarrer la VM
echo "Démarrage de la VM avec l'ISO pfSense..."
qm start $VM_ID

echo "VM créée avec succès. Connectez-vous via l'interface Proxmox pour terminer l'installation de pfSense."
