#!/bin/bash

# Variables
VM_ID=201
VM_NAME="ssh-server"
ISO_STORAGE="local"
ISO_FILE="debian-12.9.0-amd64-netinst.iso"
STORAGE="local-lvm"
DISK_SIZE="10G"
BRIDGE="vmbr1"
RAM=1024
CORES=1

# Création VM
echo "Création de la VM pour le serveur SSH..."
qm create $VM_ID \
    --name $VM_NAME \
    --memory $RAM \
    --cores $CORES \
    --net0 virtio,bridge=$BRIDGE \
    --scsihw virtio-scsi-pci \
    --ide2 $ISO_STORAGE:iso/$ISO_FILE,media=cdrom \
    --boot order=ide2 \
    --ostype l26 \

# Ajout disque
qm set $VM_ID --scsi0 $STORAGE:vm-$VM_ID-disk-0,size=$DISK_SIZE

# Activer l'agent
qm set $VM_ID --agent enabled=1

# Démarrer VM
echo "Démarrage de la VM goooooooooooo..."
qm start $VM_ID

echo "La VM SSH a été créée et démarreeeeeeyyyyyy"