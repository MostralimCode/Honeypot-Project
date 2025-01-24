#!/bin/bash

# Variables
VM_ID=103
VMNAME="fedora-client"
ISO_STORAGE="local"
ISO_FILE="Fedora-Workstation-Live-x86_64-41-1.4.iso"
DISK_SIZE=20G
BRIDGE="vmbr1"
RAM=2048
CORES=2

# Création VM
qm create $VMID --name $VMNAME --memory $RAM --cores $CORES --net0 virtio,bridge=$BRIDGE

# Ajout disque dur
qm set $VMID --scsihw virtio-scsi-pci --scsi0 $STORAGE:vm-$VMID-disk-0,size=$DISK_SIZE

#Ajout ISO
qm set $VMID --cdrom $ISO_STORAGE:iso/$ISO_FILE

#Config BIOS et agent
qm set $VMID --bios ovmf --agent enabled=1

#Config démarrage auto
qm set $VMID --boot order=scsi0

#Démarrage VM
qm start $VMID

echo "La VM $VMNAME a été créée et demarreey"


