#!/bin/bash


VM_ID=101                       
VM_NAME="pfsense-firewall" 
ISO_STORAGE="local"     
ISO_FILE="pfSense-CE-2.7.2-RELEASE-amd64.iso" 
STORAGE="local-lvm" 
DISK_SIZE="16G"           
BRIDGE_WAN="vmbr0"              
BRIDGE_LAN="vmbr1"
RAM=2048
CORES=1              

# Créer une VM sur Proxmox
echo "Création de la VM pour pfSense..."
qm create $VM_ID \
  --name $VM_NAME \
  --memory $RAM \
  --cores $CORES \
  --net0 virtio,bridge=$BRIDGE_WAN \
  --net1 virtio,bridge=$BRIDGE_LAN \
  --scsihw virtio-scsi-pci \
  --ide2 $STORAGE:iso/$ISO_PATH,media=cdrom \
  --boot order=ide2 \
  --ostype other \
  --agent 1

# Ajout disque
qm set $VM_ID --scsi0 $STORAGE:vm-$VM_ID-disk-0,size=$DISK_SIZE

# Démarrer la VM
echo "Démarrage de la VM avec l'ISO pfSense..."
qm start $VM_ID

echo "La VM PfSense a été créée et démarreeeeeey"
