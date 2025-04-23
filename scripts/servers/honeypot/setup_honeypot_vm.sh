#!/bin/bash

VM_ID=105
VMNAME="honeypot"
ISO_STORAGE="local"
ISO_FILE="debian-12.5.0-amd64-netinst.iso"
DISK_SIZE=15G
BRIDGE="vmbr2"
RAM=2048
CORES=2

DISK_STORAGE="local-lvm"  
EFI_STORAGE="local"        

echo "[+] Création de la VM $VMNAME avec l'ID $VM_ID..."
qm create $VM_ID --name $VMNAME --memory $RAM --cores $CORES --net0 virtio,bridge=$BRIDGE

echo "[+] Ajout du disque de $DISK_SIZE sur $DISK_STORAGE..."
qm set $VM_ID --scsihw virtio-scsi-pci --scsi0 $DISK_STORAGE:vm-$VM_ID-disk-0,size=$DISK_SIZE

echo "[+] Montage de l'image ISO $ISO_FILE..."
qm set $VM_ID --cdrom $ISO_STORAGE:iso/$ISO_FILE

echo "[+] Configuration BIOS (OVMF) et activation de l'agent invité..."
qm set $VM_ID --bios ovmf --agent enabled=1

echo "[+] Ajout d'un disque EFI sur le stockage $EFI_STORAGE..."
qm set $VM_ID --efidisk0 $EFI_STORAGE:1,format=raw,size=1M

echo "[+] Configuration de l'ordre de boot..."
qm set $VM_ID --boot order=scsi0

echo "[+] Démarrage de la VM $VMNAME..."
qm start $VM_ID

echo "--------------------------------------------------"
echo "La VM $VMNAME (ID $VM_ID) a été créée et démarrée !"
echo "--------------------------------------------------"
