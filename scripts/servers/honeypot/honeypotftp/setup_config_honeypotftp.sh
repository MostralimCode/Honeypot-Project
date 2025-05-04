#!/bin/bash

# Script de configuration automatique du honeypot FTP

echo "=== Installation du Honeypot FTP ==="

#Configuration principale
echo "[+] Création du fichier de configuration settings.ini..."
cat > /root/honeypot-ftp/config/settings.ini << EOF
[Server]
host = 0.0.0.0
port = 21
max_connections = 10
timeout = 300

[Security]
enable_chroot = true
max_upload_size = 10485760
allow_anonymous = true

[Vulnerabilities]
enable_weak_auth = true
enable_traversal = true
enable_command_injection = false

[Logging]
level = INFO
log_directory = /root/honeypot-ftp/logs
elk_enabled = false
EOF

# Base d'utilisateurs simulés
echo "[+] Création du fichier users.json..."
cat > /root/honeypot-ftp/config/users.json << EOF
{
  "users": [
    {"username": "admin", "password": "admin"},
    {"username": "root", "password": "root"},
    {"username": "test", "password": "test"},
    {"username": "anonymous", "password": ""}
  ]
}
EOF

# Script de déploiement
echo "[+] Création du script de déploiement..."
cat > /root/honeypot-ftp/deploy.sh << 'EOF'
#!/bin/bash
cd /root/honeypot-ftp
source honeypot-env/bin/activate

# Tuer le processus existant si présent
pkill -f "python3 run.py"

# Attendre que le port soit libéré
sleep 2

# Démarrer le honeypot
python3 run.py &

# Afficher le statut
echo "FTP Honeypot démarré"
echo "Logs: tail -f logs/ftp_server.log"
EOF

chmod +x /root/honeypot-ftp/deploy.sh

# Point d'entrée principal
echo "[+] Création du script run.py..."
cat > /root/honeypot-ftp/run.py << EOF
#!/usr/bin/env python3
import os
import sys
sys.path.append('src')

from core.ftp_server import FTPServer

if __name__ == "__main__":
    server = FTPServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Arrêt du serveur...")
        server.stop()
EOF

chmod +x /root/honeypot-ftp/run.py

# 8. Service systemd
echo "[+] Création du service systemd..."
cat > /etc/systemd/system/ftp-honeypot.service << EOF
[Unit]
Description=FTP Honeypot Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/honeypot-ftp
Environment="PATH=/root/honeypot-env/bin"
ExecStart=/root/honeypot-env/bin/python3 /root/honeypot-ftp/run.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Activer le service mais ne pas le démarrer tout de suite
systemctl daemon-reload
systemctl enable ftp-honeypot

# Script de monitoring
echo "[+] Création du script de monitoring..."
cat > /root/honeypot-ftp/monitor.sh << 'EOF'
#!/bin/bash
while true; do
    if ! pgrep -f "python3 run.py" > /dev/null; then
        echo "Honeypot arrêté, redémarrage..."
        cd /root/honeypot-ftp
        source honeypot-env/bin/activate
        python3 run.py &
    fi
    sleep 60
done
EOF

chmod +x /root/honeypot-ftp/monitor.sh

# Sécurité additionnelle
echo "[+] Configuration de la sécurité..."
# Limiter l'accès aux logs (même en root, c'est une bonne pratique)
chmod 700 /root/honeypot-ftp/logs

# Protéger les fichiers de configuration
chmod 600 /root/honeypot-ftp/config/*

# Firewall rules
echo "[+] Configuration du firewall..."
ufw allow 21/tcp
ufw --force enable

# Vérifier si un autre service FTP est actif
if systemctl is-active --quiet vsftpd; then
    echo "[+] Arrêt de vsftpd..."
    systemctl stop vsftpd
    systemctl disable vsftpd
fi

# Créer un alias pour faciliter le déploiement
echo "alias deploy-ftp='/root/honeypot-ftp/deploy.sh'" >> /root/.bashrc

echo ""
echo "=== Installation terminée ==="
echo ""
echo "Pour démarrer le honeypot:"
echo "cd /root/honeypot-ftp"
echo "./deploy.sh"
echo ""
echo "Ou utiliser le service systemd:"
echo "systemctl start ftp-honeypot"
echo ""
echo "Pour surveiller les logs:"
echo "tail -f /root/honeypot-ftp/logs/ftp_server.log"