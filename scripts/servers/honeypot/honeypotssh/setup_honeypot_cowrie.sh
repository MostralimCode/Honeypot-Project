#!/bin/bash
# Script pour la personnalisation avancée de l'environnement Cowrie (point 2.4)
# À exécuter après avoir configuré la partie basique de Cowrie

echo "[+] Démarrage de la personnalisation de l'environnement Cowrie..."
cd ~/cowrie

# Arrêter Cowrie s'il est en cours d'exécution
echo "[+] Arrêt de Cowrie pour appliquer les modifications..."
bin/cowrie stop

# 2.4.1 Création des structures de répertoires
echo "[+] Création de la structure de fichiers simulée..."
mkdir -p honeyfs/home/{admin,user,root}
mkdir -p honeyfs/var/{www,log,backups,cache}
mkdir -p honeyfs/etc/{apache2,mysql,ssh,cron.d}
mkdir -p honeyfs/opt/scripts
mkdir -p honeyfs/tmp
mkdir -p honeyfs/usr/local/bin

# 2.4.2 Création des historiques bash
echo "[+] Création des historiques bash réalistes..."
cat > honeyfs/home/admin/.bash_history << 'EOF'
ls -la
cd /var/www/html
tail -f /var/log/apache2/error.log
ps aux | grep apache
sudo service apache2 restart
mysql -u admin -p
chmod 644 /var/www/html/config.php
vim /etc/apache2/sites-available/000-default.conf
netstat -tulpn
apt-get update
apt-get upgrade
scp backup.sql user@192.168.1.20:/var/backups/
EOF

cat > honeyfs/home/root/.bash_history << 'EOF'
cd /root
ls -la
iptables -L
service mysql status
vim /etc/ssh/sshd_config
tail -f /var/log/auth.log
ps aux | grep suspicious
kill -9 1234
top
iftop
fail2ban-client status
systemctl restart ssh
EOF

# 2.4.3 Création des fichiers de configuration simulés
echo "[+] Création des fichiers de configuration système simulés..."
cat > honeyfs/etc/passwd << 'EOF'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
mysql:x:105:113:MySQL Server,,,:/var/lib/mysql:/bin/false
postfix:x:106:115::/var/spool/postfix:/usr/sbin/nologin
admin:x:1000:1000:Admin User,,,:/home/admin:/bin/bash
user:x:1001:1001:Regular User,,,:/home/user:/bin/bash
EOF

cat > honeyfs/etc/group << 'EOF'
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,admin
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
fax:x:21:
voice:x:22:
cdrom:x:24:admin,user
floppy:x:25:
tape:x:26:
sudo:x:27:admin
audio:x:29:
dip:x:30:admin
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:admin,user
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
systemd-journal:x:101:
systemd-network:x:102:
systemd-resolve:x:103:
systemd-timesync:x:104:
input:x:105:
crontab:x:106:
netdev:x:108:
mysql:x:113:
ssh:x:114:
postfix:x:115:
postdrop:x:116:
admin:x:1000:
user:x:1001:
EOF

cat > honeyfs/etc/hosts << 'EOF'
127.0.0.1       localhost
127.0.1.1       svr01

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
EOF

# 2.4.4 Création de fichiers de configuration serveur
echo "[+] Création des fichiers de configuration serveur..."
mkdir -p honeyfs/etc/apache2
cat > honeyfs/etc/apache2/apache2.conf << 'EOF'
# Global configuration
ServerRoot "/etc/apache2"
Timeout 300
KeepAlive On
MaxKeepAliveRequests 100
KeepAliveTimeout 5

# MPM prefork specific configuration
<IfModule mpm_prefork_module>
    StartServers             5
    MinSpareServers          5
    MaxSpareServers         10
    MaxRequestWorkers       150
    MaxConnectionsPerChild   0
</IfModule>

# Default directory settings
<Directory />
    Options FollowSymLinks
    AllowOverride None
    Require all denied
</Directory>

<Directory /var/www/>
    Options Indexes FollowSymLinks
    AllowOverride All
    Require all granted
</Directory>

# Logging setup
ErrorLog ${APACHE_LOG_DIR}/error.log
LogLevel warn

# Include module configuration:
IncludeOptional mods-enabled/*.load
IncludeOptional mods-enabled/*.conf

# Include list of ports to listen on
Include ports.conf

# Include generic snippets of statements
IncludeOptional conf-enabled/*.conf

# Include the virtual host configurations:
IncludeOptional sites-enabled/*.conf
EOF

mkdir -p honeyfs/etc/mysql/mysql.conf.d
cat > honeyfs/etc/mysql/mysql.conf.d/mysqld.cnf << 'EOF'
[mysqld]
user            = mysql
pid-file        = /var/run/mysqld/mysqld.pid
socket          = /var/run/mysqld/mysqld.sock
port            = 3306
basedir         = /usr
datadir         = /var/lib/mysql
tmpdir          = /tmp
lc-messages-dir = /usr/share/mysql
bind-address    = 127.0.0.1
key_buffer_size         = 16M
max_allowed_packet      = 16M
thread_stack            = 192K
thread_cache_size       = 8
myisam-recover-options  = BACKUP
query_cache_limit       = 1M
query_cache_size        = 16M
expire_logs_days        = 10
max_binlog_size         = 100M
EOF

mkdir -p honeyfs/etc/ssh
cat > honeyfs/etc/ssh/sshd_config << 'EOF'
# Package generated configuration file
# See the sshd_config(5) manpage for details

Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin prohibit-password
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server
UsePAM yes
EOF

# 2.4.5 Création d'un site web factice
echo "[+] Configuration d'un site web factice..."
mkdir -p honeyfs/var/www/html
cat > honeyfs/var/www/html/index.php << 'EOF'
<?php
// Configuration for database
$db_host = "localhost";
$db_user = "webuser";
$db_pass = "password123";
$db_name = "website";

// Connect to database
$conn = mysqli_connect($db_host, $db_user, $db_pass, $db_name);

// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}

// Get site content
$query = "SELECT * FROM content WHERE page='home'";
$result = mysqli_query($conn, $query);

// Display header
include('header.php');

// Display content
while($row = mysqli_fetch_assoc($result)) {
    echo "<h1>" . $row['title'] . "</h1>";
    echo "<div class='content'>" . $row['body'] . "</div>";
}

// Display footer
include('footer.php');

mysqli_close($conn);
?>
EOF

# 2.4.6 Création des commandes personnalisées
echo "[+] Configuration des commandes personnalisées..."
mkdir -p txtcmds/bin
mkdir -p txtcmds/sbin
mkdir -p txtcmds/usr/bin

# Commande uname -a
cat > txtcmds/bin/uname << 'EOF'
Linux svr01 4.19.0-21-amd64 #1 SMP Debian 4.19.249-2 (2022-06-30) x86_64 GNU/Linux
EOF
chmod +x txtcmds/bin/uname

# Commande df -h
cat > txtcmds/bin/df << 'EOF'
Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        50G   22G   26G  46% /
tmpfs           3.9G     0  3.9G   0% /dev/shm
/dev/sda3       450G  318G  110G  75% /var
/dev/sda2       976M  220M  689M  25% /boot
EOF
chmod +x txtcmds/bin/df

# Commande ps aux
cat > txtcmds/bin/ps << 'EOF'
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.0 168924  6100 ?        Ss   Apr30   0:12 /sbin/init
root         412  0.0  0.2  70760  8904 ?        Ss   Apr30   0:02 /usr/bin/python3 /usr/bin/fail2ban-server -xf start
root         432  0.0  0.0  31116  3188 ?        Ss   Apr30   0:00 /usr/sbin/cron -f
root         436  0.0  0.1  14428  6452 ?        Ss   Apr30   0:01 /lib/systemd/systemd-logind
root         439  0.0  0.0   5816  1484 ?        Ss   Apr30   0:01 /sbin/iscsid
root         440  0.0  0.0   5816   924 ?        S<   Apr30   0:00 /sbin/iscsid
mysql        446  0.1  2.4 1744816 98164 ?       Ssl  Apr30   2:05 /usr/sbin/mysqld
message+     454  0.0  0.0   9460  3320 ?        Ss   Apr30   0:19 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root         461  0.0  0.0  28352  2808 ?        Ss   Apr30   0:00 /usr/sbin/sshd -D
root         467  0.0  0.1 288876  5112 ?        Ssl  Apr30   0:00 /usr/lib/policykit-1/polkitd --no-debug
www-data     480  0.0  0.8 214232 32784 ?        S    Apr30   0:00 /usr/sbin/apache2 -k start
www-data     481  0.0  0.8 214364 33112 ?        S    Apr30   0:01 /usr/sbin/apache2 -k start
root         483  0.0  0.6 214232 26928 ?        Ss   Apr30   0:01 /usr/sbin/apache2 -k start
postfix      487  0.0  0.1  73596  5104 ?        S    Apr30   0:00 pickup -l -t unix -u -c
postfix      488  0.0  0.1  73892  6260 ?        S    Apr30   0:00 qmgr -l -t unix -u
syslog       500  0.0  0.0 224344  3792 ?        Ssl  Apr30   0:00 /usr/sbin/rsyslogd -n -iNONE
root        1258  0.0  0.0      0     0 ?        S<   Apr30   0:00 [loop0]
root        1531  0.0  0.0      0     0 ?        S    10:49   0:00 [kworker/0:0-events]
root        1542  0.0  0.0      0     0 ?        S    11:04   0:00 [kworker/u4:1-events_unbound]
admin       1566  0.0  0.1  21436  5420 pts/0    Ss   11:14   0:00 -bash
admin       1625  0.0  0.1  38372  3388 pts/0    R+   11:24   0:00 ps aux
EOF
chmod +x txtcmds/bin/ps

# Commande netstat -tulpn
cat > txtcmds/bin/netstat << 'EOF'
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      461/sshd           
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      446/mysqld         
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      483/apache2        
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      483/apache2        
tcp6       0      0 :::22                   :::*                    LISTEN      461/sshd           
tcp6       0      0 :::80                   :::*                    LISTEN      483/apache2        
tcp6       0      0 :::443                  :::*                    LISTEN      483/apache2        
udp        0      0 0.0.0.0:68              0.0.0.0:*                           326/dhclient       
EOF
chmod +x txtcmds/bin/netstat

# Commande w
cat > txtcmds/bin/w << 'EOF'
 11:24:18 up 1 day,  2:03,  1 user,  load average: 0.08, 0.03, 0.01
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
admin    pts/0    192.168.1.100    11:14    0.00s  0.04s  0.01s w
EOF
chmod +x txtcmds/bin/w

# Commande ifconfig
cat > txtcmds/sbin/ifconfig << 'EOF'
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.10  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::215:5dff:fe01:7c80  prefixlen 64  scopeid 0x20<link>
        ether 00:15:5d:01:7c:80  txqueuelen 1000  (Ethernet)
        RX packets 948764  bytes 165342589 (157.6 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 520313  bytes 84899245 (80.9 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 5684  bytes 456243 (445.5 KiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 5684  bytes 456243 (445.5 KiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
EOF
chmod +x txtcmds/sbin/ifconfig

# Commande apt-get update
cat > txtcmds/usr/bin/apt-get << 'EOF'
Get:1 http://security.debian.org/debian-security buster/updates InRelease [65.4 kB]
Get:2 http://deb.debian.org/debian buster InRelease [122 kB]
Get:3 http://deb.debian.org/debian buster-updates InRelease [51.9 kB]
Get:4 http://security.debian.org/debian-security buster/updates/main Sources [250 kB]
Get:5 http://deb.debian.org/debian buster/main Sources [7,838 kB]
Get:6 http://security.debian.org/debian-security buster/updates/main amd64 Packages [380 kB]
Get:7 http://deb.debian.org/debian buster/main amd64 Packages [7,907 kB]
Fetched 16.6 MB in 3s (5,553 kB/s)                        
Reading package lists... Done
EOF
chmod +x txtcmds/usr/bin/apt-get

# Commande ls personnalisée
cat > txtcmds/bin/ls << 'EOF'
#!/bin/bash
if [ "$*" = "-la" ]; then
  echo "total 52"
  echo "drwxr-xr-x 10 admin admin  4096 Apr 30 10:20 ."
  echo "drwxr-xr-x  3 root  root   4096 Feb 10 11:35 .."
  echo "-rw-------  1 admin admin   653 Apr 30 11:14 .bash_history"
  echo "-rw-r--r--  1 admin admin   220 Feb 10 11:35 .bash_logout"
  echo "-rw-r--r--  1 admin admin  3526 Feb 10 11:35 .bashrc"
  echo "drwx------  3 admin admin  4096 Apr 15 09:22 .cache"
  echo "drwx------  3 admin admin  4096 Apr 15 09:22 .config"
  echo "drwxr-xr-x  3 admin admin  4096 Apr 15 09:22 .local"
  echo "-rw-r--r--  1 admin admin   807 Feb 10 11:35 .profile"
  echo "drwx------  2 admin admin  4096 Apr 15 09:22 .ssh"
  echo "-rw-r--r--  1 admin admin     0 Apr 15 09:23 .sudo_as_admin_successful"
  echo "drwxr-xr-x  2 admin admin  4096 Apr 15 09:23 Documents"
  echo "drwxr-xr-x  2 admin admin  4096 Apr 15 09:23 Downloads"
  echo "-rw-r--r--  1 admin admin  2458 Apr 29 14:08 backup_logs.txt"
  echo "-rwxr-xr-x  1 admin admin   552 Apr 25 16:42 monitor.sh"
elif [ "$*" = "-la /var/www/html" ] || [ "$*" = "-la /var/www/html/" ]; then
  echo "total 24"
  echo "drwxr-xr-x 2 www-data www-data 4096 Apr 28 15:36 ."
  echo "drwxr-xr-x 3 root     root     4096 Feb 10 11:46 .."
  echo "-rw-r--r-- 1 www-data www-data  812 Apr 28 15:36 footer.php"
  echo "-rw-r--r-- 1 www-data www-data  945 Apr 28 15:36 header.php"
  echo "-rw-r--r-- 1 www-data www-data  689 Apr 28 15:36 index.php"
  echo "-rw-r--r-- 1 www-data www-data  321 Apr 28 15:36 config.php"
elif [ "$*" = "-la /etc" ] || [ "$*" = "-la /etc/" ]; then
  echo "total 1332"
  echo "drwxr-xr-x 128 root root    12288 Apr 30 08:45 ."
  echo "drwxr-xr-x  22 root root     4096 Apr 15 09:23 .."
  echo "drwxr-xr-x   3 root root     4096 Feb 10 11:46 apache2"
  echo "drwxr-xr-x   2 root root     4096 Apr 15 09:23 apt"
  echo "-rw-r--r--   1 root root     2319 Apr 18 10:09 bash.bashrc"
  echo "drwxr-xr-x   2 root root     4096 Apr 27 11:20 cron.d"
  echo "drwxr-xr-x   2 root root     4096 Apr 15 09:23 cron.daily"
  echo "-rw-r--r--   1 root root       24 Jan  5  2023 debian_version"
  echo "-rw-r--r--   1 root root      604 Apr 15 09:23 deluser.conf"
  echo "drwxr-xr-x   4 root root     4096 Apr 15 09:23 dpkg"
  echo "-rw-r--r--   1 root root     1748 Apr 28 14:12 fstab"
  echo "-rw-r--r--   1 root root      100 Apr 28 14:12 group"
  echo "-rw-r-----   1 root shadow     40 Apr 28 14:12 gshadow"
  echo "-rw-r--r--   1 root root      427 Apr 28 14:12 hosts"
  echo "drwxr-xr-x   2 root root     4096 Feb 10 11:46 init.d"
  echo "drwxr-xr-x   3 root root     4096 Apr 15 09:23 logrotate.d"
  echo "drwxr-xr-x   4 root root     4096 Feb 10 11:46 mysql"
  echo "-rw-r--r--   1 root root     1748 Apr 28 14:12 passwd"
  echo "-rw-r-----   1 root shadow    986 Apr 28 14:12 shadow"
  echo "drwxr-xr-x   4 root root     4096 Apr 15 09:23 ssh"
  echo "drwxr-xr-x   2 root root     4096 Apr 15 09:23 ssl"
  echo "drwxr-xr-x   2 root root     4096 Apr 15 09:23 sudoers.d"
  echo "-rw-r--r--   1 root root      160 Apr 15 09:23 hosts.allow"
  echo "-rw-r--r--   1 root root      406 Apr 15 09:23 hosts.deny"
  echo "-rw-r--r--   1 root root      191 Apr 15 09:23 crontab"
else
  echo "Cannot access '$*': No such file or directory"
fi
EOF
chmod +x txtcmds/bin/ls

# 2.4.7 Configuration des réponses interactives
echo "[+] Configuration des réponses interactives..."
mkdir -p share/cowrie/txtcmds/bin
mkdir -p share/cowrie/txtcmds/usr/bin

# Pour sudo (demande de mot de passe et échoue)
cat > share/cowrie/txtcmds/bin/sudo << 'EOF'
#!/bin/sh
read -s -p "[sudo] password for $USER: " password
echo ""
echo "Sorry, try again."
read -s -p "[sudo] password for $USER: " password
echo ""
echo "Sorry, try again."
read -s -p "[sudo] password for $USER: " password
echo ""
echo "sudo: 3 incorrect password attempts"
EOF
chmod +x share/cowrie/txtcmds/bin/sudo

# Pour mysql (simulant un comportement interactif)
cat > share/cowrie/txtcmds/usr/bin/mysql << 'EOF'
#!/bin/sh
if [ "$*" = "-u admin -p" ]; then
  read -s -p "Enter password: " password
  echo ""
  echo "ERROR 1045 (28000): Access denied for user 'admin'@'localhost' (using password: YES)"
  exit 1
elif [ "$*" = "-u root -p" ]; then
  read -s -p "Enter password: " password
  echo ""
  if [ "$password" = "toor" ] || [ "$password" = "mysql123" ]; then
    echo "Welcome to the MySQL monitor.  Commands end with ; or \g."
    echo "Your MySQL connection id is 143"
    echo "Server version: 5.7.33-0ubuntu0.18.04.1 (Ubuntu)"
    echo ""
    echo "Copyright (c) 2000, 2021, Oracle and/or its affiliates."
    echo ""
    echo "Type 'help;' or '\h' for help. Type '\c' to clear the current input statement."
    echo ""
    echo "mysql> "
    exit 0
  else
    echo "ERROR 1045 (28000): Access denied for user 'root'@'localhost' (using password: YES)"
    exit 1
  fi
else
  echo "ERROR 1046 (3D000): No database selected"
  exit 1
fi
EOF
chmod +x share/cowrie/txtcmds/usr/bin/mysql

# Pour vim (simulant un comportement basique)
cat > share/cowrie/txtcmds/usr/bin/vim << 'EOF'
#!/bin/sh
FILE=$2
if [ -z "$FILE" ]; then
  echo "No file specified"
  exit 1
fi
echo "\"$FILE\" [New File]"
echo "~"
echo "~"
echo "~"
echo "~"
echo "~"
echo "~"
echo "~"
echo "~"
echo "~"
echo "$FILE" 0L, 0C
read -p "" input
echo "E37: No write since last change (add ! to override)"
read -p "" input
echo "Press ENTER or type command to continue"
read input
exit 0
EOF
chmod +x share/cowrie/txtcmds/usr/bin/vim

# Lien symbolique pour nano
ln -sf ~/cowrie/share/cowrie/txtcmds/usr/bin/vim ~/cowrie/share/cowrie/txtcmds/bin/nano

# 2.4.8 Création du message d'accueil (MOTD)
echo "[+] Configuration du message d'accueil (MOTD)..."
mkdir -p honeyfs/etc/update-motd.d
cat > honeyfs/etc/update-motd.d/00-header << 'EOF'
#!/bin/sh
echo "Welcome to Debian GNU/Linux 10 (buster)"
echo "System information as of $(date)"
EOF
chmod +x honeyfs/etc/update-motd.d/00-header

cat > honeyfs/etc/update-motd.d/10-sysinfo << 'EOF'
#!/bin/sh
echo "System load:  0.01 0.02 0.00   Users logged in: 1"
echo "Memory usage: 24%               IPv4 address: 192.168.1.10"
echo "Usage of /:   46% of 49.95GB    Swap usage:   0%"
EOF
chmod +x honeyfs/etc/update-motd.d/10-sysinfo

cat > honeyfs/etc/update-motd.d/90-footer << 'EOF'
#!/bin/sh
echo ""
echo "Last login: $(date -d '5 hours ago' '+%a %b %d %H:%M:%S %Y') from 192.168.1.20"
echo "Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent"
echo "permitted by applicable law."
EOF
chmod +x honeyfs/etc/update-motd.d/90-footer

# 2.4.9 Création de scripts factices "intéressants" pour les attaquants
echo "[+] Création de scripts factices attractifs pour les attaquants..."
mkdir -p honeyfs/opt/backup
cat > honeyfs/opt/backup/db_backup.sh << 'EOF'
#!/bin/bash
# Script de sauvegarde automatique pour la base de données MySQL
# Créé par: admin
# Dernière modification: 15/04/2024

DB_USER="backupuser"
DB_PASS="B@ckup2023!"
DB_HOST="localhost"
DB_NAME="website"
BACKUP_DIR="/var/backups/mysql"
DATE=$(date +%Y-%m-%d)

# Vérifier si le répertoire de sauvegarde existe
if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
fi

# Créer la sauvegarde
mysqldump -h $DB_HOST -u $DB_USER -p$DB_PASS $DB_NAME > $BACKUP_DIR/$DB_NAME-$DATE.sql

# Compresser la sauvegarde
gzip $BACKUP_DIR/$DB_NAME-$DATE.sql

# Nettoyer les anciennes sauvegardes (conserver seulement les 7 derniers jours)
find $BACKUP_DIR -name "$DB_NAME-*.sql.gz" -mtime +7 -delete

# Envoyer un rapport par e-mail
echo "Sauvegarde de la base de données $DB_NAME terminée le $(date)" | mail -s "Rapport de sauvegarde DB" admin@example.com
EOF
chmod +x honeyfs/opt/backup/db_backup.sh

# Fichier de configuration PHP avec des "secrets"
mkdir -p honeyfs/var/www/html/includes
cat > honeyfs/var/www/html/includes/config.php << 'EOF'
<?php
/**
 * Configuration de la base de données
 * IMPORTANT: Ce fichier contient des informations sensibles
 * NE PAS modifier sans autorisation
 */

// Paramètres de connexion à la base de données
define('DB_HOST', 'localhost');
define('DB_NAME', 'website');
define('DB_USER', 'webuser');
define('DB_PASS', 'W3bus3r@123');

// Clés d'API 
define('API_KEY', '8f7a6b5c4d3e2f1g0h9i8j7k6l5m4n3o2p1q');
define('API_SECRET', 'secret_key_34d743a21f9de8bc5');

// Paramètres SMTP pour l'envoi d'e-mails
define('SMTP_HOST', 'smtp.example.com');
define('SMTP_PORT', 587);
define('SMTP_USER', 'notifications@example.com');
define('SMTP_PASS', 'NotifyMe2023!');

// Chemin vers les répertoires du système
define('LOG_DIR', '/var/log/website');
define('UPLOAD_DIR', '/var/www/html/uploads');
define('CACHE_DIR', '/var/www/html/cache');

// Ne pas modifier cette section - Paramètres de sécurité
define('SITE_KEY', hash('sha256', 'svr01_security_key_2023'));
?>
EOF

# Fichier .htpasswd factice
cat > honeyfs/var/www/html/.htpasswd << 'EOF'
admin:$apr1$zPF7Cqsd$dV3ld4QzSPEd8eVSSYGPo1
webmaster:$apr1$i87BvIz3$SiWAKdJ9876HGFew342sa
EOF

# Script cron factice pour exécuter les sauvegardes
mkdir -p honeyfs/etc/cron.d
cat > honeyfs/etc/cron.d/backup << 'EOF'
# Tâche de sauvegarde automatique quotidienne
0 2 * * * root /opt/backup/db_backup.sh > /dev/null 2>&1
30 2 * * * root rsync -azv /var/www/ /var/backups/www/ > /dev/null 2>&1
0 3 * * 0 root tar -czf /var/backups/full-backup-$(date +\%Y\%m\%d).tar.gz /var/www /etc/apache2 /etc/mysql > /dev/null 2>&1
EOF

# 2.4.10 Configuration des identifiants utilisateurs
echo "[+] Configuration des identifiants utilisateurs..."
cat > etc/userdb.txt << 'EOF'
# Utilisateurs par défaut avec mots de passe faibles (acceptés)
root:toor:1
root:password:1
root:123456:1
root:admin:1
root:qwerty:1
admin:admin:1
admin:password:1
admin:admin123:1
user:user:1
user:password:1
guest:guest:1
support:support:1
pi:raspberry:1
debian:debian:1
ubuntu:ubuntu:1
test:test:1
ftpuser:ftpuser:1
operator:operator:1
apache:apache:1
webmaster:webmaster:1
jenkins:jenkins:1
tomcat:tomcat:1
mysql:mysql:1
postgres:postgres:1
oracle:oracle:1

# Utilisateurs invalides (rejetés)
root:root123:0
root:adminpass:0
admin:superadmin:0
admin:adminadmin:0
admin:securepass:0
user:user123:0
user:userpass:0
test:testtest:0

# Utilisateurs avec mots de passe complexes (acceptés)
sysadmin:Passw0rd2023!:1
dbadmin:MySQL@dm1n:1
webadmin:W3b@dmin2023:1
backup:B@ckup$erver1:1
monitor:M0n1t0rSyst3m!:1
EOF

# 2.4.11 Génération des clés SSH factices
echo "[+] Génération des clés SSH factices..."
mkdir -p honeyfs/etc/ssh
mkdir -p honeyfs/home/admin/.ssh

# Générer les clés SSH factices (si elles n'existent pas déjà)
if [ ! -f honeyfs/etc/ssh/ssh_host_rsa_key ]; then
    ssh-keygen -t rsa -b 2048 -f honeyfs/etc/ssh/ssh_host_rsa_key -N ""
fi
if [ ! -f honeyfs/etc/ssh/ssh_host_dsa_key ]; then
    ssh-keygen -t dsa -b 1024 -f honeyfs/etc/ssh/ssh_host_dsa_key -N ""
fi
if [ ! -f honeyfs/etc/ssh/ssh_host_ecdsa_key ]; then
    ssh-keygen -t ecdsa -b 256 -f honeyfs/etc/ssh/ssh_host_ecdsa_key -N ""
fi
if [ ! -f honeyfs/etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -t ed25519 -f honeyfs/etc/ssh/ssh_host_ed25519_key -N ""
fi

# Créer une clé autorisée pour l'utilisateur admin
if [ ! -f /tmp/admin_key ]; then
    ssh-keygen -t rsa -b 2048 -f /tmp/admin_key -N ""
    cat /tmp/admin_key.pub > honeyfs/home/admin/.ssh/authorized_keys
    chmod 600 honeyfs/home/admin/.ssh/authorized_keys
fi

# 2.4.12 Finalisation et correction des permissions
echo "[+] Correction des permissions et finalisation..."
chmod -R 755 txtcmds
chmod -R 755 honeyfs
chmod -R 755 share/cowrie/txtcmds

# 2.4.13 Redémarrage du service Cowrie
echo "[+] Redémarrage du service Cowrie..."
bin/cowrie start

# Vérification de l'état
sleep 2
bin/cowrie status

echo "[+] Personnalisation de l'environnement Cowrie terminée avec succès !"
echo "[+] Vous pouvez maintenant tester le honeypot en vous connectant via SSH: ssh admin@<IP_DU_HONEYPOT>"