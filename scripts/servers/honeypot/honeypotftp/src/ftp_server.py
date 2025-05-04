#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import threading
import logging
from datetime import datetime
from typing import Dict, Tuple, Optional

class FTPServer:
    """Serveur FTP basique pour honeypot"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 21):
        self.host = host
        self.port = port
        self.banner = "220 FTP Server Ready"
        self.max_connections = 10
        self.running = False
        self.server_socket = None
        self.clients = []
        
        # Setup logging
        logging.basicConfig(
            filename='logs/ftp_server.log',
            format='%(asctime)s - %(levelname)s - %(message)s',
            level=logging.INFO
        )
        self.logger = logging.getLogger(__name__)
    
    def start(self):
        """Démarre le serveur FTP"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(self.max_connections)
            self.server_socket.settimeout(1.0)  # Pour pouvoir vérifier self.running
            
            self.running = True
            self.logger.info(f"FTP Server started on {self.host}:{self.port}")
            print(f"[+] FTP Honeypot listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    self.clients.append((client_socket, client_thread))
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error(f"Error accepting connection: {e}")
        
        except Exception as e:
            self.logger.error(f"Error starting server: {e}")
            print(f"[-] Error starting server: {e}")
        finally:
            self.stop()
    
    def stop(self):
        """Arrête le serveur FTP"""
        self.running = False
        
        # Fermer toutes les connexions client
        for client_socket, _ in self.clients:
            try:
                client_socket.close()
            except:
                pass
        
        # Fermer le socket serveur
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        self.logger.info("FTP Server stopped")
        print("[-] FTP Server stopped")
    
    def handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Gère une connexion client"""
        ip, port = address
        self.logger.info(f"New connection from {ip}:{port}")
        
        # État de la session client
        session = {
            'ip': ip,
            'port': port,
            'username': None,
            'authenticated': False,
            'current_dir': '/',
            'transfer_type': 'A',  # ASCII par défaut
            'passive_mode': False,
            'data_socket': None,
            'data_port': None,
            'resting': False,
            'binary_mode': False
        }
        
        try:
            # Envoyer la bannière de bienvenue
            self.send_response(client_socket, self.banner)
            
            # Boucle principale de traitement des commandes
            while self.running:
                data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                if not data:
                    break
                
                self.logger.info(f"Command from {ip}: {data}")
                
                # Parser la commande
                command_parts = data.split(' ', 1)
                command = command_parts[0].upper()
                args = command_parts[1] if len(command_parts) > 1 else ""
                
                # Traiter la commande
                response = self.process_command(command, args, session)
                
                # Envoyer la réponse
                if response:
                    self.send_response(client_socket, response)
                
                # Si c'est une commande QUIT, fermer la connexion
                if command == "QUIT":
                    break
        
        except Exception as e:
            self.logger.error(f"Error handling client {ip}:{port}: {e}")
        
        finally:
            # Fermer les sockets
            if session.get('data_socket'):
                try:
                    session['data_socket'].close()
                except:
                    pass
            
            try:
                client_socket.close()
            except:
                pass
                
            self.logger.info(f"Connection closed for {ip}:{port}")
    
    def send_response(self, client_socket: socket.socket, response: str):
        """Envoie une réponse au client"""
        if not response.endswith('\r\n'):
            response += '\r\n'
        client_socket.send(response.encode('utf-8'))
    
    def process_command(self, command: str, args: str, session: Dict) -> str:
        """Traite une commande FTP"""
        commands = {
            'USER': self.cmd_user,
            'PASS': self.cmd_pass,
            'SYST': self.cmd_syst,
            'TYPE': self.cmd_type,
            'PWD': self.cmd_pwd,
            'CWD': self.cmd_cwd,
            'LIST': self.cmd_list,
            'NLST': self.cmd_nlst,
            'NOOP': self.cmd_noop,
            'QUIT': self.cmd_quit,
            'HELP': self.cmd_help,
            'PORT': self.cmd_port,
            'PASV': self.cmd_pasv,
            'RETR': self.cmd_retr,
            'STOR': self.cmd_stor,
            'DELE': self.cmd_dele,
            'MKD': self.cmd_mkd,
            'RMD': self.cmd_rmd
        }
        
        if command in commands:
            try:
                return commands[command](args, session)
            except Exception as e:
                self.logger.error(f"Error processing command {command}: {e}")
                return "500 Internal error"
        else:
            return f"502 Command '{command}' not implemented"
    
    # ========== COMMANDES FTP ==========
    
    def cmd_user(self, username: str, session: Dict) -> str:
        """Traite la commande USER"""
        session['username'] = username
        return f"331 Username {username} OK. Password required"
    
    def cmd_pass(self, password: str, session: Dict) -> str:
        """Traite la commande PASS"""
        # Pour l'instant, on accepte tous les mots de passe
        if session.get('username'):
            session['authenticated'] = True
            return "230 User logged in, proceed"
        else:
            return "503 Login with USER first"
    
    def cmd_syst(self, args: str, session: Dict) -> str:
        """Traite la commande SYST"""
        return "215 UNIX Type: L8"
    
    def cmd_type(self, type_mode: str, session: Dict) -> str:
        """Traite la commande TYPE"""
        if type_mode in ['A', 'I']:
            session['transfer_type'] = type_mode
            mode = "ASCII" if type_mode == 'A' else "Binary"
            return f"200 Type set to {mode}"
        else:
            return "504 Command not implemented for that parameter"
    
    def cmd_pwd(self, args: str, session: Dict) -> str:
        """Traite la commande PWD"""
        current_dir = session.get('current_dir', '/')
        return f'257 "{current_dir}" is the current directory'
    
    def cmd_cwd(self, path: str, session: Dict) -> str:
        """Traite la commande CWD"""
        # Pour l'instant, on simule juste le changement de répertoire
        session['current_dir'] = path if path.startswith('/') else session['current_dir'] + '/' + path
        return f"250 Directory successfully changed to {path}"
    
    def cmd_list(self, args: str, session: Dict) -> str:
        """Traite la commande LIST"""
        # Simulation de listage de répertoire
        file_list = [
            "drwxr-xr-x   2 root     root         4096 Jan  1 00:00 .",
            "drwxr-xr-x   3 root     root         4096 Jan  1 00:00 ..",
            "-rw-r--r--   1 root     root          220 Jan  1 00:00 .bash_logout",
            "-rw-r--r--   1 root     root         3771 Jan  1 00:00 .bashrc",
            "-rw-r--r--   1 root     root          807 Jan  1 00:00 .profile",
            "drwxr-xr-x   2 root     root         4096 Jan  1 00:00 public",
            "drwxr-xr-x   2 root     root         4096 Jan  1 00:00 private"
        ]
        
        # En FTP, LIST nécessite une connexion de données
        return "150 Here comes the directory listing.\r\n" + "\r\n".join(file_list) + "\r\n226 Directory send OK."
    
    def cmd_nlst(self, args: str, session: Dict) -> str:
        """Traite la commande NLST (Name list)"""
        files = [
            ".bash_logout",
            ".bashrc",
            ".profile",
            "public",
            "private"
        ]
        
        return "150 Here comes the directory listing.\r\n" + "\r\n".join(files) + "\r\n226 Directory send OK."
    
    def cmd_noop(self, args: str, session: Dict) -> str:
        """Traite la commande NOOP"""
        return "200 Command OK"
    
    def cmd_quit(self, args: str, session: Dict) -> str:
        """Traite la commande QUIT"""
        session['resting'] = True
        return "221 Goodbye"
    
    def cmd_help(self, args: str, session: Dict) -> str:
        """Traite la commande HELP"""
        return "214-The following commands are recognized:\n USER PASS CWD PWD LIST NLST RETR STOR DELE MKD RMD TYPE SYST NOOP QUIT\n214 Help OK"
    
    def cmd_port(self, args: str, session: Dict) -> str:
        """Traite la commande PORT (mode actif)"""
        # Format: h1,h2,h3,h4,p1,p2
        session['passive_mode'] = False
        return "200 PORT command successful"
    
    def cmd_pasv(self, args: str, session: Dict) -> str:
        """Traite la commande PASV (mode passif)"""
        session['passive_mode'] = True
        # Simulation d'une réponse PASV avec une adresse IP et un port
        return "227 Entering Passive Mode (127,0,0,1,123,45)"
    
    def cmd_retr(self, filename: str, session: Dict) -> str:
        """Traite la commande RETR (téléchargement)"""
        return f"150 Opening data connection for {filename}.\r\n226 File send OK"
    
    def cmd_stor(self, filename: str, session: Dict) -> str:
        """Traite la commande STOR (upload)"""
        return f"150 Ok to send data.\r\n226 File received OK"
    
    def cmd_dele(self, filename: str, session: Dict) -> str:
        """Traite la commande DELE (suppression)"""
        return f"250 File '{filename}' deleted successfully"
    
    def cmd_mkd(self, dirname: str, session: Dict) -> str:
        """Traite la commande MKD (création de répertoire)"""
        return f'257 "{dirname}" directory created'
    
    def cmd_rmd(self, dirname: str, session: Dict) -> str:
        """Traite la commande RMD (suppression de répertoire)"""
        return f"250 Directory '{dirname}' removed successfully"

if __name__ == "__main__":
    server = FTPServer()
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
        server.stop()