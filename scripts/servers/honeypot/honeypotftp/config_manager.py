#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import configparser
import os
import argparse
import sys
from dataclasses import dataclass
from typing import Dict, Any, Optional

@dataclass
class HoneypotConfig:
    """Configuration du honeypot FTP"""
    # Server settings
    host: str = '0.0.0.0'
    port: int = 21
    max_connections: int = 10
    timeout: int = 300
    banner: str = '220 FTP Server Ready'
    
    # Security settings
    enable_chroot: bool = True
    max_upload_size: int = 10485760  # 10MB
    allow_anonymous: bool = True
    
    # Vulnerabilities
    weak_auth: bool = True
    directory_traversal: bool = True
    command_injection: bool = False
    user_enumeration: bool = True
    simulate_auth_delay: bool = True
    max_auth_attempts: int = 100
    
    # Logging settings
    log_level: str = 'INFO'
    log_directory: str = 'logs'
    enable_geoip: bool = True
    rotate_logs: bool = True
    
    # Data paths
    users_file: str = 'config/users.json'
    virtual_fs_config: str = 'config/filesystem.json'
    
    # ELK integration
    elk_enabled: bool = False
    elk_host: str = 'localhost'
    elk_port: int = 9200
    elk_index_prefix: str = 'honeypot-ftp'

class ConfigManager:
    """Gestionnaire de configuration pour le honeypot FTP"""
    
    def __init__(self, config_path: str = 'config/settings.ini'):
        self.config_path = config_path
        self.config = HoneypotConfig()
        self.load_config()
    
    def load_config(self):
        """Charge la configuration depuis le fichier"""
        if not os.path.exists(self.config_path):
            print(f"[!] Configuration file not found at {self.config_path}. Using defaults.")
            self.save_config()  # Créer le fichier par défaut
            return
        
        config_parser = configparser.ConfigParser()
        config_parser.read(self.config_path)
        
        # Server settings
        if config_parser.has_section('Server'):
            self.config.host = config_parser.get('Server', 'host', fallback=self.config.host)
            self.config.port = config_parser.getint('Server', 'port', fallback=self.config.port)
            self.config.max_connections = config_parser.getint('Server', 'max_connections', 
                                                              fallback=self.config.max_connections)
            self.config.timeout = config_parser.getint('Server', 'timeout', fallback=self.config.timeout)
            self.config.banner = config_parser.get('Server', 'banner', fallback=self.config.banner)
        
        # Security settings
        if config_parser.has_section('Security'):
            self.config.enable_chroot = config_parser.getboolean('Security', 'enable_chroot', 
                                                                fallback=self.config.enable_chroot)
            self.config.max_upload_size = config_parser.getint('Security', 'max_upload_size', 
                                                              fallback=self.config.max_upload_size)
            self.config.allow_anonymous = config_parser.getboolean('Security', 'allow_anonymous', 
                                                                   fallback=self.config.allow_anonymous)
        
        # Vulnerabilities
        if config_parser.has_section('Vulnerabilities'):
            self.config.weak_auth = config_parser.getboolean('Vulnerabilities', 'weak_auth', 
                                                            fallback=self.config.weak_auth)
            self.config.directory_traversal = config_parser.getboolean('Vulnerabilities', 
                                                                      'directory_traversal',
                                                                      fallback=self.config.directory_traversal)
            self.config.command_injection = config_parser.getboolean('Vulnerabilities', 
                                                                    'command_injection',
                                                                    fallback=self.config.command_injection)
            self.config.user_enumeration = config_parser.getboolean('Vulnerabilities', 
                                                                   'user_enumeration',
                                                                   fallback=self.config.user_enumeration)
            self.config.simulate_auth_delay = config_parser.getboolean('Vulnerabilities', 
                                                                      'simulate_auth_delay',
                                                                      fallback=self.config.simulate_auth_delay)
            self.config.max_auth_attempts = config_parser.getint('Vulnerabilities', 
                                                                'max_auth_attempts',
                                                                'max_auth_attempts',
                                                                fallback=self.config.max_auth_attempts)
        
        # Logging settings
        if config_parser.has_section('Logging'):
            self.config.log_level = config_parser.get('Logging', 'log_level', 
                                                     fallback=self.config.log_level)
            self.config.log_directory = config_parser.get('Logging', 'log_directory', 
                                                         fallback=self.config.log_directory)
            self.config.enable_geoip = config_parser.getboolean('Logging', 'enable_geoip', 
                                                               fallback=self.config.enable_geoip)
            self.config.rotate_logs = config_parser.getboolean('Logging', 'rotate_logs', 
                                                              fallback=self.config.rotate_logs)
        
        # Data paths
        if config_parser.has_section('Data'):
            self.config.users_file = config_parser.get('Data', 'users_file', 
                                                      fallback=self.config.users_file)
            self.config.virtual_fs_config = config_parser.get('Data', 'virtual_fs_config', 
                                                             fallback=self.config.virtual_fs_config)
        
        # ELK integration
        if config_parser.has_section('ELK'):
            self.config.elk_enabled = config_parser.getboolean('ELK', 'enabled', 
                                                              fallback=self.config.elk_enabled)
            self.config.elk_host = config_parser.get('ELK', 'host', fallback=self.config.elk_host)
            self.config.elk_port = config_parser.getint('ELK', 'port', fallback=self.config.elk_port)
            self.config.elk_index_prefix = config_parser.get('ELK', 'index_prefix', 
                                                            fallback=self.config.elk_index_prefix)
    
    def save_config(self):
        """Sauvegarde la configuration dans le fichier"""
        config_parser = configparser.ConfigParser()
        
        # Server settings
        config_parser['Server'] = {
            'host': self.config.host,
            'port': str(self.config.port),
            'max_connections': str(self.config.max_connections),
            'timeout': str(self.config.timeout),
            'banner': self.config.banner
        }
        
        # Security settings
        config_parser['Security'] = {
            'enable_chroot': str(self.config.enable_chroot),
            'max_upload_size': str(self.config.max_upload_size),
            'allow_anonymous': str(self.config.allow_anonymous)
        }
        
        # Vulnerabilities
        config_parser['Vulnerabilities'] = {
            'weak_auth': str(self.config.weak_auth),
            'directory_traversal': str(self.config.directory_traversal),
            'command_injection': str(self.config.command_injection),
            'user_enumeration': str(self.config.user_enumeration),
            'simulate_auth_delay': str(self.config.simulate_auth_delay),
            'max_auth_attempts': str(self.config.max_auth_attempts)
        }
        
        # Logging settings
        config_parser['Logging'] = {
            'log_level': self.config.log_level,
            'log_directory': self.config.log_directory,
            'enable_geoip': str(self.config.enable_geoip),
            'rotate_logs': str(self.config.rotate_logs)
        }
        
        # Data paths
        config_parser['Data'] = {
            'users_file': self.config.users_file,
            'virtual_fs_config': self.config.virtual_fs_config
        }
        
        # ELK integration
        config_parser['ELK'] = {
            'enabled': str(self.config.elk_enabled),
            'host': self.config.elk_host,
            'port': str(self.config.elk_port),
            'index_prefix': self.config.elk_index_prefix
        }
        
        # Créer le dossier config s'il n'existe pas
        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        
        # Sauvegarder la configuration
        with open(self.config_path, 'w') as configfile:
            config_parser.write(configfile)
    
    def get_config(self) -> HoneypotConfig:
        """Retourne la configuration actuelle"""
        return self.config
    
    def update_config(self, updates: Dict[str, Any]):
        """Met à jour la configuration"""
        for key, value in updates.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        self.save_config()
    
    def reset_to_defaults(self):
        """Réinitialise la configuration aux valeurs par défaut"""
        self.config = HoneypotConfig()
        self.save_config()
    
    def validate_config(self) -> bool:
        """Valide la configuration"""
        try:
            # Vérifier que le port est valide
            if not (1 <= self.config.port <= 65535):
                print(f"[!] Invalid port: {self.config.port}")
                return False
            
            # Vérifier que les fichiers critiques existent
            if not os.path.exists(self.config.users_file):
                print(f"[!] Users file not found: {self.config.users_file}")
                return False
            
            # Créer les dossiers nécessaires
            os.makedirs(self.config.log_directory, exist_ok=True)
            
            return True
        except Exception as e:
            print(f"[!] Configuration validation failed: {e}")
            return False
    
    def print_config(self):
        """Affiche la configuration actuelle"""
        print("\n=== FTP Honeypot Configuration ===")
        print(f"Host: {self.config.host}")
        print(f"Port: {self.config.port}")
        print(f"Max Connections: {self.config.max_connections}")
        print(f"Banner: {self.config.banner}")
        print(f"\nVulnerabilities:")
        print(f"  Weak Authentication: {self.config.weak_auth}")
        print(f"  Directory Traversal: {self.config.directory_traversal}")
        print(f"  Command Injection: {self.config.command_injection}")
        print(f"  User Enumeration: {self.config.user_enumeration}")
        print(f"\nLogging:")
        print(f"  Level: {self.config.log_level}")
        print(f"  Directory: {self.config.log_directory}")
        print(f"  GeoIP: {self.config.enable_geoip}")
        print("================================\n")

# Fonction utilitaire pour charger la configuration
def load_honeypot_config(config_path: str = 'config/settings.ini') -> HoneypotConfig:
    """Charge et retourne la configuration du honeypot"""
    config_manager = ConfigManager(config_path)
    return config_manager.get_config()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Configure FTP Honeypot')
    
    # Commandes principales
    parser.add_argument('--show', action='store_true', help='Show current configuration')
    parser.add_argument('--reset', action='store_true', help='Reset to default configuration')
    parser.add_argument('--validate', action='store_true', help='Validate current configuration')
    
    # Configuration serveur
    parser.add_argument('--port', type=int, help='Set server port')
    parser.add_argument('--host', type=str, help='Set server host')
    parser.add_argument('--banner', type=str, help='Set server banner')
    parser.add_argument('--max-connections', type=int, help='Set max connections')
    
    # Vulnérabilités
    parser.add_argument('--enable-weak-auth', action='store_true', help='Enable weak authentication')
    parser.add_argument('--disable-weak-auth', action='store_true', help='Disable weak authentication')
    parser.add_argument('--enable-traversal', action='store_true', help='Enable directory traversal')
    parser.add_argument('--disable-traversal', action='store_true', help='Disable directory traversal')
    parser.add_argument('--enable-user-enum', action='store_true', help='Enable user enumeration')
    parser.add_argument('--disable-user-enum', action='store_true', help='Disable user enumeration')
    parser.add_argument('--enable-cmd-injection', action='store_true', help='Enable command injection')
    parser.add_argument('--disable-cmd-injection', action='store_true', help='Disable command injection')
    parser.add_argument('--enable-all-vuln', action='store_true', help='Enable all vulnerabilities')
    parser.add_argument('--disable-all-vuln', action='store_true', help='Disable all vulnerabilities')
    
    # Logging
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], 
                        help='Set logging level')
    parser.add_argument('--log-dir', type=str, help='Set log directory')
    parser.add_argument('--enable-geoip', action='store_true', help='Enable GeoIP')
    parser.add_argument('--disable-geoip', action='store_true', help='Disable GeoIP')
    
    # Profils
    parser.add_argument('--profile', choices=['maximum', 'stealth', 'safe', 'research'], 
                        help='Apply configuration profile')
    
    # Actions sur le serveur
    parser.add_argument('--restart', action='store_true', help='Restart honeypot after config change')
    
    args = parser.parse_args()
    
    config_manager = ConfigManager()
    
    # Afficher l'aide si aucun argument
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    # Commandes principales
    if args.show:
        config_manager.print_config()
        sys.exit(0)
    
    if args.reset:
        config_manager.reset_to_defaults()
        print("[+] Configuration reset to defaults")
    
    if args.validate:
        if config_manager.validate_config():
            print("[+] Configuration is valid")
        else:
            print("[-] Configuration is invalid")
            sys.exit(1)
    
    # Appliquer les modifications
    updates = {}
    
    # Configuration serveur
    if args.port:
        updates['port'] = args.port
    if args.host:
        updates['host'] = args.host
    if args.banner:
        updates['banner'] = args.banner
    if args.max_connections:
        updates['max_connections'] = args.max_connections
    
    # Vulnérabilités
    if args.enable_weak_auth:
        updates['weak_auth'] = True
    if args.disable_weak_auth:
        updates['weak_auth'] = False
    if args.enable_traversal:
        updates['directory_traversal'] = True
    if args.disable_traversal:
        updates['directory_traversal'] = False
    if args.enable_user_enum:
        updates['user_enumeration'] = True
    if args.disable_user_enum:
        updates['user_enumeration'] = False
    if args.enable_cmd_injection:
        updates['command_injection'] = True
    if args.disable_cmd_injection:
        updates['command_injection'] = False
    
    if args.enable_all_vuln:
        updates.update({
            'weak_auth': True,
            'directory_traversal': True,
            'user_enumeration': True,
            'command_injection': True
        })
    
    if args.disable_all_vuln:
        updates.update({
            'weak_auth': False,
            'directory_traversal': False,
            'user_enumeration': False,
            'command_injection': False
        })
    
    # Logging
    if args.log_level:
        updates['log_level'] = args.log_level
    if args.log_dir:
        updates['log_directory'] = args.log_dir
    if args.enable_geoip:
        updates['enable_geoip'] = True
    if args.disable_geoip:
        updates['enable_geoip'] = False
    
    # Profils
    if args.profile:
        profile_path = f"config/profiles/{args.profile}.ini"
        if os.path.exists(profile_path):
            # Copier le profil
            import shutil
            shutil.copy(profile_path, config_manager.config_path)
            config_manager.load_config()
            print(f"[+] Profile '{args.profile}' applied")
        else:
            print(f"[-] Profile file not found: {profile_path}")
    
    # Appliquer les mises à jour
    if updates:
        config_manager.update_config(updates)
        print(f"[+] Configuration updated: {updates}")
        config_manager.print_config()
    
    # Redémarrer si demandé
    if args.restart:
        import subprocess
        print("[+] Restarting honeypot...")
        subprocess.run(['./deploy.sh'])