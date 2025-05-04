#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
from typing import Dict, Optional

class DirectoryTraversalVulnerability:
    """
    Simule des vulnérabilités de traversée de répertoires
    """
    
    def __init__(self, enable_traversal: bool = True, enable_symbolic_links: bool = True):
        self.enable_traversal = enable_traversal
        self.enable_symbolic_links = enable_symbolic_links
        self.logger = logging.getLogger(__name__)
        
        # Fichiers sensibles simulés
        self.sensitive_files = {
            "/etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin""",
            "/etc/shadow": "root:$6$rounds=656000$...:19234:0:99999:7:::",  # Simulé et tronqué
            "/root/.bash_history": """cat /etc/passwd
ls -la /root/
ssh user@192.168.1.10
mysql -u root -p'password123'""",
            "/.ssh/id_rsa": """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
...SIMULATED RSA KEY..."""
        }
    
    def process_path(self, current_path: str, new_path: str, session: Dict) -> tuple[str, bool]:
        """
        Traite un changement de chemin avec vulnérabilités potentielles
        
        Returns:
            tuple: (resolved_path, is_vulnerable)
        """
        original_path = new_path
        
        # Vulnérabilité 1: Permettre ../
        if self.enable_traversal and ".." in new_path:
            # Ne pas nettoyer les ".." - permettre la traversée
            self.logger.warning(f"Directory traversal attempt detected: {new_path}")
            
            # Simuler la traversée
            if not new_path.startswith('/'):
                new_path = os.path.join(current_path, new_path)
            
            # Retourner le chemin avec une vulnérabilité intentionnelle
            return new_path, True
        
        # Vulnérabilité 2: Permettre les chemins absolus sans restriction
        if new_path.startswith('/'):
            self.logger.info(f"Absolute path requested: {new_path}")
            return new_path, False
        
        # Chemin normal (non vulnérable)
        normalized_path = os.path.join(current_path, new_path)
        return normalized_path, False
    
    def get_file_content(self, path: str) -> Optional[str]:
        """
        Retourne le contenu d'un fichier sensible si le path correspond à une vulnérabilité
        """
        # Nettoyer le chemin pour la comparaison
        normalized_path = os.path.normpath(path)
        
        if normalized_path in self.sensitive_files:
            self.logger.warning(f"Sensitive file accessed: {normalized_path}")
            return self.sensitive_files[normalized_path]
        
        return None
    
    def get_directory_listing(self, path: str) -> list:
        """
        Retourne un listing de répertoire avec des entrées sensibles
        """
        # Listing par défaut
        default_listing = [
            "drwxr-xr-x   2 root     root         4096 Jan  1 00:00 .",
            "drwxr-xr-x   3 root     root         4096 Jan  1 00:00 ..",
        ]
        
        # Ajouter des fichiers sensibles si on est dans un répertoire système
        if path.startswith('/etc') or path.startswith('/root') or '/..' in path:
            sensitive_listings = [
                "-rw-r--r--   1 root     root         1234 Jan  1 00:00 passwd",
                "-rw-------   1 root     shadow       1234 Jan  1 00:00 shadow",
                "drwx------   2 root     root         4096 Jan  1 00:00 .ssh",
                "-rw-------   1 root     root         1679 Jan  1 00:00 id_rsa",
                "-rw-r--r--   1 root     root          394 Jan  1 00:00 .bash_history"
            ]
            default_listing.extend(sensitive_listings)
        
        return default_listing
    
    def check_traversal_patterns(self, path: str) -> Dict:
        """
        Vérifie les patterns typiques d'exploitation de directory traversal
        """
        patterns = {
            "basic_traversal": "../" in path or "..\\" in path,
            "encoded_traversal": "%2e%2e" in path.lower() or "%2e%2e%2f" in path.lower(),
            "double_encoded": "%252e%252e" in path.lower(),
            "null_byte": "\x00" in path or "%00" in path,
            "leading_slash": path.startswith('/'),
            "absolute_path": path.startswith('/etc') or path.startswith('/root')
        }
        
        detected_patterns = [k for k, v in patterns.items() if v]
        
        if detected_patterns:
            self.logger.warning(f"Traversal patterns detected: {detected_patterns} in path: {path}")
        
        return patterns