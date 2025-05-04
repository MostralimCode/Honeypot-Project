#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import time
import logging
from typing import Dict, List, Tuple

class VulnerableAuthHandler:
    """
    Gestionnaire d'authentification délibérément vulnérable pour honeypot
    Simule des faiblesses d'authentification communes
    """
    
    def __init__(self, users_file: str = "config/users.json"):
        self.users_file = users_file
        self.users = self._load_users()
        self.attempts = {}  # Track login attempts per IP
        self.logger = logging.getLogger(__name__)
        
        # Vulnérabilités configurables
        self.allow_default_credentials = True
        self.enable_user_enumeration = True
        self.allow_weak_passwords = True
        self.simulate_auth_delay = True
        self.max_attempts_before_warning = 100  # Intentionnellement élevé
        
        # Credentials par défaut vulnérables
        self.default_credentials = [
            ("admin", "admin"),
            ("root", "root"),
            ("administrator", "password"),
            ("test", "test"),
            ("user", "user"),
            ("ftp", "ftp")
        ]
        
        # Mots de passe faibles à accepter
        self.weak_passwords = [
            "123456", "password", "12345678", "qwerty", "123", 
            "abc123", "letmein", "admin123", "welcome", "monkey"
        ]
    
    def _load_users(self) -> Dict:
        """Charge les utilisateurs depuis le fichier de configuration"""
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self.logger.warning(f"Users file not found: {self.users_file}")
            return {"users": []}
        except json.JSONDecodeError:
            self.logger.error(f"Invalid JSON in users file: {self.users_file}")
            return {"users": []}
    
    def authenticate(self, username: str, password: str, ip: str) -> Tuple[bool, str]:
        """
        Authentifie un utilisateur avec des vulnérabilités intentionnelles
        
        Returns:
            Tuple[bool, str]: (success, response_message)
        """
        # Enregistrer la tentative d'authentification
        self._log_attempt(ip, username)
        
        # Vulnérabilité 1: Divulgation d'informations (énumération d'utilisateur)
        user_exists = self._check_user_exists(username)
        
        # Vulnérabilité 2: Délai d'authentification artificiel
        if self.simulate_auth_delay:
            if user_exists:
                time.sleep(0.2)  # Délai plus court pour utilisateur existant
            else:
                time.sleep(0.5)  # Délai plus long pour utilisateur inexistant
        
        # Vulnérabilité 3: Accepter les credentials par défaut
        if self.allow_default_credentials:
            for default_user, default_pass in self.default_credentials:
                if username == default_user and password == default_pass:
                    return True, f"230 User {username} logged in"
        
        # Vulnérabilité 4: Accepter les mots de passe faibles  
        if self.allow_weak_passwords and password in self.weak_passwords:
            return True, f"230 User {username} logged in"
        
        # Authentication normale
        for user in self.users.get("users", []):
            if user["username"] == username:
                if user["password"] == password:
                    return True, f"230 User {username} logged in"
                else:
                    # Vulnérabilité 5: Message révélant que le mot de passe est incorrect
                    if self.enable_user_enumeration:
                        return False, "530 User found but password incorrect"
                    else:
                        return False, "530 Login incorrect"
        
        # Vulnérabilité 6: Message révélant que l'utilisateur n'existe pas
        if self.enable_user_enumeration:
            return False, "530 User not found"
        else:
            return False, "530 Login incorrect"
    
    def _check_user_exists(self, username: str) -> bool:
        """Vérifie si un utilisateur existe (vulnérabilité d'énumération)"""
        # Vérifier dans les credentials par défaut
        if self.allow_default_credentials:
            for default_user, _ in self.default_credentials:
                if username == default_user:
                    return True
        
        # Vérifier dans les utilisateurs configurés
        for user in self.users.get("users", []):
            if user["username"] == username:
                return True
        
        return False
    
    def _log_attempt(self, ip: str, username: str):
        """Enregistre une tentative d'authentification"""
        if ip not in self.attempts:
            self.attempts[ip] = []
        
        self.attempts[ip].append({
            "username": username,
            "timestamp": time.time()
        })
        
        # Vulnérabilité 7: Pas de blocage après plusieurs tentatives
        attempt_count = len(self.attempts[ip])
        if attempt_count > self.max_attempts_before_warning:
            self.logger.warning(f"Brute force detected from {ip}: {attempt_count} attempts")
            # Mais on ne bloque pas l'IP !
    
    def get_login_attempts(self, ip: str = None) -> Dict:
        """Retourne les tentatives de connexion"""
        if ip:
            return self.attempts.get(ip, [])
        return self.attempts
    
    def reset_attempts(self, ip: str = None):
        """Réinitialise les tentatives d'authentification"""
        if ip:
            self.attempts[ip] = []
        else:
            self.attempts.clear()