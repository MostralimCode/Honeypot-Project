#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
import json
import os
from datetime import datetime
from typing import Dict, Any, Optional
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import geoip2.database
import requests

class HoneypotLogger:
    """
    Système de journalisation avancé pour le honeypot FTP
    Capture et enregistre tous les événements de sécurité
    """
    
    def __init__(self, log_dir: str = "logs", log_level: str = "INFO"):
        self.log_dir = log_dir
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Créer le dossier de logs s'il n'existe pas
        os.makedirs(log_dir, exist_ok=True)
        
        # Configurer différents loggers pour différents types d'événements
        self.loggers = {
            'main': self._setup_logger('main', 'ftp_server.log'),
            'auth': self._setup_logger('auth', 'auth_attempts.log'),
            'commands': self._setup_logger('commands', 'commands.log'),
            'sessions': self._setup_json_logger('sessions', 'sessions.json'),
            'security': self._setup_logger('security', 'security_events.log'),
            'data_transfer': self._setup_logger('data_transfer', 'transfers.log')
        }
        
        # Initialiser la base GeoIP (si disponible)
        self.geoip_reader = self._init_geoip()
    
    def _setup_logger(self, name: str, filename: str) -> logging.Logger:
        """Configure un logger standard avec rotation des fichiers"""
        logger = logging.getLogger(name)
        logger.setLevel(self.log_level)
        
        # Formatter pour les logs standard
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Rotation par taille (10MB max, garder 5 fichiers)
        file_handler = RotatingFileHandler(
            os.path.join(self.log_dir, filename),
            maxBytes=10*1024*1024,
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
        
        # Aussi logger en console pour le debug
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger
    
    def _setup_json_logger(self, name: str, filename: str) -> logging.Logger:
        """Configure un logger JSON pour les données structurées"""
        logger = logging.getLogger(name)
        logger.setLevel(self.log_level)
        
        # Formatter JSON personnalisé
        class JsonFormatter(logging.Formatter):
            def format(self, record):
                if hasattr(record, 'data'):
                    return json.dumps(record.data)
                return json.dumps({'message': record.getMessage()})
        
        # Rotation quotidienne
        file_handler = TimedRotatingFileHandler(
            os.path.join(self.log_dir, filename),
            when='D',
            interval=1,
            backupCount=30
        )
        file_handler.setFormatter(JsonFormatter())
        logger.addHandler(file_handler)
        
        return logger
    
    def _init_geoip(self) -> Optional[geoip2.database.Reader]:
        """Initialise la base de données GeoIP si disponible"""
        try:
            # Chemin vers la base GeoIP (à télécharger depuis MaxMind)
            geoip_path = os.path.join(self.log_dir, "GeoLite2-City.mmdb")
            if os.path.exists(geoip_path):
                return geoip2.database.Reader(geoip_path)
        except Exception as e:
            self.loggers['main'].warning(f"GeoIP database not available: {e}")
        return None
    
    def get_geo_info(self, ip: str) -> Dict[str, Any]:
        """Récupère les informations géographiques pour une IP"""
        if not self.geoip_reader:
            return {}
        
        try:
            response = self.geoip_reader.city(ip)
            return {
                'country': response.country.name,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'org': response.traits.organization if hasattr(response.traits, 'organization') else None
            }
        except Exception:
            return {}
    
    def log_connection(self, ip: str, port: int):
        """Enregistre une nouvelle connexion"""
        geo_info = self.get_geo_info(ip)
        message = f"New connection from {ip}:{port}"
        if geo_info:
            message += f" [{geo_info.get('country', 'Unknown')}, {geo_info.get('city', 'Unknown')}]"
        
        self.loggers['main'].info(message)
    
    def log_auth_attempt(self, ip: str, username: str, password: str, success: bool):
        """Enregistre une tentative d'authentification"""
        geo_info = self.get_geo_info(ip)
        
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'auth_attempt',
            'ip': ip,
            'username': username,
            'password': password,  # À utiliser avec précaution !
            'success': success,
            'geo_info': geo_info
        }
        
        # Log standard
        status = "SUCCESS" if success else "FAILED"
        self.loggers['auth'].info(f"Auth {status} - {ip} - {username}")
        
        # Log JSON pour analyse
        self.loggers['sessions'].info("", extra={'data': log_data})
    
    def log_command(self, ip: str, username: str, command: str, args: str):
        """Enregistre une commande FTP"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'ftp_command',
            'ip': ip,
            'username': username,
            'command': command,
            'args': args
        }
        
        self.loggers['commands'].info(f"{ip} [{username}] {command} {args}")
        self.loggers['sessions'].info("", extra={'data': log_data})
    
    def log_security_event(self, event_type: str, ip: str, details: Dict[str, Any], severity: str = "MEDIUM"):
        """Enregistre un événement de sécurité spécifique"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': event_type,
            'ip': ip,
            'details': details,
            'severity': severity,
            'geo_info': self.get_geo_info(ip)
        }
        
        # Log selon la sévérité
        log_method = getattr(self.loggers['security'], severity.lower(), self.loggers['security'].info)
        log_method(f"{event_type} from {ip}: {details}")
        
        self.loggers['sessions'].info("", extra={'data': log_data})
    
    def log_directory_traversal(self, ip: str, username: str, path: str):
        """Enregistre une tentative de directory traversal"""
        self.log_security_event(
            'directory_traversal',
            ip,
            {
                'username': username,
                'path': path,
                'detected_patterns': self._detect_traversal_patterns(path)
            },
            'HIGH'
        )
    
    def log_brute_force(self, ip: str, attempts: int):
        """Enregistre une attaque par force brute"""
        self.log_security_event(
            'brute_force_detected',
            ip,
            {
                'attempts': attempts,
                'threshold_exceeded': attempts > 10  # Configurable
            },
            'CRITICAL' if attempts > 50 else 'HIGH'
        )
    
    def log_file_access(self, ip: str, username: str, filename: str, action: str, success: bool):
        """Enregistre l'accès à des fichiers"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'event_type': 'file_access',
            'ip': ip,
            'username': username,
            'filename': filename,
            'action': action,  # 'read', 'write', 'delete'
            'success': success
        }
        
        self.loggers['data_transfer'].info(f"{action.upper()} - {ip} [{username}] - {filename}")
        self.loggers['sessions'].info("", extra={'data': log_data})
    
    def log_session_summary(self, session_data: Dict[str, Any]):
        """Enregistre un résumé de session complète"""
        session_data['session_end'] = datetime.now().isoformat()
        session_data['duration'] = self._calculate_duration(session_data)
        session_data['commands_count'] = len(session_data.get('commands', []))
        session_data['geo_info'] = self.get_geo_info(session_data.get('ip', ''))
        
        self.loggers['sessions'].info("", extra={'data': session_data})
    
    def _detect_traversal_patterns(self, path: str) -> list:
        """Détecte les patterns de directory traversal"""
        patterns = []
        
        if '../' in path or '..\\'in path:
            patterns.append('basic_traversal')
        if '%2e%2e' in path.lower():
            patterns.append('encoded_traversal')
        if path.startswith('/etc') or path.startswith('/root'):
            patterns.append('sensitive_dir_access')
        
        return patterns
    
    def _calculate_duration(self, session_data: Dict[str, Any]) -> float:
        """Calcule la durée d'une session"""
        try:
            start = datetime.fromisoformat(session_data.get('session_start', ''))
            end = datetime.fromisoformat(session_data.get('session_end', ''))
            return (end - start).total_seconds()
        except:
            return 0.0

class LogAggregator:
    """
    Agrégateur de logs pour générer des statistiques et rapports
    """
    
    def __init__(self, log_dir: str = "logs"):
        self.log_dir = log_dir
    
    def get_attack_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Génère un résumé des attaques des X dernières heures"""
        summary = {
            'auth_attempts': 0,
            'successful_logins': 0,
            'failed_logins': 0,
            'directory_traversal_attempts': 0,
            'brute_force_attacks': 0,
            'unique_ips': set(),
            'top_usernames': {},
            'top_commands': {},
            'countries': {}
        }
        
        # Lire les logs JSON des sessions
        try:
            sessions_file = os.path.join(self.log_dir, 'sessions.json')
            with open(sessions_file, 'r') as f:
                for line in f:
                    try:
                        data = json.loads(line)
                        self._update_summary(summary, data)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            pass
        
        # Convertir les sets en listes pour la sérialisation JSON
        summary['unique_ips'] = list(summary['unique_ips'])
        
        return summary
    
    def _update_summary(self, summary: Dict[str, Any], data: Dict[str, Any]):
        """Met à jour le résumé avec les données d'une entrée"""
        event_type = data.get('event_type')
        
        if event_type == 'auth_attempt':
            summary['auth_attempts'] += 1
            if data.get('success'):
                summary['successful_logins'] += 1
            else:
                summary['failed_logins'] += 1
            
            # Tracking des usernames
            username = data.get('username', 'unknown')
            summary['top_usernames'][username] = summary['top_usernames'].get(username, 0) + 1
        
        elif event_type == 'ftp_command':
            command = data.get('command', 'unknown')
            summary['top_commands'][command] = summary['top_commands'].get(command, 0) + 1
        
        elif event_type == 'directory_traversal':
            summary['directory_traversal_attempts'] += 1
        
        elif event_type == 'brute_force_detected':
            summary['brute_force_attacks'] += 1
        
        # Géolocalisation
        geo_info = data.get('geo_info', {})
        if geo_info and 'country' in geo_info:
            country = geo_info['country']
            summary['countries'][country] = summary['countries'].get(country, 0) + 1
        
        # IPs uniques
        if 'ip' in data:
            summary['unique_ips'].add(data['ip'])
    
    def generate_report(self, output_file: str = "attack_report.json"):
        """Génère un rapport d'attaque complet"""
        summary = self.get_attack_summary()
        report = {
            'generated_at': datetime.now().isoformat(),
            'summary': summary,
            'recommendations': self._generate_recommendations(summary)
        }
        
        output_path = os.path.join(self.log_dir, output_file)
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=4)
        
        return output_path
    
    def _generate_recommendations(self, summary: Dict[str, Any]) -> list:
        """Génère des recommandations basées sur l'analyse"""
        recommendations = []
        
        if summary['brute_force_attacks'] > 5:
            recommendations.append("Implement rate limiting for authentication attempts")
        
        if summary['directory_traversal_attempts'] > 0:
            recommendations.append("Strengthen path validation to prevent directory traversal")
        
        if summary['failed_logins'] > summary['successful_logins'] * 3:
            recommendations.append("Consider implementing CAPTCHA after multiple failed attempts")
        
        # Analyse des pays
        if summary['countries']:
            top_countries = sorted(summary['countries'].items(), key=lambda x: x[1], reverse=True)
            if len(top_countries) > 0 and top_countries[0][1] > 10:
                recommendations.append(f"High volume of attempts from {top_countries[0][0]} - consider geoblocking")
        
        return recommendations

# Fonction utilitaire pour configurer le logging global
def setup_honeypot_logging(log_dir: str = "logs", log_level: str = "INFO") -> HoneypotLogger:
    """Configure et retourne une instance du logger pour le honeypot"""
    return HoneypotLogger(log_dir, log_level)