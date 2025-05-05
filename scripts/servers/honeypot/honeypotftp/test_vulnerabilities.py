#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import socket
import time
import json
import sys
from datetime import datetime
from typing import Dict, List

class HoneypotTester:
    """Test automatisé des vulnérabilités du honeypot FTP"""
    
    def __init__(self, host: str = 'localhost', port: int = 21):
        self.host = host
        self.port = port
        self.results = {}
        self.timestamps = []
        
    def log(self, message: str, level: str = "INFO"):
        """Affiche et enregistre un message"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        colored_message = f"[{timestamp}] {level}: {message}"
        
        # Coloration en fonction du niveau
        if level == "SUCCESS":
            print(f"\033[92m{colored_message}\033[0m")
        elif level == "FAIL":
            print(f"\033[91m{colored_message}\033[0m")
        elif level == "WARNING":
            print(f"\033[93m{colored_message}\033[0m")
        else:
            print(f"\033[94m{colored_message}\033[0m")
        
        self.timestamps.append((timestamp, level, message))
    
    def connect(self, timeout: int = 5) -> socket.socket:
        """Établit une connexion au serveur FTP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((self.host, self.port))
            banner = sock.recv(1024).decode('utf-8')
            self.log(f"Connected to {self.host}:{self.port} - Banner: {banner.strip()}")
            return sock
        except Exception as e:
            self.log(f"Connection failed: {e}", "FAIL")
            return None
    
    def send_command(self, sock: socket.socket, command: str) -> str:
        """Envoie une commande et récupère la réponse"""
        try:
            sock.send(f"{command}\r\n".encode())
            time.sleep(0.1)  # Petit délai pour la réponse
            response = sock.recv(1024).decode('utf-8')
            return response
        except Exception as e:
            self.log(f"Error sending command '{command}': {e}", "FAIL")
            return ""
    
    def test_weak_authentication(self):
        """Test des credentials faibles"""
        self.log("\n=== Testing Weak Authentication ===")
        
        test_credentials = [
            ("admin", "admin"),
            ("root", "root"),
            ("test", "test"),
            ("anonymous", ""),
            ("user", "password"),
            ("ftp", "ftp")
        ]
        
        successful_logins = 0
        
        for username, password in test_credentials:
            sock = self.connect()
            if not sock:
                continue
            
            # Test USER command
            user_response = self.send_command(sock, f"USER {username}")
            self.log(f"USER {username}: {user_response.strip()}")
            
            # Test PASS command
            pass_response = self.send_command(sock, f"PASS {password}")
            
            if "230" in pass_response:  # Succès de login
                self.log(f"SUCCESS: Weak credential {username}/{password} works!", "SUCCESS")
                successful_logins += 1
            else:
                self.log(f"Login failed for {username}/{password}: {pass_response.strip()}")
            
            sock.close()
        
        self.results['weak_auth'] = successful_logins
        self.log(f"Weak Authentication Test: {successful_logins}/{len(test_credentials)} successful logins")
    
    def test_user_enumeration(self):
        """Test de l'énumération d'utilisateurs"""
        self.log("\n=== Testing User Enumeration ===")
        
        test_users = ["admin", "root", "nonexistentuser", "test", "anonymous"]
        timing_differences = {}
        
        for username in test_users:
            sock = self.connect()
            if not sock:
                continue
            
            start_time = time.time()
            user_response = self.send_command(sock, f"USER {username}")
            user_time = time.time() - start_time
            
            start_time = time.time()
            pass_response = self.send_command(sock, "PASS wrongpassword")
            pass_time = time.time() - start_time
            
            timing_differences[username] = {
                'user_response': user_response.strip(),
                'pass_response': pass_response.strip(),
                'user_timing': user_time,
                'pass_timing': pass_time
            }
            
            self.log(f"User {username}: USER time={user_time:.3f}s, PASS time={pass_time:.3f}s")
            self.log(f"  USER response: {user_response.strip()}")
            self.log(f"  PASS response: {pass_response.strip()}")
            
            sock.close()
            time.sleep(0.5)  # Pause entre les tests
        
        self.results['user_enumeration'] = timing_differences
        
        # Vérification de la vulnérabilité
        if any("User not found" in res['pass_response'] for res in timing_differences.values()):
            self.log("VULNERABLE: Server reveals when a user doesn't exist!", "WARNING")
        else:
            self.log("Server doesn't reveal user existence in responses", "INFO")
    
    def test_directory_traversal(self):
        """Test de traversée de répertoires"""
        self.log("\n=== Testing Directory Traversal ===")
        
        traversal_paths = [
            "/etc/passwd",
            "../../etc/passwd",
            "../../../../../etc/passwd",
            "/root/.bash_history",
            "/../etc/shadow",
            "%2e%2e%2f%2e%2e%2fpasswd"  # Encoded
        ]
        
        sock = self.connect()
        if not sock:
            return
        
        # Se connecter d'abord
        self.send_command(sock, "USER admin")
        self.send_command(sock, "PASS admin")
        
        for path in traversal_paths:
            self.log(f"Testing path: {path}")
            
            # Test CWD
            cwd_response = self.send_command(sock, f"CWD {path}")
            self.log(f"  CWD response: {cwd_response.strip()}")
            
            if "250" in cwd_response:
                self.log(f"VULNERABLE: CWD succeeded with {path}!", "WARNING")
                
                # Test PWD pour voir où on est
                pwd_response = self.send_command(sock, "PWD")
                self.log(f"  PWD shows: {pwd_response.strip()}")
                
                # Essayer de list
                list_response = self.send_command(sock, "LIST")
                self.log(f"  LIST response: {list_response.strip()}")
                
                # Essayer de récupérer un fichier sensible
                retr_response = self.send_command(sock, "RETR passwd")
                self.log(f"  RETR response: {retr_response.strip()}")
        
        sock.close()
        self.results['directory_traversal'] = True
    
    def test_command_injection(self):
        """Test d'injection de commandes"""
        self.log("\n=== Testing Command Injection ===")
        
        injection_payloads = [
            "; ls -la",
            "`id`",
            "$(whoami)",
            "&& cat /etc/passwd",
            "| nc localhost 4444"
        ]
        
        sock = self.connect()
        if not sock:
            return
        
        # Se connecter d'abord
        self.send_command(sock, "USER admin")
        self.send_command(sock, "PASS admin")
        
        for payload in injection_payloads:
            # Test dans différentes commandes
            commands = [
                f"CWD {payload}",
                f"MKD {payload}",
                f"DELE {payload}"
            ]
            
            for cmd in commands:
                self.log(f"Testing injection: {cmd}")
                response = self.send_command(sock, cmd)
                
                if response:
                    self.log(f"  Response: {response.strip()}")
                    if any(keyword in response for keyword in ["root:", "uid=", "usage:"]):
                        self.log(f"VULNERABLE: Command execution detected!", "WARNING")
        
        sock.close()
    
    def test_brute_force_threshold(self):
        """Test du seuil de brute force"""
        self.log("\n=== Testing Brute Force Threshold ===")
        
        sock = self.connect()
        if not sock:
            return
        
        attempts = 0
        blocked = False
        
        for i in range(20):  # Essayer 20 fois
            user_response = self.send_command(sock, "USER admin")
            pass_response = self.send_command(sock, f"PASS wrongpass{i}")
            
            attempts += 1
            
            if "421" in pass_response or "530" in pass_response:
                self.log(f"Account blocked after {attempts} attempts", "INFO")
                blocked = True
                break
            
            time.sleep(0.2)
        
        if not blocked:
            self.log("WARNING: No blocking after multiple failed attempts!", "WARNING")
        
        sock.close()
        self.results['brute_force_protection'] = blocked
    
    def generate_report(self):
        """Génère un rapport des tests"""
        self.log("\n=== Vulnerability Test Report ===")
        self.log("================================")
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': f"{self.host}:{self.port}",
            'results': self.results,
            'test_logs': self.timestamps
        }
        
        # Sauvegarder le rapport
        report_file = f"test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        self.log(f"Report saved to: {report_file}")
        
        # Afficher le résumé
        self.log("\nVULNERABILITY SUMMARY:")
        self.log("---------------------")
        
        if self.results.get('weak_auth', 0) > 0:
            self.log(f"✓ Weak Authentication: {self.results['weak_auth']} credentials work", "SUCCESS")
        
        if 'user_enumeration' in self.results:
            if any("User not found" in res['pass_response'] for res in self.results['user_enumeration'].values()):
                self.log("✓ User Enumeration: Server reveals user existence", "SUCCESS")
            else:
                self.log("✗ User Enumeration: Not vulnerable", "INFO")
        
        if 'directory_traversal' in self.results:
            self.log("✓ Directory Traversal: Paths accessible", "SUCCESS")
        
        if not self.results.get('brute_force_protection', False):
            self.log("✓ No Brute Force Protection: Multiple attempts allowed", "SUCCESS")
        
        self.log("\n=== Test Complete ===")
    
    def run_all_tests(self):
        """Exécute tous les tests"""
        self.log(f"Starting vulnerability tests for {self.host}:{self.port}")
        self.log("================================================")
        
        try:
            self.test_weak_authentication()
            time.sleep(1)
            
            self.test_user_enumeration()
            time.sleep(1)
            
            self.test_directory_traversal()
            time.sleep(1)
            
            self.test_command_injection()
            time.sleep(1)
            
            self.test_brute_force_threshold()
            
            self.generate_report()
            
        except KeyboardInterrupt:
            self.log("\nTests interrupted by user", "WARNING")
        except Exception as e:
            self.log(f"Error during testing: {e}", "FAIL")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Test FTP Honeypot Vulnerabilities')
    parser.add_argument('--host', default='localhost', help='FTP server host')
    parser.add_argument('--port', default=21, type=int, help='FTP server port')
    
    args = parser.parse_args()
    
    tester = HoneypotTester(host=args.host, port=args.port)
    tester.run_all_tests()