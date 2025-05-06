#!/usr/bin/env python3
"""
Honeypot HTTP - Configuration de base
Auteurs: AMINE OUACHA & YANIS BETTA
Description: Serveur web intentionnellement vulnérable pour capturer les attaques
"""

import os
import json
import uuid
import logging
import sqlite3
from datetime import datetime
from flask import Flask, request, g, session, render_template_string

# Configuration de l'application
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.urandom(24),
    DATABASE='/var/lib/honeypot/database.db',
    UPLOAD_FOLDER='/var/lib/honeypot/uploads',
    LOG_FOLDER='/var/log/honeypot',
    LOG_FILE='/var/log/honeypot/http_honeypot.log',
    COMPANY_NAME='TechSecure Solutions',
    ADMIN_USER='admin',
    ADMIN_PASSWORD='admin123'  # Mot de passe vulnérable intentionnel
)

# Création des répertoires nécessaires
os.makedirs(os.path.dirname(app.config['DATABASE']), exist_ok=True)
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['LOG_FOLDER'], exist_ok=True)

# Configuration du logging
logging.basicConfig(
    filename=app.config['LOG_FILE'],
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# Fonction pour obtenir une connexion à la base de données
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
    return db

# Fonction pour fermer la connexion à la base de données
@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# Fonction de journalisation des attaques
def log_attack(attack_type, data, ip=None):
    """
    Enregistre les détails d'une attaque potentielle
    
    Args:
        attack_type: Type d'attaque (sql_injection, xss, path_traversal, etc.)
        data: Données spécifiques à l'attaque
        ip: Adresse IP de l'attaquant (par défaut: IP de la requête)
    
    Returns:
        attack_id: Identifiant unique de l'attaque
    """
    if ip is None:
        ip = request.remote_addr
        
    # Création d'un ID unique pour tracer cette attaque
    attack_id = str(uuid.uuid4())
    
    # Collecte des informations sur la requête
    log_data = {
        'timestamp': datetime.now().isoformat(),
        'attack_id': attack_id,
        'attack_type': attack_type,
        'ip': ip,
        'user_agent': request.headers.get('User-Agent', 'Unknown'),
        'method': request.method,
        'path': request.path,
        'query_string': request.query_string.decode('utf-8', errors='ignore'),
        'cookies': {k: v for k, v in request.cookies.items()},
        'headers': {k: v for k, v in request.headers.items()},
        'data': data
    }
    
    # Enregistrement au format JSON
    logging.info(json.dumps(log_data))
    return attack_id

# Configuration des headers HTTP pour exposer des informations
@app.after_request
def expose_headers(response):
    """
    Ajoute intentionnellement des headers vulnérables aux réponses HTTP
    pour simuler un serveur mal configuré
    """
    # Vulnérabilité intentionnelle: divulgation d'informations
    response.headers['Server'] = 'Apache/2.4.41 (Ubuntu)'
    response.headers['X-Powered-By'] = 'PHP/7.4.3'
    # Absence intentionnelle de headers de sécurité
    return response

# Schéma SQL pour initialiser la base de données
def init_db():
    """Initialisation de la base de données avec des données de test"""
    schema = """
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL,
        role TEXT NOT NULL
    );
    
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        price REAL NOT NULL
    );
    
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        date TEXT NOT NULL
    );
    
    -- Insérer des données de test
    INSERT OR IGNORE INTO users (id, username, password, email, role)
    VALUES 
        (1, 'admin', 'admin123', 'admin@techsecure.local', 'admin'),
        (2, 'john', 'password123', 'john@example.com', 'user'),
        (3, 'alice', 'alice2025', 'alice@example.com', 'user'),
        (4, 'robert', 'secure456', 'robert@example.com', 'manager');
    
    INSERT OR IGNORE INTO products (id, name, description, price)
    VALUES 
        (1, 'Audit de sécurité basique', 'Audit de sécurité pour petites entreprises', 999.99),
        (2, 'Audit de sécurité avancé', 'Audit complet avec test d''intrusion', 2499.99),
        (3, 'Formation sécurité', 'Formation d''une journée sur les bonnes pratiques de sécurité', 799.99),
        (4, 'Surveillance continue', 'Service de surveillance 24/7', 299.99);
    """
    
    with app.app_context():
        db = get_db()
        db.executescript(schema)
        db.commit()

# Route de base pour tester que l'application fonctionne
@app.route('/')
def home():
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Honeypot HTTP - Structure de base</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
            h1 { color: #333; }
            .success { color: green; }
            .info { background: #f0f0f0; padding: 15px; border-radius: 5px; }
        </style>
    </head>
    <body>
        <h1>Honeypot HTTP - Structure de base</h1>
        <div class="success">
            <p>✅ L'application Flask est correctement en cours d'exécution!</p>
        </div>
        <div class="info">
            <p>Cette page confirme que la structure de base du honeypot HTTP est fonctionnelle.</p>
            <p>Configuration de base terminée avec succès.</p>
            <p>Prêt pour l'implémentation des vulnérabilités spécifiques.</p>
        </div>
    </body>
    </html>
    """)

# Point d'entrée principal
if __name__ == '__main__':
    # Initialiser la base de données si elle n'existe pas
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    
    # Démarrer le serveur en mode développement
    app.run(host='0.0.0.0', port=8080, debug=True)