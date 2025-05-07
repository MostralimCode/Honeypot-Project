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
from flask import Flask, request, g, session, render_template_string, redirect, url_for, flash, make_response

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
        <title>Honeypot HTTP - {{ company_name }}</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
            h1 { color: #333; }
            .success { color: green; }
            .info { background: #f0f0f0; padding: 15px; border-radius: 5px; }
            nav { margin: 20px 0; }
            nav a { margin-right: 15px; text-decoration: none; color: #0a9396; }
            .files-section { margin-top: 30px; }
        </style>
    </head>
    <body>
        <h1>{{ company_name }}</h1>
        <div class="success">
            <p>✅ Bienvenue sur le site de TechSecure Solutions</p>
        </div>
        
        <nav>
            <a href="/">Accueil</a>
            <a href="/about">À propos</a>
            <a href="/search">Recherche</a>
            <a href="/contact">Contact</a>
            <a href="/login">Portail Client</a>
            <a href="/admin">Admin</a>
        </nav>
        
        <div class="info">
            <p>Nous sommes spécialisés dans les solutions de sécurité informatique pour entreprises.</p>
            <p>Nos experts sont à votre disposition pour vous aider à sécuriser votre infrastructure.</p>
        </div>
        
        <div class="files-section">
            <h3>Ressources disponibles:</h3>
            <ul>
                <li><a href="/file?name=presentation.pdf">Présentation de nos services</a></li>
                <li><a href="/file?name=tarifs.txt">Grille tarifaire</a></li>
                <li><a href="/file?name=exemple_rapport.pdf">Exemple de rapport d'audit</a></li>
            </ul>
        </div>
    </body>
    </html>
    """, company_name=app.config['COMPANY_NAME'])

@app.route('/search', methods=['GET', 'POST'])
def search():
    """
    Page de recherche vulnérable à l'injection SQL
    et au Cross-Site Scripting (XSS) réfléchi
    """
    results = []
    search_term = ""
    error_message = None
    
    if request.method == 'POST':
        search_term = request.form.get('search', '')
        
        # Vulnérabilité intentionnelle: pas d'échappement du terme de recherche
        if search_term:
            try:
                # Vulnérabilité intentionnelle: injection SQL
                # La requête est directement concaténée avec l'entrée utilisateur
                db = get_db()
                query = f"SELECT id, name, description, price FROM products WHERE name LIKE '%{search_term}%' OR description LIKE '%{search_term}%'"
                
                # Enregistrement de la tentative d'attaque potentielle
                log_attack('sql_injection', {
                    'search_term': search_term,
                    'query': query
                })
                
                # Exécution de la requête vulnérable
                results = db.execute(query).fetchall()
            except Exception as e:
                # Vulnérabilité intentionnelle: divulgation d'erreur
                error_message = f"Erreur de base de données: {str(e)}"
                
                # Enregistrement de l'erreur
                log_attack('sql_error', {
                    'search_term': search_term,
                    'error': error_message
                })
    
    # Rendu du template avec le terme de recherche non-échappé (XSS réfléchi)
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Recherche - {{ company_name }}</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; }
            header { background: #005f73; color: white; padding: 1rem; }
            nav { background: #0a9396; padding: 0.5rem; }
            nav a { color: white; margin-right: 15px; text-decoration: none; }
            .container { width: 80%; margin: 0 auto; padding: 1rem; }
            .search-form { margin: 20px 0; }
            .search-form input[type="text"] { padding: 8px; width: 70%; }
            .search-form button { padding: 8px 15px; background: #0a9396; color: white; border: none; }
            .result { border: 1px solid #ddd; padding: 10px; margin: 10px 0; }
            .error { color: red; background: #ffe0e0; padding: 10px; margin: 10px 0; }
            footer { background: #001219; color: white; text-align: center; padding: 1rem; }
        </style>
    </head>
    <body>
        <header>
            <h1>{{ company_name }}</h1>
            <p>Solutions de sécurité informatique pour entreprises</p>
        </header>
        <nav>
            <a href="/">Accueil</a>
            <a href="/about">À propos</a>
            <a href="/search">Recherche</a>
            <a href="/contact">Contact</a>
            <a href="/login">Portail Client</a>
            <a href="/admin">Admin</a>
        </nav>
        <div class="container">
            <h2>Recherche de produits et services</h2>
            
            {% if error_message %}
                <div class="error">{{ error_message }}</div>
            {% endif %}
            
            <form class="search-form" method="post">
                <input type="text" name="search" placeholder="Rechercher un produit ou service..." value="{{ search_term }}">
                <button type="submit">Rechercher</button>
            </form>
            
            {% if search_term %}
                <!-- Vulnérabilité XSS intentionnelle: affichage non-échappé -->
                <h3>Résultats pour: {{ search_term | safe }}</h3>
            {% endif %}
            
            {% if results %}
                <div class="results">
                    {% for result in results %}
                        <div class="result">
                            <h4>{{ result.name }}</h4>
                            <p>{{ result.description }}</p>
                            <p>Prix: {{ result.price }} €</p>
                            <a href="/product/{{ result.id }}">Voir les détails</a>
                        </div>
                    {% endfor %}
                </div>
            {% elif search_term %}
                <p>Aucun résultat trouvé pour: "{{ search_term | safe }}"</p>
            {% endif %}
            
            <!-- Commentaire HTML caché intentionnel -->
            <!-- 
                Note pour les développeurs: 
                TODO: Corriger la vulnérabilité d'injection SQL. 
                La requête actuelle est dangereuse.
                - Jean (jean@techsecure.local)
            -->
        </div>
        <footer>
            &copy; 2025 {{ company_name }} - Tous droits réservés
        </footer>
    </body>
    </html>
    """, company_name=app.config['COMPANY_NAME'], search_term=search_term, results=results, error_message=error_message)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Page de connexion vulnérable à:
    - Attaques par force brute (pas de limitation de tentatives)
    - Authentification faible (mot de passe facile)
    - Stockage non sécurisé (pas de hachage)
    - XSS dans le message d'erreur
    """
    error = None
    
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Enregistrement de la tentative de connexion
        log_attack('login_attempt', {
            'username': username,
            'password': password
        })
        
        # Vulnérabilité intentionnelle: Authentification faible
        # 1. Pas de limitation de tentatives (brute force possible)
        # 2. Mot de passe statique facile
        # 3. Stockage en clair (pas de hachage)
        if username == app.config['ADMIN_USER'] and password == app.config['ADMIN_PASSWORD']:
            session['logged_in'] = True
            session['username'] = username
            session['role'] = 'admin'
            
            # Redirection vers le panneau d'administration
            return redirect(url_for('admin'))
        else:
            # Recherche de l'utilisateur dans la base de données
            try:
                db = get_db()
                # Vulnérabilité intentionnelle: requête SQL non paramétrée
                query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
                user = db.execute(query).fetchone()
                
                if user:
                    session['logged_in'] = True
                    session['username'] = username
                    session['role'] = user['role']
                    
                    # Redirection selon le rôle
                    if user['role'] == 'admin':
                        return redirect(url_for('admin'))
                    else:
                        return redirect(url_for('user_dashboard'))
                else:
                    # Vulnérabilité intentionnelle: XSS dans le message d'erreur
                    error = f"Identifiants incorrects pour: <strong>{username}</strong>"
            except Exception as e:
                # Vulnérabilité intentionnelle: divulgation d'erreur
                error = f"Erreur de base de données: {str(e)}"
                log_attack('login_error', {
                    'username': username,
                    'error': str(e)
                })
    
    # Rendu du template avec potentiellement un message d'erreur non-échappé
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Connexion - {{ company_name }}</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; }
            header { background: #005f73; color: white; padding: 1rem; }
            nav { background: #0a9396; padding: 0.5rem; }
            nav a { color: white; margin-right: 15px; text-decoration: none; }
            .container { width: 80%; margin: 0 auto; padding: 1rem; }
            .login-form { width: 400px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; }
            .login-form input { display: block; width: 90%; padding: 8px; margin: 10px 0; }
            .login-form button { padding: 8px 15px; background: #0a9396; color: white; border: none; width: 100%; margin-top: 10px; }
            .error { color: red; background: #ffe0e0; padding: 10px; margin: 10px 0; }
            footer { background: #001219; color: white; text-align: center; padding: 1rem; }
        </style>
    </head>
    <body>
        <header>
            <h1>{{ company_name }}</h1>
            <p>Solutions de sécurité informatique pour entreprises</p>
        </header>
        <nav>
            <a href="/">Accueil</a>
            <a href="/about">À propos</a>
            <a href="/search">Recherche</a>
            <a href="/contact">Contact</a>
            <a href="/login">Portail Client</a>
            <a href="/admin">Admin</a>
        </nav>
        <div class="container">
            <h2>Connexion au portail</h2>
            
            <div class="login-form">
                {% if error %}
                    <!-- Vulnérabilité XSS intentionnelle: message d'erreur non échappé -->
                    <div class="error">{{ error | safe }}</div>
                {% endif %}
                
                <form method="post">
                    <input type="text" name="username" placeholder="Nom d'utilisateur" required>
                    <input type="password" name="password" placeholder="Mot de passe" required>
                    <button type="submit">Se connecter</button>
                </form>
                
                <p><small>Mot de passe oublié? Contactez l'administrateur.</small></p>
                
                <!-- Commentaire HTML caché intentionnel -->
                <!-- 
                    Rappel: Les identifiants administrateur par défaut sont:
                    - Utilisateur: admin
                    - Mot de passe: admin123
                    
                    À ne pas partager avec les clients!
                -->
            </div>
        </div>
        <footer>
            &copy; 2025 {{ company_name }} - Tous droits réservés
        </footer>
    </body>
    </html>
    """, company_name=app.config['COMPANY_NAME'], error=error)

@app.route('/user_dashboard')
def user_dashboard():
    """
    Tableau de bord utilisateur simple pour rediriger les utilisateurs non-admin
    """
    if not session.get('logged_in'):
        return redirect(url_for('login'))
        
    username = session.get('username', 'Inconnu')
    role = session.get('role', 'utilisateur')
    
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Tableau de bord - {{ company_name }}</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; }
            header { background: #005f73; color: white; padding: 1rem; }
            nav { background: #0a9396; padding: 0.5rem; }
            nav a { color: white; margin-right: 15px; text-decoration: none; }
            .container { width: 80%; margin: 0 auto; padding: 1rem; }
            .dashboard { background: #f0f0f0; padding: 20px; border-radius: 5px; }
            footer { background: #001219; color: white; text-align: center; padding: 1rem; }
        </style>
    </head>
    <body>
        <header>
            <h1>{{ company_name }}</h1>
            <p>Solutions de sécurité informatique pour entreprises</p>
        </header>
        <nav>
            <a href="/">Accueil</a>
            <a href="/search">Recherche</a>
            <a href="/contact">Contact</a>
            <a href="/user_dashboard">Tableau de bord</a>
            <a href="/logout">Déconnexion</a>
        </nav>
        <div class="container">
            <h2>Tableau de bord utilisateur</h2>
            <div class="dashboard">
                <h3>Bienvenue, {{ username }}!</h3>
                <p>Votre rôle: {{ role }}</p>
                
                <h4>Vos services actifs:</h4>
                <ul>
                    <li>Surveillance de base - Actif jusqu'au 15/06/2025</li>
                    <li>Protection anti-phishing - Actif jusqu'au 31/12/2025</li>
                </ul>
                
                <h4>Dernières alertes:</h4>
                <ul>
                    <li>03/05/2025 - Tentative de connexion inhabituelle détectée</li>
                    <li>28/04/2025 - Mise à jour de sécurité disponible</li>
                </ul>
            </div>
        </div>
        <footer>
            &copy; 2025 {{ company_name }} - Tous droits réservés
        </footer>
    </body>
    </html>
    """, company_name=app.config['COMPANY_NAME'], username=username, role=role)

@app.route('/logout')
def logout():
    """Déconnexion de l'utilisateur"""
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('home'))

@app.route('/admin')
def admin():
    """
    Zone d'administration avec contrôle d'accès vulnérable
    La vérification se fait uniquement sur la présence de la session
    """
    # Vulnérabilité intentionnelle: contrôle d'accès faible (pas de vérification CSRF)
    # et possibilité de modification de la session côté client
    if session.get('logged_in'):
        # L'utilisateur est connecté
        username = session.get('username', 'Unknown')
        
        # Simuler des données d'administration
        db = get_db()
        users = db.execute("SELECT id, username, email, role FROM users").fetchall()
        
        return render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Administration - {{ company_name }}</title>
            <style>
                body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; }
                header { background: #005f73; color: white; padding: 1rem; }
                nav { background: #0a9396; padding: 0.5rem; }
                nav a { color: white; margin-right: 15px; text-decoration: none; }
                .container { width: 80%; margin: 0 auto; padding: 1rem; }
                .admin-panel { background: #f0f0f0; padding: 20px; border-radius: 5px; }
                table { width: 100%; border-collapse: collapse; }
                table, th, td { border: 1px solid #ddd; }
                th, td { padding: 10px; text-align: left; }
                footer { background: #001219; color: white; text-align: center; padding: 1rem; }
            </style>
        </head>
        <body>
            <header>
                <h1>{{ company_name }}</h1>
                <p>Solutions de sécurité informatique pour entreprises</p>
            </header>
            <nav>
                <a href="/">Accueil</a>
                <a href="/about">À propos</a>
                <a href="/search">Recherche</a>
                <a href="/contact">Contact</a>
                <a href="/login">Portail Client</a>
                <a href="/admin">Admin</a>
                <a href="/logout">Déconnexion</a>
            </nav>
            <div class="container">
                <h2>Panneau d'administration</h2>
                <p>Bienvenue, {{ username }}!</p>
                
                <div class="admin-panel">
                    <h3>Gestion des utilisateurs</h3>
                    <table>
                        <tr>
                            <th>ID</th>
                            <th>Nom d'utilisateur</th>
                            <th>Email</th>
                            <th>Rôle</th>
                            <th>Actions</th>
                        </tr>
                        {% for user in users %}
                            <tr>
                                <td>{{ user.id }}</td>
                                <td>{{ user.username }}</td>
                                <td>{{ user.email }}</td>
                                <td>{{ user.role }}</td>
                                <td>
                                    <a href="/admin/edit_user/{{ user.id }}">Modifier</a> |
                                    <a href="/admin/delete_user/{{ user.id }}">Supprimer</a>
                                </td>
                            </tr>
                        {% endfor %}
                    </table>
                    
                    <h3>Fonctionnalités administratives</h3>
                    <ul>
                        <li><a href="/admin/backups">Gestion des sauvegardes</a></li>
                        <li><a href="/admin/logs">Journaux système</a></li>
                        <li><a href="/admin/settings">Paramètres</a></li>
                        <li><a href="/admin/upload">Téléchargement de fichiers</a></li>
                    </ul>
                </div>
            </div>
            <footer>
                &copy; 2025 {{ company_name }} - Tous droits réservés
            </footer>
        </body>
        </html>
        """, company_name=app.config['COMPANY_NAME'], username=username, users=users)
    else:
        # L'utilisateur n'est pas connecté, redirection vers la page de connexion
        # Enregistrement de la tentative d'accès non autorisé
        log_attack('unauthorized_admin_access', {
            'headers': {k: v for k, v in request.headers.items()},
            'cookies': {k: v for k, v in request.cookies.items()}
        })
        
        return redirect(url_for('login'))

@app.route('/admin/upload', methods=['GET', 'POST'])
def admin_upload():
    """
    Page de téléchargement de fichiers vulnérable
    Peut accepter des fichiers malveillants sans vérification
    """
    if not session.get('logged_in'):
        # L'utilisateur n'est pas connecté, redirection vers la page de connexion
        return redirect(url_for('login'))
    
    uploaded_file = None
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('Aucun fichier sélectionné')
            return redirect(request.url)
            
        file = request.files['file']
        
        if file.filename == '':
            flash('Aucun fichier sélectionné')
            return redirect(request.url)
            
        # Vulnérabilité intentionnelle: aucune validation du type de fichier
        # ou du contenu du fichier
        filename = file.filename
        
        # Enregistrement de la tentative de téléchargement
        log_attack('file_upload', {
            'filename': filename,
            'content_type': file.content_type,
            'file_size': len(file.read())
        })
        
        # Réinitialiser le pointeur du fichier
        file.seek(0)
        
        # Sauvegarder le fichier
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)
        
        uploaded_file = {
            'name': filename,
            'path': upload_path,
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
    
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Téléchargement de fichiers - {{ company_name }}</title>
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 0; }
            header { background: #005f73; color: white; padding: 1rem; }
            nav { background: #0a9396; padding: 0.5rem; }
            nav a { color: white; margin-right: 15px; text-decoration: none; }
            .container { width: 80%; margin: 0 auto; padding: 1rem; }
            .upload-form { background: #f0f0f0; padding: 20px; border-radius: 5px; margin-top: 20px; }
            .alert { padding: 10px; margin: 10px 0; border-radius: 5px; }
            .alert-success { background: #d1e7dd; color: #0f5132; }
            footer { background: #001219; color: white; text-align: center; padding: 1rem; }
        </style>
    </head>
    <body>
        <header>
            <h1>{{ company_name }}</h1>
            <p>Solutions de sécurité informatique pour entreprises</p>
        </header>
        <nav>
            <a href="/">Accueil</a>
            <a href="/about">À propos</a>
            <a href="/search">Recherche</a>
            <a href="/contact">Contact</a>
            <a href="/login">Portail Client</a>
            <a href="/admin">Admin</a>
            <a href="/logout">Déconnexion</a>
        </nav>
        <div class="container">
            <h2>Téléchargement de fichiers</h2>
            
            {% for message in get_flashed_messages() %}
                <div class="alert">{{ message }}</div>
            {% endfor %}
            
            <div class="upload-form">
                <h3>Télécharger un nouveau fichier</h3>
                <form method="post" enctype="multipart/form-data">
                    <div>
                        <input type="file" name="file" required>
                    </div>
                    <div style="margin-top: 10px;">
                        <button type="submit" style="padding: 8px 15px; background: #0a9396; color: white; border: none;">Télécharger</button>
                    </div>
                </form>
            </div>
            
            {% if uploaded_file %}
                <div class="alert alert-success">
                    <h3>Fichier téléchargé avec succès</h3>
                    <p>Nom: {{ uploaded_file.name }}</p>
                    <p>Date: {{ uploaded_file.time }}</p>
                </div>
            {% endif %}
        </div>
        <footer>
            &copy; 2025 {{ company_name }} - Tous droits réservés
        </footer>
    </body>
    </html>
    """, company_name=app.config['COMPANY_NAME'], uploaded_file=uploaded_file)

@app.route('/file', methods=['GET'])
def file_access():
    """
    Endpoint vulnérable à la traversée de chemin (path traversal)
    Permet d'accéder à des fichiers en dehors du répertoire prévu
    """
    filename = request.args.get('name', '')
    
    if not filename:
        return "Erreur: Aucun fichier spécifié", 400
    
    # Enregistrement de la tentative d'accès au fichier
    log_attack('path_traversal', {
        'filename': filename
    })
    
    # Vulnérabilité intentionnelle: pas de validation du chemin
    # Un attaquant peut utiliser "../" pour sortir du répertoire uploads
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        # Tentative d'ouverture du fichier
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Déterminer le type MIME
        if filename.endswith('.txt'):
            mimetype = 'text/plain'
        elif filename.endswith('.pdf'):
            mimetype = 'application/pdf'
        elif filename.endswith('.jpg') or filename.endswith('.jpeg'):
            mimetype = 'image/jpeg'
        elif filename.endswith('.png'):
            mimetype = 'image/png'
        else:
            mimetype = 'application/octet-stream'
        
        return make_response(data, 200, {'Content-Type': mimetype})
    
    except Exception as e:
        return f"Erreur lors de la lecture du fichier: {str(e)}", 404

# Point d'entrée principal
if __name__ == '__main__':
    # Initialiser la base de données si elle n'existe pas
    if not os.path.exists(app.config['DATABASE']):
        init_db()
    
    # Démarrer le serveur en mode développement
    app.run(host='0.0.0.0', port=8080, debug=True)