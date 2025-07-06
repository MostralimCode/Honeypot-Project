# 🍯 Projet Honeypot - Infrastructure Sécurisée

> **Infrastructure honeypot pour l'analyse des cyberattaques en temps réel**

## 📖 Description

Ce projet a pour objectif de concevoir et déployer une infrastructure sécurisée intégrant un honeypot. L'objectif principal est de capturer des tentatives d'attaques en simulant des services vulnérables tels que SSH, HTTP et FTP. Les données collectées permettront d'analyser les comportements des attaquants et de proposer des recommandations pour renforcer la sécurité.

---

## 🏗️ Caractéristiques principales

### **Infrastructure composée de trois machines :**
- **Serveur 1 :** Serveur sécurisé (SSH)
- **Serveur 2 :** Serveur sécurisé (FTP)  
- **Honeypot :** Machine vulnérable simulant des services SSH, HTTP, et FTP

### **Gestion des logs :**
- Centralisation et enrichissement des logs capturés
- Visualisation via des tableaux de bord interactifs (ElasticSearch/Kibana)

### **Analyse des attaques :**
- Géolocalisation des IP attaquantes
- Extraction et classification des payloads malveillants

### **Automatisation :**
- Scripts pour le déploiement des VM, la gestion des logs, et la génération de rapports PDF

---

## 📁 Structure du projet

```
honeypot-project/
├── configs/                  # Fichiers de configuration (pare-feu, honeypot, services)
├── scripts/                  # Scripts pour automatiser les tâches (déploiement, logs, rapports)
│   ├── servers/
│   │   ├── elk/             # Scripts configuration ELK Stack
│   │   └── honeypot/        # Scripts configuration honeypots
└── README.md               # Ce fichier
```

---

## 🛠️ Outils et technologies

- **Virtualisation :** Proxmox pour l'hébergement des machines virtuelles
- **Honeypot :** Cowrie (SSH), Flask (HTTP), Python personnalisé (FTP)
- **Gestion des logs :** ElasticSearch, Logstash, Kibana (ELK Stack)
- **Automatisation :** Python, Bash
- **Analyse et rapports :** Scripts Python (FPDF pour PDF automatisés)

---

## 🚀 Installation et configuration

### 1. **Préparer l'environnement :**
- Installer Proxmox sur le serveur dédié
- Déployer les trois machines virtuelles

### 2. **Configurer les services :**
- Ajouter les configurations pour SSH (Cowrie), HTTP (Flask), et FTP (Python personnalisé)

### 3. **Configurer le réseau :**
- Mettre en place un bridge réseau pour permettre la communication des VM

### 4. **Lancer les scripts d'automatisation :**
- Centraliser les logs et configurer les tableaux de bord

---

## 📊 Honeypots implémentés

### 🔐 SSH Honeypot (Cowrie)
- Simulation d'un serveur SSH vulnérable
- Capture les tentatives de force brute et les commandes exécutées
- Configuration dans `/scripts/servers/honeypot/cowrie/`

### 🌐 HTTP Honeypot (Flask)
- Application web vulnérable "TechSecure Solutions"
- Vulnérabilités : SQL injection, XSS, path traversal
- Code source dans `/scripts/servers/honeypot/honeypothttp/`

### 📁 FTP Honeypot (Python personnalisé)
- Serveur FTP avec vulnérabilités intentionnelles
- Journalisation détaillée des interactions
- Configuration dans `/scripts/servers/honeypot/honeypotftp/`

---

## 📈 Stack ELK (Analyse)

### Composants installés :
- **Elasticsearch** : Stockage et indexation des logs
- **Logstash** : Traitement et enrichissement des données  
- **Kibana** : Dashboards et visualisations

### Configuration :
- Scripts d'installation : `/scripts/servers/elk/`
- Configuration des indices : `/scripts/servers/elk/elasticsearch/`
- Dashboards Kibana : `/scripts/servers/elk/kibana/`

---

## 🗓️ Roadmap du projet

1. **Phase 1 : Conception et planification** (2 semaines)
   - Création du cahier des charges, du diagramme de Gantt, et de la matrice RACI

2. **Phase 2 : Déploiement de l'infrastructure** (3 semaines)
   - Mise en place des VM et configuration des services vulnérables

3. **Phase 3 : Collecte et centralisation des logs** (2 semaines)
   - Configuration d'ElasticSearch et enrichissement des données capturées

4. **Phase 4 : Analyse des données et visualisation** (3 semaines)
   - Exploration des logs et génération de rapports automatisés

5. **Phase 5 : Tests et ajustements** (2 semaines)
   - Simulation d'attaques, validation et corrections

6. **Phase 6 : Présentation finale** (2 semaines)
   - Rédaction du rapport final et démonstration du projet

---

## 🧪 Tests et validation

### Scripts de test disponibles :
- `/scripts/servers/elk/complete_test.sh` - Tests complets de l'infrastructure
- `/scripts/servers/honeypot/test_vulnerabilities.py` - Tests des vulnérabilités
- Scripts de monitoring dans `/scripts/servers/elk/`

### Validation :
- Tests d'intégration ELK Stack
- Validation du fonctionnement des honeypots
- Génération de données de test

---

## 📊 Rapports et analyse

### Génération automatique :
- Scripts Python utilisant FPDF
- Rapports par type de honeypot (SSH, HTTP, FTP)
- Analyse statistique des attaques
- Géolocalisation des sources d'attaque

### Emplacements :
- `/scripts/servers/elk/rapports/` - Scripts de génération
- Rapports PDF générés automatiquement

---

## 👥 Contributeurs

- **Yanis Betta** 
- **Amine Ouacha**

---

## ⚠️ Avertissement

Ce projet est développé à des fins éducatives et de recherche en cybersécurité. Les honeypots contiennent des vulnérabilités intentionnelles et ne doivent jamais être déployés sur des réseaux de production sans isolement approprié.