# Projet Honeypot - Infrastructure Sécurisée

## **Description**
Ce projet a pour objectif de concevoir et déployer une infrastructure sécurisée intégrant un honeypot. L’objectif principal est de capturer des tentatives d’attaques en simulant des services vulnérables tels que SSH, HTTP et FTP. Les données collectées permettront d’analyser les comportements des attaquants et de proposer des recommandations pour renforcer la sécurité.

---

## **Caractéristiques principales**
- **Infrastructure composée de trois machines :**
  - **Serveur 1 :** Serveur sécurisé (SSH).
  - **Serveur 2 :** Serveur sécurisé (FTP).
  - **Honeypot :** Machine vulnérable simulant des services SSH, HTTP, et FTP.
- **Gestion des logs :**
  - Centralisation et enrichissement des logs capturés.
  - Visualisation via des tableaux de bord interactifs (ElasticSearch/Kibana).
- **Analyse des attaques :**
  - Géolocalisation des IP attaquantes.
  - Extraction et classification des payloads malveillants.
- **Automatisation :**
  - Scripts pour le déploiement des VM, la gestion des logs, et la génération de rapports PDF.

---

## **Structure du projet**
Le dépôt est organisé comme suit :
/honeypot-project/ │ ├── /docs/ # Documentation et schémas (architecture, matrice RACI, etc.). ├── /configs/ # Fichiers de configuration (pare-feu, honeypot, services). ├── /scripts/ # Scripts pour automatiser les tâches (déploiement, logs, rapports). ├── /logs/ # Exemple de logs capturés et analysés. ├── /visualizations/ # Tableaux de bord Kibana ou fichiers graphiques. └── README.md # Présentation du projet.


---

## **Outils et technologies**
- **Virtualisation :** Proxmox pour l’hébergement des machines virtuelles.
- **Honeypot :** Cowrie (SSH), Flask (HTTP), Dionaea (FTP).
- **Gestion des logs :** ElasticSearch, Logstash, Kibana.
- **Automatisation :** Docker, Python, Ansible.
- **Analyse et rapports :** Scripts Python (FPDF pour PDF automatisés).

---

## **Installation et configuration**
1. **Préparer l’environnement :**
   - Installer Proxmox sur le serveur dédié.
   - Déployer les trois machines virtuelles.
2. **Configurer les services :**
   - Ajouter les configurations pour SSH (Cowrie), HTTP (Flask), et FTP (Dionaea).
3. **Configurer le réseau :**
   - Mettre en place un bridge réseau pour permettre la communication des VM.
4. **Lancer les scripts d’automatisation :**
   - Centraliser les logs et configurer les tableaux de bord.

Pour plus de détails, consultez le dossier `/docs/`.

---

## **Roadmap**
1. **Phase 1 : Conception et planification** (2 semaines).
   - Création du cahier des charges, du diagramme de Gantt, et de la matrice RACI.
2. **Phase 2 : Déploiement de l’infrastructure** (3 semaines).
   - Mise en place des VM et configuration des services vulnérables.
3. **Phase 3 : Collecte et centralisation des logs** (2 semaines).
   - Configuration d’ElasticSearch et enrichissement des données capturées.
4. **Phase 4 : Analyse des données et visualisation** (3 semaines).
   - Exploration des logs et génération de rapports automatisés.
5. **Phase 5 : Tests et ajustements** (2 semaines).
   - Simulation d’attaques, validation et corrections.
6. **Phase 6 : Présentation finale** (2 semaines).
   - Rédaction du rapport final et démonstration du projet.

---

## **Contributeurs**
- **[Yanis Betta] :** 
- **[Amine Ouacha] :**

---

