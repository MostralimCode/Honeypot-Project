import requests

# Configuration de l'API pfSense
PFSENSE_URL = "https://192.168.2.1/api/v1"  # Remplacez par l'adresse IP du LAN de pfSense
API_KEY = "votre_api_key"
API_SECRET = "votre_api_secret"
HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json"
}

# Désactiver les avertissements SSL
requests.packages.urllib3.disable_warnings()

def configure_interface_wan():
    """Configurer l'interface WAN avec une adresse statique."""
    payload = {
        "if": "wan",
        "enable": True,
        "type": "staticv4",
        "ipaddr": "192.168.1.20",  # Adresse IP WAN
        "subnet": "24",  # Masque de sous-réseau (255.255.255.0)
        "gateway": "192.168.1.254",  # Passerelle (routeur)
    }
    response = requests.post(f"{PFSENSE_URL}/interface", headers=HEADERS, json=payload, verify=False)
    if response.status_code == 200:
        print(">> Interface WAN configurée avec succès.")
    else:
        print(f"Erreur lors de la configuration WAN : {response.text}")

def configure_interface_lan():
    """Configurer l'interface LAN avec une adresse statique."""
    payload = {
        "if": "lan",
        "enable": True,
        "type": "staticv4",
        "ipaddr": "192.168.2.1",  # Adresse IP LAN
        "subnet": "24",  # Masque de sous-réseau (255.255.255.0)
    }
    response = requests.post(f"{PFSENSE_URL}/interface", headers=HEADERS, json=payload, verify=False)
    if response.status_code == 200:
        print(">> Interface LAN configurée avec succès.")
    else:
        print(f"Erreur lors de la configuration LAN : {response.text}")

def configure_firewall_rules():
    """Ajouter des règles de pare-feu."""
    rules = [
        {"type": "pass", "interface": "wan", "protocol": "tcp", "destination_port": "22", "descr": "Allow SSH"},
        {"type": "pass", "interface": "wan", "protocol": "tcp", "destination_port": "80", "descr": "Allow HTTP"},
        {"type": "pass", "interface": "wan", "protocol": "tcp", "destination_port": "21", "descr": "Allow FTP"}
    ]
    for rule in rules:
        response = requests.post(f"{PFSENSE_URL}/firewall/rule", headers=HEADERS, json=rule, verify=False)
        if response.status_code == 200:
            print(f">> Règle ajoutée : {rule['descr']}")
        else:
            print(f"Erreur lors de l'ajout de la règle {rule['descr']} : {response.text}")

def configure_nat():
    """Configurer le NAT pour permettre aux machines LAN d'accéder à Internet."""
    payload = {
        "source": "192.168.2.0/24",  # Réseau LAN
        "destination": "any",
        "descr": "NAT pour LAN vers WAN"
    }
    response = requests.post(f"{PFSENSE_URL}/nat/outbound", headers=HEADERS, json=payload, verify=False)
    if response.status_code == 200:
        print(">> Règle NAT configurée avec succès.")
    else:
        print(f"Erreur lors de la configuration NAT : {response.text}")

def main():
    print(">> Début de la configuration automatisée de pfSense...")
    configure_interface_wan()
    configure_interface_lan()
    configure_firewall_rules()
    configure_nat()
    print(">> Configuration automatisée terminée avec succès.")

if __name__ == "__main__":
    main()
