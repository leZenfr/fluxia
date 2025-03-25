#!/usr/bin/env python3
"""
Fluxia - Outil de gestion des configurations réseau
Développé par leZen, Agridien, ReNaGe
Version 0.0.1
"""

import sys
import os
import argparse
import json
import time
import signal
import socket
from datetime import datetime

# Gestion des dépendances optionnelles
NETIFACES_AVAILABLE = False
INOTIFY_AVAILABLE = False

try:
    import netifaces
    NETIFACES_AVAILABLE = True
except ImportError:
    print("Note: Le module 'netifaces' n'est pas installé.")
    print("Certaines fonctionnalités seront limitées.")
    print("Pour l'installer: sudo apt install python3-netifaces")

try:
    from inotify_simple import INotify, flags
    INOTIFY_AVAILABLE = True
except ImportError:
    print("Note: Le module 'inotify_simple' n'est pas installé.")
    print("La surveillance en temps réel sera remplacée par un polling.")
    print("Pour l'installer: sudo apt install python3-inotify")

# ASCII Art pour le logo
LOGO = """
 ______   **         **  **     **  **     **     ______    
/\\  ___\\ /\\ \\       /\\ \\/\\ \\   /\\_\\_\\_\\   /\\ \\   /\\  __ \\   
\\ \\  **\\ \\ \\ \\**__  \\ \\ \\_\\ \\  \\/_/\\_\\/_  \\ \\ \\  \\ \\  __ \\  
\\ \\_\\    \\ \\_____\\  \\ \\_____\\   /\\_\\/\\_\\  \\ \\_\\  \\ \\_\\ \\_\\ 
\\/_/     \\/_____/   \\/_____/   \\/_/\\/_/   \\/_/   \\/_/\\/_/ 
                                                            
                fluxia : v0.0.1
             by leZen, Agridien et ReNaGe
"""

# ASCII Art pour l'affichage des configurations
CONFIG_ART = """
                                    .,,uod8B8bou,,.
                    ..,uod8BBBBBBBBBBBBBBBBRPFT?l!i:.
                ,=m8BBBBBBBBBBBBBBBRPFT?!||||||||||||||
                !...:!TVBBBRPFT||||||||||!!^^""'   ||||
                !.......:!?|||||!!^^""'            ||||
                !.........||||                     ||||
                !.........||||conf                 ||||
                !.........||||                     ||||
                !.........||||                     ||||
                !.........||||                     ||||
                !.........||||                     ||||
                `.........||||                    ,||||
                .;.......||||               _.-!!|||||
        .,uodWBBBBb.....||||       _.-!!|||||||||!:'
        !YBBBBBBBBBBBBBBb..!|||:..-!!|||||||!iof68BBBBBb....
        !..YBBBBBBBBBBBBBBb!!||||||||!iof68BBBBBBRPFT?!::   `.
        !....YBBBBBBBBBBBBBBbaaitf68BBBBBBRPFT?!:::::::::     `.
        !......YBBBBBBBBBBBBBBBBBBBRPFT?!::::::;:!^"`;:::       `.
        !........YBBBBBBBBBBRPFT?!::::::::::^''...::::::;         iBBbo.
        `..........YBRPFT?!::::::::::::::::::::::::;iof68bo.      WBBBBbo.
        `..........:::::::::::::::::::::::;iof688888888888b.     `YBBBP^'
            `........::::::::::::::::;iof688888888888888888888b.     `
            `......:::::::::;iof688888888888888888888888888888b.
                `....:::;iof688888888888888888888888888888888899fT!
                `..::!8888888888888888888888888888888899fT|!^"'
                    `' !!988888888888888888888888899fT|!^"'
                        `!!8888888888888888899fT|!^"'
                        `!988888888899fT|!^"'
                            `!9899fT|!^"'
                            `!^"'
"""


def get_server_ports_and_clients():
    """
    Obtient les ports serveurs bindés et les clients connectés à ces ports
    Compatible avec Kali Linux dans un environnement virtuel
    """
    server_ports = {}
    try:
        # Utiliser 'ss' pour obtenir les serveurs qui écoutent
        with os.popen('ss -tuln') as f:
            listener_lines = f.readlines()
        
        # Traiter les sockets qui écoutent
        for line in listener_lines[1:]:  # Ignorer l'en-tête
            parts = line.split()
            if len(parts) < 5:
                continue
                
            protocol = parts[0]
            local_address = parts[4]
            
            if ":" in local_address:
                local_ip, local_port = local_address.rsplit(":", 1)
                
                # Ajouter le port serveur au dictionnaire
                if local_port not in server_ports:
                    server_ports[local_port] = {
                        "clients": [],
                        "pid_program": "N/A",
                        "protocol": protocol
                    }
        
        # Utiliser 'netstat' ou 'ss' pour obtenir les connexions établies
        # Essayer d'abord avec netstat pour une meilleure compatibilité
        try:
            with os.popen('netstat -tna | grep ESTABLISHED') as f:
                established_lines = f.readlines()
                
            # Traiter les connexions établies avec netstat
            for line in established_lines:
                parts = line.split()
                if len(parts) < 6:
                    continue
                    
                local_address = parts[3] 
                remote_address = parts[4]
                
                if ":" in local_address and ":" in remote_address:
                    local_parts = local_address.rsplit(":", 1)
                    remote_parts = remote_address.rsplit(":", 1)
                    
                    if len(local_parts) == 2 and len(remote_parts) == 2:
                        local_ip, local_port = local_parts
                        remote_ip, remote_port = remote_parts
                        
                        if local_port in server_ports and remote_ip not in server_ports[local_port]["clients"]:
                            server_ports[local_port]["clients"].append(remote_ip)
                
        except Exception as netstat_error:
            print(f"Tentative avec ss après échec de netstat: {netstat_error}")
            # Fallback sur ss si netstat échoue
            with os.popen('ss -tna | grep ESTAB') as f:
                established_lines = f.readlines()
                
            # Traiter les connexions établies avec ss
            for line in established_lines:
                parts = line.split()
                if len(parts) < 5:
                    continue
                    
                local_address = parts[3]
                remote_address = parts[4]
                
                if ":" in local_address and ":" in remote_address:
                    local_ip, local_port = local_address.rsplit(":", 1)
                    remote_ip, remote_port = remote_address.rsplit(":", 1)
                    
                    # Si le port local est un port serveur (qui écoute)
                    if local_port in server_ports:
                        if remote_ip not in server_ports[local_port]["clients"]:
                            server_ports[local_port]["clients"].append(remote_ip)
        
        # Tentative spécifique pour SSH (port 22)
        if "22" in server_ports and not server_ports["22"]["clients"]:
            with os.popen("who | awk '{print $5}' | tr -d '()' | grep -v '^$'") as f:
                ssh_clients = f.readlines()
                
            for client in ssh_clients:
                client = client.strip()
                if client and client not in server_ports["22"]["clients"]:
                    server_ports["22"]["clients"].append(client)
        
        return server_ports
    except Exception as e:
        print(f"Erreur lors de la récupération des ports serveurs et des clients: {e}")
        return {}
        
def get_client_ports_and_hostnames():
    """
    Obtient les ports clients avec leurs adresses et noms d'hôtes
    """
    client_ports = {}
    try:
        # Obtenir les connexions ouvertes
        with os.popen('ss -tn') as f:
            lines = f.readlines()
            for line in lines[1:]:
                parts = line.split()
                local_address = parts[3]
                remote_address = parts[4]
                remote_ip, remote_port = remote_address.rsplit(":", 1)

                # Obtenir le nom d'hôte pour l'adresse distante
                try:
                    remote_hostname = socket.gethostbyaddr(remote_ip)[0]
                except socket.herror:
                    remote_hostname = "Inconnu"

                if remote_ip not in client_ports:
                    client_ports[remote_ip] = []

                client_ports[remote_ip].append({
                    "port": remote_port,
                    "hostname": remote_hostname
                })

        return client_ports
    except Exception as e:
        print(f"Erreur lors de la récupération des ports clients: {e}")
        return {}

def get_fallback_network_info():
    """
    Récupère les informations réseau de base sans dépendance à netifaces
    """
    config = {}
    try:
        # Obtenir le nom d'hôte
        hostname = socket.gethostname()
        
        # Obtenir les adresses IP associées au nom d'hôte
        host_info = socket.gethostbyname_ex(hostname)
        ip_addresses = host_info[2]
        
        # Ajouter l'interface principale
        config["primary"] = {
            "ipv4": [{"addr": ip} for ip in ip_addresses],
            "hostname": hostname
        }
        
        # Tenter d'obtenir l'adresse IP externe
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            external_ip = s.getsockname()[0]
            s.close()
            config["external"] = {
                "ipv4": [{"addr": external_ip}]
            }
        except:
            pass
        
        return config
    except Exception as e:
        print(f"Erreur lors de la récupération des informations réseau: {str(e)}")
        return {}
        
def show_server_ports_and_clients():
    """
    Affiche les ports serveurs bindés avec les clients connectés
    """
    server_ports = get_server_ports_and_clients()
    print("\n=== Ports Serveurs Bindés ===")
    
    if not server_ports:
        print("Aucun port serveur trouvé.")
        return
    
    for port, info in server_ports.items():
        print(f"\n[Port] {port}")
        print(f"  Programme/PID: {info['pid_program']}")
        print(f"  Clients connectés:")
        for client in info['clients']:
            print(f"    - {client}")

def show_client_ports_and_hostnames():
    """
    Affiche les ports clients avec leurs adresses et noms d'hôtes
    """
    client_ports = get_client_ports_and_hostnames()
    print("\n=== Ports Clients ===")
    
    if not client_ports:
        print("Aucun port client trouvé.")
        return
    
    for ip, ports in client_ports.items():
        print(f"\n[Client] {ip}")
        for port_info in ports:
            print(f"  Port: {port_info['port']}, Hôte: {port_info['hostname']}")
            

def get_network_config():
    """
    Récupère les configurations réseau du système
    Retourne un dictionnaire avec les informations des interfaces
    """
    # Si netifaces n'est pas disponible, utiliser la méthode alternative
    if not NETIFACES_AVAILABLE:
        return get_fallback_network_info()
    
    try:
        config = {}
        interfaces = netifaces.interfaces()
        
        for interface in interfaces:
            try:
                # Obtenir les adresses pour chaque interface
                addresses = netifaces.ifaddresses(interface)
                config[interface] = {}
                
                # Adresse IPv4
                if netifaces.AF_INET in addresses:
                    config[interface]['ipv4'] = addresses[netifaces.AF_INET]
                
                # Adresse IPv6
                if netifaces.AF_INET6 in addresses:
                    config[interface]['ipv6'] = addresses[netifaces.AF_INET6]
                
                # Adresse MAC
                if netifaces.AF_LINK in addresses:
                    config[interface]['mac'] = addresses[netifaces.AF_LINK]
                
                # Passerelle (si disponible)
                gateways = netifaces.gateways()
                if 'default' in gateways and netifaces.AF_INET in gateways['default']:
                    gw_info = gateways['default'][netifaces.AF_INET]
                    if gw_info[1] == interface:
                        config[interface]['gateway'] = gw_info[0]
            
            except Exception as e:
                print(f"Erreur lors de la récupération des informations pour {interface}: {str(e)}")
                
        return config
    
    except Exception as e:
        print(f"Erreur lors de la récupération des configurations réseau: {str(e)}")
        return get_fallback_network_info()

def show_config(config=None):
    """
    Affiche les configurations réseau avec un ASCII art
    """
    if config is None:
        config = get_network_config()
    
    print(CONFIG_ART)
    print("\n=== Configuration réseau ===")
    
    if not config:
        print("Aucune information réseau disponible.")
        return
    
    for interface, info in config.items():
        print(f"\n[Interface] {interface}")
        
        if 'hostname' in info:
            print(f"  Nom d'hôte: {info['hostname']}")
        
        if 'mac' in info and info['mac']:
            print(f"  MAC: {info['mac'][0]['addr']}")
        
        if 'ipv4' in info and info['ipv4']:
            for addr_info in info['ipv4']:
                print(f"  IPv4: {addr_info['addr']}")
                if 'netmask' in addr_info:
                    print(f"  Masque: {addr_info['netmask']}")
        
        if 'ipv6' in info and info['ipv6']:
            for addr_info in info['ipv6']:
                print(f"  IPv6: {addr_info['addr']}")
        
        if 'gateway' in info:
            print(f"  Passerelle: {info['gateway']}")
    
    print("\n=== Fin de la configuration ===")

def export_config(filename):
    """
    Exporte les configurations réseau dans un fichier JSON
    """
    try:
        config = get_network_config()
        
        # Vérification du chemin
        if os.path.dirname(filename) and not os.path.exists(os.path.dirname(filename)):
            print(f"Erreur: Le répertoire {os.path.dirname(filename)} n'existe pas.")
            return False
        
        # Ajout d'un timestamp
        export_data = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "config": config
        }
        
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        print(f"Configuration exportée avec succès dans {filename}")
        return True
    
    except PermissionError:
        print(f"Erreur: Permissions insuffisantes pour écrire dans {filename}")
        return False
    except Exception as e:
        print(f"Erreur lors de l'exportation: {str(e)}")
        return False

def read_config(filename):
    """
    Lit les configurations réseau depuis un fichier JSON
    """
    try:
        if not os.path.exists(filename):
            print(f"Erreur: Le fichier {filename} n'existe pas.")
            return None
        
        with open(filename, 'r') as f:
            data = json.load(f)
        
        if 'config' not in data:
            print("Erreur: Format de fichier invalide.")
            return None
        
        # Afficher les informations du fichier
        print(f"Configuration chargée depuis {filename}")
        print(f"Date de capture: {data.get('timestamp', 'Non spécifiée')}")
        
        return data['config']
    
    except json.JSONDecodeError:
        print(f"Erreur: Le fichier {filename} n'est pas un JSON valide.")
        return None
    except Exception as e:
        print(f"Erreur lors de la lecture: {str(e)}")
        return None


def monitor_network_changes_polling():
    """
    Surveille les modifications des interfaces réseau en utilisant le polling
    """
    print("Surveillance des modifications réseau (méthode polling)...")
    print("Appuyez sur Ctrl+C pour arrêter.")
    
    last_config = get_network_config()
    
    try:
        while True:
            time.sleep(2)  # Vérifier toutes les 2 secondes
            current_config = get_network_config()
            
            # Comparer avec la configuration précédente
            if current_config != last_config:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] Modification réseau détectée")
                
                # Trouver les interfaces modifiées
                for interface in set(list(current_config.keys()) + list(last_config.keys())):
                    if interface not in last_config:
                        print(f"Nouvelle interface: {interface}")
                    elif interface not in current_config:
                        print(f"Interface supprimée: {interface}")
                    elif current_config[interface] != last_config[interface]:
                        print(f"Interface modifiée: {interface}")
                        if 'ipv4' in current_config[interface]:
                            for addr in current_config[interface]['ipv4']:
                                print(f"  IPv4: {addr['addr']}")
                
                last_config = current_config
    
    except KeyboardInterrupt:
        print("\nSurveillance arrêtée.")
        sys.exit(0)
    except Exception as e:
        print(f"Erreur lors de la surveillance: {str(e)}")

def monitor_network_changes():
    """
    Point d'entrée pour la surveillance réseau qui choisit la méthode appropriée
    """
    monitor_network_changes_polling()

        

def validate_input(input_value, min_val, max_val):
    """
    Valide une entrée utilisateur pour s'assurer qu'elle est dans une plage valide
    """
    try:
        value = int(input_value)
        if min_val <= value <= max_val:
            return value
        else:
            return None
    except ValueError:
        return None

def interactive_menu():
    """
    Affiche le menu interactif et gère les choix de l'utilisateur
    """
    while True:
        print(LOGO)
        menu = """
[1]・Afficher les configurations réseau
[2]・Exporter en json
[3]・Charger depuis un fichier json
[4]・Surveiller les modifications réseau
[5]・Afficher les ports serveurs bindés et les clients connectés
[6]・Afficher les ports clients avec adresses et hôtes
[0]・Quitter
"""
        print(menu)

        try:
            user_choice = input("Veuillez choisir l'option que vous voulez (0-6) : ")
            choice = validate_input(user_choice, 0, 6)

            if choice is None:
                print("Choix invalide. Veuillez entrer un nombre entre 0 et 6.")
                input("Appuyez sur Entrée pour continuer...")
                continue

            if choice == 0:
                print("Au revoir!")
                sys.exit(0)
            elif choice == 1:
                show_config()
            elif choice == 2:
                filename = input("Nom du fichier d'exportation (par défaut: config.json): ").strip() or "config.json"
                # Validation simple du nom de fichier
                if "/" in filename and not os.path.isabs(filename):
                    print("Erreur: Veuillez utiliser un chemin absolu ou un nom de fichier sans '/'")
                else:
                    export_config(filename)
            elif choice == 3:
                filename = input("Nom du fichier à charger: ").strip()
                if not filename:
                    print("Erreur: Nom de fichier requis")
                else:
                    config = read_config(filename)
                    if config:
                        show_config(config)
            elif choice == 4:
                try:
                    monitor_network_changes()
                except KeyboardInterrupt:
                    print("\nSurveillance arrêtée.")
            elif choice == 5:
                show_server_ports_and_clients()
            elif choice == 6:
                show_client_ports_and_hostnames()
                
            input("\nAppuyez sur Entrée pour revenir au menu principal...")

        except KeyboardInterrupt:
            print("\nOpération annulée par l'utilisateur.")
            input("Appuyez sur Entrée pour revenir au menu principal...")
        except Exception as e:
            print(f"Erreur inattendue: {str(e)}")
            input("Appuyez sur Entrée pour revenir au menu principal...")

def main():
    """
    Fonction principale du programme
    """
    # Vérification que l'utilisateur n'essaie pas d'exploiter des privilèges
    if os.geteuid() == 0:
        print("Attention: Ce script ne nécessite pas d'être exécuté en tant que root.")
        
    # Créer le parseur d'arguments avec aide personnalisée
    parser = argparse.ArgumentParser(
        description="Fluxia: Outil de gestion des configurations réseau",
        add_help=False
    )
    
    parser.add_argument(
        "-h", "--help", 
        action="help", 
        default=argparse.SUPPRESS,
        help="Affiche ce message d'aide et quitte"
    )
    
    parser.add_argument(
        "-r", "--read",
        type=str,
        metavar="FICHIER",
        help="Afficher les configurations depuis un fichier JSON"
    )
    
    parser.add_argument(
        "-w", "--write",
        type=str,
        metavar="FICHIER",
        help="Exporter les configurations dans un fichier JSON"
    )
    
    parser.add_argument(
        "-m", "--monitor",
        action="store_true",
        help="Surveiller les modifications des interfaces réseau"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Activer le mode verbeux pour plus d'informations"
    )
    
    # Analyser les arguments
    args = parser.parse_args()
    
    # Traiter les arguments
    if args.read:
        config = read_config(args.read)
        if config:
            show_config(config)
    elif args.write:
        export_config(args.write)
    elif args.monitor:
        monitor_network_changes()
    else:
        # Si aucun argument spécifique n'est donné, afficher le menu interactif
        interactive_menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nProgramme interrompu par l'utilisateur.")
        sys.exit(0)
    except Exception as e:
        print(f"Erreur fatale: {str(e)}")
        sys.exit(1)
