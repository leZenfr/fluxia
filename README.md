# Fluxia

```

                ______   **         **  **     **  **     **     ______    
                /\  ___\ /\ \       /\ \/\ \   /\_\_\_\   /\ \   /\  __ \   
                \ \  **\ \ \ \**__  \ \ \_\ \  \/_/\_\/_  \ \ \  \ \  __ \  
                \ \_\    \ \_____\  \ \_____\   /\_\/\_\  \ \_\  \ \_\ \_\ 
                \/_/     \/_____/   \/_____/   \/_/\/_/   \/_/   \/_/\/_/ 

```

Fluxia est un script permettant la présentation des configurations réseau de la machine.


## 🎯 Objectifs

L'objectif principal de **Fluxia** est pouvoir gagner du temps sur la consultation et la sauvegarde d'une configuration réseau.

La portabilité de l'outil permet une facilité de transfert entre différentes machines. 


## 🛠️ Fonctionnalités

| Fonction                          | Description |
|----------------------------------|-------------|
| 🔍 Afficher les interfaces       | Liste toutes les interfaces réseau et leurs propriétés (IP, MAC, etc.) |
| 📁 Export JSON                   | Exporte les interfaces et leurs paramètres dans un fichier JSON |
| 📡 Surveiller les modifications  | Active un mode de surveillance continue des changements d'IP, de statut, etc. |
| 🔐 Voir les ports ouverts        | Affiche les ports TCP/UDP ouverts, ainsi que les processus associés |
| ❌ Quitter                       | Ferme l’outil proprement |

## 📦 Dépendances

- Python 3.6+
- [psutil](https://pypi.org/project/psutil/) (pour la récupération des données réseau)

