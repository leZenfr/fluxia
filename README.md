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
| 📁 Charger depuis un JSON        | Charge et affiche la configuration des interfaces depuis un fichier JSON |
| 📡 Surveiller les modifications  | Active un mode de surveillance continue des changements d'IP, de statut, etc. |
| 🔐 Voir les ports ouverts        | Affiche les ports TCP/UDP ouverts, ainsi que les processus associés |

## 📖 Documentation

Vous retrouverez ci-dessous les informations utiles concernant l'utilisation de l'outil.


### 🔧 Installation

<details><summary>Kali Linux</summary>

```
git clone https://github.com/leZenfr/fluxia.git

python3 -m venv <nom>
source <nom>/bin/activate

cd fluxia
```

Installation des dépendances 
```
python ./install.py
```

### ⚙️ Utilisation

#### Pour lancer l'interface via le menu.
```
python ./app.py
```

#### Pour utiliser le tool via les arguments.

```
python ./app.py [-h] [-r FICHIER] [-w FICHIER] [-m] [-v]
```

</details>

<details><summary>Debian 12</summary>

Préparation de la machine
```
apt install git-all
apt install python3-pip
apt install python3.11-venv
```

```
git clone https://github.com/leZenfr/fluxia.git

python3 -m venv <nom>
source <nom>/bin/activate

cd fluxia
```


Installation des dépendances 
```
python ./install.py
```

### ⚙️ Utilisation

#### Pour lancer l'interface via le menu.
```
python ./app.py
```

#### Pour utiliser le tool via les arguments.

```
python ./app.py [-h] [-r FICHIER] [-w FICHIER] [-m] [-v]
```

</details>




