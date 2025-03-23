import subprocess
import sys
import os

def install_requirements(requirements_file="requirements.txt"):
    if not os.path.exists(requirements_file):
        print(f"❌ Le fichier '{requirements_file}' est introuvable.")
        return

    try:
        print(f"📦 Installation des dépendances depuis {requirements_file}...\n")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", requirements_file])
        print("\n✅ Installation terminée.")
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Une erreur est survenue pendant l'installation : {e}")

if __name__ == "__main__":
    install_requirements()
