# AMI - Application de Messagerie Instantanée

## 📋 Description

AMI (Application de Messagerie Instantanée) est une application de chat peer-to-peer en temps réel utilisant le multicast UDP. Elle permet à plusieurs utilisateurs sur le même réseau local de communiquer instantanément avec un historique persistant SQLite.

## ✨ Fonctionnalités

### Chat en temps réel
- ✅ Messages publics visibles par tous
- ✅ Messages privés entre utilisateurs (@user message)
- ✅ Notifications de connexion/déconnexion
- ✅ Détection automatique des utilisateurs inactifs
- ✅ Mode silencieux (désactivation des notifications)

### Historique SQLite
- 📊 Sauvegarde automatique de tous les messages
- 🔍 Recherche dans l'historique (/search mot)
- 📜 Affichage des derniers messages (/history N)
- 📈 Statistiques d'utilisation (/stats)
- 📤 Export CSV pour Excel/LibreOffice (/export)

### Interface utilisateur
- 🎨 Affichage coloré (support ANSI)
- 👤 Nom d'utilisateur avec couleur unique
- ⌚ Horodatage des messages
- 📋 Liste des utilisateurs connectés
- 🖥️ Support Windows et Linux

## 🔧 Prérequis

### Linux
```bash
sudo apt-get install build-essential libsqlite3-dev
```

### Windows
- MinGW ou MinGW-w64
- SQLite3 (inclure sqlite3.h et sqlite3.lib/dll)

## 🚀 Compilation

### Avec Make (recommandé)
```bash
# Compiler
make

# Nettoyer
make clean

# Recompiler
make rebuild

# Installer (Linux uniquement)
sudo make install
```

### Compilation manuelle

#### Linux
```bash
gcc -Wall -O2 -pthread \
    AMI.c \
    -o ami.exe\
    -lsqlite3 -lpthread
```

#### Windows (MinGW)
```bash
gcc AMI.c sqlite3.c -o ami.exe -lws2_32 -Wall
```

## 📖 Utilisation

### Lancer l'application
```bash
# Linux
./build/ami

# Windows
build\ami.exe
```

### Commandes disponibles

#### Chat & Réseau
- `/aide` - Afficher l'aide
- `/liste` - Lister les utilisateurs connectés
- `@user message` - Envoyer un message privé
- `/prive user message` - Envoyer un message privé (syntaxe alternative)
- `/silence` - Activer/désactiver le mode silencieux
- `/effacer` - Effacer l'écran

#### Historique SQLite
- `/search mot` - Rechercher dans l'historique
- `/history [N]` - Afficher les N derniers messages (par défaut: 20)
- `/stats` - Afficher les statistiques
- `/export` - Exporter l'historique en CSV

#### Système
- `/infos` - Informations système
- `/quitter` ou `/exit` - Quitter le chat

## 🌐 Configuration réseau

Par défaut, AMI utilise :
- **Groupe multicast** : 224.0.0.1
- **Port** : 8888
- **TTL** : 2 (réseau local)

## 💾 Base de données

Chaque utilisateur possède sa propre base SQLite :
- **Nom** : `chat_<username>.db`
- **Emplacement** : Répertoire courant
- **Tables** : messages (id, timestamp, sender, recipient, type, content)

### Export CSV
La commande `/export` génère un fichier `chat_export_<username>.csv` compatible Excel/LibreOffice.

## 🔒 Sécurité

⚠️ **Attention** : Cette application est conçue pour les réseaux locaux de confiance.

- Les messages ne sont **pas chiffrés**
- Aucune authentification utilisateur
- Vulnérable au spoofing (usurpation d'identité)

Pour une utilisation en production, il est recommandé d'ajouter :
- Chiffrement TLS/SSL
- Authentification des utilisateurs
- Signature des messages

## 🐛 Dépannage

### Problème de multicast
Si le groupe multicast est déjà utilisé sous Windows, l'application tente automatiquement un nettoyage.

### Encodage UTF-8
Assurez-vous que votre terminal supporte UTF-8 :
```bash
# Linux
export LANG=fr_FR.UTF-8

# Windows (PowerShell)
chcp 65001
```

### Firewall
Autorisez le port UDP 8888 dans votre pare-feu.

## 📝 Licence

Ce projet est sous licence libre. Vous êtes libre de l'utiliser, le modifier et le distribuer.

**Bon chat ! 💬**
