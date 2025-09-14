# Server Disk Monitor - Version Web avec Notifications

Dashboard web pour la surveillance des disques durs sur serveurs distants, accessible depuis n'importe quel PC du réseau local et déployable dans Portainer. **Nouveauté : Notifications Telegram en temps réel !**

## 🚀 Fonctionnalités

- **Interface Web Moderne** : Dashboard responsive accessible via navigateur
- **Temps Réel** : Mise à jour automatique via WebSocket
- **Multi-Serveurs** : Surveillance de plusieurs serveurs simultanément
- **Configuration Flexible** : Sections personnalisables avec grilles configurables
- **Sécurité** : Chiffrement des mots de passe
- **Persistance** : Configuration sauvegardée dans volumes Docker
- **Déploiement Facile** : Compatible Portainer Stack
- **🆕 Notifications Telegram** : Alertes instantanées des changements d'état
- **🆕 Détection Intelligente** : Surveillance des déconnexions/reconnexions de disques
- **🆕 Indicateurs Visuels SSH** : Statut des mots de passe SSH sur les fiches serveurs
- **🆕 Réorganisation Serveurs** : Modification de l'ordre d'affichage par glisser-déposer
- **🆕 Interface Moderne** : Boutons d'action colorés avec icônes SVG cohérentes
- **🆕 Thèmes Adaptatifs** : Contraste optimisé pour les modes sombre et clair

## 📢 Système de Notifications Telegram

### Fonctionnalités des Notifications

- **Alertes en Temps Réel** : Notification immédiate lors de changements d'état
- **Types d'Alertes Disques** :
  - 🚨 **Disque disparu** : Détection immédiate d'une déconnexion
  - ❌ **Disque démonté** : Notification si un disque se démonte
  - ✅ **Disque remonté** : Confirmation du remontage
  - 🔄 **Disque réapparu** : Notification de reconnexion
- **🆕 Types d'Alertes Serveurs** :
  - 🔴 **Serveur hors ligne** : Notification immédiate si un serveur devient inaccessible
  - 🟢 **Serveur en ligne** : Confirmation du retour en ligne d'un serveur
- **Multi-Destinataires** : Envoi vers plusieurs chats Telegram
- **Configuration Simple** : Interface web intuitive
- **Messages Enrichis** : Informations détaillées (serveur, IP, position, etc.)
- **Test Intégré** : Fonction de test pour vérifier la configuration

### Configuration des Notifications

#### Étape 1 : Créer un Bot Telegram

1. **Contacter @BotFather** sur Telegram
2. **Créer un nouveau bot** : `/newbot`
3. **Choisir un nom** pour votre bot
4. **Récupérer le token** : `123456789:ABCdefGHIjklMNOpqr...`

#### Étape 2 : Obtenir les Chat IDs

1. **Pour un chat personnel** :
   - Envoyer `/start` à @userinfobot
   - Noter votre Chat ID (ex: `123456789`)

2. **Pour un groupe** :
   - Ajouter @userinfobot au groupe
   - Envoyer `/start` dans le groupe
   - Noter le Chat ID du groupe (ex: `-987654321`)

#### Étape 3 : Configuration dans l'Interface

1. **Accéder au Dashboard** : `http://votre-serveur:5000`
2. **Cliquer sur "📢 Notifications"**
3. **Activer Telegram** : Cocher la case
4. **Saisir le Token** : Coller le token de @BotFather
5. **Ajouter les Chat IDs** : Un par ligne
6. **Tester** : Utiliser le bouton "🧪 Test"
7. **Sauvegarder** : Confirmer la configuration

### Exemple de Messages Telegram

**Alerte Disque :**
```
🚨 Server Disk Monitor - ALERTE

Serveur: PROD-SERVER-01
IP: 192.168.1.100
Position: FRONT-2-3
Disque: Stockage Données

Changement détecté:
🚨 DISQUE DISPARU: Stockage Données

Timestamp: 2025-01-15 14:30:15
```

**🆕 Alerte Serveur :**
```
🔴 Server Disk Monitor - ALERTE SERVEUR

Serveur: PROD-SERVER-01
IP: 192.168.1.100
Nouveau statut: HORS LIGNE

Description:
Le serveur ne répond plus aux requêtes ping.

Timestamp: 2025-01-15 14:25:42
```

## 📋 Prérequis

- Docker et Docker Compose
- Portainer (optionnel mais recommandé)
- Accès SSH aux serveurs à surveiller
- `sshpass` installé sur les serveurs cibles
- **Nouveau** : Bot Telegram (optionnel, pour les notifications)

## 🔧 Installation et Déploiement

### Option 1: Déploiement via Portainer Stack (Recommandé)

1. **Préparer les fichiers** :
   ```bash
   mkdir server-disk-monitor
   cd server-disk-monitor
   ```

2. **Créer la structure** :
   ```
   server-disk-monitor/
   ├── Dockerfile
   ├── requirements.txt
   ├── app.py
   ├── templates/
   │   └── index.html
   ├── data/              # Sera créé automatiquement
   └── ssh_keys/          # Optionnel
   ```

3. **Construire l'image** :
   ```bash
   docker build -t server-disk-monitor:latest .
   ```

4. **Déployer dans Portainer** :
   - Aller dans Portainer > Stacks
   - Cliquer "Add Stack"
   - Nommer la stack : `server-disk-monitor`
   - Copier le contenu du fichier `portainer-stack.yml`
   - Configurer les variables d'environnement :
     ```
     MONITOR_PORT=5000
     TIMEZONE=Europe/Paris
     DOMAIN=disk-monitor.local
     REFRESH_INTERVAL=30
     ```
   - Déployer la stack

### Option 2: Déploiement via Docker Compose

1. **Cloner et builder** :
   ```bash
   git clone <votre-repo>
   cd server-disk-monitor
   docker-compose build
   ```

2. **Lancer les services** :
   ```bash
   docker-compose up -d
   ```

### Option 3: Déploiement Direct Docker

```bash
# Construction de l'image
docker build -t server-disk-monitor .

# Lancement du conteneur
docker run -d \
  --name server-disk-monitor \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/ssh_keys:/root/.ssh:ro \
  --restart unless-stopped \
  server-disk-monitor:latest
```

## 🌐 Accès à l'Application

Une fois déployée, l'application est accessible via :

- **URL Locale** : `http://localhost:5000`
- **URL Réseau** : `http://[IP-DU-SERVEUR]:5000`
- **Avec Reverse Proxy** : `http://disk-monitor.local` (si configuré)

## ⚙️ Configuration Initiale

1. **Accéder à l'interface web**
2. **Ajouter un serveur** :
   - Cliquer sur "➕ Ajouter Serveur"
   - Entrer le nom, IP et nom d'utilisateur SSH
3. **Configurer les sections** :
   - Cliquer sur "➕ Ajouter Section" dans chaque serveur
   - Définir le nom, dimensions et orientation de chaque section
4. **Configurer les disques** :
   - Cliquer sur "⚙️ Configurer" dans chaque section
   - Remplir UUID, device, label, numéro de série, description et capacité
5. **Définir les mots de passe** :
   - Cliquer sur "🔐 Mots de passe"
   - Entrer les mots de passe SSH pour chaque serveur
6. **🆕 Configurer les notifications** :
   - Cliquer sur "📢 Notifications"
   - Activer Telegram et configurer le bot

### Format de Configuration JSON

```json
{
  "servers": {
    "SERVER-01": {
      "ip": "192.168.1.10",
      "username": "admin",
      "sections": [
        {
          "name": "Section principale",
          "rows": 3,
          "cols": 4,
          "orientation": "horizontal"
        },
        {
          "name": "Section stockage",
          "rows": 2,
          "cols": 6,
          "orientation": "vertical"
        }
      ],
      "disk_mappings": {
        "s0_0_0": {
          "uuid": "550e8400-e29b-41d4-a716-446655440001",
          "device": "/dev/sda",
          "label": "OS Principal",
          "serial": "WD123456789",
          "description": "Disque système Ubuntu Server",
          "capacity": "500GB SSD"
        }
      }
    }
  },
  "refresh_interval": 30
}
```

## 📊 Utilisation

### Dashboard Principal

- **Statistiques Globales** : Vue d'ensemble des serveurs et disques
- **Cartes Serveurs** : Affichage en temps réel de l'état de chaque serveur
- **Sections Configurables** : Grilles personnalisables par section
- **Informations Détaillées** : Numéro de série, capacité, position discrète
- **🆕 Bouton Notifications** : Configuration des alertes Telegram
- **Codes Couleur** :
  - 🟢 **Vert** : Disque monté et fonctionnel
  - 🟠 **Orange** : Disque détecté mais non monté
  - 🔴 **Rouge** : Disque non détecté ou serveur hors ligne
  - ⚫ **Gris** : Slot vide
- **Thèmes** : Mode sombre et mode clair avec lisibilité optimisée

### Interactions

- **Clic sur un disque** : Affiche les détails complets avec numéro de série
- **Configuration par section** : Boutons "⚙️ Configurer" spécifiques
- **Ajout de sections** : Boutons "➕" pour créer de nouvelles sections
- **Actualisation** : Bouton de refresh manuel
- **Export/Import** : Sauvegarde et restauration de configuration
- **🆕 Test Notifications** : Vérification des alertes Telegram
- **🆕 Indicateurs SSH** : Statut visuel des mots de passe SSH (🔒 configuré / 🔓 manquant)
- **🆕 Réorganisation** : Bouton ↕️ pour modifier l'ordre d'affichage des serveurs
- **🆕 Menu d'Actions** : 8 boutons colorés avec icônes SVG uniformes et lisibles
- **Basculement de thème** : Mode sombre/clair adaptatif

## 🔧 Configuration Avancée

### Variables d'Environnement

```bash
# Port d'écoute
MONITOR_PORT=5000

# Fuseau horaire
TIMEZONE=Europe/Paris

# Intervalle de rafraîchissement (secondes)
REFRESH_INTERVAL=30

# Domaine pour reverse proxy
DOMAIN=disk-monitor.local

# Chemin vers les clés SSH
SSH_KEYS_PATH=./ssh_keys
```

### Persistence des Données

Les données sont automatiquement persistées dans le volume `/app/data` :

```
data/
├── config.json           # Configuration des serveurs
├── cipher.key            # Clé de chiffrement des mots de passe
└── notifications.json    # 🆕 Configuration des notifications
```

### Configuration SSH

Pour une sécurité optimale, vous pouvez utiliser des clés SSH :

1. **Créer le répertoire** :
   ```bash
   mkdir ssh_keys
   chmod 700 ssh_keys
   ```

2. **Copier vos clés** :
   ```bash
   cp ~/.ssh/id_rsa ssh_keys/
   cp ~/.ssh/id_rsa.pub ssh_keys/
   chmod 600 ssh_keys/*
   ```

3. **Configurer le conteneur** pour monter les clés

### Reverse Proxy avec Nginx

Si vous n'utilisez pas Traefik, voici une configuration Nginx :

```nginx
# nginx.conf
events {
    worker_connections 1024;
}

http {
    upstream disk_monitor {
        server disk-monitor:5000;
    }

    server {
        listen 80;
        server_name disk-monitor.local;

        location / {
            proxy_pass http://disk_monitor;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location /socket.io/ {
            proxy_pass http://disk_monitor;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
    }
}
```

## 🔒 Sécurité

### Chiffrement des Mots de Passe et Tokens

- Tous les mots de passe SSH sont chiffrés avec `cryptography.fernet`
- **🆕 Les tokens Telegram sont également chiffrés**
- La clé de chiffrement est générée automatiquement et stockée de manière sécurisée
- Aucune donnée sensible n'est stockée en clair

### Recommandations

1. **Utilisez des clés SSH** plutôt que des mots de passe
2. **Configurez un reverse proxy** avec HTTPS en production
3. **Limitez l'accès réseau** au dashboard
4. **Sauvegardez régulièrement** le volume de données
5. **🆕 Protégez votre token Telegram** : ne le partagez jamais
6. **🆕 Utilisez des groupes privés** pour les notifications sensibles

## 📱 Responsive Design

L'interface s'adapte automatiquement :

- **Desktop** : Vue complète avec grilles détaillées
- **Tablet** : Layout optimisé pour écrans moyens
- **Mobile** : Interface simplifiée avec navigation tactile

## 🚨 Surveillance et Alertes

### Health Checks

Le conteneur inclut un health check automatique :

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:5000/api/status"]
  interval: 30s
  timeout: 10s
  retries: 3
```

### API Endpoints

#### Endpoints Existants
- `GET /api/status` : État global du système
- `GET /api/config` : Configuration actuelle
- `POST /api/config` : Mise à jour de configuration
- `POST /api/refresh` : Actualisation manuelle
- `POST /api/server/{name}/password` : Mise à jour mot de passe

#### 🆕 Nouveaux Endpoints pour Notifications
- `GET /api/notifications/config` : Configuration des notifications
- `POST /api/notifications/config` : Mise à jour de la config notifications
- `POST /api/notifications/test` : Test d'envoi de notification

### WebSocket Events

- `disk_status_update` : Mise à jour des statuts
- `request_refresh` : Demande d'actualisation
- `connect/disconnect` : Gestion des connexions

### 🆕 Logique de Détection des Changements

Le système surveille automatiquement :

1. **États précédents** : Stockage de l'état de chaque disque ET serveur
2. **Comparaison** : Détection des changements à chaque scan (30 secondes par défaut)
3. **Classification** : Types d'alertes selon le changement détecté
4. **Notification** : Envoi immédiat si changement critique
5. **🆕 Surveillance serveurs** : Détection ping/perte de connectivité réseau

## 🔧 Dépannage

### Problèmes Courants

1. **Conteneur ne démarre pas** :
   ```bash
   docker logs server-disk-monitor
   ```

2. **Connexion SSH échoue** :
   - Vérifier les credentials
   - Tester la connectivité réseau
   - Vérifier que `sshpass` est installé

3. **Interface inaccessible** :
   - Vérifier le port 5000
   - Contrôler les règles firewall
   - Vérifier les logs du conteneur

4. **Données perdues** :
   - Vérifier le montage du volume `/app/data`
   - Sauvegarder la configuration via export

5. **🆕 Notifications Telegram ne fonctionnent pas** :
   - Vérifier le token du bot avec @BotFather
   - Confirmer les Chat IDs avec @userinfobot
   - Tester la connectivité réseau (port 443 HTTPS)
   - Vérifier les logs : `docker logs server-disk-monitor | grep -i telegram`

### Logs et Debug

```bash
# Logs du conteneur
docker logs -f server-disk-monitor

# Filtrer les logs de notifications
docker logs server-disk-monitor | grep -i notification

# Accès au conteneur
docker exec -it server-disk-monitor /bin/bash

# Vérification des volumes
docker volume inspect disk_monitor_config
```

### 🆕 Debug des Notifications

```bash
# Test manuel depuis le conteneur
docker exec -it server-disk-monitor python3 -c "
import requests
response = requests.post('https://api.telegram.org/bot<YOUR_TOKEN>/getMe')
print(response.json())
"

# Vérification des fichiers de config
docker exec -it server-disk-monitor cat /app/data/notifications.json
```

## 🔄 Mise à Jour

### Via Portainer

1. Aller dans la stack
2. Cliquer "Update the stack"
3. Rebuild l'image si nécessaire
4. Redéployer

### Via Docker Compose

```bash
# Arrêter les services
docker-compose down

# Rebuilder l'image
docker-compose build --no-cache

# Relancer
docker-compose up -d
```

## 📈 Évolutions Futures

### Fonctionnalités Prévues

- **Éditeur de configuration graphique** complet
- **Alertes email/Slack** en plus de Telegram
- **Métriques avancées** (SMART, température, etc.)
- **API REST** étendue pour intégrations
- **Thèmes personnalisables**
- **Multi-utilisateurs** avec authentification
- **🆕 Notifications Discord/Teams** : Autres plateformes de messagerie
- **🆕 Seuils personnalisables** : Alertes basées sur des métriques
- **🆕 Historique des alertes** : Journal des notifications envoyées

### Contributions

Le projet est open source. Les contributions sont les bienvenues :

1. Fork du projet
2. Créer une branche feature
3. Commit des modifications
4. Push et création d'une PR

## 📞 Support

### Documentation

- Configuration : Voir exemples JSON fournis
- API : Documentation Swagger disponible sur `/api/docs`
- WebSocket : Events listés dans la section surveillance
- **🆕 Notifications** : Guide complet dans cette documentation

### Communauté

- Issues GitHub pour les bugs
- Discussions pour les suggestions
- Wiki pour la documentation collaborative

### 🆕 Support Telegram

Pour le support des notifications Telegram :
1. Vérifier la [documentation officielle de l'API Telegram](https://core.telegram.org/bots/api)
2. Tester avec @BotFather pour valider le token
3. Utiliser @userinfobot pour confirmer les Chat IDs

## 📝 Licence

Ce projet est sous licence MIT. Libre d'utilisation, modification et distribution.

---

## 🎯 Avantages par rapport à la Version Desktop

| Critère | Version Desktop (Tkinter) | Version Web avec Notifications |
|---------|---------------------------|--------------------------------|
| **Accessibilité** | Un seul poste | Tout le réseau |
| **Déploiement** | Installation sur chaque PC | Conteneur unique |
| **Maintenance** | Mise à jour individuelle | Mise à jour centralisée |
| **Portabilité** | OS spécifique | Cross-platform |
| **Collaboration** | Usage individuel | Multi-utilisateurs |
| **Intégration** | Limitée | API + WebSocket |
| **Scalabilité** | Non scalable | Scalable horizontalement |
| **Monitoring** | Local uniquement | Surveillance centralisée |
| **🆕 Alertes** | Aucune | **Telegram en temps réel** |
| **🆕 Mobilité** | Bureau uniquement | **Notifications mobiles** |

## 🌟 Nouveautés de cette Version

### ✨ Fonctionnalités Ajoutées

- **📢 Bouton Notifications** dans l'interface
- **🤖 Intégration Telegram Bot API** complète
- **🔔 Alertes en Temps Réel** pour les changements d'état
- **🖥️ Notifications Serveurs** : Alertes hors ligne/en ligne
- **💾 Notifications Disques** : Alertes montage/démontage
- **🧪 Fonction de Test** intégrée
- **🔐 Chiffrement des Tokens** pour la sécurité
- **📱 Support Multi-Chat** (personnel + groupes)
- **🎨 Interface Responsive** améliorée avec thèmes optimisés
- **📊 Statistiques Notifications** dans le dashboard
- **⚙️ Système de sections** : Configuration flexible par sections nommées
- **🔢 Numéros de série** : Suivi détaillé des disques
- **🎯 Positions discrètes** : Numérotation compacte et claire
- **🌗 Thème clair amélioré** : Lisibilité et contraste optimisés

### 🛠️ Améliorations Techniques

- **Cache Intelligent** : Évite les faux positifs
- **Gestion d'Erreurs** : Robustesse accrue
- **Logs Détaillés** : Debug facilité
- **API RESTful** : Endpoints pour notifications
- **Persistance** : Configuration sauvegardée automatiquement

La version web avec notifications offre une solution complète, moderne et alertes en temps réel qui répond parfaitement aux besoins d'infrastructure réseau critique et s'intègre naturellement dans un environnement Portainer tout en gardant les équipes informées 24/7.