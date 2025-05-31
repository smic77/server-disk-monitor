# Server Disk Monitor - Version Web

Dashboard web pour la surveillance des disques durs sur serveurs distants, accessible depuis n'importe quel PC du réseau local et déployable dans Portainer.

## 🚀 Fonctionnalités

- **Interface Web Moderne** : Dashboard responsive accessible via navigateur
- **Temps Réel** : Mise à jour automatique via WebSocket
- **Multi-Serveurs** : Surveillance de plusieurs serveurs simultanément
- **Configuration Flexible** : Racks configurables (lignes × colonnes)
- **Sécurité** : Chiffrement des mots de passe
- **Persistance** : Configuration sauvegardée dans volumes Docker
- **Déploiement Facile** : Compatible Portainer Stack

## 📋 Prérequis

- Docker et Docker Compose
- Portainer (optionnel mais recommandé)
- Accès SSH aux serveurs à surveiller
- `sshpass` installé sur les serveurs cibles

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
2. **Configurer les serveurs** :
   - Cliquer sur "⚙️ Configuration"
   - La configuration se fait actuellement via import/export JSON
3. **Définir les mots de passe** :
   - Cliquer sur "🔐 Mots de passe"
   - Entrer les mots de passe SSH pour chaque serveur

### Format de Configuration JSON

```json
{
  "servers": {
    "SERVER-01": {
      "ip": "192.168.1.10",
      "username": "admin",
      "front_rack": {
        "enabled": true,
        "rows": 3,
        "cols": 4,
        "total_slots": 12
      },
      "back_rack": {
        "enabled": true,
        "rows": 2,
        "cols": 2,
        "total_slots": 4
      },
      "disk_mappings": {
        "front_0_0": {
          "uuid": "550e8400-e29b-41d4-a716-446655440001",
          "device": "/dev/sda",
          "label": "OS Principal",
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
- **Racks Visuels** : Représentation graphique des faces avant/arrière
- **Codes Couleur** :
  - 🟢 **Vert** : Disque monté et fonctionnel
  - 🟠 **Orange** : Disque détecté mais non monté
  - 🔴 **Rouge** : Disque non détecté ou serveur hors ligne
  - ⚫ **Gris** : Slot vide

### Interactions

- **Clic sur un disque** : Affiche les détails complets
- **Actualisation** : Bouton de refresh manuel
- **Export/Import** : Sauvegarde et restauration de configuration

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
├── config.json        # Configuration des serveurs
└── cipher.key         # Clé de chiffrement des mots de passe
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

### Chiffrement des Mots de Passe

- Tous les mots de passe sont chiffrés avec `cryptography.fernet`
- La clé de chiffrement est générée automatiquement et stockée de manière sécurisée
- Les mots de passe ne sont jamais stockés en clair

### Recommandations

1. **Utilisez des clés SSH** plutôt que des mots de passe
2. **Configurez un reverse proxy** avec HTTPS en production
3. **Limitez l'accès réseau** au dashboard
4. **Sauvegardez régulièrement** le volume de données

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

- `GET /api/status` : État global du système
- `GET /api/config` : Configuration actuelle
- `POST /api/config` : Mise à jour de configuration
- `POST /api/refresh` : Actualisation manuelle
- `POST /api/server/{name}/password` : Mise à jour mot de passe

### WebSocket Events

- `disk_status_update` : Mise à jour des statuts
- `request_refresh` : Demande d'actualisation
- `connect/disconnect` : Gestion des connexions

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

### Logs et Debug

```bash
# Logs du conteneur
docker logs -f server-disk-monitor

# Accès au conteneur
docker exec -it server-disk-monitor /bin/bash

# Vérification des volumes
docker volume inspect disk_monitor_config
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
- **Alertes email/Slack** en cas de problème
- **Métriques avancées** (SMART, température, etc.)
- **API REST** étendue pour intégrations
- **Thèmes personnalisables**
- **Multi-utilisateurs** avec authentification

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

### Communauté

- Issues GitHub pour les bugs
- Discussions pour les suggestions
- Wiki pour la documentation collaborative

## 📝 Licence

Ce projet est sous licence MIT. Libre d'utilisation, modification et distribution.

---

## 🎯 Avantages par rapport à la Version Desktop

| Critère | Version Desktop (Tkinter) | Version Web |
|---------|---------------------------|-------------|
| **Accessibilité** | Un seul poste | Tout le réseau |
| **Déploiement** | Installation sur chaque PC | Conteneur unique |
| **Maintenance** | Mise à jour individuelle | Mise à jour centralisée |
| **Portabilité** | OS spécifique | Cross-platform |
| **Collaboration** | Usage individuel | Multi-utilisateurs |
| **Intégration** | Limitée | API + WebSocket |
| **Scalabilité** | Non scalable | Scalable horizontalement |
| **Monitoring** | Local uniquement | Surveillance centralisée |

La version web offre une solution moderne, scalable et accessible qui répond parfaitement aux besoins d'infrastructure réseau et s'intègre naturellement dans un environnement Portainer.