# CLAUDE.md - Règles et Instructions Projet

## 📋 Informations Générales
- **Projet** : Server Disk Monitor
- **Version actuelle** : v2.0.1
- **Type** : Dashboard de surveillance des disques durs via SSH
- **Déploiement** : Portainer Stack avec Docker

## 🔢 RÈGLE : Auto-incrémentation de Version

**À chaque `git commit` et `git push`, la version DOIT être automatiquement incrémentée selon cette convention :**

### 📊 Convention Semantic Versioning (SemVer: X.Y.Z)

#### 🔴 Version MAJEURE (X.0.0) - Breaking Changes
**Incrémenter quand :**
- Changements incompatibles de l'API
- Suppression de fonctionnalités existantes
- Modifications qui cassent la compatibilité

**Mots-clés déclencheurs :**
- `breaking`, `major`, `incompatible`, `💥`
- `api change`, `remove`, `deprecated`

#### 🟡 Version MINEURE (X.Y.0) - Nouvelles Fonctionnalités  
**Incrémenter quand :**
- Ajout de nouvelles fonctionnalités
- Améliorations significatives
- Nouvelles routes/endpoints

**Mots-clés déclencheurs :**
- `✨`, `feat:`, `feature:`, `add`, `new`
- `implement`, `fonctionnalité`, `ajouter`

#### 🟢 Version PATCH (X.Y.Z) - Corrections et Améliorations
**Incrémenter quand :**
- Corrections de bugs
- Améliorations mineures
- Optimisations de performance
- **PAR DÉFAUT** si aucun autre type détecté

**Mots-clés déclencheurs :**
- `🐛`, `🔧`, `⚡`, `🚨`, `fix:`, `bug:`
- `hotfix:`, `patch:`, `improve:`, `update:`

### 🤖 Processus Automatique Claude

**À chaque commit, Claude DOIT :**

1. **Analyser le message de commit** pour déterminer le type d'incrémentation
2. **Modifier app.py** pour mettre à jour :
   - `VERSION = "X.Y.Z"` (nouvelle version)
   - `BUILD_DATE = "YYYY-MM-DD"` (date du jour)
3. **Inclure dans le commit** le fichier app.py modifié
4. **Ajouter au message** les informations de version

### 📝 Format de Commit Enrichi

```
[MESSAGE ORIGINAL]

🔢 Version: vX.Y.Z (patch/minor/major)
📅 Build: YYYY-MM-DD

🤖 Generated with [Claude Code](https://claude.ai/code)

Co-Authored-By: Claude <noreply@anthropic.com>
```

### 📋 Exemples Pratiques

```bash
# Message original → Type → Version
"🐛 Fix password saving issue"          → PATCH → 2.0.1 → 2.0.2
"✨ Add new dashboard widget"            → MINOR → 2.0.2 → 2.1.0  
"💥 Breaking: Change API endpoints"     → MAJOR → 2.1.0 → 3.0.0
"🔧 Improve SSH connection handling"    → PATCH → 3.0.0 → 3.0.1
```

## 🎯 Autres Règles Projet

### 🐳 Déploiement
- **Portainer Stack** : Utilise docker-compose.yml
- **Volume persistant** : `/app/data` pour la configuration
- **GitHub Actions** : Build automatique des images Docker

### 🔒 Sécurité
- **Mots de passe chiffrés** : Cryptography.fernet
- **Validation des données** : Éviter les injections
- **Pool SSH** : Connexions réutilisables et sécurisées

### 🎨 Interface
- **Version visible** : Badge dans le header avec VERSION du app.py
- **Temps réel** : WebSocket pour les mises à jour
- **Responsive** : Design adaptatif

### 📁 Structure Fichiers
- `app.py` : Application principale avec VERSION et BUILD_DATE
- `templates/index.html` : Interface utilisateur
- `data/config.json` : Configuration serveurs (persistant)
- `docker-compose.yml` : Configuration Portainer

## ✅ Workflow Standard

1. **Modification du code**
2. **Commit avec message descriptif**
3. **Claude incrémente automatiquement la version**
4. **Push vers GitHub** 
5. **GitHub Actions build nouvelle image**
6. **Redéploiement Portainer** avec nouvelle version visible

---

**⚠️ IMPORTANT :** Cette règle est OBLIGATOIRE pour TOUS les commits du projet.