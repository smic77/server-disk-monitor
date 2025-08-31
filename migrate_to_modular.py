#!/usr/bin/env python3
"""
Script de migration vers la version modulaire
Permet de passer de l'ancien app.py vers la version refactorisée
"""

import os
import shutil
import sys
from datetime import datetime

def backup_current_version():
    """Sauvegarde la version actuelle"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = f"backup_{timestamp}"
    
    print(f"📦 Création de la sauvegarde dans {backup_dir}/")
    os.makedirs(backup_dir, exist_ok=True)
    
    # Sauvegarder les fichiers importants
    files_to_backup = [
        'app.py',
        'data/config.json',
        'data/notifications.json', 
        'data/cipher.key'
    ]
    
    for file_path in files_to_backup:
        if os.path.exists(file_path):
            shutil.copy2(file_path, backup_dir)
            print(f"✅ {file_path} sauvegardé")
        else:
            print(f"⚠️  {file_path} non trouvé (ignoré)")
    
    return backup_dir

def migrate_to_modular():
    """Migration vers la version modulaire"""
    print("🔄 Début de la migration vers la version modulaire...")
    
    # 1. Sauvegarde
    backup_dir = backup_current_version()
    
    # 2. Vérifier que les modules existent
    if not os.path.exists('modules/__init__.py'):
        print("❌ Erreur: Les modules ne sont pas présents")
        print("   Assurez-vous que les dossiers 'modules/' existe avec les fichiers:")
        print("   - modules/__init__.py")
        print("   - modules/config_manager.py") 
        print("   - modules/notifications.py")
        print("   - modules/server_monitor.py")
        return False
    
    # 3. Vérifier que app_refactored.py existe
    if not os.path.exists('app_refactored.py'):
        print("❌ Erreur: app_refactored.py n'existe pas")
        return False
    
    # 4. Renommer l'ancien app.py
    if os.path.exists('app.py'):
        shutil.move('app.py', 'app_legacy.py')
        print("📄 app.py renommé en app_legacy.py")
    
    # 5. Activer la nouvelle version
    shutil.copy2('app_refactored.py', 'app.py')
    print("📄 app_refactored.py copié vers app.py")
    
    # 6. Tester la compatibilité des données
    print("🧪 Test de compatibilité des données...")
    try:
        sys.path.insert(0, '.')
        from modules.config_manager import ConfigManager
        from modules.notifications import NotificationManager
        
        # Test chargement config
        config_mgr = ConfigManager()
        config = config_mgr.load_config()
        print(f"✅ Configuration chargée: {len(config.get('servers', {}))} serveur(s)")
        
        # Test notifications
        notif_mgr = NotificationManager(cipher=config_mgr.cipher)
        print("✅ Gestionnaire de notifications initialisé")
        
    except Exception as e:
        print(f"❌ Erreur test compatibilité: {e}")
        print("🔄 Restauration de la version précédente...")
        
        # Restaurer l'ancienne version
        shutil.copy2('app_legacy.py', 'app.py')
        print("⚠️  Migration annulée, ancienne version restaurée")
        return False
    
    print("")
    print("🎉 === MIGRATION RÉUSSIE ===")
    print(f"✅ Sauvegarde créée dans: {backup_dir}/")
    print("✅ Version modulaire activée")
    print("✅ Données existantes compatibles")
    print("")
    print("📋 Prochaines étapes:")
    print("   1. Tester l'application: docker-compose up -d")
    print("   2. Vérifier les logs: docker logs server-disk-monitor")
    print("   3. Accéder à l'interface: http://localhost:5000")
    print("   4. Si tout fonctionne, supprimer app_legacy.py")
    print("")
    print("🔧 Structure modulaire:")
    print("   📁 modules/")
    print("     ├── __init__.py")
    print("     ├── config_manager.py     # Gestion configuration")
    print("     ├── notifications.py      # Notifications Telegram")  
    print("     └── server_monitor.py     # Monitoring SSH")
    print("   📄 app.py                   # Application principale")
    
    return True

def rollback():
    """Revenir à la version précédente"""
    if not os.path.exists('app_legacy.py'):
        print("❌ Impossible de revenir en arrière: app_legacy.py non trouvé")
        return False
    
    print("🔄 Retour à la version précédente...")
    shutil.copy2('app_legacy.py', 'app.py')
    print("✅ Version précédente restaurée")
    return True

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "rollback":
        rollback()
    else:
        migrate_to_modular()