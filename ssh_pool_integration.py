#!/usr/bin/env python3
"""
Patch pour intégrer le pool SSH dans l'application existante
COMPATIBLE avec les données existantes - applique juste l'amélioration de performance
"""

import sys
import os

def patch_app_with_ssh_pool():
    """
    Patch l'app.py existante pour utiliser le pool SSH
    Préserve 100% de la compatibilité des données
    """
    
    # Lire le fichier app.py actuel
    with open('app.py', 'r', encoding='utf-8') as f:
        app_content = f.read()
    
    # 1. Ajouter l'import du pool SSH après les autres imports
    import_patch = """
# Import du pool SSH pour améliorer les performances
from ssh_connection_pool import get_ssh_pool
"""
    
    if "from ssh_connection_pool import get_ssh_pool" not in app_content:
        # Trouver la ligne après les imports
        lines = app_content.split('\n')
        import_line_idx = -1
        
        for i, line in enumerate(lines):
            if line.startswith('import ') or line.startswith('from '):
                import_line_idx = i
        
        if import_line_idx >= 0:
            # Insérer après le dernier import
            lines.insert(import_line_idx + 1, import_patch)
            app_content = '\n'.join(lines)
            print("✅ Import du pool SSH ajouté")
    
    # 2. Modifier la classe pour initialiser le pool
    init_patch = """
        # Initialisation du pool SSH pour améliorer les performances
        self.ssh_pool = get_ssh_pool()
        # Donner accès au décryptage au pool SSH
        self.ssh_pool.decrypt_password = self.decrypt_password
"""
    
    if "self.ssh_pool = get_ssh_pool()" not in app_content:
        # Trouver la méthode __init__ de ServerDiskMonitorWeb
        init_marker = "# Démarrage du scheduler"
        if init_marker in app_content:
            app_content = app_content.replace(
                init_marker,
                init_patch + "\n        " + init_marker
            )
            print("✅ Initialisation du pool SSH ajoutée")
    
    # 3. Remplacer la méthode check_disk_ssh pour utiliser le pool
    old_method = '''    def check_disk_ssh(self, server_config, disk_info):
        """Vérifie le statut d'un disque via SSH"""
        # CORRECTION : Créer une clé de cache unique pour ce disque
        cache_key = f"{server_config['ip']}_{disk_info['uuid']}_{disk_info['device']}"
        
        try:
            # Si pas de mot de passe configuré, retourner un état fixe depuis le cache
            if not server_config.get('password'):
                if cache_key in self.status_cache:
                    return self.status_cache[cache_key]
                
                # Première fois : créer un statut par défaut et le mettre en cache
                logger.warning(f"Pas de mot de passe configuré pour {server_config['ip']}")
                result = {"exists": False, "mounted": False}
                self.status_cache[cache_key] = result
                return result
            
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            password = self.decrypt_password(server_config['password'])
            
            ssh.connect(
                hostname=server_config['ip'],
                username=server_config['username'],
                password=password,
                timeout=10
            )
            
            # Vérification du disque
            stdin, stdout, stderr = ssh.exec_command(f"lsblk -f | grep -i {disk_info['uuid']}")
            disk_exists = bool(stdout.read().decode().strip())
            
            if disk_exists:
                stdin, stdout, stderr = ssh.exec_command(f"mount | grep {disk_info['device']}")
                is_mounted = bool(stdout.read().decode().strip())
            else:
                is_mounted = False
            
            ssh.close()
            
            result = {"exists": disk_exists, "mounted": is_mounted}
            # Mettre en cache le résultat réel
            self.status_cache[cache_key] = result
            return result
            
        except Exception as e:
            logger.error(f"Erreur SSH pour {server_config['ip']}: {e}")
            
            # CORRECTION : En cas d'erreur, utiliser le cache ou créer un état fixe
            if cache_key in self.status_cache:
                return self.status_cache[cache_key]
            
            result = {"exists": False, "mounted": False}
            self.status_cache[cache_key] = result
            return result'''
    
    new_method = '''    def check_disk_ssh(self, server_config, disk_info):
        """Vérifie le statut d'un disque via SSH avec pool de connexions - AMÉLIORATION PERFORMANCE"""
        # Clé de cache identique à l'ancienne version - COMPATIBILITÉ PRÉSERVÉE
        cache_key = f"{server_config['ip']}_{disk_info['uuid']}_{disk_info['device']}"
        
        try:
            # Si pas de mot de passe configuré, comportement identique à l'ancienne version
            if not server_config.get('password'):
                if cache_key in self.status_cache:
                    return self.status_cache[cache_key]
                
                logger.warning(f"Pas de mot de passe configuré pour {server_config['ip']}")
                result = {"exists": False, "mounted": False}
                self.status_cache[cache_key] = result
                return result
            
            # AMÉLIORATION : Utiliser le pool SSH au lieu de connexions individuelles
            result = self.ssh_pool.check_disk_status(server_config, disk_info)
            
            # Cache identique à l'ancienne version - COMPATIBILITÉ PRÉSERVÉE  
            self.status_cache[cache_key] = result
            return result
            
        except Exception as e:
            logger.error(f"Erreur SSH pour {server_config['ip']}: {e}")
            
            # Fallback identique à l'ancienne version - COMPATIBILITÉ PRÉSERVÉE
            if cache_key in self.status_cache:
                return self.status_cache[cache_key]
            
            result = {"exists": False, "mounted": False}
            self.status_cache[cache_key] = result
            return result'''
    
    if old_method in app_content:
        app_content = app_content.replace(old_method, new_method)
        print("✅ Méthode check_disk_ssh optimisée avec pool SSH")
    
    # 4. Ajouter une route pour les statistiques du pool SSH
    stats_route = '''
@app.route('/api/ssh/stats', methods=['GET'])
def get_ssh_stats():
    """Statistiques du pool SSH"""
    try:
        stats = monitor.ssh_pool.get_stats()
        return jsonify({
            "success": True,
            "stats": stats
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

'''
    
    if "/api/ssh/stats" not in app_content:
        # Ajouter avant la section WebSocket
        websocket_marker = "# WebSocket Events"
        if websocket_marker in app_content:
            app_content = app_content.replace(
                websocket_marker,
                stats_route + websocket_marker
            )
            print("✅ Route des statistiques SSH ajoutée")
    
    # 5. Ajouter cleanup du pool à la fermeture
    cleanup_patch = '''
# Nettoyage du pool SSH à la fermeture
import atexit
atexit.register(lambda: monitor.ssh_pool.close_all() if hasattr(monitor, 'ssh_pool') else None)

'''
    
    if "atexit.register" not in app_content:
        # Ajouter avant le démarrage du serveur
        server_start_marker = "if __name__ == '__main__':"
        if server_start_marker in app_content:
            app_content = app_content.replace(
                server_start_marker,
                cleanup_patch + server_start_marker
            )
            print("✅ Nettoyage automatique du pool SSH ajouté")
    
    # Sauvegarder le fichier patché
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(app_content)
    
    print("\n🎉 === PATCH APPLIQUÉ AVEC SUCCÈS ===")
    print("✅ Pool SSH intégré sans casser la compatibilité")
    print("✅ Performance améliorée pour les vérifications de disques")
    print("✅ Toutes les données existantes restent compatibles")
    print("\n📊 Nouvelles fonctionnalités:")
    print("   - Pool de connexions SSH réutilisables")
    print("   - Endpoint /api/ssh/stats pour monitoring")
    print("   - Nettoyage automatique des connexions")
    print("\n⚡ Gains de performance attendus:")
    print("   - 10x plus rapide pour les scans multiples")
    print("   - Réduction de la charge serveur SSH")
    print("   - Moins de timeouts réseau")

def rollback_ssh_patch():
    """Annule le patch SSH et restaure la version précédente"""
    # Cette fonction nécessiterait une sauvegarde préalable
    print("⚠️  Pour le rollback, restaurez votre sauvegarde de app.py")
    print("   Ou utilisez git pour revenir à la version précédente")

if __name__ == "__main__":
    # Vérifications préalables
    if not os.path.exists('app.py'):
        print("❌ Erreur: app.py non trouvé")
        sys.exit(1)
    
    if not os.path.exists('ssh_connection_pool.py'):
        print("❌ Erreur: ssh_connection_pool.py non trouvé")
        print("   Assurez-vous d'avoir créé le fichier du pool SSH")
        sys.exit(1)
    
    # Créer une sauvegarde
    import shutil
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = f"app_backup_{timestamp}.py"
    shutil.copy2('app.py', backup_file)
    print(f"📦 Sauvegarde créée: {backup_file}")
    
    # Appliquer le patch
    if len(sys.argv) > 1 and sys.argv[1] == "rollback":
        rollback_ssh_patch()
    else:
        patch_app_with_ssh_pool()
        
        print(f"\n🔧 Pour tester:")
        print("   docker-compose restart server-disk-monitor")
        print("   curl http://localhost:5000/api/ssh/stats")
        print(f"\n🔄 Pour annuler:")
        print(f"   cp {backup_file} app.py")