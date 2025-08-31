#!/usr/bin/env python3
"""
Installation automatique de toutes les améliorations du Server Disk Monitor
Applique toutes les optimisations de performance et sécurité en préservant la compatibilité
"""

import os
import sys
import shutil
import subprocess
from datetime import datetime
from typing import List, Tuple, Optional
import argparse

class ImprovementInstaller:
    """Installateur des améliorations du Server Disk Monitor"""
    
    def __init__(self, backup_enabled: bool = True):
        self.backup_enabled = backup_enabled
        self.backup_dir = f"backup_improvements_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.improvements_applied = []
        self.errors = []
    
    def create_backup(self) -> bool:
        """Crée une sauvegarde complète avant modifications"""
        if not self.backup_enabled:
            return True
        
        try:
            os.makedirs(self.backup_dir, exist_ok=True)
            
            # Fichiers critiques à sauvegarder
            files_to_backup = [
                'app.py',
                'requirements.txt',
                'data/config.json',
                'data/notifications.json',
                'data/cipher.key'
            ]
            
            for file_path in files_to_backup:
                if os.path.exists(file_path):
                    if '/' in file_path:
                        # Créer le sous-répertoire si nécessaire
                        subdir = os.path.join(self.backup_dir, os.path.dirname(file_path))
                        os.makedirs(subdir, exist_ok=True)
                    
                    backup_path = os.path.join(self.backup_dir, file_path)
                    shutil.copy2(file_path, backup_path)
                    print(f"✅ Sauvegardé: {file_path}")
            
            print(f"📦 Sauvegarde créée dans: {self.backup_dir}")
            return True
            
        except Exception as e:
            print(f"❌ Erreur lors de la sauvegarde: {e}")
            return False
    
    def check_prerequisites(self) -> List[str]:
        """Vérifie que tous les prérequis sont présents"""
        missing = []
        
        # Fichiers requis
        required_files = [
            'app.py',
            'requirements.txt',
            'templates/index.html'
        ]
        
        for file_path in required_files:
            if not os.path.exists(file_path):
                missing.append(f"Fichier manquant: {file_path}")
        
        # Modules Python requis
        required_modules = [
            'flask',
            'paramiko',
            'cryptography'
        ]
        
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                missing.append(f"Module Python manquant: {module}")
        
        return missing
    
    def install_ssh_pool(self) -> bool:
        """Installe le pool de connexions SSH"""
        print("\n🔧 Installation du pool SSH...")
        
        try:
            # Les fichiers doivent déjà être créés
            if not os.path.exists('ssh_connection_pool.py'):
                self.errors.append("Fichier ssh_connection_pool.py manquant")
                return False
            
            # Appliquer le patch
            result = subprocess.run([sys.executable, 'ssh_pool_integration.py'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Pool SSH installé avec succès")
                self.improvements_applied.append("Pool de connexions SSH")
                return True
            else:
                print(f"❌ Erreur installation pool SSH: {result.stderr}")
                self.errors.append(f"Pool SSH: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Exception lors de l'installation du pool SSH: {e}")
            self.errors.append(f"Pool SSH: {e}")
            return False
    
    def install_json_validation(self) -> bool:
        """Installe la validation JSON"""
        print("\n🔒 Installation de la validation JSON...")
        
        try:
            if not os.path.exists('json_validator.py'):
                self.errors.append("Fichier json_validator.py manquant")
                return False
            
            # Appliquer le patch
            result = subprocess.run([sys.executable, 'json_validation_patch.py'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Validation JSON installée avec succès")
                self.improvements_applied.append("Validation et sanitisation JSON")
                return True
            else:
                print(f"❌ Erreur installation validation JSON: {result.stderr}")
                self.errors.append(f"Validation JSON: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"❌ Exception lors de l'installation validation JSON: {e}")
            self.errors.append(f"Validation JSON: {e}")
            return False
    
    def install_error_handling(self) -> bool:
        """Installe la gestion d'erreurs améliorée"""
        print("\n🛠️ Installation de la gestion d'erreurs SSH...")
        
        try:
            if not os.path.exists('ssh_error_handler.py'):
                self.errors.append("Fichier ssh_error_handler.py manquant")
                return False
            
            # Patcher app.py pour intégrer le gestionnaire d'erreurs
            with open('app.py', 'r', encoding='utf-8') as f:
                app_content = f.read()
            
            # Ajouter l'import
            if "from ssh_error_handler import ssh_error_handler" not in app_content:
                import_line = "from ssh_connection_pool import get_ssh_pool"
                if import_line in app_content:
                    app_content = app_content.replace(
                        import_line,
                        import_line + "\nfrom ssh_error_handler import ssh_error_handler"
                    )
                
                # Ajouter une route pour les statistiques d'erreurs
                stats_route = '''
@app.route('/api/ssh/errors', methods=['GET'])
def get_ssh_error_stats():
    \"\"\"Statistiques des erreurs SSH\"\"\"
    try:
        stats = ssh_error_handler.get_global_stats()
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
                
                websocket_marker = "# WebSocket Events"
                if websocket_marker in app_content:
                    app_content = app_content.replace(
                        websocket_marker,
                        stats_route + websocket_marker
                    )
                
                # Sauvegarder
                with open('app.py', 'w', encoding='utf-8') as f:
                    f.write(app_content)
                
                print("✅ Gestion d'erreurs SSH installée")
                self.improvements_applied.append("Gestion d'erreurs SSH améliorée")
                return True
            else:
                print("ℹ️ Gestion d'erreurs SSH déjà installée")
                return True
                
        except Exception as e:
            print(f"❌ Exception lors de l'installation gestion d'erreurs: {e}")
            self.errors.append(f"Gestion erreurs: {e}")
            return False
    
    def install_intelligent_cache(self) -> bool:
        """Installe le système de cache intelligent"""
        print("\n⚡ Installation du cache intelligent...")
        
        try:
            if not os.path.exists('intelligent_cache.py'):
                self.errors.append("Fichier intelligent_cache.py manquant")
                return False
            
            # Patcher app.py pour intégrer le cache
            with open('app.py', 'r', encoding='utf-8') as f:
                app_content = f.read()
            
            # Ajouter l'import
            if "from intelligent_cache import disk_cache" not in app_content:
                import_line = "from ssh_error_handler import ssh_error_handler"
                if import_line in app_content:
                    app_content = app_content.replace(
                        import_line,
                        import_line + "\nfrom intelligent_cache import disk_cache"
                    )
                
                # Ajouter une route pour les statistiques de cache
                cache_stats_route = '''
@app.route('/api/cache/stats', methods=['GET'])
def get_cache_stats():
    \"\"\"Statistiques du cache intelligent\"\"\"
    try:
        stats = disk_cache.get_stats()
        return jsonify({
            "success": True,
            "stats": stats
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

@app.route('/api/cache/clear', methods=['POST'])
def clear_intelligent_cache():
    \"\"\"Vide le cache intelligent\"\"\"
    try:
        disk_cache.invalidate()
        return jsonify({
            "success": True,
            "message": "Cache intelligent vidé"
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "message": str(e)
        }), 500

'''
                
                error_stats_marker = "@app.route('/api/ssh/errors'"
                if error_stats_marker in app_content:
                    insertion_point = app_content.find(error_stats_marker)
                    app_content = app_content[:insertion_point] + cache_stats_route + app_content[insertion_point:]
                
                # Sauvegarder
                with open('app.py', 'w', encoding='utf-8') as f:
                    f.write(app_content)
                
                print("✅ Cache intelligent installé")
                self.improvements_applied.append("Système de cache intelligent")
                return True
            else:
                print("ℹ️ Cache intelligent déjà installé")
                return True
                
        except Exception as e:
            print(f"❌ Exception lors de l'installation cache intelligent: {e}")
            self.errors.append(f"Cache intelligent: {e}")
            return False
    
    def update_requirements(self) -> bool:
        """Met à jour requirements.txt si nécessaire"""
        print("\n📋 Vérification des dépendances...")
        
        try:
            # Nouvelles dépendances potentielles (déjà présentes normalement)
            new_deps = []  # Toutes les dépendances sont déjà dans requirements.txt
            
            if new_deps:
                with open('requirements.txt', 'a', encoding='utf-8') as f:
                    for dep in new_deps:
                        f.write(f"\n{dep}")
                
                print(f"✅ Dépendances ajoutées: {', '.join(new_deps)}")
            else:
                print("ℹ️ Aucune nouvelle dépendance nécessaire")
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur mise à jour requirements: {e}")
            return False
    
    def test_installation(self) -> bool:
        """Teste que l'installation fonctionne"""
        print("\n🧪 Test de l'installation...")
        
        try:
            # Test d'import des modules
            test_imports = [
                'ssh_connection_pool',
                'json_validator', 
                'ssh_error_handler',
                'intelligent_cache'
            ]
            
            for module in test_imports:
                if os.path.exists(f'{module}.py'):
                    try:
                        __import__(module)
                        print(f"✅ Module {module} importé avec succès")
                    except Exception as e:
                        print(f"❌ Erreur import {module}: {e}")
                        return False
            
            # Vérifier que app.py n'a pas d'erreurs de syntaxe
            result = subprocess.run([sys.executable, '-m', 'py_compile', 'app.py'], 
                                  capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ app.py compile sans erreur")
            else:
                print(f"❌ Erreurs de syntaxe dans app.py: {result.stderr}")
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ Erreur lors du test: {e}")
            return False
    
    def rollback(self) -> bool:
        """Restaure la sauvegarde en cas d'erreur"""
        if not self.backup_enabled or not os.path.exists(self.backup_dir):
            print("❌ Pas de sauvegarde disponible pour rollback")
            return False
        
        try:
            print(f"\n🔄 Restauration depuis {self.backup_dir}...")
            
            # Restaurer les fichiers sauvegardés
            for root, dirs, files in os.walk(self.backup_dir):
                for file in files:
                    backup_path = os.path.join(root, file)
                    relative_path = os.path.relpath(backup_path, self.backup_dir)
                    
                    # Créer le répertoire de destination si nécessaire
                    dest_dir = os.path.dirname(relative_path)
                    if dest_dir and dest_dir != '.':
                        os.makedirs(dest_dir, exist_ok=True)
                    
                    shutil.copy2(backup_path, relative_path)
                    print(f"✅ Restauré: {relative_path}")
            
            print("✅ Rollback terminé avec succès")
            return True
            
        except Exception as e:
            print(f"❌ Erreur lors du rollback: {e}")
            return False
    
    def install_all(self) -> bool:
        """Installe toutes les améliorations"""
        print("🚀 === INSTALLATION DES AMÉLIORATIONS SERVER DISK MONITOR ===\n")
        
        # Vérifications préalables
        missing = self.check_prerequisites()
        if missing:
            print("❌ Prérequis manquants:")
            for item in missing:
                print(f"   - {item}")
            return False
        
        # Sauvegarde
        if not self.create_backup():
            print("❌ Échec de la sauvegarde. Installation annulée.")
            return False
        
        # Installation des améliorations dans l'ordre
        improvements = [
            ("Pool SSH", self.install_ssh_pool),
            ("Validation JSON", self.install_json_validation), 
            ("Gestion erreurs SSH", self.install_error_handling),
            ("Cache intelligent", self.install_intelligent_cache),
            ("Dépendances", self.update_requirements)
        ]
        
        success = True
        for name, install_func in improvements:
            if not install_func():
                print(f"❌ Échec installation: {name}")
                success = False
                break
        
        if success:
            # Test final
            if self.test_installation():
                print(self._format_success_summary())
                return True
            else:
                print("❌ Test d'installation échoué")
                success = False
        
        # Rollback en cas d'erreur
        if not success:
            print(f"\n⚠️ Installation échouée. Rollback automatique...")
            self.rollback()
            print(self._format_error_summary())
        
        return success
    
    def _format_success_summary(self) -> str:
        """Formate le résumé de succès"""
        summary = f"""
🎉 === INSTALLATION RÉUSSIE ===

✅ Améliorations installées:
"""
        for improvement in self.improvements_applied:
            summary += f"   ✓ {improvement}\n"
        
        summary += f"""
📁 Sauvegarde disponible: {self.backup_dir}

🚀 Prochaines étapes:
   1. Redémarrer l'application: docker-compose restart
   2. Vérifier les logs: docker logs -f server-disk-monitor
   3. Tester l'interface: http://localhost:5000
   4. Consulter les nouvelles API:
      • /api/ssh/stats - Statistiques pool SSH
      • /api/ssh/errors - Erreurs SSH  
      • /api/cache/stats - Statistiques cache
      • /api/validate/test - Test validation

⚡ Performances attendues:
   • 5-10x plus rapide pour les scans multi-serveurs
   • Sécurité renforcée contre les attaques JSON
   • Gestion intelligente des erreurs réseau
   • Cache adaptatif pour minimiser les requêtes SSH

🔄 Pour annuler: python install_improvements.py --rollback
"""
        return summary
    
    def _format_error_summary(self) -> str:
        """Formate le résumé d'erreurs"""
        summary = f"""
❌ === INSTALLATION ÉCHOUÉE ===

Erreurs rencontrées:
"""
        for error in self.errors:
            summary += f"   ❌ {error}\n"
        
        summary += f"""
🔄 Les fichiers originaux ont été restaurés depuis: {self.backup_dir}

🔧 Dépannage:
   1. Vérifiez les prérequis système
   2. Assurez-vous que tous les fichiers d'amélioration sont présents
   3. Consultez les logs détaillés
   4. Contactez le support si le problème persiste
"""
        return summary

def main():
    parser = argparse.ArgumentParser(description="Installation des améliorations Server Disk Monitor")
    parser.add_argument('--no-backup', action='store_true', help="Désactive la sauvegarde automatique")
    parser.add_argument('--rollback', action='store_true', help="Restaure la dernière sauvegarde")
    
    args = parser.parse_args()
    
    if args.rollback:
        # Rechercher le répertoire de sauvegarde le plus récent
        backup_dirs = [d for d in os.listdir('.') if d.startswith('backup_improvements_')]
        if not backup_dirs:
            print("❌ Aucune sauvegarde trouvée")
            sys.exit(1)
        
        latest_backup = max(backup_dirs)
        installer = ImprovementInstaller(backup_enabled=True)
        installer.backup_dir = latest_backup
        
        if installer.rollback():
            print("✅ Rollback réussi")
            sys.exit(0)
        else:
            print("❌ Rollback échoué")
            sys.exit(1)
    
    # Installation normale
    installer = ImprovementInstaller(backup_enabled=not args.no_backup)
    
    if installer.install_all():
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()