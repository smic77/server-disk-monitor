#!/usr/bin/env python3
"""
Correction complète du problème de montage incohérent
Amélioration robuste du système de monitoring
"""

import hashlib
import threading
from datetime import datetime, timedelta

class ServerDiskMonitorWeb:
    def __init__(self):
        # ... code existant ...
        
        # AJOUT : Système de cache et état persistant
        self.disk_status_cache = {}
        self.cache_timestamps = {}
        self.cache_ttl = 60  # TTL du cache en secondes
        self.status_lock = threading.Lock()
        
    def get_cache_key(self, server_config, disk_info):
        """Génère une clé de cache unique et déterministe"""
        key_data = f"{server_config['ip']}_{server_config['username']}_{disk_info['uuid']}_{disk_info['device']}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def is_cache_valid(self, cache_key):
        """Vérifie si le cache est encore valide"""
        if cache_key not in self.cache_timestamps:
            return False
        
        cache_time = self.cache_timestamps[cache_key]
        return datetime.now() - cache_time < timedelta(seconds=self.cache_ttl)
    
    def set_cache(self, cache_key, result):
        """Stocke un résultat en cache avec timestamp"""
        with self.status_lock:
            self.disk_status_cache[cache_key] = result
            self.cache_timestamps[cache_key] = datetime.now()
    
    def get_cache(self, cache_key):
        """Récupère un résultat depuis le cache"""
        with self.status_lock:
            return self.disk_status_cache.get(cache_key)
    
    def check_disk_ssh(self, server_config, disk_info):
        """Vérifie le statut d'un disque via SSH avec cache intelligent"""
        cache_key = self.get_cache_key(server_config, disk_info)
        
        # Vérifier le cache d'abord
        if self.is_cache_valid(cache_key):
            cached_result = self.get_cache(cache_key)
            if cached_result:
                logger.debug(f"Cache hit pour {server_config['ip']}:{disk_info['device']}")
                return cached_result
        
        try:
            # Si pas de mot de passe configuré
            if not server_config.get('password'):
                logger.warning(f"Pas de credentials pour {server_config['ip']}")
                result = {
                    "exists": False, 
                    "mounted": False, 
                    "status": "no_credentials",
                    "message": "Aucun mot de passe configuré"
                }
                self.set_cache(cache_key, result)
                return result
            
            # Tentative de connexion SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            password = self.decrypt_password(server_config['password'])
            
            ssh.connect(
                hostname=server_config['ip'],
                username=server_config['username'],
                password=password,
                timeout=10
            )
            
            # 1. Vérification par UUID (méthode la plus fiable)
            stdin, stdout, stderr = ssh.exec_command(f"blkid | grep -i '{disk_info['uuid']}'")
            uuid_output = stdout.read().decode().strip()
            
            disk_exists = bool(uuid_output)
            actual_device = disk_info['device']  # Par défaut
            
            if disk_exists:
                # Extraire le vrai device depuis blkid
                if ':' in uuid_output:
                    actual_device = uuid_output.split(':')[0]
                
                # 2. Vérification du montage
                stdin, stdout, stderr = ssh.exec_command(f"mount | grep '{actual_device}'")
                mount_output = stdout.read().decode().strip()
                is_mounted = bool(mount_output)
                
                # 3. Informations supplémentaires si monté
                mount_point = ""
                fs_type = ""
                if is_mounted and mount_output:
                    parts = mount_output.split()
                    if len(parts) >= 3:
                        mount_point = parts[2]
                        if 'type' in mount_output:
                            fs_parts = mount_output.split('type ')
                            if len(fs_parts) > 1:
                                fs_type = fs_parts[1].split()[0]
            else:
                is_mounted = False
                mount_point = ""
                fs_type = ""
            
            ssh.close()
            
            result = {
                "exists": disk_exists,
                "mounted": is_mounted,
                "status": "checked",
                "device": actual_device,
                "mount_point": mount_point,
                "fs_type": fs_type,
                "checked_at": datetime.now().isoformat()
            }
            
            # Mise en cache du résultat
            self.set_cache(cache_key, result)
            
            logger.debug(f"Disque {actual_device}: exists={disk_exists}, mounted={is_mounted}")
            return result
            
        except paramiko.AuthenticationException:
            logger.error(f"Authentification échouée pour {server_config['ip']}")
            result = {
                "exists": False, 
                "mounted": False, 
                "status": "auth_error",
                "message": "Erreur d'authentification"
            }
            self.set_cache(cache_key, result)
            return result
            
        except paramiko.SSHException as e:
            logger.error(f"Erreur SSH pour {server_config['ip']}: {e}")
            result = {
                "exists": False, 
                "mounted": False, 
                "status": "ssh_error",
                "message": f"Erreur SSH: {str(e)}"
            }
            self.set_cache(cache_key, result)
            return result
            
        except Exception as e:
            logger.error(f"Erreur générale pour {server_config['ip']}: {e}")
            result = {
                "exists": False, 
                "mounted": False, 
                "status": "error",
                "message": f"Erreur: {str(e)}"
            }
            self.set_cache(cache_key, result)
            return result
    
    def ping_server(self, ip):
        """Vérifie si un serveur est accessible avec cache"""
        cache_key = f"ping_{ip}"
        
        if self.is_cache_valid(cache_key):
            cached_result = self.get_cache(cache_key)
            if cached_result is not None:
                return cached_result.get('online', False)
        
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '3', ip], 
                                  capture_output=True, timeout=5)
            is_online = result.returncode == 0
            
            # Cache du résultat de ping
            self.set_cache(cache_key, {'online': is_online, 'ping_time': datetime.now().isoformat()})
            
            return is_online
        except Exception as e:
            logger.warning(f"Impossible de pinger {ip}: {e}")
            self.set_cache(cache_key, {'online': False, 'error': str(e)})
            return False
    
    def clear_cache(self, older_than_seconds=None):
        """Nettoie le cache"""
        with self.status_lock:
            if older_than_seconds:
                cutoff_time = datetime.now() - timedelta(seconds=older_than_seconds)
                keys_to_remove = [
                    key for key, timestamp in self.cache_timestamps.items()
                    if timestamp < cutoff_time
                ]
                for key in keys_to_remove:
                    self.disk_status_cache.pop(key, None)
                    self.cache_timestamps.pop(key, None)
                logger.info(f"Cache nettoyé: {len(keys_to_remove)} entrées supprimées")
            else:
                self.disk_status_cache.clear()
                self.cache_timestamps.clear()
                logger.info("Cache entièrement vidé")
    
    def get_cache_stats(self):
        """Retourne les statistiques du cache"""
        with self.status_lock:
            total_entries = len(self.disk_status_cache)
            valid_entries = sum(1 for key in self.disk_status_cache.keys() if self.is_cache_valid(key))
            return {
                'total_entries': total_entries,
                'valid_entries': valid_entries,
                'expired_entries': total_entries - valid_entries,
                'cache_ttl': self.cache_ttl
            }

# AJOUT : Route API pour la gestion du cache
@app.route('/api/cache/stats')
def get_cache_stats():
    """Récupère les statistiques du cache"""
    return jsonify(monitor.get_cache_stats())

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Vide le cache"""
    monitor.clear_cache()
    return jsonify({'success': True, 'message': 'Cache vidé'})

# AJOUT : Nettoyage automatique du cache
def setup_cache_cleanup():
    """Configure le nettoyage automatique du cache"""
    def cleanup_job():
        monitor.clear_cache(older_than_seconds=300)  # Nettoie les entrées > 5 min
    
    monitor.scheduler.add_job(
        func=cleanup_job,
        trigger="interval",
        minutes=10,  # Nettoyage toutes les 10 minutes
        id='cache_cleanup',
        replace_existing=True
    )