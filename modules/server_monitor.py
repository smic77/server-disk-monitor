#!/usr/bin/env python3
"""
Module de monitoring des serveurs
Gère les connexions SSH, vérifications de disques et surveillance en temps réel
"""

import subprocess
import paramiko
import logging
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)

class ServerMonitor:
    def __init__(self, config_manager, notification_manager, socketio=None):
        self.config_manager = config_manager
        self.notification_manager = notification_manager
        self.socketio = socketio
        
        # État de surveillance
        self.monitoring = False
        self.disk_status = {}
        self.last_update = None
        self.status_cache = {}
        
        # Configuration et scheduler
        self.servers_config = self.config_manager.load_config()
        self.refresh_interval = self.servers_config.get('refresh_interval', 30)
        self.scheduler = BackgroundScheduler()
        
    def ping_server(self, ip):
        """Vérifie si un serveur est accessible via ping"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '3', ip], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception as e:
            logger.warning(f"Impossible de pinger {ip}: {e}")
            return False
    
    def check_disk_ssh(self, server_config, disk_info):
        """Vérifie le statut d'un disque via SSH - COMPATIBLE avec format existant"""
        cache_key = f"{server_config['ip']}_{disk_info['uuid']}_{disk_info['device']}"
        
        try:
            # Si pas de mot de passe configuré, utiliser le cache
            if not server_config.get('password'):
                if cache_key in self.status_cache:
                    return self.status_cache[cache_key]
                
                logger.warning(f"Pas de mot de passe configuré pour {server_config['ip']}")
                result = {"exists": False, "mounted": False}
                self.status_cache[cache_key] = result
                return result
            
            # Connexion SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            password = self.config_manager.decrypt_password(server_config['password'])
            
            ssh.connect(
                hostname=server_config['ip'],
                username=server_config['username'],
                password=password,
                timeout=10
            )
            
            # Vérification de l'existence du disque via UUID
            stdin, stdout, stderr = ssh.exec_command(f"lsblk -f | grep -i {disk_info['uuid']}")
            disk_exists = bool(stdout.read().decode().strip())
            
            # Vérification du montage si le disque existe
            if disk_exists:
                stdin, stdout, stderr = ssh.exec_command(f"mount | grep {disk_info['device']}")
                is_mounted = bool(stdout.read().decode().strip())
            else:
                is_mounted = False
            
            ssh.close()
            
            result = {"exists": disk_exists, "mounted": is_mounted}
            self.status_cache[cache_key] = result
            return result
            
        except Exception as e:
            logger.error(f"Erreur SSH pour {server_config['ip']}: {e}")
            
            # En cas d'erreur, utiliser le cache ou créer un état par défaut
            if cache_key in self.status_cache:
                return self.status_cache[cache_key]
            
            result = {"exists": False, "mounted": False}
            self.status_cache[cache_key] = result
            return result
    
    def clear_status_cache(self):
        """Vide le cache de statut"""
        self.status_cache.clear()
        logger.info("Cache de statut vidé")
    
    def update_all_disk_status(self):
        """Met à jour le statut de tous les disques avec notifications"""
        logger.info("Mise à jour du statut des disques...")
        
        # Recharger la configuration pour prendre en compte les changements
        self.servers_config = self.config_manager.load_config()
        
        total_disks = 0
        mounted_disks = 0
        online_servers = 0
        
        for server_name, config in self.servers_config.get('servers', {}).items():
            server_online = self.ping_server(config['ip'])
            
            if server_online:
                online_servers += 1
            
            server_status = {
                "name": server_name,
                "online": server_online,
                "ip": config['ip'],
                "username": config['username'],
                "disks": {}
            }
            
            # Traitement des disques
            for position, disk_info in config.get('disk_mappings', {}).items():
                total_disks += 1
                
                if server_online:
                    disk_status = self.check_disk_ssh(config, disk_info)
                    if disk_status['mounted']:
                        mounted_disks += 1
                else:
                    disk_status = {"exists": False, "mounted": False}
                
                server_status["disks"][position] = {
                    "uuid": disk_info['uuid'],
                    "device": disk_info['device'],
                    "label": disk_info.get('label', ''),
                    "capacity": disk_info.get('capacity', ''),
                    "description": disk_info.get('description', ''),
                    "exists": disk_status['exists'],
                    "mounted": disk_status['mounted']
                }
            
            self.disk_status[server_name] = server_status
        
        self.last_update = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Notifications pour les changements d'état
        notifications = self.notification_manager.check_disk_state_changes(self.disk_status)
        
        if notifications:
            logger.info(f"Notifications envoyées: {len(notifications)}")
            for notif in notifications:
                logger.info(f"  - {notif['type']}: {notif['server']} - {notif['change']}")
        
        # Statistiques globales
        stats = {
            "total_servers": len(self.servers_config.get('servers', {})),
            "online_servers": online_servers,
            "total_disks": total_disks,
            "mounted_disks": mounted_disks,
            "last_update": self.last_update
        }
        
        # Envoi via WebSocket si disponible
        if self.socketio:
            self.socketio.emit('disk_status_update', {
                'servers': self.disk_status,
                'stats': stats,
                'config': self.get_safe_config()
            })
        
        logger.info(f"Mise à jour terminée: {mounted_disks}/{total_disks} disques montés")
        
        return {
            'disk_status': self.disk_status,
            'stats': stats,
            'notifications': notifications
        }
    
    def get_safe_config(self):
        """Retourne la configuration sans les mots de passe - COMPATIBLE format existant"""
        safe_config = {}
        for server_name, config in self.servers_config.get('servers', {}).items():
            safe_config[server_name] = config.copy()
            safe_config[server_name]['password'] = '***' if config.get('password') else ''
        return safe_config
    
    def start_monitoring(self):
        """Démarre la surveillance automatique"""
        if not self.monitoring:
            self.monitoring = True
            self.scheduler.add_job(
                func=self.update_all_disk_status,
                trigger="interval",
                seconds=self.refresh_interval,
                id='disk_monitoring',
                replace_existing=True
            )
            
            if not self.scheduler.running:
                self.scheduler.start()
            
            logger.info(f"Surveillance démarrée (intervalle: {self.refresh_interval}s)")
    
    def stop_monitoring(self):
        """Arrête la surveillance"""
        if self.monitoring:
            self.monitoring = False
            if self.scheduler.get_job('disk_monitoring'):
                self.scheduler.remove_job('disk_monitoring')
            logger.info("Surveillance arrêtée")
    
    def update_refresh_interval(self, new_interval):
        """Met à jour l'intervalle de rafraîchissement"""
        self.refresh_interval = max(10, new_interval)
        self.servers_config['refresh_interval'] = self.refresh_interval
        
        # Sauvegarder la nouvelle configuration
        self.config_manager.save_config(self.servers_config)
        
        # Modifier le job si la surveillance est active
        if self.monitoring and self.scheduler.get_job('disk_monitoring'):
            self.scheduler.modify_job('disk_monitoring', seconds=self.refresh_interval)
            logger.info(f"Intervalle de rafraîchissement mis à jour: {self.refresh_interval}s")
    
    def manual_refresh(self):
        """Force une mise à jour manuelle"""
        logger.info("Mise à jour manuelle demandée")
        return self.update_all_disk_status()
    
    def get_status(self):
        """Retourne le statut actuel"""
        return {
            'disk_status': self.disk_status,
            'last_update': self.last_update,
            'monitoring': self.monitoring,
            'refresh_interval': self.refresh_interval
        }
    
    def test_ssh_connection(self, server_config):
        """Teste la connexion SSH à un serveur"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            password = self.config_manager.decrypt_password(server_config['password'])
            
            ssh.connect(
                hostname=server_config['ip'],
                username=server_config['username'],
                password=password,
                timeout=10
            )
            
            # Test simple de commande
            stdin, stdout, stderr = ssh.exec_command('echo "test"')
            output = stdout.read().decode().strip()
            
            ssh.close()
            
            return output == "test", "Connexion réussie"
            
        except Exception as e:
            logger.error(f"Erreur test SSH: {e}")
            return False, str(e)