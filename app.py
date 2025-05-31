#!/usr/bin/env python3
"""
Server Disk Monitor - Version Web Corrigée
Dashboard de surveillance des disques durs accessible via navigateur
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import json
import os
import threading
import time
import subprocess
import paramiko
import base64
from cryptography.fernet import Fernet
from apscheduler.schedulers.background import BackgroundScheduler
import uuid
import logging
from datetime import datetime

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialisation de l'application Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

class ServerDiskMonitorWeb:
    def __init__(self):
        self.data_dir = "/app/data"
        self.config_file = os.path.join(self.data_dir, "config.json")
        self.cipher_key_file = os.path.join(self.data_dir, "cipher.key")
        
        # Création du répertoire de données
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Initialisation du chiffrement
        self.init_encryption()
        
        # Configuration par défaut améliorée
        self.default_config = {
            "servers": {
                "EXAMPLE-SERVER": {
                    "ip": "192.168.1.100",
                    "username": "root",
                    "password": "",
                    "front_rack": {
                        "enabled": True,
                        "rows": 2,
                        "cols": 3,
                        "total_slots": 6
                    },
                    "back_rack": {
                        "enabled": False,
                        "rows": 0,
                        "cols": 0,
                        "total_slots": 0
                    },
                    "disk_mappings": {
                        "front_0_0": {
                            "uuid": "example-uuid-1234-5678-90ab-cdef12345678",
                            "device": "/dev/sda",
                            "label": "Système",
                            "description": "Disque système principal",
                            "capacity": "256GB SSD"
                        },
                        "front_0_1": {
                            "uuid": "example-uuid-2345-6789-01bc-def123456789",
                            "device": "/dev/sdb",
                            "label": "Données",
                            "description": "Stockage des données",
                            "capacity": "1TB HDD"
                        }
                    }
                }
            },
            "refresh_interval": 30
        }
        
        # Chargement de la configuration
        self.servers_config = self.load_config()
        
        # État de surveillance
        self.monitoring = False
        self.refresh_interval = self.servers_config.get('refresh_interval', 30)
        self.disk_status = {}
        self.last_update = None
        
        # AJOUT : Cache pour éviter les changements de statut aléatoires
        self.status_cache = {}
        
        # Démarrage du scheduler
        self.scheduler = BackgroundScheduler()
        self.start_monitoring()
    
    def init_encryption(self):
        """Initialise le système de chiffrement"""
        if os.path.exists(self.cipher_key_file):
            with open(self.cipher_key_file, 'rb') as f:
                self.cipher_key = f.read()
        else:
            self.cipher_key = Fernet.generate_key()
            with open(self.cipher_key_file, 'wb') as f:
                f.write(self.cipher_key)
        
        self.cipher = Fernet(self.cipher_key)
    
    def load_config(self):
        """Charge la configuration depuis le fichier"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    logger.info(f"Configuration chargée: {len(config.get('servers', {}))} serveur(s)")
                    return config
            except Exception as e:
                logger.error(f"Erreur lors du chargement de la configuration: {e}")
                return self.default_config.copy()
        else:
            logger.info("Aucune configuration trouvée, utilisation de la configuration par défaut")
            # Sauvegarder la config par défaut
            self.save_config_to_file(self.default_config)
            return self.default_config.copy()
    
    def save_config(self):
        """Sauvegarde la configuration dans le fichier"""
        return self.save_config_to_file(self.servers_config)
    
    def save_config_to_file(self, config):
        """Sauvegarde une configuration dans le fichier"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            logger.info("Configuration sauvegardée")
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde: {e}")
            return False
    
    def encrypt_password(self, password):
        """Chiffre un mot de passe"""
        if not password:
            return ""
        encrypted = self.cipher.encrypt(password.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_password(self, encrypted_password):
        """Déchiffre un mot de passe"""
        if not encrypted_password:
            return ""
        try:
            encrypted_bytes = base64.b64decode(encrypted_password.encode())
            return self.cipher.decrypt(encrypted_bytes).decode()
        except:
            return ""
    
    def ping_server(self, ip):
        """Vérifie si un serveur est accessible"""
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '3', ip], 
                                  capture_output=True, timeout=5)
            return result.returncode == 0
        except:
            # CORRECTION : Pas de simulation aléatoire, retourner False
            logger.warning(f"Impossible de pinger {ip}")
            return False
    
    def check_disk_ssh(self, server_config, disk_info):
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
            return result
    
    def clear_status_cache(self):
        """Vide le cache de statut si nécessaire"""
        self.status_cache.clear()
        logger.info("Cache de statut vidé")
    
    def update_all_disk_status(self):
        """Met à jour le statut de tous les disques"""
        logger.info("Mise à jour du statut des disques...")
        
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
        
        # Statistiques globales
        stats = {
            "total_servers": len(self.servers_config.get('servers', {})),
            "online_servers": online_servers,
            "total_disks": total_disks,
            "mounted_disks": mounted_disks,
            "last_update": self.last_update
        }
        
        # Envoi des données via WebSocket
        socketio.emit('disk_status_update', {
            'servers': self.disk_status,
            'stats': stats,
            'config': self.get_safe_config()
        })
        
        logger.info(f"Mise à jour terminée: {mounted_disks}/{total_disks} disques montés")
    
    def get_safe_config(self):
        """Retourne la configuration sans les mots de passe"""
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
            self.scheduler.start()
            logger.info("Surveillance démarrée")
    
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
        if self.monitoring:
            self.scheduler.modify_job('disk_monitoring', seconds=self.refresh_interval)

# Instance globale
monitor = ServerDiskMonitorWeb()

# Routes Flask
@app.route('/')
def index():
    """Page principale"""
    return render_template('index.html')

@app.route('/api/config', methods=['GET'])
def get_config():
    """Récupère la configuration"""
    return jsonify({
        'servers': monitor.get_safe_config(),
        'refresh_interval': monitor.refresh_interval
    })

@app.route('/api/config', methods=['POST'])
def update_config():
    """Met à jour la configuration"""
    try:
        data = request.get_json()
        
        if 'servers' in data:
            # Préserver les mots de passe existants
            for server_name, new_config in data['servers'].items():
                if server_name in monitor.servers_config.get('servers', {}):
                    old_password = monitor.servers_config['servers'][server_name].get('password', '')
                    new_config['password'] = old_password
            
            monitor.servers_config['servers'] = data['servers']
            monitor.save_config()
        
        if 'refresh_interval' in data:
            monitor.update_refresh_interval(data['refresh_interval'])
            monitor.save_config()
        
        return jsonify({'success': True, 'message': 'Configuration mise à jour'})
    
    except Exception as e:
        logger.error(f"Erreur mise à jour config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/server/<server_name>/password', methods=['POST'])
def update_server_password(server_name):
    """Met à jour le mot de passe d'un serveur"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if server_name in monitor.servers_config.get('servers', {}):
            monitor.servers_config['servers'][server_name]['password'] = monitor.encrypt_password(password)
            monitor.save_config()
            return jsonify({'success': True, 'message': 'Mot de passe mis à jour'})
        else:
            return jsonify({'success': False, 'error': 'Serveur non trouvé'}), 404
    
    except Exception as e:
        logger.error(f"Erreur mot de passe: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/refresh', methods=['POST'])
def manual_refresh():
    """Rafraîchissement manuel"""
    try:
        threading.Thread(target=monitor.update_all_disk_status, daemon=True).start()
        return jsonify({'success': True, 'message': 'Rafraîchissement en cours'})
    except Exception as e:
        logger.error(f"Erreur refresh: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/status')
def get_status():
    """Récupère le statut actuel"""
    stats = {
        "total_servers": len(monitor.servers_config.get('servers', {})),
        "online_servers": sum(1 for s in monitor.disk_status.values() if s.get('online', False)),
        "total_disks": sum(len(config.get('disk_mappings', {})) for config in monitor.servers_config.get('servers', {}).values()),
        "mounted_disks": sum(
            sum(1 for d in server.get('disks', {}).values() if d.get('mounted', False))
            for server in monitor.disk_status.values()
        ),
        "last_update": monitor.last_update,
        "monitoring": monitor.monitoring
    }
    
    return jsonify({
        'status': 'OK',
        'servers': monitor.disk_status,
        'stats': stats,
        'config': monitor.get_safe_config()
    })

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Vide le cache de statut"""
    try:
        monitor.clear_status_cache()
        return jsonify({'success': True, 'message': 'Cache vidé'})
    except Exception as e:
        logger.error(f"Erreur lors du vidage du cache: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# WebSocket events
@socketio.on('connect')
def handle_connect():
    """Gestion de la connexion WebSocket"""
    logger.info('Client connecté')
    emit('connected', {'message': 'Connexion établie'})
    
    # Envoi des données actuelles
    threading.Thread(target=monitor.update_all_disk_status, daemon=True).start()

@socketio.on('disconnect')
def handle_disconnect():
    """Gestion de la déconnexion WebSocket"""
    logger.info('Client déconnecté')

@socketio.on('request_refresh')
def handle_refresh_request():
    """Gestion des demandes de rafraîchissement"""
    threading.Thread(target=monitor.update_all_disk_status, daemon=True).start()

if __name__ == '__main__':
    logger.info("Démarrage du Server Disk Monitor Web")
    logger.info(f"Configuration chargée: {len(monitor.servers_config.get('servers', {}))} serveur(s)")
    
    # Rafraîchissement initial
    threading.Thread(target=monitor.update_all_disk_status, daemon=True).start()
    
    # Démarrage du serveur
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)