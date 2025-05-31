#!/usr/bin/env python3
"""
Server Disk Monitor - Version Web
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
app.config['SECRET_KEY'] = 'your-secret-key-change-this'
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
        
        # Configuration par défaut
        self.default_config = {
            "SERVER-01": {
                "ip": "192.168.1.10",
                "username": "admin",
                "password": "",
                "front_rack": {
                    "enabled": True,
                    "rows": 3,
                    "cols": 4,
                    "total_slots": 12
                },
                "back_rack": {
                    "enabled": True,
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
                    },
                    "front_0_1": {
                        "uuid": "550e8400-e29b-41d4-a716-446655440002",
                        "device": "/dev/sdb",
                        "label": "Data 01",
                        "description": "Stockage données utilisateurs",
                        "capacity": "2TB HDD"
                    }
                }
            }
        }
        
        # Chargement de la configuration
        self.servers_config = self.load_config()
        
        # État de surveillance
        self.monitoring = False
        self.refresh_interval = 30
        self.disk_status = {}
        self.last_update = None
        
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
                    return json.load(f)
            except Exception as e:
                logger.error(f"Erreur lors du chargement de la configuration: {e}")
                return self.default_config.copy()
        else:
            return self.default_config.copy()
    
    def save_config(self):
        """Sauvegarde la configuration dans le fichier"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.servers_config, f, indent=4, ensure_ascii=False)
            return True
        except Exception as e:
            logger.error(f"Erreur lors de la sauvegarde: {e}")
            return False
    
    def encrypt_password(self, password):
        """Chiffre un mot de passe"""
        encrypted = self.cipher.encrypt(password.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_password(self, encrypted_password):
        """Déchiffre un mot de passe"""
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
            return False
    
    def check_disk_ssh(self, server_config, disk_info):
        """Vérifie le statut d'un disque via SSH"""
        try:
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
            return {"exists": disk_exists, "mounted": is_mounted}
            
        except Exception as e:
            logger.error(f"Erreur SSH pour {server_config['ip']}: {e}")
            return {"exists": False, "mounted": False}
    
    def update_all_disk_status(self):
        """Met à jour le statut de tous les disques"""
        logger.info("Mise à jour du statut des disques...")
        
        total_disks = 0
        mounted_disks = 0
        online_servers = 0
        
        for server_name, config in self.servers_config.items():
            server_online = self.ping_server(config['ip'])
            
            if server_online:
                online_servers += 1
            
            server_status = {
                "name": server_name,
                "online": server_online,
                "disks": {}
            }
            
            for position, disk_info in config['disk_mappings'].items():
                total_disks += 1
                
                if server_online and config.get('password'):
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
            "total_servers": len(self.servers_config),
            "online_servers": online_servers,
            "total_disks": total_disks,
            "mounted_disks": mounted_disks,
            "last_update": self.last_update
        }
        
        # Envoi des données via WebSocket
        socketio.emit('disk_status_update', {
            'servers': self.disk_status,
            'stats': stats
        })
        
        logger.info(f"Mise à jour terminée: {mounted_disks}/{total_disks} disques montés")
    
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
            self.scheduler.remove_job('disk_monitoring')
            logger.info("Surveillance arrêtée")
    
    def update_refresh_interval(self, new_interval):
        """Met à jour l'intervalle de rafraîchissement"""
        self.refresh_interval = max(10, new_interval)  # Minimum 10 secondes
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
    # Masquer les mots de passe dans la réponse
    safe_config = {}
    for server_name, config in monitor.servers_config.items():
        safe_config[server_name] = config.copy()
        safe_config[server_name]['password'] = '***' if config.get('password') else ''
    
    return jsonify({
        'servers': safe_config,
        'refresh_interval': monitor.refresh_interval
    })

@app.route('/api/config', methods=['POST'])
def update_config():
    """Met à jour la configuration"""
    try:
        data = request.get_json()
        
        if 'servers' in data:
            monitor.servers_config = data['servers']
            monitor.save_config()
        
        if 'refresh_interval' in data:
            monitor.update_refresh_interval(data['refresh_interval'])
        
        return jsonify({'success': True, 'message': 'Configuration mise à jour'})
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/server/<server_name>/password', methods=['POST'])
def update_server_password(server_name):
    """Met à jour le mot de passe d'un serveur"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if server_name in monitor.servers_config:
            if password:
                monitor.servers_config[server_name]['password'] = monitor.encrypt_password(password)
            else:
                monitor.servers_config[server_name]['password'] = ''
            
            monitor.save_config()
            return jsonify({'success': True, 'message': 'Mot de passe mis à jour'})
        else:
            return jsonify({'success': False, 'error': 'Serveur non trouvé'}), 404
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/refresh', methods=['POST'])
def manual_refresh():
    """Rafraîchissement manuel"""
    try:
        threading.Thread(target=monitor.update_all_disk_status, daemon=True).start()
        return jsonify({'success': True, 'message': 'Rafraîchissement en cours'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/status')
def get_status():
    """Récupère le statut actuel"""
    stats = {
        "total_servers": len(monitor.servers_config),
        "online_servers": sum(1 for s in monitor.disk_status.values() if s.get('online', False)),
        "total_disks": sum(len(config['disk_mappings']) for config in monitor.servers_config.values()),
        "mounted_disks": sum(
            sum(1 for d in server.get('disks', {}).values() if d.get('mounted', False))
            for server in monitor.disk_status.values()
        ),
        "last_update": monitor.last_update,
        "monitoring": monitor.monitoring
    }
    
    return jsonify({
        'servers': monitor.disk_status,
        'stats': stats
    })

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
    logger.info(f"Configuration chargée: {len(monitor.servers_config)} serveur(s)")
    
    # Rafraîchissement initial
    threading.Thread(target=monitor.update_all_disk_status, daemon=True).start()
    
    # Démarrage du serveur
    socketio.run(app, host='0.0.0.0', port=5000, debug=False)