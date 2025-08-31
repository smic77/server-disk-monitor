#!/usr/bin/env python3
"""
Server Disk Monitor - Version Web avec Notifications Telegram
Dashboard de surveillance des disques durs accessible via navigateur
"""

# Version de l'application
VERSION = "2.6.0"
BUILD_DATE = "2025-08-31"

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
import requests

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialisation de l'application Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

class NotificationManager:
    def __init__(self, cipher=None):
        self.previous_disk_states = {}
        self.previous_server_states = {}  # NOUVEAU: États précédents des serveurs
        self.telegram_config = {
            'enabled': False,
            'bot_token': '',
            'chat_ids': [],
            'parse_mode': 'HTML'
        }
        self.cipher = cipher  # Référence vers le cipher de la classe principale
        self.load_notification_config()
    
    def load_notification_config(self):
        """Charge la configuration des notifications"""
        config_file = os.path.join("data", "notifications.json")
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    self.telegram_config.update(config.get('telegram', {}))
                    logger.info("Configuration notifications chargée")
            except Exception as e:
                logger.error(f"Erreur chargement config notifications: {e}")
    
    def save_notification_config(self):
        """Sauvegarde la configuration des notifications"""
        os.makedirs("data", exist_ok=True)
        config_file = os.path.join("data", "notifications.json")
        try:
            config = {
                'telegram': self.telegram_config
            }
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            logger.info("Configuration notifications sauvegardée")
            return True
        except Exception as e:
            logger.error(f"Erreur sauvegarde config notifications: {e}")
            return False
    
    def decrypt_token(self, encrypted_token):
        """Déchiffre le token Telegram"""
        if not encrypted_token or not self.cipher:
            return ""
        try:
            if encrypted_token == '***':  # Token masqué, ne pas déchiffrer
                return ""
            encrypted_bytes = base64.b64decode(encrypted_token.encode())
            return self.cipher.decrypt(encrypted_bytes).decode()
        except Exception as e:
            logger.error(f"Erreur déchiffrement token: {e}")
            return ""
    
    def send_telegram_notification(self, message):
        """Envoie une notification Telegram"""
        if not self.telegram_config['enabled'] or not self.telegram_config['bot_token']:
            logger.warning("Notifications Telegram désactivées ou token manquant")
            return False
        
        try:
            # Déchiffrer le token
            bot_token = self.decrypt_token(self.telegram_config['bot_token'])
            if not bot_token:
                logger.error("Impossible de déchiffrer le token Telegram")
                return False
            
            success_count = 0
            
            for chat_id in self.telegram_config['chat_ids']:
                if not chat_id:
                    continue
                    
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                
                # CORRECTION: Utiliser les paramètres dans l'URL ET le body JSON
                # pour une meilleure compatibilité
                payload = {
                    'chat_id': str(chat_id),
                    'text': message,
                    'parse_mode': self.telegram_config['parse_mode'],
                    'disable_web_page_preview': True
                }
                
                logger.info(f"Envoi vers Chat ID: {chat_id}")
                logger.debug(f"URL: {url}")
                logger.debug(f"Payload: {payload}")
                
                response = requests.post(url, json=payload, timeout=10)
                
                logger.info(f"Response status: {response.status_code}")
                logger.debug(f"Response: {response.text}")
                
                if response.status_code == 200:
                    success_count += 1
                    logger.info(f"Message Telegram envoyé avec succès à {chat_id}")
                else:
                    logger.error(f"Erreur Telegram {chat_id}: {response.status_code} - {response.text}")
            
            return success_count > 0
            
        except Exception as e:
            logger.error(f"Erreur envoi Telegram: {e}")
            return False
    
    def format_telegram_message(self, server_name, server_ip, position, disk_label, changes):
        """Formate un message pour Telegram"""
        # Emojis pour les différents types d'alertes
        emoji_map = {
            'DÉMONTÉ': '❌',
            'DISPARU': '🚨',
            'REMONTÉ': '✅',
            'RÉAPPARU': '🔄'
        }
        
        # Trouver l'emoji approprié
        emoji = '⚠️'
        for key, em in emoji_map.items():
            if key in changes[0]:
                emoji = em
                break
        
        message = f"""
{emoji} <b>Server Disk Monitor - ALERTE</b>

<b>Serveur:</b> {server_name}
<b>IP:</b> {server_ip}
<b>Position:</b> {position}
<b>Disque:</b> {disk_label}

<b>Changement détecté:</b>
{changes[0]}

<b>Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """.strip()
        
        return message
    
    def format_server_telegram_message(self, server_name, server_ip, server_status):
        """Formate un message pour les changements d'état des serveurs"""
        if server_status == 'online':
            emoji = '🟢'
            status_text = 'EN LIGNE'
            description = 'Le serveur est maintenant accessible et opérationnel.'
        else:
            emoji = '🔴'
            status_text = 'HORS LIGNE'
            description = 'Le serveur ne répond plus aux requêtes ping.'
        
        message = f"""
{emoji} <b>Server Disk Monitor - ALERTE SERVEUR</b>

<b>Serveur:</b> {server_name}
<b>IP:</b> {server_ip}
<b>Nouveau statut:</b> {status_text}

<b>Description:</b>
{description}

<b>Timestamp:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """.strip()
        
        return message
    
    def check_disk_state_changes(self, current_disk_status):
        """Vérifie les changements d'état des disques et serveurs, envoie des notifications"""
        notifications_sent = []
        
        # NOUVEAU: Vérification des changements d'état des serveurs
        for server_name, server_data in current_disk_status.items():
            current_server_online = server_data.get('online', False)
            
            # Vérifier s'il y a un état précédent pour le serveur
            if server_name in self.previous_server_states:
                previous_server_online = self.previous_server_states[server_name]
                
                # Détecter les changements d'état du serveur
                if previous_server_online != current_server_online:
                    server_status = 'online' if current_server_online else 'offline'
                    
                    if self.telegram_config['enabled']:
                        server_message = self.format_server_telegram_message(
                            server_name,
                            server_data.get('ip', 'N/A'),
                            server_status
                        )
                        
                        if self.send_telegram_notification(server_message):
                            notifications_sent.append({
                                'type': 'telegram_server',
                                'server': server_name,
                                'change': f"SERVEUR {server_status.upper()}"
                            })
            
            # Mettre à jour l'état précédent du serveur
            self.previous_server_states[server_name] = current_server_online
        
        # Vérification existante des changements d'état des disques
        for server_name, server_data in current_disk_status.items():
            if not server_data.get('online', False):
                continue
            
            for position, disk_data in server_data.get('disks', {}).items():
                disk_key = f"{server_name}_{position}"
                current_state = {
                    'exists': disk_data.get('exists', False),
                    'mounted': disk_data.get('mounted', False),
                    'label': disk_data.get('label', 'Disque inconnu'),
                    'device': disk_data.get('device', 'N/A'),
                    'capacity': disk_data.get('capacity', 'N/A')
                }
                
                # Vérifier s'il y a un état précédent
                if disk_key in self.previous_disk_states:
                    previous_state = self.previous_disk_states[disk_key]
                    
                    # Détecter les changements critiques
                    changes = []
                    
                    # Disque démonté
                    if previous_state['mounted'] and not current_state['mounted']:
                        changes.append(f"❌ DISQUE DÉMONTÉ: {current_state['label']}")
                        
                    # Disque disparu
                    elif previous_state['exists'] and not current_state['exists']:
                        changes.append(f"🚨 DISQUE DISPARU: {current_state['label']}")
                    
                    # Disque remonté (bonne nouvelle)
                    elif not previous_state['mounted'] and current_state['mounted']:
                        changes.append(f"✅ DISQUE REMONTÉ: {current_state['label']}")
                    
                    # Disque réapparu
                    elif not previous_state['exists'] and current_state['exists']:
                        changes.append(f"🔄 DISQUE RÉAPPARU: {current_state['label']}")
                    
                    # Envoyer notification Telegram si changement détecté
                    if changes and self.telegram_config['enabled']:
                        telegram_message = self.format_telegram_message(
                            server_name, 
                            server_data.get('ip', 'N/A'),
                            position,
                            current_state['label'],
                            changes
                        )
                        
                        if self.send_telegram_notification(telegram_message):
                            notifications_sent.append({
                                'type': 'telegram',
                                'server': server_name,
                                'disk': current_state['label'],
                                'change': changes[0]
                            })
                
                # Mettre à jour l'état précédent
                self.previous_disk_states[disk_key] = current_state.copy()
        
        return notifications_sent

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
        
        # AJOUT: Gestionnaire de notifications avec référence au cipher
        self.notification_manager = NotificationManager(cipher=self.cipher)
        
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
        """Met à jour le statut de tous les disques avec notifications"""
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
        
        # AJOUT: Vérification des changements et notifications
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
        try:
            self.refresh_interval = max(10, new_interval)
            self.servers_config['refresh_interval'] = self.refresh_interval
            
            # Si la surveillance est active, recréer le job avec le nouvel intervalle
            if self.monitoring:
                # Vérifier et supprimer tous les anciens jobs de monitoring
                try:
                    if self.scheduler.get_job('disk_monitoring'):
                        self.scheduler.remove_job('disk_monitoring')
                        logger.info("Ancien job de monitoring supprimé")
                except Exception as e:
                    logger.warning(f"Erreur suppression ancien job: {e}")
                
                # Créer un nouveau job avec le nouvel intervalle
                try:
                    self.scheduler.add_job(
                        func=self.update_all_disk_status,
                        trigger="interval",
                        seconds=self.refresh_interval,
                        id='disk_monitoring',
                        replace_existing=True
                    )
                    logger.info(f"Nouveau job créé avec intervalle: {self.refresh_interval}s")
                except Exception as e:
                    logger.error(f"Erreur création nouveau job: {e}")
                    # En cas d'erreur, la surveillance continuera au prochain redémarrage
                    
        except Exception as e:
            logger.error(f"Erreur globale update_refresh_interval: {e}")
            # L'erreur n'est pas fatale, l'intervalle sera appliqué au redémarrage

# Instance globale
monitor = ServerDiskMonitorWeb()

# Routes Flask
@app.route('/')
def index():
    """Page principale"""
    return render_template('index.html', version=VERSION, build_date=BUILD_DATE)

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
            try:
                monitor.update_refresh_interval(data['refresh_interval'])
                monitor.save_config()
            except Exception as e:
                logger.warning(f"Erreur mise à jour intervalle: {e}")
                # Continuer malgré l'erreur - l'intervalle sera appliqué au prochain démarrage
        
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

# NOUVELLES ROUTES API pour les notifications Telegram

@app.route('/api/notifications/config', methods=['GET'])
def get_notification_config():
    """Récupère la configuration des notifications"""
    telegram_config = monitor.notification_manager.telegram_config.copy()
    
    # Masquer le token
    if telegram_config.get('bot_token'):
        telegram_config['bot_token'] = '***'
    
    return jsonify({'telegram': telegram_config})

@app.route('/api/notifications/config', methods=['POST'])
def update_notification_config():
    """Met à jour la configuration des notifications"""
    try:
        data = request.get_json()
        
        # Configuration Telegram
        telegram_config = data.get('telegram', {})
        for key, value in telegram_config.items():
            if key == 'bot_token' and value and value != '***':
                # CORRECTION: Chiffrer le token avec le cipher du monitor
                monitor.notification_manager.telegram_config[key] = monitor.encrypt_password(value)
            elif key != 'bot_token':
                monitor.notification_manager.telegram_config[key] = value
        
        # Sauvegarde
        if monitor.notification_manager.save_notification_config():
            return jsonify({'success': True, 'message': 'Configuration notifications mise à jour'})
        else:
            return jsonify({'success': False, 'error': 'Erreur sauvegarde'}), 500
            
    except Exception as e:
        logger.error(f"Erreur config notifications: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/notifications/test', methods=['POST'])
def test_notification():
    """Test d'envoi de notification Telegram"""
    try:
        message = f"""
🧪 <b>Test - Server Disk Monitor</b>

Test de notification TELEGRAM envoyé le {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Si vous recevez ce message, la configuration Telegram fonctionne correctement !

--
Server Disk Monitor
        """.strip()
        
        if monitor.notification_manager.send_telegram_notification(message):
            return jsonify({'success': True, 'message': 'Notification de test envoyée'})
        else:
            return jsonify({'success': False, 'error': 'Échec envoi notification'}), 500
            
    except Exception as e:
        logger.error(f"Erreur test notification: {e}")
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