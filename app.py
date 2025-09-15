#!/usr/bin/env python3
"""
Server Disk Monitor - Version Web avec Notifications Telegram

Dashboard web moderne pour la surveillance en temps réel des disques durs
sur serveurs distants avec notifications Telegram intelligentes.

Fonctionnalités principales:
- Interface web responsive avec thèmes sombre/clair
- Surveillance temps réel via WebSocket
- Configuration flexible des serveurs et sections
- Notifications Telegram instantanées
- Chiffrement des mots de passe et tokens
- API REST complète
- Compatible Docker/Portainer

Architecture:
- Flask: Framework web principal
- SocketIO: Communication temps réel
- APScheduler: Tâches de surveillance automatisées
- Paramiko: Connexions SSH sécurisées
- Cryptography: Chiffrement des données sensibles

Auteur: Server Disk Monitor Team
License: MIT
Repository: https://github.com/smic77/server-disk-monitor
"""

# Version de l'application - Incrémentée automatiquement par Claude
VERSION = "5.0.4"
BUILD_DATE = "2025-09-15"

# =============================================================================
# IMPORTS DES DÉPENDANCES
# =============================================================================

# Framework web et communication temps réel
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS

# Utilitaires Python standard
import json
import os
import threading
import time
import subprocess
import uuid
import logging
from datetime import datetime

# Connexions SSH et sécurité
import paramiko
import base64
from cryptography.fernet import Fernet

# Planification des tâches et API externe
from apscheduler.schedulers.background import BackgroundScheduler
import requests

# =============================================================================
# CONFIGURATION DU LOGGING
# =============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# =============================================================================
# INITIALISATION DE L'APPLICATION FLASK
# =============================================================================

# Création de l'instance Flask principale
app = Flask(__name__)

# Configuration sécurisée de la clé secrète
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')

# Activation CORS pour permettre les requêtes cross-origin
CORS(app)

# Configuration SocketIO pour la communication temps réel
# - cors_allowed_origins="*": Permet toutes les origines (production: spécifier les domaines)
# - logger=True: Active les logs SocketIO pour le debug
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# =============================================================================
# GESTIONNAIRE DES NOTIFICATIONS
# =============================================================================

class NotificationManager:
    """
    Gestionnaire des notifications Telegram avec détection intelligente des changements.
    
    Cette classe gère:
    - L'envoi de notifications Telegram via l'API Bot
    - La détection des changements d'état des disques et serveurs
    - Le chiffrement/déchiffrement des tokens sensibles
    - La persistence de la configuration des notifications
    - La prévention des faux positifs via cache intelligent
    """
    
    def __init__(self, cipher=None):
        """
        Initialise le gestionnaire de notifications.
        
        Args:
            cipher (Fernet): Instance de chiffrement pour les tokens sensibles
        """
        # Cache des états précédents pour détecter les changements
        self.previous_disk_states = {}      # États des disques par serveur
        self.previous_server_states = {}    # États de connectivité des serveurs
        
        # Configuration par défaut des notifications Telegram
        self.telegram_config = {
            'enabled': False,        # Notifications désactivées par défaut
            'bot_token': '',         # Token du bot Telegram (chiffré)
            'chat_ids': [],         # Liste des IDs de chat destinations
            'parse_mode': 'HTML'    # Format des messages (HTML ou Markdown)
        }
        
        # Référence vers l'instance de chiffrement partagée
        self.cipher = cipher
        
        # Chargement de la configuration persistante
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
        
        # Plus de templates de serveurs - configuration libre par serveur

        # Configuration par défaut simplifiée
        self.default_config = {
            "servers": {
                "EXAMPLE-SERVER": {
                    "ip": "192.168.1.100",
                    "username": "root",
                    "password": "",
                    "sections": [
                        {
                            "name": "Section principale",
                            "rows": 2,
                            "cols": 6,
                            "orientation": "horizontal"
                        }
                    ],
                    "disk_mappings": {
                        "s0_0_0": {
                            "uuid": "example-uuid-1234-5678-90ab-cdef12345678",
                            "device": "/dev/sda",
                            "label": "Système",
                            "description": "Disque système principal",
                            "capacity": "256GB SSD",
                            "section": 0,
                            "row": 0,
                            "col": 0
                        },
                        "s0_0_1": {
                            "uuid": "example-uuid-2345-6789-01bc-def123456789",
                            "device": "/dev/sdb",
                            "label": "Données",
                            "description": "Stockage des données",
                            "capacity": "1TB HDD",
                            "section": 0,
                            "row": 0,
                            "col": 1
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
        
        # Cache spécialisé pour les données SMART (durée de vie plus longue)
        self.smart_cache = {}
        
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
                    # Nettoyage des champs legacy
                    # Migration supprimée - le système de sections est maintenant standard
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
    
    # Méthode supprimée : plus de templates de serveurs
    
    # Méthode supprimée : plus de templates de serveurs
    
    # Méthode supprimée : plus de templates de serveurs
    
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
    
    def generate_all_positions(self, server_config):
        """Générer toutes les positions possibles basées sur les sections du serveur"""
        all_positions = set()
        
        # Récupérer les sections configurées
        sections = server_config.get('sections', [])
        
        if not sections:
            # Si pas de sections, vérifier s'il y a d'anciennes configurations rack
            if server_config.get('front_rack', {}).get('enabled'):
                rack = server_config['front_rack']
                for row in range(rack.get('rows', 0)):
                    for col in range(rack.get('cols', 0)):
                        all_positions.add(f"front_{row}_{col}")
            
            if server_config.get('back_rack', {}).get('enabled'):
                rack = server_config['back_rack']
                for row in range(rack.get('rows', 0)):
                    for col in range(rack.get('cols', 0)):
                        all_positions.add(f"back_{row}_{col}")
        else:
            # Générer positions basées sur les sections
            for section_index, section in enumerate(sections):
                rows = section.get('rows', 0)
                cols = section.get('cols', 0)
                
                for row in range(rows):
                    for col in range(cols):
                        position = f"s{section_index}_{row}_{col}"
                        all_positions.add(position)
        
        return sorted(all_positions)
    
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
    
    def check_disk_smart(self, server_config, disk_info):
        """
        Collecte les données SMART d'un disque via SSH
        
        Args:
            server_config (dict): Configuration du serveur
            disk_info (dict): Information du disque avec 'device'
            
        Returns:
            dict: Données SMART {health_status, temperature, power_on_hours, reallocated_sectors}
        """
        cache_key = f"smart_{server_config['ip']}_{disk_info['device']}"
        
        try:
            # Vérifier si mot de passe configuré
            if not server_config.get('password'):
                return {"health_status": "UNKNOWN", "temperature": None, "error": "No password configured"}
            
            # Déchiffrer le mot de passe
            encrypted_password = server_config['password']
            if encrypted_password == '***':
                return {"health_status": "UNKNOWN", "temperature": None, "error": "Password masked"}
            
            try:
                encrypted_bytes = base64.b64decode(encrypted_password.encode())
                password = self.cipher.decrypt(encrypted_bytes).decode()
            except Exception as e:
                logger.error(f"Erreur déchiffrement mot de passe: {e}")
                return {"health_status": "UNKNOWN", "temperature": None, "error": "Password decrypt failed"}
            
            # Connexion SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(
                hostname=server_config['ip'],
                username=server_config['username'],
                password=password,
                timeout=10
            )
            
            device = disk_info['device']
            smart_data = {"health_status": "UNKNOWN", "temperature": None}
            
            # 1. Vérifier d'abord si smartctl est disponible et le device accessible
            stdin, stdout, stderr = ssh.exec_command(f"which smartctl")
            smartctl_path = stdout.read().decode('utf-8', errors='ignore').strip()
            if not smartctl_path:
                logger.warning(f"smartctl non trouvé sur {server_config['ip']}")
                smart_data["health_status"] = "ERROR"
                smart_data["error"] = "smartctl not found"
                return smart_data
            
            # 2. Tester l'accès au device avec PTY et environnement complet
            stdin, stdout, stderr = ssh.exec_command(
                f"sudo /usr/sbin/smartctl -i {device}", 
                get_pty=True, 
                environment={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
            )
            device_info = stdout.read().decode('utf-8', errors='ignore')
            device_error = stderr.read().decode('utf-8', errors='ignore')
            
            logger.info(f"SMART device info for {device}: {device_info[:200]}...")
            if device_error:
                logger.warning(f"SMART device error for {device}: {device_error}")
            
            # Vérifier si le device supporte SMART
            if "SMART support is" in device_info and "Disabled" in device_info:
                logger.warning(f"SMART disabled on {device}")
                smart_data["health_status"] = "DISABLED"
                smart_data["error"] = "SMART disabled"
                return smart_data
            
            # 3. Vérifier l'état de santé global avec PTY
            stdin, stdout, stderr = ssh.exec_command(
                f"sudo /usr/sbin/smartctl -H {device}",
                get_pty=True,
                environment={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
            )
            health_output = stdout.read().decode('utf-8', errors='ignore')
            health_error = stderr.read().decode('utf-8', errors='ignore')
            
            logger.info(f"SMART health for {device}: {health_output}")
            if health_error:
                logger.warning(f"SMART health error for {device}: {health_error}")
            
            # Parsing plus robuste de l'état de santé
            if "PASSED" in health_output or "OK" in health_output:
                smart_data["health_status"] = "PASSED"
            elif "FAILED" in health_output or "FAILING_NOW" in health_output:
                smart_data["health_status"] = "FAILED"
            elif "unavailable" in health_output.lower() or "not supported" in health_output.lower():
                smart_data["health_status"] = "UNSUPPORTED"
                smart_data["error"] = "SMART not supported by device"
            else:
                smart_data["health_status"] = "UNKNOWN"
                smart_data["error"] = f"Unparseable health output: {health_output[:100]}"
            
            # 4. Récupérer la température avec PTY
            stdin, stdout, stderr = ssh.exec_command(
                f"sudo /usr/sbin/smartctl -A {device}",
                get_pty=True,
                environment={'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin'}
            )
            temp_output = stdout.read().decode('utf-8', errors='ignore')
            
            logger.info(f"SMART attributes for {device}: {temp_output[:300]}...")
            
            # Parsing de température plus robuste
            import re
            # Méthode 1: Format standard avec Temperature_Celsius
            temp_match = re.search(r'Temperature_Celsius.*?(\d+)', temp_output)
            if temp_match:
                smart_data["temperature"] = int(temp_match.group(1))
            else:
                # Méthode 2: Recherche générale de température
                temp_match = re.search(r'(?i)temperature.*?(\d+)', temp_output)
                if temp_match:
                    smart_data["temperature"] = int(temp_match.group(1))
                else:
                    # Méthode 3: Parsing par ligne
                    for line in temp_output.split('\n'):
                        if 'temperature' in line.lower():
                            numbers = re.findall(r'\b(\d+)\b', line)
                            if numbers:
                                # Prendre le premier nombre raisonnable (20-100°C)
                                for num in numbers:
                                    temp_val = int(num)
                                    if 20 <= temp_val <= 100:
                                        smart_data["temperature"] = temp_val
                                        break
                                if smart_data["temperature"]:
                                    break
            
            ssh.close()
            
            # Mettre en cache avec durée de vie plus longue (SMART change lentement)
            self.smart_cache[cache_key] = {
                'data': smart_data,
                'timestamp': time.time(),
                'ttl': 300  # 5 minutes de cache pour SMART
            }
            
            return smart_data
            
        except Exception as e:
            logger.error(f"Erreur collecte SMART pour {server_config['ip']}: {e}")
            
            # Utiliser cache si disponible
            if cache_key in self.smart_cache:
                cached = self.smart_cache[cache_key]
                if time.time() - cached['timestamp'] < cached['ttl']:
                    return cached['data']
            
            return {"health_status": "ERROR", "temperature": None, "error": str(e)}
    
    def update_all_disk_status(self):
        """Met à jour le statut de tous les disques avec notifications"""
        logger.info("Mise à jour du statut des disques...")
        
        total_disks = 0
        mounted_disks = 0
        online_servers = 0
        
        logger.info(f"Traitement de {len(self.servers_config.get('servers', {}))} serveurs")
        
        for server_name, config in self.servers_config.get('servers', {}).items():
            try:
                logger.info(f"Traitement du serveur {server_name}...")
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
                
                # Générer toutes les positions possibles basées sur les sections
                all_positions = self.generate_all_positions(config)
                disk_mappings = config.get('disk_mappings', {})
                
                logger.info(f"Serveur {server_name}: {len(all_positions)} positions générées, {len(disk_mappings)} configurées")
                
                for position in all_positions:
                    disk_info = disk_mappings.get(position)
                    
                    if disk_info:
                        # Position configurée - vérification SSH normale
                        total_disks += 1
                        
                        if server_online:
                            disk_status = self.check_disk_ssh(config, disk_info)
                            if disk_status['mounted']:
                                mounted_disks += 1
                            
                            # Collecter données SMART si le disque existe
                            smart_data = {"health_status": "UNKNOWN", "temperature": None}
                            if disk_status['exists'] and disk_info.get('device'):
                                try:
                                    smart_data = self.check_disk_smart(config, disk_info)
                                except Exception as e:
                                    logger.error(f"Erreur collecte SMART pour {position}: {e}")
                        else:
                            disk_status = {"exists": False, "mounted": False}
                            smart_data = {"health_status": "UNKNOWN", "temperature": None}
                        
                        server_status["disks"][position] = {
                            "uuid": disk_info['uuid'],
                            "device": disk_info['device'],
                            "label": disk_info.get('label', ''),
                            "capacity": disk_info.get('capacity', ''),
                            "description": disk_info.get('description', ''),
                            "exists": disk_status['exists'],
                            "mounted": disk_status['mounted'],
                            # Nouvelles données SMART
                            "smart_health": smart_data.get("health_status", "UNKNOWN"),
                            "smart_temperature": smart_data.get("temperature"),
                            "smart_error": smart_data.get("error")
                        }
                    else:
                        # Position non configurée - slot vide
                        server_status["disks"][position] = {
                            "uuid": "",
                            "device": "",
                            "label": "",
                            "capacity": "",
                            "description": "",
                            "exists": False,
                            "mounted": False,
                            # Données SMART vides pour slots vides
                            "smart_health": "EMPTY",
                            "smart_temperature": None,
                            "smart_error": None
                        }
                
                self.disk_status[server_name] = server_status
                logger.info(f"Serveur {server_name} traité avec succès - {len(server_status['disks'])} positions")
                
            except Exception as e:
                logger.error(f"ERREUR lors du traitement du serveur {server_name}: {e}")
                logger.error(f"Stack trace:", exc_info=True)
                # Créer un status minimal pour éviter de casser l'affichage
                error_status = {
                    "name": server_name,
                    "online": False,
                    "ip": config.get('ip', ''),
                    "username": config.get('username', ''),
                    "disks": {}
                }
                self.disk_status[server_name] = error_status
                continue
        
        self.last_update = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Debug: vérifier que les serveurs sont bien ajoutés
        logger.info(f"Serveurs dans disk_status: {list(self.disk_status.keys())}")
        logger.debug(f"Contenu disk_status: {self.disk_status}")
        
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
    
    def get_clean_config_for_export(self):
        """Retourne la configuration nettoyée pour l'export"""
        clean_config = {}
        
        for server_name, config in self.servers_config.get('servers', {}).items():
            clean_server = {}
            
            # Données de base (sans server_template)
            for field in ['ip', 'username']:
                if field in config:
                    clean_server[field] = config[field]
            
            # Masquer le mot de passe mais l'inclure pour indiquer qu'il existe
            clean_server['password'] = '***' if config.get('password') else ''
            
            # Inclure tous les disk_mappings sans filtrage
            if 'disk_mappings' in config:
                clean_server['disk_mappings'] = config['disk_mappings']
            
            clean_config[server_name] = clean_server
        
        return clean_config, []
    
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

@app.route('/api/smart/test/<server_name>/<path:device>', methods=['GET'])
def test_smart_device(server_name, device):
    """Test SMART pour un device spécifique avec logs détaillés"""
    try:
        if server_name not in monitor.servers_config.get('servers', {}):
            return jsonify({'success': False, 'error': 'Serveur non trouvé'}), 404
        
        server_config = monitor.servers_config['servers'][server_name]
        disk_info = {'device': f"/{device}"}  # Reconstituer le path device
        
        logger.info(f"Test SMART manuel pour {server_name}:{device}")
        smart_result = monitor.check_disk_smart(server_config, disk_info)
        
        return jsonify({
            'success': True, 
            'server': server_name,
            'device': f"/{device}",
            'smart_data': smart_result
        })
        
    except Exception as e:
        logger.error(f"Erreur test SMART {server_name}:{device}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/server-types', methods=['POST'])
def update_server_types():
    """Met à jour les types de serveurs"""
    try:
        data = request.get_json()
        logger.info(f"Mise à jour types serveurs: {data}")
        
        if not data:
            return jsonify({'success': False, 'error': 'Données manquantes'}), 400
        
        # Valider que toutes les clés correspondent à des serveurs existants
        for server_name in data.keys():
            if server_name not in monitor.servers_config.get('servers', {}):
                return jsonify({'success': False, 'error': f'Serveur inconnu: {server_name}'}), 400
        
        # Mettre à jour les types de serveurs
        for server_name, server_type in data.items():
            if server_name in monitor.servers_config['servers']:
                monitor.servers_config['servers'][server_name]['server_type'] = server_type
                logger.info(f"Type serveur mis à jour: {server_name} -> {server_type}")
        
        # Sauvegarder la configuration
        if monitor.save_config():
            return jsonify({'success': True, 'message': f'{len(data)} type(s) de serveur(s) mis à jour'})
        else:
            return jsonify({'success': False, 'error': 'Erreur lors de la sauvegarde'}), 500
            
    except Exception as e:
        logger.error(f"Erreur mise à jour types serveurs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# Route supprimée : plus de templates de serveurs

# Route supprimée : plus de templates de serveurs

@app.route('/api/export/complete', methods=['GET'])
def export_complete_config():
    """Export complet de toute la configuration dans un format unifié"""
    try:
        # Configuration serveurs (nettoyée, sans données obsolètes)
        servers_config, export_warnings = monitor.get_clean_config_for_export()
        
        # Plus de templates de serveurs
        
        # Configuration notifications (masquer le token)
        notifications_config = monitor.notification_manager.telegram_config.copy()
        if notifications_config.get('bot_token'):
            notifications_config['bot_token'] = '***'
        
        # Format unifié simple et lisible
        complete_config = {
            "server_disk_monitor_config": {
                "version": "2025.01.01",
                "export_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "description": "Configuration complète Server Disk Monitor"
            },
            "global_settings": {
                "refresh_interval": monitor.refresh_interval
            },
            "servers": servers_config,
            "notifications": {
                "telegram": notifications_config
            }
        }
        
        # Ajouter les avertissements d'export s'il y en a
        if export_warnings:
            complete_config["server_disk_monitor_config"]["export_warnings"] = export_warnings
        
        return jsonify(complete_config)
    except Exception as e:
        logger.error(f"Erreur export complet: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/import/complete', methods=['POST'])
def import_complete_config():
    """Import complet depuis un format unifié"""
    try:
        data = request.get_json()
        
        # Vérification du format
        if 'server_disk_monitor_config' not in data:
            return jsonify({'success': False, 'error': 'Format d\'import invalide'}), 400
        
        success_messages = []
        
        # Import des paramètres globaux
        if 'global_settings' in data:
            monitor.refresh_interval = data['global_settings'].get('refresh_interval', 30)
            success_messages.append("Paramètres globaux")
        
        # Import des serveurs
        if 'servers' in data:
            # Préserver les mots de passe existants pour les serveurs déjà configurés
            for server_name, new_config in data['servers'].items():
                if server_name in monitor.servers_config.get('servers', {}):
                    old_password = monitor.servers_config['servers'][server_name].get('password', '')
                    if old_password and not new_config.get('password'):
                        new_config['password'] = old_password
            
            # Mise à jour de la configuration serveurs
            monitor.servers_config['servers'] = data['servers']
            monitor.servers_config['refresh_interval'] = monitor.refresh_interval
            
            # Sauvegarde
            if monitor.save_config():
                success_messages.append(f"{len(data['servers'])} serveur(s)")
        
        # Plus d'import de templates de serveurs
        
        # Import des notifications
        if 'notifications' in data and 'telegram' in data['notifications']:
            telegram_config = data['notifications']['telegram']
            
            # Gérer le token masqué
            if telegram_config.get('bot_token') == '***':
                # Garder le token existant
                telegram_config['bot_token'] = monitor.notification_manager.telegram_config.get('bot_token', '')
            elif telegram_config.get('bot_token'):
                # Chiffrer le nouveau token
                encrypted_token = monitor.cipher.encrypt(telegram_config['bot_token'].encode()).decode()
                telegram_config['bot_token'] = encrypted_token
            
            # Mise à jour de la configuration
            monitor.notification_manager.telegram_config.update(telegram_config)
            if monitor.notification_manager.save_notification_config():
                success_messages.append("Notifications")
        
        # Rafraîchissement pour appliquer les changements
        threading.Thread(target=monitor.update_all_disk_status, daemon=True).start()
        
        message = f"Configuration importée: {', '.join(success_messages)}"
        logger.info(message)
        return jsonify({'success': True, 'message': message})
        
    except Exception as e:
        logger.error(f"Erreur import complet: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/save_server_order', methods=['POST'])
def save_server_order():
    """Sauvegarde l'ordre d'affichage des serveurs"""
    try:
        data = request.get_json()
        
        # Vérifier que les données sont valides
        if not data or not isinstance(data, dict):
            return jsonify({'success': False, 'error': 'Données invalides'}), 400
        
        # Mettre à jour l'ordre d'affichage pour chaque serveur
        servers_config = monitor.servers_config.get('servers', {})
        
        for server_name, display_order in data.items():
            if server_name in servers_config:
                servers_config[server_name]['display_order'] = int(display_order)
        
        # Sauvegarder la configuration
        if monitor.save_config():
            logger.info(f"Ordre des serveurs mis à jour: {data}")
            return jsonify({'success': True, 'message': 'Ordre des serveurs sauvegardé'})
        else:
            return jsonify({'success': False, 'error': 'Erreur lors de la sauvegarde'}), 500
            
    except Exception as e:
        logger.error(f"Erreur sauvegarde ordre serveurs: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/server/<server_name>/delete', methods=['DELETE'])
def delete_server(server_name):
    """Supprime un serveur de la configuration"""
    try:
        # Vérifier que le serveur existe
        if server_name not in monitor.servers_config.get('servers', {}):
            return jsonify({'success': False, 'error': 'Serveur non trouvé'}), 404
        
        # Supprimer le serveur de la configuration
        del monitor.servers_config['servers'][server_name]
        
        # Sauvegarder la configuration
        if monitor.save_config():
            logger.info(f"Serveur supprimé: {server_name}")
            return jsonify({'success': True, 'message': f'Serveur {server_name} supprimé'})
        else:
            return jsonify({'success': False, 'error': 'Erreur lors de la sauvegarde'}), 500
            
    except Exception as e:
        logger.error(f"Erreur suppression serveur {server_name}: {e}")
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