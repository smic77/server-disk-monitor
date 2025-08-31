#!/usr/bin/env python3
"""
Module de gestion des notifications
Gère les alertes Telegram et la détection de changements d'état
"""

import json
import os
import base64
import requests
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class NotificationManager:
    def __init__(self, cipher=None, data_dir="data"):
        self.previous_disk_states = {}
        self.previous_server_states = {}
        self.telegram_config = {
            'enabled': False,
            'bot_token': '',
            'chat_ids': [],
            'parse_mode': 'HTML'
        }
        self.cipher = cipher
        self.data_dir = data_dir
        self.load_notification_config()
    
    def load_notification_config(self):
        """Charge la configuration des notifications"""
        config_file = os.path.join(self.data_dir, "notifications.json")
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
        os.makedirs(self.data_dir, exist_ok=True)
        config_file = os.path.join(self.data_dir, "notifications.json")
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
            if encrypted_token == '***':
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
            bot_token = self.decrypt_token(self.telegram_config['bot_token'])
            if not bot_token:
                logger.error("Impossible de déchiffrer le token Telegram")
                return False
            
            success_count = 0
            
            for chat_id in self.telegram_config['chat_ids']:
                if not chat_id:
                    continue
                    
                url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
                
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
        emoji_map = {
            'DÉMONTÉ': '❌',
            'DISPARU': '🚨',
            'REMONTÉ': '✅',
            'RÉAPPARU': '🔄'
        }
        
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
        
        # Vérification des changements d'état des serveurs
        for server_name, server_data in current_disk_status.items():
            current_server_online = server_data.get('online', False)
            
            if server_name in self.previous_server_states:
                previous_server_online = self.previous_server_states[server_name]
                
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
            
            self.previous_server_states[server_name] = current_server_online
        
        # Vérification des changements d'état des disques
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
                
                if disk_key in self.previous_disk_states:
                    previous_state = self.previous_disk_states[disk_key]
                    changes = []
                    
                    # Détecter les changements critiques
                    if previous_state['mounted'] and not current_state['mounted']:
                        changes.append(f"❌ DISQUE DÉMONTÉ: {current_state['label']}")
                    elif previous_state['exists'] and not current_state['exists']:
                        changes.append(f"🚨 DISQUE DISPARU: {current_state['label']}")
                    elif not previous_state['mounted'] and current_state['mounted']:
                        changes.append(f"✅ DISQUE REMONTÉ: {current_state['label']}")
                    elif not previous_state['exists'] and current_state['exists']:
                        changes.append(f"🔄 DISQUE RÉAPPARU: {current_state['label']}")
                    
                    # Envoyer notification si changement détecté
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
                
                self.previous_disk_states[disk_key] = current_state.copy()
        
        return notifications_sent