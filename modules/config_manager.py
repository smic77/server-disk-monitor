#!/usr/bin/env python3
"""
Module de gestion de configuration
Gère le chargement, sauvegarde et chiffrement des configurations
"""

import json
import os
import base64
import logging
from cryptography.fernet import Fernet

logger = logging.getLogger(__name__)

class ConfigManager:
    def __init__(self, data_dir="/app/data"):
        self.data_dir = data_dir
        self.config_file = os.path.join(self.data_dir, "config.json")
        self.cipher_key_file = os.path.join(self.data_dir, "cipher.key")
        
        # Création du répertoire de données
        os.makedirs(self.data_dir, exist_ok=True)
        
        # Initialisation du chiffrement
        self.init_encryption()
        
        # Configuration par défaut (compatible avec format existant)
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
    
    def init_encryption(self):
        """Initialise le système de chiffrement - COMPATIBLE avec format existant"""
        if os.path.exists(self.cipher_key_file):
            with open(self.cipher_key_file, 'rb') as f:
                self.cipher_key = f.read()
            logger.info("Clé de chiffrement existante chargée")
        else:
            self.cipher_key = Fernet.generate_key()
            with open(self.cipher_key_file, 'wb') as f:
                f.write(self.cipher_key)
            logger.info("Nouvelle clé de chiffrement générée")
        
        self.cipher = Fernet(self.cipher_key)
    
    def load_config(self):
        """Charge la configuration depuis le fichier - COMPATIBLE format existant"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    
                # Migration automatique si nécessaire (ajout de champs manquants)
                config = self._migrate_config(config)
                    
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
    
    def _migrate_config(self, config):
        """Migration automatique de configuration - ASSURE LA COMPATIBILITÉ"""
        # Assurer que tous les champs obligatoires existent
        if 'servers' not in config:
            config['servers'] = {}
        
        if 'refresh_interval' not in config:
            config['refresh_interval'] = 30
        
        # Migration des serveurs
        for server_name, server_config in config['servers'].items():
            # Champs serveur obligatoires avec valeurs par défaut
            server_defaults = {
                'ip': '127.0.0.1',
                'username': 'root',
                'password': '',
                'front_rack': {
                    'enabled': True,
                    'rows': 2,
                    'cols': 3,
                    'total_slots': 6
                },
                'back_rack': {
                    'enabled': False,
                    'rows': 0,
                    'cols': 0,
                    'total_slots': 0
                },
                'disk_mappings': {}
            }
            
            # Appliquer les valeurs par défaut pour les champs manquants
            for key, default_value in server_defaults.items():
                if key not in server_config:
                    server_config[key] = default_value
                    logger.info(f"Ajout du champ manquant '{key}' pour le serveur '{server_name}'")
            
            # Migration des disk_mappings
            if 'disk_mappings' in server_config:
                for position, disk_info in server_config['disk_mappings'].items():
                    disk_defaults = {
                        'uuid': '',
                        'device': '/dev/sdX',
                        'label': 'Disque inconnu',
                        'description': 'Description manquante',
                        'capacity': 'Inconnue'
                    }
                    
                    for key, default_value in disk_defaults.items():
                        if key not in disk_info:
                            disk_info[key] = default_value
        
        return config
    
    def save_config(self, config):
        """Sauvegarde la configuration dans le fichier"""
        return self.save_config_to_file(config)
    
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
        """Chiffre un mot de passe - COMPATIBLE avec format existant"""
        if not password:
            return ""
        encrypted = self.cipher.encrypt(password.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_password(self, encrypted_password):
        """Déchiffre un mot de passe - COMPATIBLE avec format existant"""
        if not encrypted_password:
            return ""
        try:
            encrypted_bytes = base64.b64decode(encrypted_password.encode())
            return self.cipher.decrypt(encrypted_bytes).decode()
        except Exception as e:
            logger.error(f"Erreur déchiffrement mot de passe: {e}")
            return ""
    
    def encrypt_token(self, token):
        """Chiffre un token (pour Telegram) - COMPATIBLE avec format existant"""
        return self.encrypt_password(token)
    
    def decrypt_token(self, encrypted_token):
        """Déchiffre un token - COMPATIBLE avec format existant"""
        return self.decrypt_password(encrypted_token)
    
    def validate_config(self, config):
        """Valide une configuration avant sauvegarde"""
        if not isinstance(config, dict):
            return False, "Configuration doit être un dictionnaire"
        
        if 'servers' not in config:
            return False, "Section 'servers' manquante"
        
        if not isinstance(config['servers'], dict):
            return False, "Section 'servers' doit être un dictionnaire"
        
        # Validation basique des serveurs
        for server_name, server_config in config['servers'].items():
            if not isinstance(server_config, dict):
                return False, f"Configuration serveur '{server_name}' invalide"
            
            required_fields = ['ip', 'username']
            for field in required_fields:
                if field not in server_config:
                    return False, f"Champ '{field}' manquant pour le serveur '{server_name}'"
        
        return True, "Configuration valide"
    
    def get_server_config(self, server_name, config):
        """Récupère la configuration d'un serveur spécifique"""
        return config.get('servers', {}).get(server_name, {})
    
    def update_server_password(self, config, server_name, password):
        """Met à jour le mot de passe d'un serveur"""
        if server_name in config.get('servers', {}):
            encrypted_password = self.encrypt_password(password)
            config['servers'][server_name]['password'] = encrypted_password
            return True
        return False