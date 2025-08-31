#!/usr/bin/env python3
"""
Validateur et sanitizer JSON pour l'application Server Disk Monitor
Sécurise les endpoints contre les données malveillantes
"""

import json
import re
import ipaddress
import uuid
from typing import Dict, Any, Union, List, Optional
from functools import wraps
from flask import request, jsonify
import logging

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Exception pour les erreurs de validation"""
    pass

class JSONValidator:
    """Validateur et sanitizer pour les données JSON"""
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 255, allowed_chars: Optional[str] = None) -> str:
        """Nettoie et valide une chaîne de caractères"""
        if not isinstance(value, str):
            raise ValidationError(f"Attendu une chaîne, reçu {type(value).__name__}")
        
        # Limite de longueur
        if len(value) > max_length:
            raise ValidationError(f"Chaîne trop longue (max {max_length} caractères)")
        
        # Caractères autorisés
        if allowed_chars:
            if not re.match(allowed_chars, value):
                raise ValidationError(f"Caractères non autorisés dans la chaîne")
        
        # Suppression des caractères de contrôle dangereux
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]', '', value)
        
        return sanitized.strip()
    
    @staticmethod
    def validate_ip_address(ip: str) -> str:
        """Valide une adresse IP"""
        try:
            # Valide IPv4 ou IPv6
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValidationError(f"Adresse IP invalide: {ip}")
    
    @staticmethod
    def validate_username(username: str) -> str:
        """Valide un nom d'utilisateur"""
        username = JSONValidator.sanitize_string(
            username, 
            max_length=32, 
            allowed_chars=r'^[a-zA-Z0-9_.-]+$'
        )
        
        if len(username) < 1:
            raise ValidationError("Nom d'utilisateur vide")
        
        return username
    
    @staticmethod
    def validate_server_name(name: str) -> str:
        """Valide un nom de serveur"""
        name = JSONValidator.sanitize_string(
            name,
            max_length=64,
            allowed_chars=r'^[a-zA-Z0-9_.-]+$'
        )
        
        if len(name) < 1:
            raise ValidationError("Nom de serveur vide")
        
        return name
    
    @staticmethod
    def validate_uuid(uuid_str: str) -> str:
        """Valide un UUID"""
        uuid_str = JSONValidator.sanitize_string(uuid_str, max_length=128)
        
        # Pattern UUID flexible
        if not re.match(r'^[a-fA-F0-9-]{8,36}$', uuid_str):
            raise ValidationError(f"Format UUID invalide: {uuid_str}")
        
        return uuid_str
    
    @staticmethod
    def validate_device_path(device: str) -> str:
        """Valide un chemin de périphérique"""
        device = JSONValidator.sanitize_string(
            device,
            max_length=64,
            allowed_chars=r'^[a-zA-Z0-9/_.-]+$'
        )
        
        if not device.startswith('/dev/'):
            raise ValidationError("Le périphérique doit commencer par /dev/")
        
        return device
    
    @staticmethod
    def validate_positive_integer(value: Union[int, str], min_val: int = 0, max_val: int = 10000) -> int:
        """Valide un entier positif"""
        try:
            if isinstance(value, str):
                int_value = int(value)
            else:
                int_value = int(value)
            
            if not min_val <= int_value <= max_val:
                raise ValidationError(f"Entier hors limites ({min_val}-{max_val}): {int_value}")
            
            return int_value
            
        except (ValueError, TypeError):
            raise ValidationError(f"Entier invalide: {value}")
    
    @staticmethod
    def validate_rack_config(rack_config: Dict[str, Any]) -> Dict[str, Any]:
        """Valide la configuration d'un rack"""
        if not isinstance(rack_config, dict):
            raise ValidationError("Configuration rack doit être un objet")
        
        validated = {}
        
        # Champs obligatoires avec validation
        validated['enabled'] = bool(rack_config.get('enabled', False))
        validated['rows'] = JSONValidator.validate_positive_integer(
            rack_config.get('rows', 0), min_val=0, max_val=50
        )
        validated['cols'] = JSONValidator.validate_positive_integer(
            rack_config.get('cols', 0), min_val=0, max_val=50
        )
        validated['total_slots'] = JSONValidator.validate_positive_integer(
            rack_config.get('total_slots', 0), min_val=0, max_val=2500
        )
        
        # Vérification de cohérence
        if validated['enabled'] and (validated['rows'] * validated['cols'] != validated['total_slots']):
            raise ValidationError("total_slots doit égaler rows × cols")
        
        return validated
    
    @staticmethod
    def validate_disk_mapping(disk_info: Dict[str, Any]) -> Dict[str, Any]:
        """Valide les informations d'un disque"""
        if not isinstance(disk_info, dict):
            raise ValidationError("Informations disque doivent être un objet")
        
        validated = {}
        
        # UUID obligatoire
        if 'uuid' not in disk_info:
            raise ValidationError("UUID du disque manquant")
        validated['uuid'] = JSONValidator.validate_uuid(disk_info['uuid'])
        
        # Device obligatoire
        if 'device' not in disk_info:
            raise ValidationError("Périphérique du disque manquant")
        validated['device'] = JSONValidator.validate_device_path(disk_info['device'])
        
        # Champs optionnels
        validated['label'] = JSONValidator.sanitize_string(
            disk_info.get('label', ''), max_length=128
        ) or 'Disque sans nom'
        
        validated['description'] = JSONValidator.sanitize_string(
            disk_info.get('description', ''), max_length=256
        ) or 'Aucune description'
        
        validated['capacity'] = JSONValidator.sanitize_string(
            disk_info.get('capacity', ''), max_length=64
        ) or 'Inconnue'
        
        return validated
    
    @staticmethod
    def validate_server_config(server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Valide la configuration complète d'un serveur"""
        if not isinstance(server_config, dict):
            raise ValidationError("Configuration serveur doit être un objet")
        
        validated = {}
        
        # IP obligatoire
        if 'ip' not in server_config:
            raise ValidationError("Adresse IP manquante")
        validated['ip'] = JSONValidator.validate_ip_address(server_config['ip'])
        
        # Username obligatoire
        if 'username' not in server_config:
            raise ValidationError("Nom d'utilisateur manquant")
        validated['username'] = JSONValidator.validate_username(server_config['username'])
        
        # Mot de passe optionnel (peut être vide)
        validated['password'] = JSONValidator.sanitize_string(
            server_config.get('password', ''), max_length=1024
        )
        
        # Racks
        validated['front_rack'] = JSONValidator.validate_rack_config(
            server_config.get('front_rack', {'enabled': False, 'rows': 0, 'cols': 0, 'total_slots': 0})
        )
        
        validated['back_rack'] = JSONValidator.validate_rack_config(
            server_config.get('back_rack', {'enabled': False, 'rows': 0, 'cols': 0, 'total_slots': 0})
        )
        
        # Disk mappings
        disk_mappings = server_config.get('disk_mappings', {})
        if not isinstance(disk_mappings, dict):
            raise ValidationError("disk_mappings doit être un objet")
        
        validated['disk_mappings'] = {}
        for position, disk_info in disk_mappings.items():
            # Valider la position
            position_clean = JSONValidator.sanitize_string(
                position, max_length=32, allowed_chars=r'^[a-zA-Z0-9_-]+$'
            )
            validated['disk_mappings'][position_clean] = JSONValidator.validate_disk_mapping(disk_info)
        
        return validated
    
    @staticmethod
    def validate_full_config(config: Dict[str, Any]) -> Dict[str, Any]:
        """Valide une configuration complète"""
        if not isinstance(config, dict):
            raise ValidationError("Configuration doit être un objet JSON")
        
        validated = {}
        
        # Serveurs
        servers = config.get('servers', {})
        if not isinstance(servers, dict):
            raise ValidationError("Section 'servers' doit être un objet")
        
        validated['servers'] = {}
        for server_name, server_config in servers.items():
            server_name_clean = JSONValidator.validate_server_name(server_name)
            validated['servers'][server_name_clean] = JSONValidator.validate_server_config(server_config)
        
        # Refresh interval
        validated['refresh_interval'] = JSONValidator.validate_positive_integer(
            config.get('refresh_interval', 30), min_val=10, max_val=3600
        )
        
        return validated
    
    @staticmethod
    def validate_telegram_config(telegram_config: Dict[str, Any]) -> Dict[str, Any]:
        """Valide la configuration Telegram"""
        if not isinstance(telegram_config, dict):
            raise ValidationError("Configuration Telegram doit être un objet")
        
        validated = {}
        
        # Enabled
        validated['enabled'] = bool(telegram_config.get('enabled', False))
        
        # Bot token
        bot_token = telegram_config.get('bot_token', '')
        if bot_token and bot_token != '***':  # *** = token masqué
            # Valider le format du token Telegram
            if not re.match(r'^[0-9]+:[a-zA-Z0-9_-]+$', bot_token):
                raise ValidationError("Format de token Telegram invalide")
        validated['bot_token'] = JSONValidator.sanitize_string(bot_token, max_length=256)
        
        # Chat IDs
        chat_ids = telegram_config.get('chat_ids', [])
        if not isinstance(chat_ids, list):
            raise ValidationError("chat_ids doit être un tableau")
        
        validated['chat_ids'] = []
        for chat_id in chat_ids:
            # Nettoyer et valider les chat IDs
            chat_id_str = JSONValidator.sanitize_string(str(chat_id), max_length=32)
            if chat_id_str and re.match(r'^-?[0-9]+$', chat_id_str):
                validated['chat_ids'].append(chat_id_str)
        
        # Parse mode
        parse_mode = telegram_config.get('parse_mode', 'HTML')
        if parse_mode not in ['HTML', 'Markdown', 'MarkdownV2']:
            parse_mode = 'HTML'
        validated['parse_mode'] = parse_mode
        
        return validated

def validate_json(schema_name: str):
    """Décorateur pour valider automatiquement les données JSON des routes Flask"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Obtenir les données JSON
                data = request.get_json(force=True, silent=True)
                if data is None:
                    return jsonify({
                        'success': False,
                        'error': 'Données JSON manquantes ou invalides'
                    }), 400
                
                # Validation selon le schéma
                if schema_name == 'server_config':
                    validated_data = JSONValidator.validate_full_config(data)
                elif schema_name == 'telegram_config':
                    telegram_data = data.get('telegram', {})
                    validated_data = {'telegram': JSONValidator.validate_telegram_config(telegram_data)}
                elif schema_name == 'password_update':
                    password = JSONValidator.sanitize_string(
                        data.get('password', ''), max_length=256
                    )
                    validated_data = {'password': password}
                else:
                    validated_data = data  # Pas de validation spécifique
                
                # Injecter les données validées dans la requête
                request.validated_json = validated_data
                
                return f(*args, **kwargs)
                
            except ValidationError as e:
                logger.warning(f"Erreur validation JSON: {e}")
                return jsonify({
                    'success': False,
                    'error': f'Données invalides: {str(e)}'
                }), 400
            except Exception as e:
                logger.error(f"Erreur validation inattendue: {e}")
                return jsonify({
                    'success': False,
                    'error': 'Erreur de validation interne'
                }), 500
        
        return decorated_function
    return decorator

def get_validated_json():
    """Récupère les données JSON validées depuis la requête"""
    return getattr(request, 'validated_json', {})