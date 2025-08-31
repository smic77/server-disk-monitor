#!/usr/bin/env python3
"""
Server Disk Monitor - Version Optimisée pour Portainer
Dashboard de surveillance des disques durs avec améliorations de performance intégrées
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
from datetime import datetime, timedelta
import requests
import socket
import hashlib
import ipaddress
import re
from typing import Dict, Any, Optional, Callable, Tuple, List, Union
from functools import wraps
from enum import Enum
from dataclasses import dataclass

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Logging de sécurité
security_logger = logging.getLogger('security')
security_handler = logging.StreamHandler()
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
))
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.WARNING)

# Initialisation de l'application Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

# === CLASSES D'AMÉLIORATION INTÉGRÉES ===

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
        
        if len(value) > max_length:
            raise ValidationError(f"Chaîne trop longue (max {max_length} caractères)")
        
        if allowed_chars and not re.match(allowed_chars, value):
            raise ValidationError(f"Caractères non autorisés dans la chaîne")
        
        sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]', '', value)
        return sanitized.strip()
    
    @staticmethod
    def validate_ip_address(ip: str) -> str:
        """Valide une adresse IP"""
        try:
            ipaddress.ip_address(ip)
            return ip
        except ValueError:
            raise ValidationError(f"Adresse IP invalide: {ip}")
    
    @staticmethod
    def validate_server_name(name: str) -> str:
        """Valide un nom de serveur"""
        name = JSONValidator.sanitize_string(
            name, max_length=64, allowed_chars=r'^[a-zA-Z0-9_.-]+$'
        )
        if len(name) < 1:
            raise ValidationError("Nom de serveur vide")
        return name

class SSHErrorType(Enum):
    """Types d'erreurs SSH classifiées"""
    NETWORK_UNREACHABLE = "network_unreachable"
    CONNECTION_REFUSED = "connection_refused"
    AUTHENTICATION_FAILED = "authentication_failed"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"

class SSHErrorContext:
    """Contexte d'erreur SSH avec informations diagnostiques"""
    def __init__(self, error_type: SSHErrorType, message: str, suggestion: str, 
                 is_recoverable: bool = True, retry_delay: int = 30):
        self.error_type = error_type
        self.message = message
        self.suggestion = suggestion
        self.is_recoverable = is_recoverable
        self.retry_delay = retry_delay
        self.timestamp = datetime.now()

class SSHErrorHandler:
    """Gestionnaire intelligent des erreurs SSH"""
    def __init__(self):
        self.error_history = {}
        self.blacklisted_servers = {}
        self.connection_attempts = {}
        self.max_attempts_per_hour = 10
        self.blacklist_duration = timedelta(minutes=15)
    
    def classify_error(self, exception: Exception, server_config: Dict[str, Any]) -> SSHErrorContext:
        """Classifie une erreur SSH et fournit un contexte détaillé"""
        server_ip = server_config.get('ip', 'unknown')
        
        if isinstance(exception, socket.timeout):
            return SSHErrorContext(
                SSHErrorType.TIMEOUT,
                f"Timeout de connexion vers {server_ip}",
                "Le serveur met trop de temps à répondre",
                is_recoverable=True, retry_delay=60
            )
        elif isinstance(exception, ConnectionRefusedError):
            return SSHErrorContext(
                SSHErrorType.CONNECTION_REFUSED,
                f"Connexion refusée par {server_ip}:22",
                "Vérifiez que SSH est démarré et le port ouvert",
                is_recoverable=True, retry_delay=120
            )
        elif isinstance(exception, paramiko.AuthenticationException):
            return SSHErrorContext(
                SSHErrorType.AUTHENTICATION_FAILED,
                f"Échec d'authentification sur {server_ip}",
                "Vérifiez le nom d'utilisateur et mot de passe",
                is_recoverable=False
            )
        else:
            return SSHErrorContext(
                SSHErrorType.UNKNOWN,
                f"Erreur SSH sur {server_ip}: {str(exception)}",
                "Vérifiez la connectivité réseau",
                is_recoverable=True, retry_delay=30
            )
    
    def should_retry(self, server_config: Dict[str, Any], error_context: SSHErrorContext) -> bool:
        """Détermine si une connexion SSH doit être retentée"""
        server_key = f"{server_config.get('username', 'unknown')}@{server_config.get('ip', 'unknown')}"
        
        if self._is_blacklisted(server_key):
            return False
        
        if not error_context.is_recoverable:
            self._blacklist_server(server_key, duration=timedelta(hours=1))
            return False
        
        if self._too_many_attempts(server_key):
            self._blacklist_server(server_key)
            return False
        
        return True
    
    def _is_blacklisted(self, server_key: str) -> bool:
        """Vérifie si un serveur est en blacklist"""
        if server_key not in self.blacklisted_servers:
            return False
        blacklist_until = self.blacklisted_servers[server_key]
        if datetime.now() > blacklist_until:
            del self.blacklisted_servers[server_key]
            return False
        return True
    
    def _blacklist_server(self, server_key: str, duration: Optional[timedelta] = None):
        """Met un serveur en blacklist temporaire"""
        if duration is None:
            duration = self.blacklist_duration
        blacklist_until = datetime.now() + duration
        self.blacklisted_servers[server_key] = blacklist_until
        logger.warning(f"Serveur {server_key} blacklisté jusqu'à {blacklist_until}")
    
    def _too_many_attempts(self, server_key: str) -> bool:
        """Vérifie s'il y a eu trop de tentatives récemment"""
        return self.connection_attempts.get(server_key, 0) >= self.max_attempts_per_hour
    
    def get_global_stats(self) -> Dict[str, Any]:
        """Statistiques globales du gestionnaire d'erreurs"""
        return {
            'total_servers_tracked': len(self.error_history),
            'blacklisted_servers': len(self.blacklisted_servers),
            'error_count': sum(len(errors) for errors in self.error_history.values())
        }

class SSHConnectionPool:
    """Pool de connexions SSH réutilisables"""
    def __init__(self, max_connections_per_server=3, connection_timeout=300):
        self.max_connections_per_server = max_connections_per_server
        self.connection_timeout = connection_timeout
        self.connections = {}
        self.connection_locks = {}
        self.last_used = {}
        self.pool_lock = threading.Lock()
        self.decrypt_password = None  # Sera défini par l'app
        
        logger.info(f"Pool SSH initialisé (max {max_connections_per_server} conn/serveur)")
    
    def _get_server_key(self, server_config):
        return f"{server_config['username']}@{server_config['ip']}"
    
    def get_connection(self, server_config):
        """Récupère une connexion SSH réutilisable"""
        server_key = self._get_server_key(server_config)
        
        with self.pool_lock:
            if server_key not in self.connections:
                self.connections[server_key] = []
                self.connection_locks[server_key] = threading.Lock()
                self.last_used[server_key] = {}
        
        with self.connection_locks[server_key]:
            # Chercher une connexion libre et valide
            for i, (ssh_client, in_use) in enumerate(self.connections[server_key]):
                if not in_use and self._is_connection_alive(ssh_client):
                    self.connections[server_key][i] = (ssh_client, True)
                    self.last_used[server_key][id(ssh_client)] = datetime.now()
                    logger.debug(f"Connexion SSH réutilisée pour {server_key}")
                    return ssh_client
            
            # Créer une nouvelle connexion si possible
            if len(self.connections[server_key]) < self.max_connections_per_server:
                ssh_client = self._create_connection(server_config)
                if ssh_client:
                    self.connections[server_key].append((ssh_client, True))
                    self.last_used[server_key][id(ssh_client)] = datetime.now()
                    logger.debug(f"Nouvelle connexion SSH créée pour {server_key}")
                    return ssh_client
            
            logger.warning(f"Pool SSH plein pour {server_key}")
            return None
    
    def _create_connection(self, server_config):
        """Crée une nouvelle connexion SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            password = self.decrypt_password(server_config['password']) if self.decrypt_password else server_config.get('password', '')
            
            ssh.connect(
                hostname=server_config['ip'],
                username=server_config['username'],
                password=password,
                timeout=10,
                look_for_keys=False,
                allow_agent=False
            )
            return ssh
        except Exception as e:
            logger.error(f"Erreur création connexion SSH {server_config['ip']}: {e}")
            return None
    
    def _is_connection_alive(self, ssh_client):
        """Vérifie si une connexion SSH est encore active"""
        try:
            transport = ssh_client.get_transport()
            if transport is None or not transport.is_active():
                return False
            stdin, stdout, stderr = ssh_client.exec_command('echo ping', timeout=5)
            return stdout.read().decode().strip() == 'ping'
        except:
            return False
    
    def release_connection(self, ssh_client):
        """Libère une connexion pour la remettre dans le pool"""
        if not ssh_client:
            return
        
        with self.pool_lock:
            for server_key, connections in self.connections.items():
                for i, (client, in_use) in enumerate(connections):
                    if client is ssh_client and in_use:
                        self.connections[server_key][i] = (client, False)
                        self.last_used[server_key][id(client)] = datetime.now()
                        logger.debug(f"Connexion SSH libérée pour {server_key}")
                        return
    
    def execute_command(self, server_config, command, timeout=30):
        """Exécute une commande SSH en utilisant le pool"""
        ssh_client = self.get_connection(server_config)
        if not ssh_client:
            return False, "", "Impossible d'obtenir une connexion SSH"
        
        try:
            stdin, stdout, stderr = ssh_client.exec_command(command, timeout=timeout)
            stdout_data = stdout.read().decode().strip()
            stderr_data = stderr.read().decode().strip()
            return True, stdout_data, stderr_data
        except Exception as e:
            logger.error(f"Erreur exécution commande SSH: {e}")
            return False, "", str(e)
        finally:
            self.release_connection(ssh_client)
    
    def check_disk_status(self, server_config, disk_info):
        """Vérifie le statut d'un disque via SSH avec pool de connexions"""
        try:
            success, stdout, stderr = self.execute_command(
                server_config, f"lsblk -f | grep -i {disk_info['uuid']}"
            )
            
            if not success:
                return {"exists": False, "mounted": False}
            
            disk_exists = bool(stdout)
            
            if disk_exists:
                success, stdout, stderr = self.execute_command(
                    server_config, f"mount | grep {disk_info['device']}"
                )
                is_mounted = bool(stdout) if success else False
            else:
                is_mounted = False
            
            return {"exists": disk_exists, "mounted": is_mounted}
        except Exception as e:
            logger.error(f"Erreur vérification disque {disk_info['device']}: {e}")
            return {"exists": False, "mounted": False}
    
    def get_stats(self):
        """Retourne les statistiques du pool"""
        with self.pool_lock:
            stats = {}
            total_connections = 0
            active_connections = 0
            
            for server_key, connections in self.connections.items():
                active = sum(1 for _, in_use in connections if in_use)
                total = len(connections)
                stats[server_key] = {'total': total, 'active': active, 'free': total - active}
                total_connections += total
                active_connections += active
            
            return {
                'servers': stats,
                'total_connections': total_connections,
                'active_connections': active_connections,
                'free_connections': total_connections - active_connections
            }
    
    def close_all(self):
        """Ferme toutes les connexions du pool"""
        with self.pool_lock:
            for server_key, connections in self.connections.items():
                for ssh_client, _ in connections:
                    try:
                        ssh_client.close()
                    except:
                        pass
                logger.info(f"Connexions fermées pour {server_key}")
            self.connections.clear()
            self.last_used.clear()
        logger.info("Pool SSH fermé")

@dataclass
class CacheEntry:
    """Entrée de cache avec métadonnées"""
    key: str
    value: Any
    created_at: datetime
    last_accessed: datetime
    access_count: int
    ttl_seconds: int
    
    def is_expired(self) -> bool:
        return datetime.now() > (self.created_at + timedelta(seconds=self.ttl_seconds))
    
    def age_seconds(self) -> int:
        return int((datetime.now() - self.created_at).total_seconds())
    
    def access(self):
        self.last_accessed = datetime.now()
        self.access_count += 1

class IntelligentCache:
    """Cache intelligent avec éviction automatique"""
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.cache: Dict[str, CacheEntry] = {}
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.lock = threading.RLock()
        
        logger.info(f"Cache intelligent initialisé (taille max: {max_size})")
    
    def _generate_key(self, base_key: str, **kwargs) -> str:
        if kwargs:
            param_str = json.dumps(kwargs, sort_keys=True, separators=(',', ':'))
            combined = f"{base_key}::{param_str}"
        else:
            combined = base_key
        return hashlib.md5(combined.encode()).hexdigest()[:16] + f"__{base_key}"
    
    def get(self, key: str, default=None, **kwargs) -> Any:
        cache_key = self._generate_key(key, **kwargs)
        
        with self.lock:
            if cache_key in self.cache:
                entry = self.cache[cache_key]
                if not entry.is_expired():
                    entry.access()
                    self.hits += 1
                    logger.debug(f"Cache HIT: {key} (age: {entry.age_seconds()}s)")
                    return entry.value
                else:
                    del self.cache[cache_key]
                    logger.debug(f"Cache EXPIRED: {key}")
            
            self.misses += 1
            logger.debug(f"Cache MISS: {key}")
            return default
    
    def set(self, key: str, value: Any, ttl: int = None, **kwargs):
        cache_key = self._generate_key(key, **kwargs)
        ttl = ttl or self.default_ttl
        
        with self.lock:
            if len(self.cache) >= self.max_size:
                self._evict_entries()
            
            entry = CacheEntry(
                key=cache_key, value=value, created_at=datetime.now(),
                last_accessed=datetime.now(), access_count=1, ttl_seconds=ttl
            )
            self.cache[cache_key] = entry
            logger.debug(f"Cache SET: {key} (TTL: {ttl}s)")
    
    def _evict_entries(self):
        if not self.cache:
            return
        
        # Supprimer les entrées expirées
        expired_keys = [key for key, entry in self.cache.items() if entry.is_expired()]
        for key in expired_keys:
            del self.cache[key]
            self.evictions += 1
        
        # Si toujours plein, supprimer les moins utilisées
        if len(self.cache) >= self.max_size:
            entries_by_usage = sorted(self.cache.items(), key=lambda x: x[1].access_count)
            to_remove = len(self.cache) - self.max_size + 1
            for i in range(min(to_remove, len(entries_by_usage))):
                key, _ = entries_by_usage[i]
                del self.cache[key]
                self.evictions += 1
    
    def invalidate(self, key_pattern: str = None, **kwargs):
        with self.lock:
            if key_pattern is None:
                cleared = len(self.cache)
                self.cache.clear()
                logger.info(f"Cache vidé: {cleared} entrées")
            else:
                keys_to_remove = [k for k in self.cache.keys() if key_pattern in k]
                for key in keys_to_remove:
                    del self.cache[key]
                logger.debug(f"Cache invalidé: {len(keys_to_remove)} entrées pour '{key_pattern}'")
    
    def get_stats(self) -> Dict[str, Any]:
        with self.lock:
            total_requests = self.hits + self.misses
            hit_rate = (self.hits / total_requests * 100) if total_requests > 0 else 0
            
            return {
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'evictions': self.evictions,
                'hit_rate_percent': round(hit_rate, 2)
            }

# Décorateur de validation JSON
def validate_json(schema_name: str):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                data = request.get_json(force=True, silent=True)
                if data is None:
                    return jsonify({'success': False, 'error': 'Données JSON manquantes'}), 400
                
                # Validation basique selon le schéma
                if schema_name == 'password_update':
                    # Validation spéciale pour les mots de passe - PAS de sanitization
                    password = data.get('password', '')
                    if not isinstance(password, str):
                        raise ValidationError("Le mot de passe doit être une chaîne")
                    if len(password) > 512:  # Limite généreuse
                        raise ValidationError("Mot de passe trop long (max 512 caractères)")
                    request.validated_json = {'password': password}
                else:
                    request.validated_json = data
                
                return f(*args, **kwargs)
            except ValidationError as e:
                security_logger.warning(f"Erreur validation JSON: {e}")
                return jsonify({'success': False, 'error': f'Données invalides: {str(e)}'}), 400
            except Exception as e:
                logger.error(f"Erreur validation inattendue: {e}")
                return jsonify({'success': False, 'error': 'Erreur de validation interne'}), 500
        return decorated_function
    return decorator

def get_validated_json():
    return getattr(request, 'validated_json', {})

# === CLASSES PRINCIPALES ===

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
            config = {'telegram': self.telegram_config}
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
                
                response = requests.post(url, json=payload, timeout=10)
                if response.status_code == 200:
                    success_count += 1
                    logger.info(f"Message Telegram envoyé avec succès à {chat_id}")
                else:
                    logger.error(f"Erreur Telegram {chat_id}: {response.status_code}")
            
            return success_count > 0
        except Exception as e:
            logger.error(f"Erreur envoi Telegram: {e}")
            return False
    
    def format_telegram_message(self, server_name, server_ip, position, disk_label, changes):
        """Formate un message pour Telegram"""
        emoji_map = {
            'DÉMONTÉ': '❌', 'DISPARU': '🚨', 'REMONTÉ': '✅', 'RÉAPPARU': '🔄'
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
            emoji, status_text = '🟢', 'EN LIGNE'
            description = 'Le serveur est maintenant accessible et opérationnel.'
        else:
            emoji, status_text = '🔴', 'HORS LIGNE'
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
        """Vérifie les changements d'état des disques et serveurs"""
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
                            server_name, server_data.get('ip', 'N/A'), server_status
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
                    'label': disk_data.get('label', 'Disque inconnu')
                }
                
                if disk_key in self.previous_disk_states:
                    previous_state = self.previous_disk_states[disk_key]
                    changes = []
                    
                    if previous_state['mounted'] and not current_state['mounted']:
                        changes.append(f"❌ DISQUE DÉMONTÉ: {current_state['label']}")
                    elif previous_state['exists'] and not current_state['exists']:
                        changes.append(f"🚨 DISQUE DISPARU: {current_state['label']}")
                    elif not previous_state['mounted'] and current_state['mounted']:
                        changes.append(f"✅ DISQUE REMONTÉ: {current_state['label']}")
                    elif not previous_state['exists'] and current_state['exists']:
                        changes.append(f"🔄 DISQUE RÉAPPARU: {current_state['label']}")
                    
                    if changes and self.telegram_config['enabled']:
                        telegram_message = self.format_telegram_message(
                            server_name, server_data.get('ip', 'N/A'),
                            position, current_state['label'], changes
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

class ServerDiskMonitorWeb:
    def __init__(self):
        self.data_dir = "/app/data"
        self.config_file = os.path.join(self.data_dir, "config.json")
        self.cipher_key_file = os.path.join(self.data_dir, "cipher.key")
        self._config_lock = threading.Lock()  # Verrouillage pour éviter les conflits
        
        os.makedirs(self.data_dir, exist_ok=True)
        self.init_encryption()
        
        # Configuration par défaut avec migration automatique
        self.default_config = {
            "servers": {
                "EXAMPLE-SERVER": {
                    "ip": "192.168.1.100",
                    "username": "root",
                    "password": "",
                    "front_rack": {"enabled": True, "rows": 2, "cols": 3, "total_slots": 6},
                    "back_rack": {"enabled": False, "rows": 0, "cols": 0, "total_slots": 0},
                    "disk_mappings": {
                        "front_0_0": {
                            "uuid": "example-uuid-1234-5678-90ab-cdef12345678",
                            "device": "/dev/sda",
                            "label": "Système",
                            "description": "Disque système principal",
                            "capacity": "256GB SSD"
                        }
                    }
                }
            },
            "refresh_interval": 30
        }
        
        self.servers_config = self.load_config()
        
        # État de surveillance
        self.monitoring = False
        self.refresh_interval = self.servers_config.get('refresh_interval', 30)
        self.disk_status = {}
        self.last_update = None
        
        # Améliorations intégrées
        self.ssh_pool = SSHConnectionPool()
        self.ssh_pool.decrypt_password = self.decrypt_password
        self.ssh_error_handler = SSHErrorHandler()
        self.cache = IntelligentCache()
        
        # Gestionnaire de notifications avec référence au cipher
        self.notification_manager = NotificationManager(cipher=self.cipher, data_dir=self.data_dir)
        
        # Démarrage du scheduler
        self.scheduler = BackgroundScheduler()
        self.start_monitoring()
        
        logger.info("=== Server Disk Monitor - Version Optimisée Portainer ===")
    
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
        """Charge la configuration avec migration automatique"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    config = self._migrate_config(config)
                    logger.info(f"Configuration chargée: {len(config.get('servers', {}))} serveur(s)")
                    return config
            except Exception as e:
                logger.error(f"Erreur lors du chargement: {e}")
                return self.default_config.copy()
        else:
            logger.info("Configuration par défaut créée")
            self.save_config_to_file(self.default_config)
            return self.default_config.copy()
    
    def _migrate_config(self, config):
        """Migration automatique pour compatibilité"""
        if 'servers' not in config:
            config['servers'] = {}
        if 'refresh_interval' not in config:
            config['refresh_interval'] = 30
        
        # Migration des serveurs
        for server_name, server_config in config['servers'].items():
            defaults = {
                'ip': '127.0.0.1', 'username': 'root', 'password': '',
                'front_rack': {'enabled': True, 'rows': 2, 'cols': 3, 'total_slots': 6},
                'back_rack': {'enabled': False, 'rows': 0, 'cols': 0, 'total_slots': 0},
                'disk_mappings': {}
            }
            
            for key, default_value in defaults.items():
                if key not in server_config:
                    server_config[key] = default_value
            
            # Migration disk_mappings
            for position, disk_info in server_config['disk_mappings'].items():
                disk_defaults = {
                    'uuid': '', 'device': '/dev/sdX', 'label': 'Disque inconnu',
                    'description': 'Description manquante', 'capacity': 'Inconnue'
                }
                for key, default_value in disk_defaults.items():
                    if key not in disk_info:
                        disk_info[key] = default_value
        
        return config
    
    def save_config(self):
        return self.save_config_to_file(self.servers_config)
    
    def save_config_to_file(self, config):
        with self._config_lock:  # Verrouillage pour éviter les conflits de sauvegarde
            try:
                # Créer une sauvegarde avant la modification
                backup_file = f"{self.config_file}.backup"
                if os.path.exists(self.config_file):
                    import shutil
                    shutil.copy2(self.config_file, backup_file)
                    logger.debug(f"Sauvegarde créée: {backup_file}")
                
                # Sauvegarder avec verrouillage de fichier
                with open(self.config_file, 'w', encoding='utf-8') as f:
                    json.dump(config, f, indent=4, ensure_ascii=False)
                    f.flush()  # Force l'écriture
                    os.fsync(f.fileno())  # Force la synchronisation disque
                
                logger.info(f"Configuration sauvegardée ({len(config.get('servers', {}))} serveurs)")
                
                # Vérification de l'intégrité
                try:
                    with open(self.config_file, 'r', encoding='utf-8') as f:
                        verification = json.load(f)
                        if len(verification.get('servers', {})) != len(config.get('servers', {})):
                            logger.error("ERREUR: Nombre de serveurs différent après sauvegarde!")
                            if os.path.exists(backup_file):
                                shutil.copy2(backup_file, self.config_file)
                                logger.info("Configuration restaurée depuis la sauvegarde")
                            return False
                except Exception as e:
                    logger.error(f"Erreur vérification intégrité: {e}")
                    return False
                
                return True
            except Exception as e:
                logger.error(f"Erreur sauvegarde: {e}")
                logger.error(f"Tentative de sauvegarde pour {len(config.get('servers', {}))} serveurs")
                return False
    
    def encrypt_password(self, password):
        if not password:
            return ""
        encrypted = self.cipher.encrypt(password.encode())
        return base64.b64encode(encrypted).decode()
    
    def decrypt_password(self, encrypted_password):
        if not encrypted_password:
            return ""
        try:
            encrypted_bytes = base64.b64decode(encrypted_password.encode())
            return self.cipher.decrypt(encrypted_bytes).decode()
        except:
            return ""
    
    def ping_server(self, ip):
        """Vérifie si un serveur est accessible avec cache"""
        cache_key = f"ping_{ip}"
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        try:
            result = subprocess.run(['ping', '-c', '1', '-W', '3', ip], 
                                  capture_output=True, timeout=5)
            is_online = result.returncode == 0
            self.cache.set(cache_key, is_online, ttl=30)  # Cache 30s
            return is_online
        except:
            self.cache.set(cache_key, False, ttl=30)
            return False
    
    def check_disk_ssh(self, server_config, disk_info):
        """Vérifie le statut d'un disque via SSH avec améliorations intégrées"""
        cache_key = f"disk_{server_config['ip']}_{disk_info['device']}"
        
        # Vérifier le cache d'abord
        cached_result = self.cache.get(cache_key)
        if cached_result is not None:
            return cached_result
        
        try:
            if not server_config.get('password'):
                result = {"exists": False, "mounted": False}
                self.cache.set(cache_key, result, ttl=300)
                return result
            
            # Utiliser le pool SSH pour performance
            result = self.ssh_pool.check_disk_status(server_config, disk_info)
            self.cache.set(cache_key, result, ttl=60)  # Cache 1 minute
            return result
            
        except Exception as e:
            # Utiliser le gestionnaire d'erreurs
            error_context = self.ssh_error_handler.classify_error(e, server_config)
            logger.error(f"Erreur SSH {server_config['ip']}: {error_context.message}")
            
            # Fallback avec cache plus long pour éviter les requêtes répétées
            result = {"exists": False, "mounted": False}
            self.cache.set(cache_key, result, ttl=300)
            return result
    
    def update_all_disk_status(self):
        """Met à jour le statut de tous les disques avec toutes les améliorations"""
        logger.info("Mise à jour du statut des disques (version optimisée)...")
        
        # Recharger config pour changements dynamiques
        self.servers_config = self.load_config()
        
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
        
        # Notifications avec gestionnaire intégré
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
        
        # WebSocket avec données optimisées
        socketio.emit('disk_status_update', {
            'servers': self.disk_status,
            'stats': stats,
            'config': self.get_safe_config()
        })
        
        logger.info(f"Mise à jour terminée: {mounted_disks}/{total_disks} disques montés")
    
    def get_safe_config(self):
        """Configuration sans mots de passe"""
        safe_config = {}
        for server_name, config in self.servers_config.get('servers', {}).items():
            safe_config[server_name] = config.copy()
            safe_config[server_name]['password'] = '***' if config.get('password') else ''
        return safe_config
    
    def start_monitoring(self):
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
            logger.info("Surveillance démarrée avec améliorations")
    
    def stop_monitoring(self):
        if self.monitoring:
            self.monitoring = False
            if self.scheduler.get_job('disk_monitoring'):
                self.scheduler.remove_job('disk_monitoring')
            logger.info("Surveillance arrêtée")
    
    def update_refresh_interval(self, new_interval):
        self.refresh_interval = max(10, new_interval)
        self.servers_config['refresh_interval'] = self.refresh_interval
        if self.monitoring:
            self.scheduler.modify_job('disk_monitoring', seconds=self.refresh_interval)

# Instance globale
monitor = ServerDiskMonitorWeb()

# Middleware de sécurité
@app.before_request
def security_middleware():
    if request.method == 'POST' and request.is_json:
        endpoint = request.endpoint or 'unknown'
        remote_ip = request.remote_addr or 'unknown'
        logger.info(f"API POST request: {endpoint} from {remote_ip}")
        
        content_length = request.content_length
        if content_length and content_length > 1024 * 1024:
            security_logger.warning(f"Large payload: {content_length} bytes from {remote_ip}")
            return jsonify({'success': False, 'error': 'Payload trop volumineux'}), 413

# === ROUTES FLASK OPTIMISÉES ===

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({
        'servers': monitor.get_safe_config(),
        'refresh_interval': monitor.refresh_interval
    })

@app.route('/api/config', methods=['POST'])
def update_config():
    """Met à jour la configuration avec validation intégrée"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'error': 'Données manquantes'}), 400
        
        # Validation basique
        if 'servers' in data:
            for server_name, server_config in data['servers'].items():
                if 'ip' in server_config:
                    try:
                        JSONValidator.validate_ip_address(server_config['ip'])
                    except ValidationError as e:
                        return jsonify({'success': False, 'error': str(e)}), 400
        
        # Mise à jour
        monitor.servers_config = data
        monitor.save_config()
        
        # Invalider le cache pour forcer une mise à jour
        monitor.cache.invalidate()
        
        # Mise à jour de l'intervalle si nécessaire
        if 'refresh_interval' in data:
            monitor.update_refresh_interval(data['refresh_interval'])
        
        # Force une mise à jour immédiate
        monitor.update_all_disk_status()
        
        return jsonify({'success': True, 'message': 'Configuration mise à jour'})
        
    except Exception as e:
        logger.error(f"Erreur mise à jour config: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/server/<server_name>/password', methods=['POST'])
@validate_json('password_update')
def update_server_password(server_name):
    """Met à jour le mot de passe d'un serveur avec validation"""
    try:
        server_name = JSONValidator.validate_server_name(server_name)
        data = get_validated_json()
        password = data.get('password', '')
        
        # CORRECTION: Verrouillage pour éviter les conflits lors de modifications multiples
        with monitor._config_lock:
            logger.info(f"Mise à jour mot de passe pour {server_name} (config actuelle: {len(monitor.servers_config.get('servers', {}))} serveurs)")
            
            if server_name in monitor.servers_config.get('servers', {}):
                try:
                    encrypted_password = monitor.encrypt_password(password)
                    
                    # Modification atomique de la configuration (copie profonde)
                    import copy
                    config_copy = copy.deepcopy(monitor.servers_config)
                    config_copy['servers'][server_name]['password'] = encrypted_password
                    
                    # Sauvegarder la configuration modifiée
                    if monitor.save_config_to_file(config_copy):
                        # Mettre à jour la configuration en mémoire seulement si sauvegarde réussie
                        monitor.servers_config = config_copy
                        
                        # Invalider le cache SSH pour ce serveur
                        try:
                            server_ip = monitor.servers_config['servers'][server_name]['ip']
                            monitor.cache.invalidate(f"disk_{server_ip}")
                            monitor.cache.invalidate(f"ping_{server_ip}")
                            logger.info(f"Mot de passe mis à jour pour {server_name} ({server_ip})")
                        except Exception as cache_error:
                            logger.warning(f"Erreur invalidation cache pour {server_name}: {cache_error}")
                        
                        return jsonify({'success': True, 'message': 'Mot de passe mis à jour avec succès'})
                    else:
                        return jsonify({'success': False, 'error': 'Erreur lors de la sauvegarde'}), 500
                        
                except Exception as encrypt_error:
                    logger.error(f"Erreur chiffrement mot de passe pour {server_name}: {encrypt_error}")
                    return jsonify({'success': False, 'error': 'Erreur lors du chiffrement du mot de passe'}), 500
            else:
                return jsonify({'success': False, 'error': 'Serveur non trouvé'}), 404
            
    except ValidationError as e:
        logger.warning(f"Erreur validation pour {server_name}: {e}")
        return jsonify({'success': False, 'error': f"Données invalides: {str(e)}"}), 400
    except Exception as e:
        logger.error(f"Erreur générale mot de passe pour {server_name}: {e}")
        return jsonify({'success': False, 'error': f"Erreur inattendue: {str(e)}"}), 500

@app.route('/api/debug/password/<server_name>', methods=['POST'])
def debug_password_update(server_name):
    """Route de debug pour tester la sauvegarde des mots de passe"""
    try:
        # Validation simple sans décorateur
        data = request.get_json(force=True, silent=True)
        if data is None:
            return jsonify({'success': False, 'error': 'JSON invalide ou manquant'}), 400
        
        password = data.get('password', '')
        logger.info(f"DEBUG - Tentative de mise à jour mot de passe pour: {server_name}")
        logger.info(f"DEBUG - Longueur mot de passe: {len(password)}")
        logger.info(f"DEBUG - Serveurs configurés: {list(monitor.servers_config.get('servers', {}).keys())}")
        
        if server_name not in monitor.servers_config.get('servers', {}):
            return jsonify({'success': False, 'error': f'Serveur "{server_name}" non trouvé'}), 404
        
        # Test du chiffrement
        try:
            encrypted = monitor.encrypt_password(password)
            logger.info(f"DEBUG - Chiffrement réussi: {len(encrypted)} caractères")
        except Exception as e:
            logger.error(f"DEBUG - Erreur chiffrement: {e}")
            return jsonify({'success': False, 'error': f'Erreur chiffrement: {str(e)}'}), 500
        
        # Test de la sauvegarde
        try:
            monitor.servers_config['servers'][server_name]['password'] = encrypted
            save_result = monitor.save_config()
            logger.info(f"DEBUG - Résultat sauvegarde: {save_result}")
            
            if save_result:
                return jsonify({'success': True, 'message': f'Debug: Mot de passe mis à jour pour {server_name}'})
            else:
                return jsonify({'success': False, 'error': 'Échec de la sauvegarde'}), 500
                
        except Exception as e:
            logger.error(f"DEBUG - Erreur sauvegarde: {e}")
            return jsonify({'success': False, 'error': f'Erreur sauvegarde: {str(e)}'}), 500
    
    except Exception as e:
        logger.error(f"DEBUG - Erreur générale: {e}")
        return jsonify({'success': False, 'error': f'Erreur générale: {str(e)}'}), 500

@app.route('/api/refresh', methods=['POST'])
def manual_refresh():
    try:
        monitor.cache.invalidate()  # Vider le cache pour forcer la mise à jour
        monitor.update_all_disk_status()
        return jsonify({'success': True, 'message': 'Rafraîchissement en cours'})
    except Exception as e:
        logger.error(f"Erreur refresh: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    return jsonify({
        "monitoring": monitor.monitoring,
        "total_servers": len(monitor.servers_config.get('servers', {})),
        "total_disks": sum(len(config.get('disk_mappings', {})) for config in monitor.servers_config.get('servers', {}).values()),
        "mounted_disks": sum(
            sum(1 for d in server.get('disks', {}).values() if d.get('mounted', False))
            for server in monitor.disk_status.values()
        ),
        "last_update": monitor.last_update,
        "refresh_interval": monitor.refresh_interval
    })

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    try:
        monitor.cache.invalidate()
        return jsonify({'success': True, 'message': 'Cache vidé'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# === NOUVELLES ROUTES D'AMÉLIORATION ===

@app.route('/api/ssh/stats', methods=['GET'])
def get_ssh_stats():
    """Statistiques du pool SSH"""
    try:
        stats = monitor.ssh_pool.get_stats()
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/ssh/errors', methods=['GET'])
def get_ssh_error_stats():
    """Statistiques des erreurs SSH"""
    try:
        stats = monitor.ssh_error_handler.get_global_stats()
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/cache/stats', methods=['GET'])
def get_cache_stats():
    """Statistiques du cache intelligent"""
    try:
        stats = monitor.cache.get_stats()
        return jsonify({"success": True, "stats": stats})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/notifications/config', methods=['GET'])
def get_notification_config():
    telegram_config = monitor.notification_manager.telegram_config.copy()
    if telegram_config.get('bot_token'):
        telegram_config['bot_token'] = '***'
    return jsonify({'telegram': telegram_config})

@app.route('/api/notifications/config', methods=['POST'])
def update_notification_config():
    try:
        data = request.get_json()
        telegram_config = data.get('telegram', {})
        
        # Chiffrement du token si nécessaire
        if telegram_config.get('bot_token') and telegram_config['bot_token'] != '***':
            encrypted_token = monitor.encrypt_password(telegram_config['bot_token'])
            telegram_config['bot_token'] = encrypted_token
        elif telegram_config.get('bot_token') == '***':
            telegram_config['bot_token'] = monitor.notification_manager.telegram_config['bot_token']
        
        monitor.notification_manager.telegram_config.update(telegram_config)
        
        if monitor.notification_manager.save_notification_config():
            return jsonify({'success': True, 'message': 'Configuration notifications mise à jour'})
        else:
            return jsonify({'success': False, 'error': 'Erreur sauvegarde'}), 500
            
    except Exception as e:
        logger.error(f"Erreur config notifications: {e}")
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/notifications/test', methods=['POST'])
def test_notification():
    try:
        test_message = f"""
🧪 <b>Test de Notification</b>

Ceci est un message de test pour vérifier la configuration Telegram.

<b>Timestamp:</b> {monitor.last_update or "N/A"}
        """
        
        if monitor.notification_manager.send_telegram_notification(test_message):
            return jsonify({'success': True, 'message': 'Notification de test envoyée'})
        else:
            return jsonify({'success': False, 'error': 'Échec envoi notification'}), 500
            
    except Exception as e:
        logger.error(f"Erreur test notification: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

# === WEBSOCKET EVENTS ===

@socketio.on('connect')
def handle_connect():
    logger.info("Client connecté")
    emit('disk_status_update', {
        'servers': monitor.disk_status,
        'stats': {
            "total_servers": len(monitor.servers_config.get('servers', {})),
            "mounted_disks": sum(
                sum(1 for d in server.get('disks', {}).values() if d.get('mounted', False))
                for server in monitor.disk_status.values()
            ),
            "last_update": monitor.last_update
        },
        'config': monitor.get_safe_config()
    })

@socketio.on('disconnect')
def handle_disconnect():
    logger.info("Client déconnecté")

@socketio.on('request_refresh')
def handle_refresh_request():
    logger.info("Refresh demandé via WebSocket")
    monitor.cache.invalidate()
    monitor.update_all_disk_status()

# Nettoyage automatique à la fermeture
import atexit
atexit.register(lambda: monitor.ssh_pool.close_all())

# Point d'entrée
if __name__ == '__main__':
    logger.info("=== Server Disk Monitor - Version Portainer Optimisée ===")
    logger.info("🚀 Améliorations intégrées:")
    logger.info("   ✓ Pool de connexions SSH réutilisables")
    logger.info("   ✓ Validation JSON sécurisée") 
    logger.info("   ✓ Gestion d'erreurs SSH intelligente")
    logger.info("   ✓ Cache adaptatif multi-niveaux")
    logger.info("   ✓ 100% compatible avec données existantes")
    
    port = int(os.environ.get('MONITOR_PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=True
    )