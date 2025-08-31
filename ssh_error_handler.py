#!/usr/bin/env python3
"""
Gestionnaire d'erreurs SSH amélioré
Gère intelligemment les erreurs de connexion et fournit des diagnostics détaillés
"""

import socket
import paramiko
import time
import logging
from enum import Enum
from typing import Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SSHErrorType(Enum):
    """Types d'erreurs SSH classifiées"""
    NETWORK_UNREACHABLE = "network_unreachable"
    CONNECTION_REFUSED = "connection_refused"
    AUTHENTICATION_FAILED = "authentication_failed"
    HOST_KEY_VERIFICATION = "host_key_verification"
    TIMEOUT = "timeout"
    PERMISSION_DENIED = "permission_denied"
    CHANNEL_ERROR = "channel_error"
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
        self.error_history = {}  # {server_key: [errors]}
        self.blacklisted_servers = {}  # {server_key: blacklist_until}
        self.connection_attempts = {}  # {server_key: attempt_count}
        self.max_attempts_per_hour = 10
        self.blacklist_duration = timedelta(minutes=15)
    
    def classify_error(self, exception: Exception, server_config: Dict[str, Any]) -> SSHErrorContext:
        """Classifie une erreur SSH et fournit un contexte détaillé"""
        
        server_ip = server_config.get('ip', 'unknown')
        
        if isinstance(exception, socket.gaierror):
            # Erreur de résolution DNS
            return SSHErrorContext(
                SSHErrorType.NETWORK_UNREACHABLE,
                f"Impossible de résoudre l'adresse {server_ip}",
                "Vérifiez l'adresse IP ou la résolution DNS",
                is_recoverable=False
            )
        
        elif isinstance(exception, socket.timeout):
            # Timeout de connexion
            return SSHErrorContext(
                SSHErrorType.TIMEOUT,
                f"Timeout de connexion vers {server_ip}",
                "Le serveur met trop de temps à répondre. Vérifiez la connectivité réseau",
                is_recoverable=True,
                retry_delay=60
            )
        
        elif isinstance(exception, ConnectionRefusedError):
            # Port fermé ou service SSH non démarré
            return SSHErrorContext(
                SSHErrorType.CONNECTION_REFUSED,
                f"Connexion refusée par {server_ip}:22",
                "Vérifiez que le service SSH est démarré et que le port 22 est ouvert",
                is_recoverable=True,
                retry_delay=120
            )
        
        elif isinstance(exception, paramiko.AuthenticationException):
            # Échec d'authentification
            return SSHErrorContext(
                SSHErrorType.AUTHENTICATION_FAILED,
                f"Échec d'authentification sur {server_ip}",
                "Vérifiez le nom d'utilisateur et le mot de passe",
                is_recoverable=False  # Nécessite intervention manuelle
            )
        
        elif isinstance(exception, paramiko.SSHException):
            error_msg = str(exception).lower()
            
            if "host key verification failed" in error_msg:
                return SSHErrorContext(
                    SSHErrorType.HOST_KEY_VERIFICATION,
                    f"Vérification de clé d'hôte échouée pour {server_ip}",
                    "La clé d'hôte a changé. Vérifiez la sécurité du serveur",
                    is_recoverable=False
                )
            
            elif "channel" in error_msg:
                return SSHErrorContext(
                    SSHErrorType.CHANNEL_ERROR,
                    f"Erreur de canal SSH sur {server_ip}",
                    "Problème lors de l'exécution de commande. Réessayez",
                    is_recoverable=True,
                    retry_delay=10
                )
            
            else:
                return SSHErrorContext(
                    SSHErrorType.UNKNOWN,
                    f"Erreur SSH inconnue sur {server_ip}: {str(exception)}",
                    "Erreur technique. Consultez les logs détaillés",
                    is_recoverable=True,
                    retry_delay=45
                )
        
        elif isinstance(exception, PermissionError):
            return SSHErrorContext(
                SSHErrorType.PERMISSION_DENIED,
                f"Permission refusée sur {server_ip}",
                "L'utilisateur n'a pas les permissions nécessaires",
                is_recoverable=False
            )
        
        else:
            # Erreur générique
            return SSHErrorContext(
                SSHErrorType.UNKNOWN,
                f"Erreur inattendue sur {server_ip}: {str(exception)}",
                "Erreur technique non classifiée. Vérifiez la connectivité",
                is_recoverable=True,
                retry_delay=30
            )
    
    def should_retry(self, server_config: Dict[str, Any], error_context: SSHErrorContext) -> bool:
        """Détermine si une connexion SSH doit être retentée"""
        
        server_key = f"{server_config.get('username', 'unknown')}@{server_config.get('ip', 'unknown')}"
        
        # Vérifier si le serveur est en blacklist
        if self._is_blacklisted(server_key):
            logger.warning(f"Serveur {server_key} en blacklist temporaire")
            return False
        
        # Erreurs non récupérables
        if not error_context.is_recoverable:
            logger.error(f"Erreur non récupérable pour {server_key}: {error_context.message}")
            self._blacklist_server(server_key, duration=timedelta(hours=1))
            return False
        
        # Limiter le nombre de tentatives par heure
        if self._too_many_attempts(server_key):
            logger.warning(f"Trop de tentatives pour {server_key}, blacklist temporaire")
            self._blacklist_server(server_key)
            return False
        
        return True
    
    def handle_error(self, exception: Exception, server_config: Dict[str, Any]) -> SSHErrorContext:
        """Gère une erreur SSH et met à jour les statistiques"""
        
        server_key = f"{server_config.get('username', 'unknown')}@{server_config.get('ip', 'unknown')}"
        
        # Classifier l'erreur
        error_context = self.classify_error(exception, server_config)
        
        # Enregistrer l'erreur dans l'historique
        self._record_error(server_key, error_context)
        
        # Incrémenter le compteur de tentatives
        self._increment_attempts(server_key)
        
        # Logging approprié selon la gravité
        if error_context.error_type in [SSHErrorType.AUTHENTICATION_FAILED, SSHErrorType.PERMISSION_DENIED]:
            logger.error(f"SSH ERROR - {server_key}: {error_context.message}")
        elif error_context.error_type == SSHErrorType.TIMEOUT:
            logger.warning(f"SSH TIMEOUT - {server_key}: {error_context.message}")
        else:
            logger.info(f"SSH ISSUE - {server_key}: {error_context.message}")
        
        return error_context
    
    def get_server_status(self, server_config: Dict[str, Any]) -> Dict[str, Any]:
        """Récupère le statut d'un serveur avec informations d'erreur"""
        
        server_key = f"{server_config.get('username', 'unknown')}@{server_config.get('ip', 'unknown')}"
        
        status = {
            'server_key': server_key,
            'is_blacklisted': self._is_blacklisted(server_key),
            'blacklist_until': self.blacklisted_servers.get(server_key),
            'attempt_count': self.connection_attempts.get(server_key, 0),
            'recent_errors': self._get_recent_errors(server_key),
            'last_error': None,
            'health_score': self._calculate_health_score(server_key)
        }
        
        # Ajouter la dernière erreur
        if server_key in self.error_history and self.error_history[server_key]:
            last_error = self.error_history[server_key][-1]
            status['last_error'] = {
                'type': last_error.error_type.value,
                'message': last_error.message,
                'suggestion': last_error.suggestion,
                'timestamp': last_error.timestamp.isoformat(),
                'is_recoverable': last_error.is_recoverable
            }
        
        return status
    
    def _is_blacklisted(self, server_key: str) -> bool:
        """Vérifie si un serveur est en blacklist"""
        if server_key not in self.blacklisted_servers:
            return False
        
        blacklist_until = self.blacklisted_servers[server_key]
        if datetime.now() > blacklist_until:
            # Blacklist expirée
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
        """Vérifie si il y a eu trop de tentatives récemment"""
        attempt_count = self.connection_attempts.get(server_key, 0)
        return attempt_count >= self.max_attempts_per_hour
    
    def _increment_attempts(self, server_key: str):
        """Incrémente le compteur de tentatives"""
        if server_key not in self.connection_attempts:
            self.connection_attempts[server_key] = 0
        
        self.connection_attempts[server_key] += 1
        
        # Programmer la remise à zéro du compteur après 1 heure
        # (Dans une implémentation complète, utiliser un scheduler)
    
    def _record_error(self, server_key: str, error_context: SSHErrorContext):
        """Enregistre une erreur dans l'historique"""
        if server_key not in self.error_history:
            self.error_history[server_key] = []
        
        self.error_history[server_key].append(error_context)
        
        # Limiter l'historique à 50 erreurs par serveur
        if len(self.error_history[server_key]) > 50:
            self.error_history[server_key] = self.error_history[server_key][-50:]
    
    def _get_recent_errors(self, server_key: str, hours: int = 1) -> int:
        """Compte les erreurs récentes"""
        if server_key not in self.error_history:
            return 0
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        recent_errors = [
            error for error in self.error_history[server_key]
            if error.timestamp > cutoff_time
        ]
        
        return len(recent_errors)
    
    def _calculate_health_score(self, server_key: str) -> float:
        """Calcule un score de santé pour le serveur (0-100)"""
        if server_key not in self.error_history:
            return 100.0
        
        recent_errors = self._get_recent_errors(server_key, hours=24)
        is_blacklisted = self._is_blacklisted(server_key)
        
        # Score de base
        score = 100.0
        
        # Pénalités
        if is_blacklisted:
            score -= 30.0
        
        score -= min(recent_errors * 5, 50.0)  # -5 points par erreur, max -50
        
        return max(0.0, score)
    
    def cleanup_old_data(self, days: int = 7):
        """Nettoie les données anciennes"""
        cutoff_time = datetime.now() - timedelta(days=days)
        
        # Nettoyer l'historique d'erreurs
        for server_key in list(self.error_history.keys()):
            self.error_history[server_key] = [
                error for error in self.error_history[server_key]
                if error.timestamp > cutoff_time
            ]
            
            # Supprimer les serveurs sans erreurs récentes
            if not self.error_history[server_key]:
                del self.error_history[server_key]
        
        # Nettoyer les blacklists expirées
        now = datetime.now()
        expired_blacklists = [
            server_key for server_key, blacklist_until in self.blacklisted_servers.items()
            if now > blacklist_until
        ]
        
        for server_key in expired_blacklists:
            del self.blacklisted_servers[server_key]
        
        logger.info(f"Nettoyage terminé: données antérieures à {days} jours supprimées")
    
    def get_global_stats(self) -> Dict[str, Any]:
        """Statistiques globales du gestionnaire d'erreurs"""
        total_servers = len(set(list(self.error_history.keys()) + list(self.blacklisted_servers.keys())))
        blacklisted_count = len(self.blacklisted_servers)
        
        error_counts = {}
        for errors in self.error_history.values():
            for error in errors:
                error_type = error.error_type.value
                error_counts[error_type] = error_counts.get(error_type, 0) + 1
        
        return {
            'total_servers_tracked': total_servers,
            'blacklisted_servers': blacklisted_count,
            'error_distribution': error_counts,
            'recent_errors_24h': sum(self._get_recent_errors(key, hours=24) for key in self.error_history.keys())
        }

# Instance globale
ssh_error_handler = SSHErrorHandler()