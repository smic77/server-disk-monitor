#!/usr/bin/env python3
"""
Pool de connexions SSH réutilisables
Améliore drastiquement les performances en évitant les reconnexions constantes
"""

import paramiko
import threading
import time
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SSHConnectionPool:
    def __init__(self, max_connections_per_server=3, connection_timeout=300):
        """
        Pool de connexions SSH
        
        Args:
            max_connections_per_server: Nombre max de connexions par serveur
            connection_timeout: Timeout en secondes pour fermer les connexions inactives
        """
        self.max_connections_per_server = max_connections_per_server
        self.connection_timeout = connection_timeout
        
        # Pool organisé par serveur: {server_key: [connections]}
        self.connections = {}
        self.connection_locks = {}
        self.last_used = {}
        
        # Verrou global pour accès thread-safe
        self.pool_lock = threading.Lock()
        
        # Thread de nettoyage
        self.cleanup_thread = threading.Thread(target=self._cleanup_connections, daemon=True)
        self.cleanup_running = True
        self.cleanup_thread.start()
        
        logger.info(f"Pool SSH initialisé (max {max_connections_per_server} conn/serveur)")
    
    def _get_server_key(self, server_config):
        """Génère une clé unique pour identifier un serveur"""
        return f"{server_config['username']}@{server_config['ip']}"
    
    def get_connection(self, server_config):
        """
        Récupère une connexion SSH réutilisable
        
        Returns:
            paramiko.SSHClient: Connexion SSH active ou None si erreur
        """
        server_key = self._get_server_key(server_config)
        
        with self.pool_lock:
            # Initialiser les structures pour ce serveur si nécessaire
            if server_key not in self.connections:
                self.connections[server_key] = []
                self.connection_locks[server_key] = threading.Lock()
                self.last_used[server_key] = {}
        
        # Verrouillage au niveau serveur pour éviter les races conditions
        with self.connection_locks[server_key]:
            # Chercher une connexion libre et valide
            for i, (ssh_client, in_use) in enumerate(self.connections[server_key]):
                if not in_use:
                    # Vérifier que la connexion est encore valide
                    if self._is_connection_alive(ssh_client):
                        # Marquer comme utilisée
                        self.connections[server_key][i] = (ssh_client, True)
                        self.last_used[server_key][id(ssh_client)] = datetime.now()
                        logger.debug(f"Connexion SSH réutilisée pour {server_key}")
                        return ssh_client
                    else:
                        # Connexion fermée, la retirer du pool
                        logger.debug(f"Connexion fermée détectée pour {server_key}")
                        ssh_client.close()
                        del self.connections[server_key][i]
                        if id(ssh_client) in self.last_used[server_key]:
                            del self.last_used[server_key][id(ssh_client)]
            
            # Si pas de connexion libre, en créer une nouvelle si sous la limite
            if len(self.connections[server_key]) < self.max_connections_per_server:
                ssh_client = self._create_connection(server_config)
                if ssh_client:
                    self.connections[server_key].append((ssh_client, True))
                    self.last_used[server_key][id(ssh_client)] = datetime.now()
                    logger.debug(f"Nouvelle connexion SSH créée pour {server_key}")
                    return ssh_client
            
            # Pool plein, attendre qu'une connexion se libère (avec timeout)
            logger.warning(f"Pool SSH plein pour {server_key}, attente...")
            return None
    
    def _create_connection(self, server_config):
        """Crée une nouvelle connexion SSH"""
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Import du décryptage - compatible avec l'app existante
            if hasattr(self, 'decrypt_password'):
                password = self.decrypt_password(server_config['password'])
            else:
                # Fallback si utilisé indépendamment
                password = server_config.get('password', '')
            
            ssh.connect(
                hostname=server_config['ip'],
                username=server_config['username'],
                password=password,
                timeout=10,
                # Paramètres optimisés pour keep-alive
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
            # Test simple et rapide
            transport = ssh_client.get_transport()
            if transport is None:
                return False
            
            # Vérifier que le transport est actif
            if not transport.is_active():
                return False
            
            # Test avec une commande très légère
            stdin, stdout, stderr = ssh_client.exec_command('echo ping', timeout=5)
            result = stdout.read().decode().strip()
            return result == 'ping'
            
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
                        # Marquer comme libre
                        self.connections[server_key][i] = (client, False)
                        self.last_used[server_key][id(client)] = datetime.now()
                        logger.debug(f"Connexion SSH libérée pour {server_key}")
                        return
    
    def execute_command(self, server_config, command, timeout=30):
        """
        Exécute une commande SSH en utilisant le pool
        
        Args:
            server_config: Configuration du serveur
            command: Commande à exécuter
            timeout: Timeout en secondes
            
        Returns:
            tuple: (success: bool, stdout: str, stderr: str)
        """
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
        """
        Vérifie le statut d'un disque via SSH avec pool de connexions
        COMPATIBLE avec la fonction existante check_disk_ssh
        """
        try:
            # Vérification de l'existence du disque
            success, stdout, stderr = self.execute_command(
                server_config, 
                f"lsblk -f | grep -i {disk_info['uuid']}"
            )
            
            if not success:
                return {"exists": False, "mounted": False}
            
            disk_exists = bool(stdout)
            
            if disk_exists:
                # Vérification du montage
                success, stdout, stderr = self.execute_command(
                    server_config,
                    f"mount | grep {disk_info['device']}"
                )
                is_mounted = bool(stdout) if success else False
            else:
                is_mounted = False
            
            return {"exists": disk_exists, "mounted": is_mounted}
            
        except Exception as e:
            logger.error(f"Erreur vérification disque {disk_info['device']}: {e}")
            return {"exists": False, "mounted": False}
    
    def _cleanup_connections(self):
        """Thread de nettoyage des connexions inactives"""
        while self.cleanup_running:
            try:
                time.sleep(60)  # Vérification toutes les minutes
                
                current_time = datetime.now()
                cutoff_time = current_time - timedelta(seconds=self.connection_timeout)
                
                with self.pool_lock:
                    for server_key in list(self.connections.keys()):
                        connections_to_remove = []
                        
                        for i, (ssh_client, in_use) in enumerate(self.connections[server_key]):
                            client_id = id(ssh_client)
                            
                            # Ne fermer que les connexions inactives et anciennes
                            if not in_use and client_id in self.last_used[server_key]:
                                last_used = self.last_used[server_key][client_id]
                                
                                if last_used < cutoff_time:
                                    connections_to_remove.append(i)
                                    logger.debug(f"Fermeture connexion inactive {server_key}")
                                    ssh_client.close()
                                    del self.last_used[server_key][client_id]
                        
                        # Retirer les connexions fermées
                        for i in reversed(connections_to_remove):
                            del self.connections[server_key][i]
                
            except Exception as e:
                logger.error(f"Erreur nettoyage pool SSH: {e}")
    
    def close_all(self):
        """Ferme toutes les connexions du pool"""
        self.cleanup_running = False
        
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
    
    def get_stats(self):
        """Retourne les statistiques du pool"""
        with self.pool_lock:
            stats = {}
            total_connections = 0
            active_connections = 0
            
            for server_key, connections in self.connections.items():
                active = sum(1 for _, in_use in connections if in_use)
                total = len(connections)
                
                stats[server_key] = {
                    'total': total,
                    'active': active,
                    'free': total - active
                }
                
                total_connections += total
                active_connections += active
            
            return {
                'servers': stats,
                'total_connections': total_connections,
                'active_connections': active_connections,
                'free_connections': total_connections - active_connections
            }

# Instance globale réutilisable
ssh_pool = None

def get_ssh_pool():
    """Factory pour obtenir l'instance globale du pool SSH"""
    global ssh_pool
    if ssh_pool is None:
        ssh_pool = SSHConnectionPool()
    return ssh_pool