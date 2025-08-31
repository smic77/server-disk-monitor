#!/usr/bin/env python3
"""
Server Disk Monitor - Version Web Refactorisée avec Modules
Dashboard de surveillance des disques durs accessible via navigateur
"""

from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import os
import logging

# Import des modules refactorisés
from modules.config_manager import ConfigManager
from modules.notifications import NotificationManager  
from modules.server_monitor import ServerMonitor

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialisation de l'application Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-key-change-in-production')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

class ServerDiskMonitorApp:
    """Classe principale orchestrant tous les modules"""
    
    def __init__(self):
        self.data_dir = "/app/data"
        
        # Initialisation des modules dans le bon ordre
        self.config_manager = ConfigManager(self.data_dir)
        self.notification_manager = NotificationManager(
            cipher=self.config_manager.cipher, 
            data_dir=self.data_dir
        )
        self.server_monitor = ServerMonitor(
            self.config_manager,
            self.notification_manager,
            socketio
        )
        
        # Démarrage de la surveillance
        self.server_monitor.start_monitoring()
        
        logger.info("Application Server Disk Monitor initialisée (version modulaire)")
    
    def get_config(self):
        """Récupère la configuration sécurisée"""
        config = self.config_manager.load_config()
        return {
            'servers': self.server_monitor.get_safe_config(),
            'refresh_interval': config.get('refresh_interval', 30)
        }
    
    def update_config(self, new_config):
        """Met à jour la configuration"""
        # Validation
        is_valid, message = self.config_manager.validate_config(new_config)
        if not is_valid:
            return False, message
        
        # Sauvegarde
        if self.config_manager.save_config(new_config):
            # Mise à jour de l'intervalle si modifié
            if 'refresh_interval' in new_config:
                self.server_monitor.update_refresh_interval(new_config['refresh_interval'])
            
            logger.info("Configuration mise à jour avec succès")
            return True, "Configuration mise à jour"
        else:
            return False, "Erreur lors de la sauvegarde"
    
    def update_server_password(self, server_name, password):
        """Met à jour le mot de passe d'un serveur"""
        config = self.config_manager.load_config()
        
        if self.config_manager.update_server_password(config, server_name, password):
            if self.config_manager.save_config(config):
                logger.info(f"Mot de passe mis à jour pour le serveur: {server_name}")
                return True, "Mot de passe mis à jour"
        
        return False, "Erreur lors de la mise à jour du mot de passe"
    
    def get_status(self):
        """Récupère le statut global"""
        status = self.server_monitor.get_status()
        config = self.config_manager.load_config()
        
        return {
            "monitoring": status['monitoring'],
            "total_servers": len(config.get('servers', {})),
            "total_disks": sum(len(srv.get('disk_mappings', {})) for srv in config.get('servers', {}).values()),
            "mounted_disks": sum(
                sum(1 for d in server.get('disks', {}).values() if d.get('mounted', False))
                for server in status['disk_status'].values()
            ),
            "last_update": status['last_update'],
            "refresh_interval": status['refresh_interval']
        }
    
    def get_notification_config(self):
        """Récupère la configuration des notifications"""
        config = self.notification_manager.telegram_config.copy()
        # Masquer le token pour la sécurité
        if config.get('bot_token'):
            config['bot_token'] = '***'
        return {'telegram': config}
    
    def update_notification_config(self, telegram_config):
        """Met à jour la configuration des notifications"""
        try:
            # Si le token n'est pas masqué, le chiffrer
            if telegram_config.get('bot_token') and telegram_config['bot_token'] != '***':
                encrypted_token = self.config_manager.encrypt_token(telegram_config['bot_token'])
                telegram_config['bot_token'] = encrypted_token
            elif telegram_config.get('bot_token') == '***':
                # Garder le token existant
                telegram_config['bot_token'] = self.notification_manager.telegram_config['bot_token']
            
            # Mettre à jour la configuration
            self.notification_manager.telegram_config.update(telegram_config)
            
            if self.notification_manager.save_notification_config():
                logger.info("Configuration des notifications mise à jour")
                return True, "Configuration sauvegardée"
            else:
                return False, "Erreur lors de la sauvegarde"
        except Exception as e:
            logger.error(f"Erreur mise à jour notifications: {e}")
            return False, str(e)
    
    def test_notification(self):
        """Test d'envoi de notification"""
        try:
            test_message = """
🧪 <b>Test de Notification</b>

Ceci est un message de test pour vérifier la configuration Telegram.

<b>Timestamp:</b> """ + self.server_monitor.last_update or "N/A"
            
            if self.notification_manager.send_telegram_notification(test_message):
                return True, "Notification test envoyée avec succès"
            else:
                return False, "Échec de l'envoi de la notification test"
        except Exception as e:
            logger.error(f"Erreur test notification: {e}")
            return False, str(e)

# Instance globale
app_instance = ServerDiskMonitorApp()

# === ROUTES FLASK ===

@app.route('/')
def index():
    """Page principale"""
    return render_template('index.html')

@app.route('/api/config', methods=['GET'])
def get_config():
    """Récupère la configuration"""
    return jsonify(app_instance.get_config())

@app.route('/api/config', methods=['POST'])
def update_config():
    """Met à jour la configuration"""
    try:
        new_config = request.get_json()
        success, message = app_instance.update_config(new_config)
        
        if success:
            # Force une mise à jour immédiate
            app_instance.server_monitor.manual_refresh()
            return jsonify({"success": True, "message": message})
        else:
            return jsonify({"success": False, "message": message}), 400
            
    except Exception as e:
        logger.error(f"Erreur mise à jour config: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/server/<server_name>/password', methods=['POST'])
def update_server_password(server_name):
    """Met à jour le mot de passe d'un serveur"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        success, message = app_instance.update_server_password(server_name, password)
        
        if success:
            # Vider le cache et forcer une mise à jour
            app_instance.server_monitor.clear_status_cache()
            app_instance.server_monitor.manual_refresh()
            return jsonify({"success": True, "message": message})
        else:
            return jsonify({"success": False, "message": message}), 400
            
    except Exception as e:
        logger.error(f"Erreur mot de passe: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/refresh', methods=['POST'])
def manual_refresh():
    """Force une mise à jour manuelle"""
    try:
        result = app_instance.server_monitor.manual_refresh()
        return jsonify({
            "success": True, 
            "message": "Mise à jour effectuée",
            "stats": result['stats']
        })
    except Exception as e:
        logger.error(f"Erreur refresh manuel: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/status', methods=['GET'])
def get_status():
    """Récupère le statut global"""
    return jsonify(app_instance.get_status())

@app.route('/api/cache/clear', methods=['POST'])
def clear_cache():
    """Vide le cache de statut"""
    try:
        app_instance.server_monitor.clear_status_cache()
        return jsonify({"success": True, "message": "Cache vidé"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

# === ROUTES NOTIFICATIONS ===

@app.route('/api/notifications/config', methods=['GET'])
def get_notification_config():
    """Récupère la configuration des notifications"""
    return jsonify(app_instance.get_notification_config())

@app.route('/api/notifications/config', methods=['POST'])
def update_notification_config():
    """Met à jour la configuration des notifications"""
    try:
        data = request.get_json()
        telegram_config = data.get('telegram', {})
        
        success, message = app_instance.update_notification_config(telegram_config)
        
        return jsonify({"success": success, "message": message})
    except Exception as e:
        logger.error(f"Erreur config notifications: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/notifications/test', methods=['POST'])
def test_notification():
    """Test d'envoi de notification"""
    try:
        success, message = app_instance.test_notification()
        return jsonify({"success": success, "message": message})
    except Exception as e:
        logger.error(f"Erreur test notification: {e}")
        return jsonify({"success": False, "message": str(e)}), 500

# === WEBSOCKET EVENTS ===

@socketio.on('connect')
def handle_connect():
    """Gestion de la connexion WebSocket"""
    logger.info(f"Client connecté")
    # Envoi immédiat du statut actuel
    result = app_instance.server_monitor.get_status()
    emit('disk_status_update', {
        'servers': result['disk_status'],
        'stats': app_instance.get_status(),
        'config': app_instance.server_monitor.get_safe_config()
    })

@socketio.on('disconnect')
def handle_disconnect():
    """Gestion de la déconnexion WebSocket"""
    logger.info(f"Client déconnecté")

@socketio.on('request_refresh')
def handle_refresh_request():
    """Gestion des demandes de refresh via WebSocket"""
    logger.info("Refresh demandé via WebSocket")
    app_instance.server_monitor.manual_refresh()

# Point d'entrée
if __name__ == '__main__':
    logger.info("=== Server Disk Monitor - Version Modulaire ===")
    logger.info("Démarrage du serveur Flask-SocketIO...")
    
    # Configuration du serveur
    port = int(os.environ.get('MONITOR_PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=True
    )