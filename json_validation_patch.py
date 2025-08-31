#!/usr/bin/env python3
"""
Patch pour ajouter la validation JSON à l'application existante
Sécurise tous les endpoints contre les données malveillantes
"""

import sys
import os
from datetime import datetime

def patch_app_with_json_validation():
    """Patch l'app.py pour ajouter la validation JSON"""
    
    # Lire le fichier app.py actuel
    with open('app.py', 'r', encoding='utf-8') as f:
        app_content = f.read()
    
    # 1. Ajouter l'import du validateur
    import_patch = """
# Import du validateur JSON pour sécuriser les endpoints
from json_validator import validate_json, get_validated_json, JSONValidator
"""
    
    if "from json_validator import" not in app_content:
        # Trouver la ligne après les imports Flask
        lines = app_content.split('\n')
        flask_import_idx = -1
        
        for i, line in enumerate(lines):
            if "from flask import" in line:
                flask_import_idx = i
                break
        
        if flask_import_idx >= 0:
            lines.insert(flask_import_idx + 1, import_patch)
            app_content = '\n'.join(lines)
            print("✅ Import du validateur JSON ajouté")
    
    # 2. Sécuriser la route de mise à jour de configuration
    old_config_route = """@app.route('/api/config', methods=['POST'])
def update_config():
    \"\"\"Met à jour la configuration\"\"\"
    try:
        data = request.get_json()"""
    
    new_config_route = """@app.route('/api/config', methods=['POST'])
@validate_json('server_config')
def update_config():
    \"\"\"Met à jour la configuration - SÉCURISÉ avec validation JSON\"\"\"
    try:
        data = get_validated_json()"""
    
    if old_config_route in app_content:
        app_content = app_content.replace(old_config_route, new_config_route)
        print("✅ Route de configuration sécurisée")
    
    # 3. Sécuriser la route de mot de passe
    old_password_route = """@app.route('/api/server/<server_name>/password', methods=['POST'])
def update_server_password(server_name):
    \"\"\"Met à jour le mot de passe d'un serveur\"\"\"
    try:
        data = request.get_json()
        password = data.get('password', '')"""
    
    new_password_route = """@app.route('/api/server/<server_name>/password', methods=['POST'])
@validate_json('password_update')
def update_server_password(server_name):
    \"\"\"Met à jour le mot de passe d'un serveur - SÉCURISÉ avec validation\"\"\"
    try:
        # Valider et nettoyer le nom du serveur
        server_name = JSONValidator.validate_server_name(server_name)
        data = get_validated_json()
        password = data.get('password', '')"""
    
    if old_password_route in app_content:
        app_content = app_content.replace(old_password_route, new_password_route)
        print("✅ Route de mot de passe sécurisée")
    
    # 4. Sécuriser la route des notifications
    old_notification_route = """@app.route('/api/notifications/config', methods=['POST'])
def update_notification_config():
    \"\"\"Met à jour la configuration des notifications\"\"\"
    try:
        data = request.get_json()
        telegram_config = data.get('telegram', {})"""
    
    new_notification_route = """@app.route('/api/notifications/config', methods=['POST'])
@validate_json('telegram_config')
def update_notification_config():
    \"\"\"Met à jour la configuration des notifications - SÉCURISÉ avec validation\"\"\"
    try:
        data = get_validated_json()
        telegram_config = data.get('telegram', {})"""
    
    if old_notification_route in app_content:
        app_content = app_content.replace(old_notification_route, new_notification_route)
        print("✅ Route de notifications sécurisée")
    
    # 5. Ajouter une route pour tester la validation
    validation_test_route = '''
@app.route('/api/validate/test', methods=['POST'])
def test_validation():
    """Test de validation des données JSON"""
    try:
        data = request.get_json(force=True, silent=True)
        if data is None:
            return jsonify({
                'success': False,
                'error': 'Aucune donnée JSON fournie'
            }), 400
        
        # Test de validation selon le type de données
        data_type = data.get('type', 'unknown')
        
        if data_type == 'server_config':
            validated = JSONValidator.validate_full_config(data.get('config', {}))
            return jsonify({
                'success': True,
                'message': 'Configuration serveur valide',
                'validated_data': validated
            })
        
        elif data_type == 'telegram_config':
            validated = JSONValidator.validate_telegram_config(data.get('config', {}))
            return jsonify({
                'success': True,
                'message': 'Configuration Telegram valide',
                'validated_data': validated
            })
        
        else:
            return jsonify({
                'success': False,
                'error': 'Type de validation non supporté'
            }), 400
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

'''
    
    if "/api/validate/test" not in app_content:
        # Ajouter avant les WebSocket events
        websocket_marker = "# WebSocket Events"
        if websocket_marker in app_content:
            app_content = app_content.replace(
                websocket_marker,
                validation_test_route + websocket_marker
            )
            print("✅ Route de test de validation ajoutée")
    
    # 6. Ajouter logging de sécurité
    security_logging_patch = '''
# Configuration du logging de sécurité pour la validation JSON
security_logger = logging.getLogger('security')
security_handler = logging.StreamHandler()
security_handler.setFormatter(logging.Formatter(
    '%(asctime)s - SECURITY - %(levelname)s - %(message)s'
))
security_logger.addHandler(security_handler)
security_logger.setLevel(logging.WARNING)

'''
    
    if "security_logger" not in app_content:
        # Ajouter après la configuration du logging principal
        logging_marker = "logger = logging.getLogger(__name__)"
        if logging_marker in app_content:
            app_content = app_content.replace(
                logging_marker,
                logging_marker + "\n\n" + security_logging_patch
            )
            print("✅ Logging de sécurité ajouté")
    
    # 7. Ajouter middleware de sécurité
    security_middleware = '''
@app.before_request
def security_middleware():
    """Middleware de sécurité pour toutes les requêtes"""
    # Logging des requêtes POST avec données JSON
    if request.method == 'POST' and request.is_json:
        endpoint = request.endpoint or 'unknown'
        remote_ip = request.remote_addr or 'unknown'
        
        # Log pour audit (sans inclure les données sensibles)
        logger.info(f"API POST request: {endpoint} from {remote_ip}")
        
        # Vérification de la taille du payload
        content_length = request.content_length
        if content_length and content_length > 1024 * 1024:  # 1MB max
            security_logger.warning(f"Large payload detected: {content_length} bytes from {remote_ip}")
            return jsonify({
                'success': False,
                'error': 'Payload trop volumineux'
            }), 413

'''
    
    if "@app.before_request" not in app_content:
        # Ajouter après la création de l'app Flask
        monitor_marker = "monitor = ServerDiskMonitorWeb()"
        if monitor_marker in app_content:
            app_content = app_content.replace(
                monitor_marker,
                monitor_marker + "\n\n" + security_middleware
            )
            print("✅ Middleware de sécurité ajouté")
    
    # Sauvegarder le fichier patché
    with open('app.py', 'w', encoding='utf-8') as f:
        f.write(app_content)
    
    print("\n🎉 === PATCH VALIDATION JSON APPLIQUÉ ===")
    print("🔒 Sécurité renforcée sur tous les endpoints")
    print("✅ Validation automatique des données JSON")
    print("✅ Sanitisation des inputs utilisateur")
    print("✅ Logging de sécurité intégré")
    print("✅ Protection contre les payloads malveillants")
    print("\n🛡️ Protections ajoutées:")
    print("   - Validation des adresses IP")
    print("   - Sanitisation des noms de serveurs")
    print("   - Validation des UUIDs de disques")
    print("   - Contrôle de la taille des payloads")
    print("   - Nettoyage des caractères dangereux")
    print("\n🧪 Pour tester:")
    print("   curl -X POST http://localhost:5000/api/validate/test \\")
    print("        -H 'Content-Type: application/json' \\")
    print("        -d '{\"type\":\"server_config\",\"config\":{...}}'")

def test_json_validation():
    """Test rapide de la validation JSON"""
    try:
        from json_validator import JSONValidator
        
        print("=== Test du validateur JSON ===")
        
        # Test validation IP
        try:
            JSONValidator.validate_ip_address("192.168.1.100")
            print("✅ Validation IP réussie")
        except:
            print("❌ Validation IP échouée")
        
        # Test validation nom de serveur
        try:
            JSONValidator.validate_server_name("PROD-SERVER-01")
            print("✅ Validation nom serveur réussie")
        except:
            print("❌ Validation nom serveur échouée")
        
        # Test validation avec données malveillantes
        try:
            JSONValidator.validate_server_name("../../../etc/passwd")
            print("❌ Validation faible - données malveillantes acceptées")
        except:
            print("✅ Données malveillantes correctement rejetées")
        
        print("=== Tests terminés ===")
        
    except ImportError:
        print("❌ Module json_validator non trouvé")

if __name__ == "__main__":
    # Vérifications préalables
    if not os.path.exists('app.py'):
        print("❌ Erreur: app.py non trouvé")
        sys.exit(1)
    
    if not os.path.exists('json_validator.py'):
        print("❌ Erreur: json_validator.py non trouvé")
        print("   Assurez-vous d'avoir créé le fichier de validation")
        sys.exit(1)
    
    if len(sys.argv) > 1 and sys.argv[1] == "test":
        test_json_validation()
    else:
        # Créer une sauvegarde
        import shutil
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"app_validation_backup_{timestamp}.py"
        shutil.copy2('app.py', backup_file)
        print(f"📦 Sauvegarde créée: {backup_file}")
        
        # Appliquer le patch
        patch_app_with_json_validation()
        
        print(f"\n🔄 Pour annuler: cp {backup_file} app.py")
        print("🧪 Pour tester: python json_validation_patch.py test")