from dotenv import load_dotenv
load_dotenv()

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify
from flask_cors import CORS
from flask_login import LoginManager

# --- Khởi tạo Ứng dụng Flask trước khi import blueprints ---
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))
CORS(app)

# Đảm bảo biến 'app' có thể được Gunicorn tìm thấy
application = app  # Alias cho Gunicorn nếu cần

# --- Khởi tạo LoginManager ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "admin_blueprint.login"

# --- Import các Blueprints sau khi app đã được khởi tạo ---
# Sử dụng import có điều kiện để tránh crash
analyze_endpoint = None
webhook_blueprint = None
admin_blueprint = None

try:
    from api.analyze import analyze_endpoint
    print("✅ analyze_endpoint imported successfully")
except ImportError as e:
    print(f"⚠️ Cannot import analyze_endpoint: {e}")
except Exception as e:
    print(f"❌ Error importing analyze_endpoint: {e}")

try:
    from webhook import webhook_blueprint
    print("✅ webhook_blueprint imported successfully")
except ImportError as e:
    print(f"⚠️ Cannot import webhook_blueprint: {e}")
except Exception as e:
    print(f"❌ Error importing webhook_blueprint: {e}")

try:
    from admin import admin_blueprint
    print("✅ admin_blueprint imported successfully")
except ImportError as e:
    print(f"⚠️ Cannot import admin_blueprint: {e}")
except Exception as e:
    print(f"❌ Error importing admin_blueprint: {e}")

# Debug: In ra các biến có trong module
print(f"📋 Module variables: {[var for var in dir() if not var.startswith('_')]}")
print(f"🚀 Flask app instance: {app}")
print(f"🔧 App name: {app.name}")

# --- Cấu hình Logging Nâng cao ---
LOG_FILE = "cybershield.log"

# Tạo thư mục logs nếu chưa tồn tại
log_dir = os.path.dirname(LOG_FILE) if os.path.dirname(LOG_FILE) else '.'
os.makedirs(log_dir, exist_ok=True)

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=10485760, backupCount=5, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- User loader cho Flask-Login ---
@login_manager.user_loader
def load_user(user_id):
    # TODO: Implement user loading logic
    # Ví dụ: return User.get(user_id)
    return None

# --- Đăng ký các Blueprints nếu import thành công ---
if analyze_endpoint:
    app.register_blueprint(analyze_endpoint, url_prefix='/api')
    logger.info("Registered analyze_endpoint blueprint")

if webhook_blueprint:
    app.register_blueprint(webhook_blueprint)  # Webhook ở root
    logger.info("Registered webhook_blueprint")

if admin_blueprint:
    app.register_blueprint(admin_blueprint, url_prefix='/admin')
    logger.info("Registered admin_blueprint")

# --- Các Route Cơ bản ---

@app.route('/')
def home():
    """Home endpoint - cyberpunk gaming vibe"""
    return jsonify({
        'banner': '⚡ WELCOME TO ARENA OF CYBERSHIELD ⚡',
        'status': '🟢 Sẵn Sàng',
        'version': '1.0.0',
        'server': '0xCyb3r-Sh13ld',
        'message': [
            "Chào mừng đến với Server của Cyber Shield",
            "Kẻ địch sẽ xuất trận sau 5 giây"
        ]
    })

@app.route('/health')
def health_check():
    return jsonify({
        'status': '🟢 Systems Nominal',
        'hp': '100/100',
        'mana': '∞',
        'latency_ms': 5,
        'service': 'cybershield-backend',
        'note': 'Tế đàn còn ổn'
    })

# --- Error Handlers ---

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': '❌ 404: Page Not Found ://'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}")
    return jsonify({'error': '💥 500: Quay về phòng thủ. Tế đàn bị tấn công'}), 500

@app.errorhandler(ImportError)
def import_error(error):
    logger.error(f"Import error: {str(error)}")
    return jsonify({'error': '🔧 Module import failed'}), 500

# --- Chạy Server ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    logger.info(f"Starting CyberShield server on port {port}")
    
    # Kiểm tra các biến môi trường quan trọng
    if not os.environ.get('FLASK_SECRET_KEY'):
        logger.warning("FLASK_SECRET_KEY not set, using random key")
    
    app.run(host='0.0.0.0', port=port, debug=False)

# Đảm bảo biến app luôn có sẵn cho Gunicorn
print(f"🎯 Final check - app variable: {app}")
print(f"🎯 App is callable: {callable(app)}")

# Export app cho WSGI servers
__all__ = ['app']
