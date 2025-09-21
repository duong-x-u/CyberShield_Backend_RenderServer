from dotenv import load_dotenv
load_dotenv()

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify
from flask_cors import CORS

# --- Import các Blueprints của bạn ---
from api.analyze import analyze_endpoint
from webhook import webhook_blueprint
from admin import admin_blueprint, login_manager # <<< CHỈ CẦN IMPORT login_manager TỪ admin.py

# --- Cấu hình Logging (Đặt ở đầu để ghi log ngay từ khi khởi động) ---
LOG_FILE = "cybershield.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        RotatingFileHandler(LOG_FILE, maxBytes=10485760, backupCount=5, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Khởi tạo Ứng dụng Flask ---
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')

if not app.config['SECRET_KEY']:
    logger.critical("FLASK_SECRET_KEY chưa được thiết lập! Ứng dụng sẽ không hoạt động đúng.")
    raise ValueError("FLASK_SECRET_KEY is required for sessions.")

CORS(app)

# --- Khởi tạo và Gắn Flask-Login vào App ---
# login_manager được import từ admin.py, nơi nó đã được cấu hình
login_manager.init_app(app)

# --- Đăng ký tất cả các Blueprints ---
app.register_blueprint(analyze_endpoint, url_prefix='/api')
app.register_blueprint(webhook_blueprint, url_prefix='/messenger') 
app.register_blueprint(admin_blueprint, url_prefix='/admin')

logger.info("✅ All blueprints registered successfully.")

# --- Các Route Cơ bản và Error Handlers ---

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

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': '❌ 404: Page Not Found ://'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}", exc_info=True)
    return jsonify({'error': '💥 500: Quay về phòng thủ. Tế đàn bị tấn công'}), 500

# --- Chạy Server ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    logger.info(f"🚀 Starting CyberShield server on port {port}")
    app.run(host='0.0.0.0', port=port, debug=False)
