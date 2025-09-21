from dotenv import load_dotenv
load_dotenv()

import os
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, jsonify
from flask_cors import CORS
from flask_login import LoginManager

# --- Import các Blueprints của bạn ---
from api.analyze import analyze_endpoint
from webhook import webhook_blueprint
from admin import admin_blueprint, login_manager  

# --- Cấu hình Logging Nâng cao ---
# Ghi log ra cả console (cho Render xem) và file (cho dashboard đọc)
LOG_FILE = "cybershield.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        # Giới hạn file log ở 10MB, giữ lại 5 file cũ
        RotatingFileHandler(LOG_FILE, maxBytes=10485760, backupCount=5, encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Khởi tạo Ứng dụng Flask ---
app = Flask(__name__)
# SECRET_KEY là bắt buộc để Flask-Login và sessions hoạt động an toàn
app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY', os.urandom(24))
CORS(app)

# --- Khởi tạo và Gắn Flask-Login vào App ---
login_manager.init_app(app)
# Nếu người dùng chưa đăng nhập và cố truy cập trang cần login,
# họ sẽ bị chuyển hướng đến trang này.
login_manager.login_view = "admin_blueprint.login"

# --- Đăng ký tất cả các Blueprints ---
app.register_blueprint(analyze_endpoint, url_prefix='/api')
app.register_blueprint(webhook_blueprint) # Webhook nên ở root để Facebook dễ tìm
app.register_blueprint(admin_blueprint, url_prefix='/admin') # Giao diện admin có tiền tố /admin

# --- Các Route Cơ bản và Error Handlers (Giữ nguyên) ---

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
    logger.error(f"Internal error: {str(error)}")
    return jsonify({'error': '💥 500: Quay về phòng thủ. Tế đàn bị tấn công'}), 500

# --- Chạy Server ---
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)