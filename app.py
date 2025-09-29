from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os
import logging
from api.analyze import analyze_endpoint
from webhook import webhook_blueprint  # Import Blueprint từ file webhook.py
from zalo_webhook import zalo_blueprint
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Register blueprints
app.register_blueprint(analyze_endpoint, url_prefix='/api')
app.register_blueprint(webhook_blueprint, url_prefix='/messenger') # Đăng ký Blueprint của webhook
app.register_blueprint(zalo_blueprint, url_prefix='/zalo') # <-- MỚI: Đăng ký Blueprint của Zalo


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
    "Kẻ địch sẽ xuất trận sau 5 giây"]
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

@app.route('/zalo_verifierJIUJTRN25q5owArPZi8IPNVYeZkRb7LZE3Gm.html')
def zalo_domain_verification():
    try:
        # Flask sẽ tìm file này trong thư mục 'static' mà bạn vừa tạo
        return send_file('static/JIUJTRN25q5owArPZi8IPNVYeZkRb7LZE3Gm.html')
    except FileNotFoundError:
        return "Verification file not found.", 404


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': '❌ 404: Page Not Found ://'}), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {str(error)}")
    return jsonify({'error': '💥 500: Quay về phòng thủ. Tế đàn bị tấn công'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
