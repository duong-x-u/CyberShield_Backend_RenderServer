from dotenv import load_dotenv
load_dotenv()

# SỬA LẠI DÒNG NÀY: Thêm 'send_from_directory' và bỏ 'send_file' nếu không dùng chỗ khác
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import os
import logging
from api.analyze import analyze_endpoint
from webhook import webhook_blueprint
from zalo_webhook import zalo_blueprint

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
app.register_blueprint(webhook_blueprint, url_prefix='/messenger')
app.register_blueprint(zalo_blueprint, url_prefix='/zalo')


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

# DI CHUYỂN ROUTE XÁC THỰC XUỐNG DƯỚI NÀY
@app.route('/<path:filename>')
def serve_static_file(filename):
    # Chỉ phản hồi nếu tên file bắt đầu bằng 'zalo_verifier'
    if filename.startswith('zalo_verifier') and filename.endswith('.html'):
        # Lấy đường dẫn đến thư mục chứa file app.py hiện tại
        root_dir = os.path.dirname(os.path.abspath(__file__))
        # Tìm file trong thư mục 'static' nằm cùng cấp
        static_dir = os.path.join(root_dir, 'static')
        
        try:
            print(f"Attempting to serve file: {filename} from directory: {static_dir}")
            return send_from_directory(static_dir, filename)
        except FileNotFoundError:
            print(f"Error: File {filename} not found in {static_dir}")
            # Trả về lỗi 404 mặc định của Flask, để errorhandler bên dưới xử lý
            from werkzeug.exceptions import NotFound
            raise NotFound()
    
    # Nếu không khớp, để Flask tiếp tục xử lý và trả về 404
    from werkzeug.exceptions import NotFound
    raise NotFound()


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
