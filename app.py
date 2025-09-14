from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import logging
from api.analyze import analyze_endpoint

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


@app.route('/verify-keys-debug')
def verify_keys_debug():
    import re
    from Cryptodome.PublicKey import RSA

    def get_private_key_from_env(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('SERVER_PRIVATE_KEY='):
                        key_with_escapes = line.split('=', 1)[1].strip().strip('"')
                        return key_with_escapes.replace('\n', '\n')
        except Exception as e:
            return f"Error reading .env file: {e}"
        return None

    def get_public_key_from_kt(path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                content = f.read()
                match = re.search(r'const val SERVER_PUBLIC_KEY = """(.*?)"""', content, re.DOTALL)
                if match:
                    return match.group(1).strip()
        except Exception as e:
            return f"Error reading .kt file: {e}"
        return None

    private_key_pem = get_private_key_from_env("D:\\DuAn\\NewCyberShield\\Server\\Render_Server\\.env")
    public_key_pem_from_client = get_public_key_from_kt("D:\\DuAn\\NewCyberShield\\android\\app\\src\\main\\java\\com\\thaiduong\\cybershield\\security\\SecurityConstants.kt")

    if not private_key_pem or not isinstance(private_key_pem, str):
        return jsonify({'status': 'FAILURE', 'error': 'Could not read private key from .env', 'details': private_key_pem})

    if not public_key_pem_from_client or not isinstance(public_key_pem_from_client, str):
        return jsonify({'status': 'FAILURE', 'error': 'Could not read public key from .kt file', 'details': public_key_pem_from_client})

    try:
        private_key = RSA.import_key(private_key_pem)
        derived_public_key = private_key.publickey()
        derived_public_key_pem = derived_public_key.export_key('PEM').decode('utf-8')

        clean_derived_key = ''.join(derived_public_key_pem.splitlines()[1:-1])
        clean_client_key = ''.join(public_key_pem_from_client.splitlines())

        if clean_derived_key == clean_client_key:
            return jsonify({'status': 'SUCCESS', 'message': 'The public key on the client MATCHES the private key on the server.'})
        else:
            return jsonify({
                'status': 'FAILURE', 
                'error': 'Key mismatch detected!',
                'derived_public_key': derived_public_key_pem,
                'client_public_key': public_key_pem_from_client
            })

    except Exception as e:
        return jsonify({'status': 'FAILURE', 'error': f'An error occurred during key verification: {str(e)}'})





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
