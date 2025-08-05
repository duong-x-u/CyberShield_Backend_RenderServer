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
    """Home endpoint - welcome message"""
    return jsonify({
        'message': 'Welcome to CyberShield Backend API',
        'version': '1.0.0',
        'status': 'running'
    })

@app.route('/health')
def health_check():
    """Health check endpoint for Render"""
    return jsonify({
        'status': 'healthy',
        'service': 'cybershield-backend',
        'timestamp': logging.Formatter().formatTime(logging.LogRecord(
            name='health', level=logging.INFO, pathname='', lineno=0,
            msg='', args=(), exc_info=None
        ))
    })



@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port, debug=False)
