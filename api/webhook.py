import os
import json
from flask import Blueprint, request, jsonify

# Khởi tạo blueprint để đăng ký các endpoints webhook
webhook_blueprint = Blueprint('webhook_blueprint', __name__)

# Endpoint cho Telegram webhook
@webhook_blueprint.route('/telegram', methods=['POST'])
def telegram_webhook():
    """
    Xử lý các cập nhật từ Telegram.
    Đây là logic hiện tại của bạn, giữ nguyên.
    """
    # ... logic xử lý Telegram webhook của bạn
    return jsonify({'status': 'ok'}), 200

# Endpoint mới cho Facebook Messenger webhook
@webhook_blueprint.route('/facebook', methods=['GET', 'POST'])
def facebook_webhook():
    """
    Xử lý các yêu cầu từ Facebook Messenger.
    - GET: Xác thực webhook.
    - POST: Nhận và xử lý tin nhắn từ người dùng.
    """
    # 1. Xử lý yêu cầu GET để xác thực webhook
    if request.method == 'GET':
        verify_token = os.environ.get('FB_VERIFY_TOKEN')
        mode = request.args.get('hub.mode')
        token = request.args.get('hub.verify_token')
        challenge = request.args.get('hub.challenge')

        if mode and token:
            if mode == 'subscribe' and token == verify_token:
                print('✅ [Facebook Webhook] Đã xác thực thành công.')
                return challenge, 200
            else:
                print('🔴 [Facebook Webhook] Token xác thực không hợp lệ.')
                return 'Token xác thực không hợp lệ.', 403
    
    # 2. Xử lý yêu cầu POST để nhận tin nhắn
    data = request.get_json(silent=True)
    if not data:
        return 'Invalid data', 400

    print('\n----- Nhận được payload từ Facebook -----')
    print(json.dumps(data, indent=2, ensure_ascii=False))
    print('----------------------------------------\n')

    try:
        if 'object' in data and data['object'] == 'page':
            for entry in data.get('entry', []):
                for messaging_event in entry.get('messaging', []):
                    # Chỉ xử lý các sự kiện có tin nhắn và văn bản
                    if messaging_event.get('message') and messaging_event['message'].get('text'):
                        sender_id = messaging_event['sender']['id']
                        message_text = messaging_event['message']['text']
                        print(f'📬 [Facebook] Tin nhắn từ người dùng {sender_id}: "{message_text}"')

        return 'EVENT_RECEIVED', 200
    except Exception as e:
        print(f'🔴 [Facebook Webhook] Lỗi xử lý payload: {e}')
        return 'Internal Server Error', 500