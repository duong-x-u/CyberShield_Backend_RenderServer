import os
import json
import asyncio
from flask import Blueprint, request, jsonify
import aiohttp

# Import bộ não AI (dùng chung với Messenger)
from api.analyze import perform_full_analysis

# --- Cấu hình Zalo ---
zalo_blueprint = Blueprint('zalo_blueprint', __name__)
APP_ID = os.environ.get('ZALO_APP_ID')
VERIFY_TOKEN = os.environ.get('ZALO_VERIFY_TOKEN') # Token bạn tự định nghĩa
ACCESS_TOKEN = os.environ.get('ZALO_ACCESS_TOKEN')
CONVERSATION_DELAY = 1.5

# --- Hàm Gửi Tin Nhắn Zalo (Async) ---
async def send_zalo_message(recipient_id, message_text):
    """Gửi tin nhắn đến người dùng Zalo qua OA API."""
    API_URL = 'https://openapi.zalo.me/v3.0/oa/message/cs'
    headers = {'access_token': ACCESS_TOKEN}
    payload = {
        'recipient': {'user_id': recipient_id},
        'message': {'text': message_text}
    }
    
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(API_URL, json=payload, headers=headers) as resp:
                if resp.status == 200:
                    print(f"✅ Gửi tin nhắn Zalo thành công đến user_id: {recipient_id}")
                    return True
                else:
                    error_data = await resp.json()
                    print(f"🔴 Lỗi khi gửi tin nhắn Zalo: {resp.status} - {error_data}")
                    return False
    except Exception as e:
        print(f"🔴 Lỗi ngoại lệ khi gửi tin nhắn Zalo: {e}")
        return False

# --- Zalo Webhook Endpoints ---

@zalo_blueprint.route('/zalo_webhook', methods=['GET'])
def verify_zalo_webhook():
    """Xác thực webhook với Zalo."""
    # Zalo không dùng 'hub.mode' hay 'hub.challenge' như Facebook
    # Họ chỉ gửi 1 request GET đến URL của bạn khi bạn cấu hình
    # Ta có thể kiểm tra một tham số nào đó để chắc chắn, nhưng thường không cần thiết
    print("ZALO_WEBHOOK_VERIFIED (GET request received)")
    return 'OK', 200 # Chỉ cần trả về 200 OK là được

@zalo_blueprint.route('/zalo_webhook', methods=['POST'])
async def handle_zalo_message():
    """Nhận và xử lý tin nhắn từ Zalo."""
    try:
        data = request.get_json(force=True)
        print(f"📬 Nhận được sự kiện từ Zalo: {json.dumps(data, ensure_ascii=False)}")

        # Zalo gửi các sự kiện khác nhau, ta chỉ xử lý tin nhắn văn bản từ người dùng
        if data.get('event_name') == 'user_send_text':
            sender_id = data['sender']['id']
            message_text = data['message']['text']
            
            print(f'Received Zalo message: "{message_text}" from UserID: {sender_id}')
            
            # <<< DÙNG CHUNG BỘ NÃO PHÂN TÍCH >>>
            analysis_result = await perform_full_analysis(message_text, [])
            print(f"✅ Analysis result: {json.dumps(analysis_result, ensure_ascii=False)}")

            # <<< BẮT ĐẦU LUỒNG HỘI THOẠI (Tương tự Messenger) >>>
            if analysis_result and analysis_result.get('is_dangerous'):
                # Luồng 1: Tin nhắn NGUY HIỂM
                await send_zalo_message(sender_id, "⚠️ Tớ phát hiện tin nhắn này có dấu hiệu không an toàn, cậu nên cẩn thận nhé.")
                await asyncio.sleep(CONVERSATION_DELAY)

                reason = analysis_result.get('reason')
                if reason:
                    await send_zalo_message(sender_id, f"🔎 Cụ thể là: {reason}")
                    await asyncio.sleep(CONVERSATION_DELAY)

                recommend = analysis_result.get('recommend')
                if recommend:
                    await send_zalo_message(sender_id, f"💡 Vì vậy, tớ gợi ý cậu nên: {recommend}")
            
            else:
                # Luồng 2: Tin nhắn AN TOÀN
                await send_zalo_message(sender_id, "✅ Tớ đã quét và thấy tin nhắn này an toàn nhé.")
            # <<< KẾT THÚC LUỒNG HỘI THOẠI >>>

    except Exception as e:
        print(f"🔴 Lỗi nghiêm trọng khi xử lý Zalo webhook: {e}")
    
    return 'OK', 200