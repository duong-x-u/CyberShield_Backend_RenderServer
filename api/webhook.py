# Tên file: api/webhook.py

import os
import asyncio
import aiohttp
from flask import Blueprint, request

# Import hàm phân tích cốt lõi
from .analyze import perform_full_analysis

# Đặt tên cho blueprint
webhook_blueprint = Blueprint('webhook_blueprint', __name__)

# Lấy các token từ biến môi trường
PAGE_ACCESS_TOKEN = os.environ.get('PAGE_ACCESS_TOKEN')
VERIFY_TOKEN = os.environ.get('VERIFY_TOKEN')


async def process_message_in_background(sender_id, message_text):
    """
    Hàm này chứa toàn bộ logic nặng, được thiết kế để chạy ở chế độ nền
    để không làm block webhook.
    """
    print(f"🕵️ [Tác vụ nền] Bắt đầu phân tích cho người dùng {sender_id}: '{message_text[:50]}...'")
    
    # Bước 1: Chạy luồng phân tích LEO + ANNA
    analysis_result = await perform_full_analysis(message_text, [])
    
    # Bước 2: Gửi kết quả trả lời lại cho người dùng
    await send_messenger_reply(sender_id, analysis_result)
    print(f"✅ [Tác vụ nền] Hoàn thành xử lý cho người dùng {sender_id}.")


# --- HÀM XỬ LÝ WEBHOOK TỪ FACEBOOK ---
@webhook_blueprint.route('/webhook', methods=['GET', 'POST'])
async def handle_webhook():
    # --- Xử lý yêu cầu GET để xác minh Webhook ---
    if request.method == 'GET':
        mode = request.args.get("hub.mode")
        token = request.args.get("hub.verify_token")
        challenge = request.args.get("hub.challenge")

        if mode and token:
            if mode == "subscribe" and token == VERIFY_TOKEN:
                print("✅ [Webhook] Xác minh Webhook thành công!")
                return challenge, 200
            else:
                print("🔴 [Webhook] Xác minh Webhook thất bại. Token không khớp.")
                return "Verification token mismatch", 403
        
        return "Missing verification parameters", 400

    # --- Xử lý yêu cầu POST khi người dùng gửi tin nhắn ---
    elif request.method == 'POST':
        data = request.get_json()
        print(f"📬 [Webhook] Nhận được dữ liệu từ Messenger: {data}")

        if data.get("object") == "page":
            for entry in data.get("entry", []):
                for messaging_event in entry.get("messaging", []):
                    if messaging_event.get("message"):
                        sender_id = messaging_event["sender"]["id"]
                        message_text = messaging_event["message"].get("text", "")

                        if message_text:
                            # *** LOGIC TỐI ƯU ***
                            # Lên lịch cho tác vụ phân tích và trả lời chạy trong nền.
                            # KHÔNG `await` ở đây để trả lời Facebook ngay lập tức.
                            asyncio.create_task(process_message_in_background(sender_id, message_text))

        # Luôn trả về 200 OK cho Facebook NGAY LẬP TỨC
        print("🚀 [Webhook] Đã lên lịch tác vụ và gửi 200 OK cho Facebook.")
        return "EVENT_RECEIVED", 200


# --- HÀM GỬI TIN NHẮN TRẢ LỜI CHO NGƯỜI DÙNG ---
async def send_messenger_reply(recipient_id, analysis_result):
    """Soạn và gửi tin nhắn trả lời qua Facebook Graph API."""
    
    reply_text = ""
    if 'error' in analysis_result:
        reply_text = f"🤖 Rất tiếc, đã có lỗi xảy ra trong quá trình phân tích: {analysis_result['error']}"
    else:
        is_dangerous = str(analysis_result.get("is_dangerous", False)).lower() == 'true'
        reason = analysis_result.get("reason", "Không có lý do cụ thể.")
        recommend = analysis_result.get("recommend", "Hãy tự mình xem xét cẩn thận.")
        score = analysis_result.get("score", 0)
        types = analysis_result.get("types", "Không xác định")

        if is_dangerous:
            emoji = "❌" if score >= 4 else "⚠️"
            reply_text = (
                f"{emoji} Cảnh báo từ CyberShield! Tin nhắn này có dấu hiệu NGUY HIỂM.\n\n"
                f"- Loại nguy hiểm: {types}\n"
                f"- Lý do: {reason}\n"
                f"➡️ Hành động đề xuất: {recommend}"
            )
        else:
            reply_text = (
                f"✅ Tin nhắn này có vẻ An Toàn.\n\n"
                f"- Phân tích: {reason}"
            )

    params = {"access_token": PAGE_ACCESS_TOKEN}
    headers = {"Content-Type": "application/json"}
    payload = {
        "recipient": {"id": recipient_id},
        "message": {"text": reply_text},
        "messaging_type": "RESPONSE"
    }

    graph_api_url = "https://graph.facebook.com/v23.0/me/messages"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(graph_api_url, params=params, headers=headers, json=payload) as resp:
                if resp.status == 200:
                    print(f"✅ [Messenger] Đã gửi tin nhắn trả lời đến người dùng {recipient_id}")
                else:
                    error_data = await resp.text()
                    print(f"🔴 [Messenger] Gửi tin nhắn thất bại. Trạng thái: {resp.status}, Lỗi: {error_data}")
    except Exception as e:
        print(f"🔴 [Messenger] Lỗi ngoại lệ khi gửi tin nhắn: {e}")
