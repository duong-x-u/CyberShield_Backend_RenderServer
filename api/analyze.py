import json
import asyncio
import os
import random
import gc
import smtplib
from email.mime.text import MIMEText
from flask import Blueprint, request, jsonify
import aiohttp
import threading
import base64

# --- Crypto Imports ---
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# --- Blueprint ---
analyze_endpoint = Blueprint('analyze_endpoint', __name__)

# --- Cấu hình ---
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
if not GOOGLE_API_KEYS_STR:
    raise ValueError("Biến môi trường GOOGLE_API_KEYS là bắt buộc.")
GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]

APPS_SCRIPT_URL = os.environ.get('APPS_SCRIPT_URL')
GMAIL_USER = os.environ.get('GMAIL_USER')
GMAIL_APP_PASSWORD = os.environ.get('GMAIL_APP_PASSWORD')

# --- CRYPTO CONFIG ---
SERVER_PRIVATE_KEY_PEM = os.environ.get('SERVER_PRIVATE_KEY')
if not SERVER_PRIVATE_KEY_PEM:
    raise ValueError("Biến môi trường SERVER_PRIVATE_KEY là bắt buộc.")
try:
    SERVER_PRIVATE_KEY = RSA.import_key(SERVER_PRIVATE_KEY_PEM)
except Exception as e:
    raise ValueError(f"Không thể import Private Key. Lỗi: {e}")


# --- HÀM HỖ TRỢ (giữ nguyên) ---
async def check_urls_safety_optimized(urls: list):
    if not SAFE_BROWSING_API_KEY or not urls: return []
    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {"threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url} for url in urls[:5]]}}
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(safe_browsing_url, json=payload) as resp:
                if resp.status == 200: return (await resp.json()).get("matches", [])
                return []
    except Exception as e:
        print(f"🔴 [Kiểm tra URL] Thất bại: {e}")
        return []

async def call_gas_db_ai(text: str):
    if not APPS_SCRIPT_URL:
        print("🔴 [Leo] Lỗi: Biến môi trường APPS_SCRIPT_URL chưa được thiết lập.")
        return {"found": False, "reason": "GAS URL chưa được cấu hình."}
    payload = {"text": text}
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(APPS_SCRIPT_URL, json=payload) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    error_text = await resp.text()
                    print(f"🔴 [Leo] Lỗi từ GAS. Trạng thái: {resp.status}, Phản hồi: {error_text}")
                    return {"found": False, "reason": f"GAS trả về lỗi {resp.status}"}
    except Exception as e:
        print(f"🔴 [Leo] Lỗi kết nối đến GAS: {e}")
        return {"found": False, "reason": f"Ngoại lệ: {str(e)}"}

def create_anna_ai_prompt(text: str) -> str:
    return f'''
Bạn là hệ thống phân tích an toàn thông minh, chuyên phân tích các tin nhắn được gửi đến người dùng. Tên của bạn là Anna. Nhiệm vụ của bạn là phát hiện các nguy cơ, bao gồm cả những nguy cơ ẩn sau các từ ngữ đa nghĩa và ngữ cảnh phức tạp. 
⚡ Khi nào flag ("is_dangerous": true):
1. Lừa đảo/phishing: Ưu đãi "quá tốt để tin", kêu gọi hành động khẩn cấp, yêu cầu cung cấp thông tin cá nhân.
2. Quấy rối/toxic: Ngôn ngữ thô tục, xúc phạm, đe dọa trực tiếp.
3. Nội dung nhạy cảm/chính trị: Kích động bạo lực, phát tán tin sai lệch.
⚡ CẢNH BÁO NGỮ CẢNH & TỪ ĐA NGHĨA (QUAN TRỌNG):
Bạn phải cực kỳ nhạy cảm với những từ ngữ có vẻ trong sáng nhưng được dùng với ý định xấu.
- VÍ DỤ 1 (Body Shaming): Từ "chubby" có thể vô hại, nhưng trong ngữ cảnh chê bai ("Dạo này trông chubby quá, ăn lắm vào rồi lăn nhé") thì đó là hành vi độc hại.
- VÍ DỤ 2 ("Brainrot"): Nội dung có vẻ "vô tri" nhưng lặp đi lặp lại một cách ám ảnh, gây sai lệch nhận thức cho trẻ em thì phải được gắn cờ là có hại.
⚡ Safe-case (không flag):
- Meme, châm biếm vui, không có ý công kích cá nhân.
- Link từ domain chính thống.
- CÁC CUỘC TRÒ CHUYỆN THÔNG THƯỜNG, HỎI HAN, NHỜ VẢ GIỮA BẠN BÈ (ví dụ: "Ai làm hộ tớ với", "Làm gì mà trễ vậy"). Hãy xem xét chúng là an toàn trừ khi có dấu hiệu đe dọa hoặc xúc phạm rõ ràng.
⚡ Output JSON (ngắn gọn, chỉ trả lời bằng Tiếng Việt):
- "is_dangerous" (boolean)
- "reason" (string, ≤ 2 câu, đưa ra lý do bạn đánh giá nó nguy hiểm)
- "types" (string, có thể bao gồm nhiều loại)
- "score" (0-5, đánh dấu là 0 nếu an toàn)
- "recommend" (string, đưa ra gợi ý cho người dùng)
Sau đây là đoạn tin nhắn người dùng đã nhận được: {text}
'''

async def analyze_with_anna_ai_http(text: str):
    api_key = random.choice(GOOGLE_API_KEYS)
    gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={api_key}"
    prompt = create_anna_ai_prompt(text[:2500])
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": { "temperature": 0.2, "maxOutputTokens": 400, "responseMimeType": "application/json" }
    }
    try:
        timeout = aiohttp.ClientTimeout(total=25)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(gemini_url, json=payload) as resp:
                if resp.status == 200:
                    response_json = await resp.json()
                    json_text = response_json['candidates'][0]['content']['parts'][0]['text']
                    result = json.loads(json_text)
                    return result
                else:
                    error_text = await resp.text()
                    print(f"🔴 [Anna] Lỗi HTTP! Trạng thái: {resp.status}, Phản hồi: {error_text}")
                    return {"error": f"Lỗi API Anna {resp.status}", "status_code": 500}
    except Exception as e:
        print(f"🔴 [Anna] Lỗi ngoại lệ khi gọi HTTP: {e}")
        return {"error": "Phân tích với Anna thất bại do có ngoại lệ.", "status_code": 500}

def _send_sync_email(original_text, analysis_result):
    # ... (giữ nguyên hàm gửi email)
    print("➡️  [Email] Bắt đầu tiến trình gửi email trong luồng riêng...")
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        print("🟡 [Email] Thiếu thông tin xác thực. Bỏ qua việc gửi email.")
        return
    
    detected_types = analysis_result.get("types", "Không xác định")
    score = analysis_result.get("score", "N/A")
    subject = f"[CyberShield Report] Nguy hiểm mới: {detected_types} (Điểm: {score})"

    body = f'''Một tin nhắn mới đã được Anna-AI phân tích và gắn cờ NGUY HIỂM.

Vui lòng xem xét và bổ sung vào Google Sheets.
----------------------------------------------------------
TIN NHẮN GỐC:
{original_text}
----------------------------------------------------------
KẾT QUẢ PHÂN TÍCH:
{json.dumps(analysis_result, indent=2, ensure_ascii=False)}
'''
    to_email = 'duongpham18210@gmail.com'
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['From'], msg['To'], msg['Subject'] = GMAIL_USER, to_email, subject
    
    try:
        print(f"📦 [Email] Chuẩn bị gửi email. Tiêu đề: '{subject}'")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, to_email, msg.as_string())
        server.quit()
        print("✅ [Email] Gửi email phản hồi thành công.")
    except Exception as e:
        print(f"🔴 [Email] Gửi email phản hồi thất bại: {e}")


# --- HÀM ĐIỀU PHỐI CHÍNH ---
async def perform_full_analysis(text: str, urls: list):
    final_result = None
    is_new_case_by_anna = False
    
    # Đã vô hiệu hóa để bảo mật, chỉ bật khi debug sâu
    # print(f"📜 [Bắt đầu] Phân tích tin nhắn: '{text[:150]}...'" ) 
    print("➡️ [Luồng 1] Bắt đầu gọi Leo (GAS DB-AI)...")
    gas_result = await call_gas_db_ai(text)

    if gas_result and gas_result.get("found"):
        print("✅ [Luồng 1] Thành công. Tìm thấy kết quả trùng khớp trong CSDL.")
        final_result = gas_result.get("data")
        print(f"📄 [Kết quả của Leo] Trả về dữ liệu từ cache: {json.dumps(final_result, ensure_ascii=False)}")
    else:
        reason = "Không xác định"
        if gas_result:
            reason = gas_result.get('reason', 'Không tìm thấy trong CSDL')
        print(f"🟡 [Luồng 1] Thất bại (Lý do: {reason}). Bắt đầu Luồng 2: Anna-AI...")
        
        final_result = await analyze_with_anna_ai_http(text)
        print(f"📄 [Kết quả của Anna] Phân tích AI trả về: {json.dumps(final_result, ensure_ascii=False)}")

        if 'error' in final_result:
            return final_result
            
        is_new_case_by_anna = True 

    if urls:
        url_matches = await check_urls_safety_optimized(urls)
        if url_matches:
            final_result.update({'url_analysis': url_matches, 'is_dangerous': True, 'score': max(final_result.get('score', 0), 4), 'reason': (final_result.get('reason', '') + " + Các URL không an toàn")[:100]})

    if is_new_case_by_anna and final_result.get("is_dangerous"):
        print("➡️ [Phản hồi] Phát hiện ca nguy hiểm mới. Lên lịch gửi email...")
        email_thread = threading.Thread(target=_send_sync_email, args=(text, final_result))
        email_thread.start()
    elif is_new_case_by_anna:
        print("➡️ [Phản hồi] Phát hiện ca an toàn mới. Bỏ qua việc gửi email.")

    gc.collect()
    return final_result

# --- ENDPOINTS (ĐÃ CẬP NHẬT VÀ SỬA LỖI IV REUSE) ---
@analyze_endpoint.route('/analyze', methods=['POST'])
async def analyze_text_encrypted():
    try:
        request_data = request.get_json(silent=True)
        if not request_data or 'encrypted_key' not in request_data or 'encrypted_data' not in request_data or 'iv' not in request_data:
            return jsonify({'error': 'Yêu cầu không hợp lệ. Thiếu các trường mã hóa.'}), 400

        print("--------------------\n📬 [Đầu vào] Nhận được yêu cầu đã mã hóa...")
        print(f"🐛 DEBUG: Dữ liệu mã hóa nhận được: {request_data}")

        # 1. Giải mã session key
        try:
            cipher_rsa = PKCS1_OAEP.new(SERVER_PRIVATE_KEY)
            session_key = cipher_rsa.decrypt(base64.b64decode(request_data['encrypted_key']))
        except Exception as e:
            print(f"🔴 [Crypto] Lỗi giải mã session key: {e}")
            return jsonify({'error': 'Không thể giải mã khóa phiên.'}), 400

        # 2. Giải mã dữ liệu
        try:
            iv_from_client = base64.b64decode(request_data['iv'])
            tag = base64.b64decode(request_data['tag'])
            encrypted_data = base64.b64decode(request_data['encrypted_data'])
            
            cipher_aes = AES.new(session_key, AES.MODE_GCM, nonce=iv_from_client)
            decrypted_payload_bytes = cipher_aes.decrypt_and_verify(encrypted_data, tag)
            payload = json.loads(decrypted_payload_bytes.decode('utf-8'))
            text = payload.get('text', '').strip()
            urls = payload.get('urls', [])
            print("✅ [Crypto] Giải mã yêu cầu thành công.")
            print(f"🐛 DEBUG: Dữ liệu đã giải mã: {text}")
        except (ValueError, KeyError) as e:
            print(f"🔴 [Crypto] Lỗi giải mã dữ liệu hoặc xác thực thất bại: {e}")
            return jsonify({'error': 'Dữ liệu không hợp lệ hoặc đã bị thay đổi.'}), 400

        if not text:
            return jsonify({'error': 'Không có văn bản để phân tích sau khi giải mã.'}), 400

        # 3. Thực hiện phân tích như cũ
        result = await perform_full_analysis(text[:3000], urls)
        
        # Chuẩn bị dữ liệu phản hồi
        if 'error' in result:
            response_data = {"status": "error", "message": result['error']}
        else:
            response_data = {"status": "success", "result": result}
        
        print(f"🐛 DEBUG: Kết quả phân tích (chưa mã hóa): {response_data}")

        # 4. Mã hóa kết quả trả về với IV MỚI
        response_iv = get_random_bytes(12) # KHẮC PHỤC: Tạo IV mới cho mỗi lần mã hóa
        cipher_aes_out = AES.new(session_key, AES.MODE_GCM, nonce=response_iv)
        encrypted_response, response_tag = cipher_aes_out.encrypt_and_digest(json.dumps(response_data).encode('utf-8'))

        response_payload = {
            "iv": base64.b64encode(response_iv).decode('utf-8'),
            "encrypted_response": base64.b64encode(encrypted_response).decode('utf-8'),
            "tag": base64.b64encode(response_tag).decode('utf-8')
        }
        
        print(f"🐛 DEBUG: Kết quả phản hồi (đã mã hóa): {response_payload}")
        print("✅ [Phản hồi] Đã mã hóa và gửi kết quả về cho client.")
        
        if 'error' in result:
             return jsonify(response_payload), result.get('status_code', 500)
        else:
             return jsonify(response_payload)

    except Exception as e:
        print(f"🔴 [LỖI NGHIÊM TRỌNG] Lỗi server trong hàm analyze_text_encrypted: {e}")
        gc.collect()
        return jsonify({'error': 'Lỗi nội bộ server'}), 500


@analyze_endpoint.route('/health', methods=['GET'])
async def health_check():
    return jsonify({'status': 'Bình thường', 'architecture': 'Encrypted (IV Reuse Fixed) | GAS + Anna-AI'})