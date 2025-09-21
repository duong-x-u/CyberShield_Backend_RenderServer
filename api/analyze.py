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

# --- HÀM HỖ TRỢ ---
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

# --- LUỒNG 1: GỌI LEO QUA GOOGLE APPS SCRIPT ---
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
    return f"""
Bạn là Anna, một chuyên gia phân tích an ninh mạng với trí tuệ cảm xúc cao, chuyên đánh giá các tin nhắn Tiếng Việt. Sứ mệnh của bạn là bảo vệ người dùng khỏi nguy hiểm thực sự, đồng thời phải hiểu rõ sự phức tạp trong giao tiếp của con người để tránh báo động sai.

Hãy tuân thủ quy trình tư duy 3 bước sau đây:

---
**BƯỚC 1: ĐÁNH GIÁ MỨC ĐỘ RÕ RÀNG CỦA TIN NHẮN**

- **Câu hỏi:** "Tin nhắn này có đủ thông tin để đưa ra kết luận chắc chắn không?"
- **Hành động:**
    - **NẾU** tin nhắn quá ngắn (dưới 4 từ), viết tắt ("R á", "vào dc ch"), hoặc chỉ chứa biểu tượng cảm xúc => **DỪNG LẠI.** Kết luận ngay là **AN TOÀN (is_dangerous: false, score: 0)** với lý do "Tin nhắn quá ngắn và thiếu ngữ cảnh để đánh giá." Đừng cố suy diễn thêm.
    - **NẾU** tin nhắn đủ dài và rõ nghĩa, chuyển sang Bước 2.

---
**BƯỚC 2: PHÂN TÍCH Ý ĐỊNH DỰA TRÊN NGỮ CẢNH**

- **Câu hỏi:** "Ý định thực sự đằng sau câu chữ này là gì? Đây là một cuộc trò chuyện giữa người lạ hay bạn bè?"
- **Hành động:**
    - **ƯU TIÊN GIẢ ĐỊNH BẠN BÈ:** Hãy luôn bắt đầu với giả định rằng đây là cuộc trò chuyện giữa những người quen biết. Trong ngữ cảnh này, các từ như "mày", "tao", "khùng", "hâm", "giỡn" thường là **trêu đùa và AN TOÀN**. Chỉ gắn cờ nguy hiểm nếu nó đi kèm với một lời đe dọa trực tiếp và rõ ràng.
        - *Ví dụ an toàn:* "m giỡn vs cj m à?" -> Chỉ là cách nói thân mật.
        - *Ví dụ nguy hiểm:* "m mà giỡn nữa thì đừng trách tao ác." -> Có đe dọa hậu quả.
    - **NHẬN DIỆN LỪA ĐẢO:** Tìm kiếm các "cờ đỏ" kinh điển: Ưu đãi phi thực tế, link lạ, tạo áp lực thời gian, yêu cầu thông tin.
    - **NHẬN DIỆN XÚC PHẠM NẶNG:** Tìm kiếm các từ ngữ miệt thị, phân biệt đối xử, thô tục một cách rõ ràng và không thể biện minh bằng ngữ cảnh bạn bè. ("câm mồm", "chết đi").

---
**BƯỚC 3: ĐƯA RA KẾT LUẬN CUỐI CÙNG**

- **Hành động:** Dựa trên phân tích từ Bước 1 và 2, hãy tạo ra đối tượng JSON.
    - **Nếu an toàn:** `is_dangerous` phải là `false`, `score` phải là `0`.
    - **Nếu nguy hiểm:** `is_dangerous` phải là `true`, `score` phải từ 1-5, và `reason`, `recommend` phải rõ ràng, súc tích.

---
**Output JSON (Tiếng Việt):**
- "is_dangerous": (boolean)
- "reason": (string, giải thích ngắn gọn logic của bạn)
- "types": (string)
- "score": (0-5)
- "recommend": (string)

**TIN NHẮN CẦN PHÂN TÍCH:** "{text}"
"""

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
    print("➡️  [Email] Bắt đầu tiến trình gửi email trong luồng riêng...")
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        print("🟡 [Email] Thiếu thông tin xác thực. Bỏ qua việc gửi email.")
        return
    
    detected_types = analysis_result.get("types", "Không xác định")
    score = analysis_result.get("score", "N/A")
    subject = f"[CyberShield Report] Nguy hiểm mới: {detected_types} (Điểm: {score})"

    body = f"""Một tin nhắn mới đã được Anna-AI phân tích và gắn cờ NGUY HIỂM.
Vui lòng xem xét và bổ sung vào Google Sheets.
----------------------------------------------------------
TIN NHẮN GỐC:
{original_text}
----------------------------------------------------------
KẾT QUẢ PHÂN TÍCH:
{json.dumps(analysis_result, indent=2, ensure_ascii=False)}
"""
    to_email = 'duongpham18210@gmail.com'
    msg = MIMEText(body, 'plain', 'utf-8')
    msg['From'], msg['To'], msg['Subject'] = GMAIL_USER, to_email, subject
    
    try:
        print(f"📦 [Email] Chuẩn bị gửi email. Tiêu đề: '{subject}'")
        server = smtplib.SMTP('smtp.gmail.com', 587)
        print("🔌 [Email] Đã kết nối đến server SMTP.")
        server.starttls()
        print("🔐 [Email] Đã bắt đầu TLS.")
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        print("👤 [Email] Đăng nhập thành công.")
        server.sendmail(GMAIL_USER, to_email, msg.as_string())
        print("🚀 [Email] Lệnh gửi email đã được thực thi.")
        server.quit()
        print("✅ [Email] Gửi email phản hồi thành công và đã đóng kết nối.")
    except Exception as e:
        print(f"🔴 [Email] Gửi email phản hồi thất bại: {e}")

# --- HÀM ĐIỀU PHỐI CHÍNH ---
async def perform_full_analysis(text: str, urls: list):
    final_result = None
    is_new_case_by_anna = False
    
    print(f"📜 [Bắt đầu] Phân tích tin nhắn: '{text[:150]}...'")
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

# --- ENDPOINTS ---
@analyze_endpoint.route('/analyze', methods=['POST'])
async def analyze_text():
    try:
        data = request.get_json(silent=True)
        if not data or 'text' not in data: return jsonify({'error': 'Định dạng yêu cầu không hợp lệ'}), 400
        text = data.get('text', '').strip()
        
        print(f"--------------------\n📬 [Đầu vào] Nhận được tin nhắn: '{text[:100]}...'")
        if not text: return jsonify({'error': 'Không có văn bản để phân tích'}), 400
        
        result = await perform_full_analysis(text[:3000], data.get('urls', []))
        
        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status_code', 500)
        
        print("✅ [Phản hồi] Đã gửi kết quả về cho client.")
        return jsonify({'result': result})
    except Exception as e:
        print(f"🔴 [LỖI NGHIÊM TRỌNG] Lỗi server trong hàm analyze_text: {e}")
        gc.collect()
        return jsonify({'error': 'Lỗi nội bộ server'}), 500

@analyze_endpoint.route('/health', methods=['GET'])
async def health_check():
    return jsonify({'status': 'Bình thường', 'architecture': 'GAS + Anna-AI (Phản hồi qua luồng & có bộ lọc)'})
