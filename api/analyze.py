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
    print("➡️  [Kiểm tra URL] Bắt đầu kiểm tra URL với Google Safe Browsing...")
    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {"threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url} for url in urls[:5]]}}
    try:
        timeout = aiohttp.ClientTimeout(total=15)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(safe_browsing_url, json=payload) as resp:
                if resp.status == 200:
                    matches = (await resp.json()).get("matches", [])
                    print(f"✅ [Kiểm tra URL] Hoàn tất. Tìm thấy {len(matches)} kết quả không an toàn.")
                    return matches
                print(f"🟡 [Kiểm tra URL] API trả về trạng thái {resp.status}.")
                return []
    except Exception as e:
        print(f"🔴 [Kiểm tra URL] Thất bại: {e}")
        return []

# --- LUỒNG 1: GỌI "ĐIỆP VIÊN LEO" QUA GOOGLE APPS SCRIPT ---
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
                    print("✅ [Leo] Nhận được phản hồi thành công từ GAS.")
                    return await resp.json()
                else:
                    error_text = await resp.text()
                    print(f"🔴 [Leo] Lỗi từ GAS. Trạng thái: {resp.status}, Phản hồi: {error_text}")
                    return {"found": False, "reason": f"GAS trả về lỗi {resp.status}"}
    except Exception as e:
        print(f"🔴 [Leo] Lỗi kết nối đến GAS: {e}")
        return {"found": False, "reason": f"Ngoại lệ: {str(e)}"}

# --- LUỒNG 2: ANNA-AI & BỘ NÃO TĂNG CƯỜNG ---
def create_anna_ai_prompt(text: str, context_hint: str = None):
    # Xây dựng phần gợi ý, chỉ thêm vào prompt nếu có
    hint_section = ""
    if context_hint:
        hint_section = f"""
---
**THÔNG TIN TÌNH BÁO BỔ SUNG (QUAN TRỌNG):**
Hệ thống Leo đã cung cấp một gợi ý về bối cảnh của tin nhắn này. Hãy ưu tiên thông tin này khi phân tích:
"{context_hint}"
---
"""
    # Ghép phần gợi ý vào prompt chính
    return f"""
Bạn là Anna, một chuyên gia phân tích an ninh mạng với trí tuệ cảm xúc cao, chuyên đánh giá các tin nhắn Tiếng Việt. Sứ mệnh của bạn là bảo vệ người dùng khỏi các mối đe dọa **có chủ đích và rõ ràng**, đồng thời phải **bỏ qua các nhiễu thông tin** từ những cuộc trò chuyện thông thường.

{hint_section}
Hãy tuân thủ nghiêm ngặt khung phân tích 3 bước sau đây:

---
**BƯỚC 1: LỌC NHIỄU BAN ĐẦU**

*   **Câu hỏi cốt lõi:** "Tin nhắn này có đủ nội dung để phân tích không?"
*   **Hành động:** Nếu tin nhắn quá ngắn (dưới 4 từ), mơ hồ, hoặc chỉ là biểu cảm mà không có thông tin tình báo bổ sung, hãy **kết luận ngay là AN TOÀN**. Đừng lãng phí tài nguyên để suy diễn các kịch bản tiêu cực không có cơ sở.

---
**BƯỚC 2: XÁC ĐỊNH BỐI CẢNH & Ý ĐỊNH**

*   **Câu hỏi cốt lõi:** "Đây là lời nói của một người lạ có ý đồ xấu, hay là lời nói giữa những người bạn đang trêu đùa?"
*   **Quy tắc ưu tiên:** Mặc định coi mọi cuộc trò chuyện là **thân mật và vô hại**, trừ khi có bằng chứng không thể chối cãi về ý định xấu.
*   **Hành động:**
    *   **Phân tích ngôn ngữ:** Tìm kiếm các từ ngữ tiêu cực. Sau đó, tự hỏi: "Trong bối cảnh bạn bè trêu đùa, từ này có được sử dụng với ý nghĩa nhẹ nhàng hơn không?". Ví dụ, các từ chỉ sự 'ngốc nghếch', 'khờ khạo' hay lời 'thách đố' vui vẻ thường là an toàn.
    *   **Phân tích cảm xúc:** Đánh giá xem cảm xúc thể hiện trong câu là sự tức giận thực sự, hay chỉ là sự bộc phát cảm xúc nhất thời, than thở, hoặc châm biếm? Các lời than thở cá nhân không nhắm vào ai cụ thể thì **KHÔNG phải là mối đe dọa**.
    *   **Phân tích hành động:** Tin nhắn có kêu gọi một hành động nguy hiểm rõ ràng không (VD: đưa tiền, cung cấp thông tin, đến một địa điểm lạ)? Nếu không, hãy hạ mức độ ưu tiên.

---
**BƯỚC 3: KẾT LUẬN DỰA TRÊN BẰNG CHỨNG**

*   **Câu hỏi cốt lõi:** "Tôi có đủ bằng chứng **rõ ràng** để gắn cờ tin nhắn này là nguy hiểm không?"
*   **Hành động:**
    *   **NGUY HIỂM:** Chỉ khi có sự kết hợp của **ý định xấu rõ ràng** VÀ **hành động tiềm tàng gây hại**.
    *   **AN TOÀN:** Tất cả các trường hợp còn lại, đặc biệt là khi ý định không rõ ràng hoặc chỉ là lời nói suông.
*   **Định dạng kết quả:**
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

async def analyze_with_anna_ai_http(text: str, context_hint: str = None):
    api_key = random.choice(GOOGLE_API_KEYS)
    gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={api_key}"    
    prompt = create_anna_ai_prompt(text[:2500], context_hint)
    
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": { "temperature": 0.2, "maxOutputTokens": 400, "responseMimeType": "application/json" }
    }
    try:
        timeout = aiohttp.ClientTimeout(total=25)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            print(f"➡️  [Anna] Đang gửi yêu cầu phân tích tới Google AI...")
            async with session.post(gemini_url, json=payload) as resp:
                if resp.status == 200:
                    response_json = await resp.json()
                    if not response_json.get('candidates'):
                        print(f"🔴 [Anna] Lỗi! Phản hồi không có 'candidates'. Bị bộ lọc an toàn chặn. Chi tiết: {response_json}")
                        return {'error': 'BLOCKED_BY_GOOGLE', 'message': 'Bị bộ lọc an toàn của Google chặn.'}
                    
                    json_text = response_json['candidates'][0]['content']['parts'][0]['text']
                    result = json.loads(json_text)
                    print("✅ [Anna] Phân tích thành công.")
                    return result
                else:
                    error_text = await resp.text()
                    print(f"🔴 [Anna] Lỗi HTTP! Trạng thái: {resp.status}, Phản hồi: {error_text}")
                    return {"error": f"Lỗi API Anna {resp.status}", "status_code": 500}
    except Exception as e:
        print(f"🔴 [Anna] Lỗi ngoại lệ khi gọi HTTP: {e}", exc_info=True)
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
    context_hint_from_leo = None
    
    print(f"📜 [Bắt đầu] Phân tích tin nhắn: '{text[:150]}...'")
    print("➡️ [Luồng 1] Bắt đầu gọi Điệp viên Leo (GAS)...")
    gas_result = await call_gas_db_ai(text)

    if gas_result and gas_result.get("found"):
        result_type = gas_result.get("type")
        
        if result_type == "trivial_pattern":
            print("✅ [Luồng 1] THÀNH CÔNG. Leo xác định tin nhắn là tầm thường (Trivial).")
            return {'is_dangerous': False, 'reason': 'Tin nhắn quá đơn giản để phân tích.', 'score': 0, 'types': 'Trivial'}
        
        elif result_type == "dangerous_pattern":
            print("✅ [Luồng 1] THÀNH CÔNG. Tìm thấy trong Sổ Đen (Blacklist) bằng AI.")
            final_result = gas_result.get("data")
        elif result_type == "context_hint":
            print("📝 [Luồng 1] Nhận được thông tin tình báo từ Leo.")
            context_hint_from_leo = gas_result.get("data")
            
    if final_result is None:
        if context_hint_from_leo:
             print(f"🟡 [Luồng 2] Bắt đầu gọi Anna-AI với thông tin tình báo: '{context_hint_from_leo}'")
        else:
             print(f"🟡 [Luồng 2] Bắt đầu gọi Anna-AI (không có thông tin tình báo).")
        
        final_result = await analyze_with_anna_ai_http(text, context_hint_from_leo)
        
        print(f"📄 [Kết quả của Anna] Phân tích AI trả về: {json.dumps(final_result, ensure_ascii=False)}")

        if 'error' in final_result:
            return final_result
            
        is_new_case_by_anna = True 
    
    if urls:
        url_matches = await check_urls_safety_optimized(urls)
        if url_matches:
            print(f"⚠️ [Phân tích URL] Phát hiện {len(url_matches)} URL không an toàn! Cập nhật kết quả cuối cùng.")
            final_result.update({'url_analysis': url_matches, 'is_dangerous': True, 'score': max(final_result.get('score', 0), 4), 'reason': (final_result.get('reason', '') + " + Các URL không an toàn")[:100]})

    if is_new_case_by_anna and final_result.get("is_dangerous"):
        print("➡️ [Phản hồi] Phát hiện ca nguy hiểm mới. Lên lịch gửi email...")
        email_thread = threading.Thread(target=_send_sync_email, args=(text, final_result))
        email_thread.start()
    elif is_new_case_by_anna:
        print("➡️ [Phản hồi] Phát hiện ca an toàn mới. Bỏ qua việc gửi email.")

    gc.collect()
    print(f"🏁 [Kết thúc] Phân tích hoàn tất cho tin nhắn: '{text[:50]}...'")
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
            return jsonify({'error': result.get('message', 'Lỗi không xác định')}), result.get('status_code', 500)
        
        print("✅ [Phản hồi] Đã gửi kết quả về cho client.")
        return jsonify({'result': result})
    except Exception as e:
        print(f"🔴 [LỖI NGHIÊM TRỌNG] Lỗi server trong hàm analyze_text: {e}", exc_info=True)
        gc.collect()
        return jsonify({'error': 'Lỗi nội bộ server'}), 500

@analyze_endpoint.route('/health', methods=['GET'])
async def health_check():
    return jsonify({'status': 'Bình thường', 'architecture': 'Trivial Filter + Blacklist (AI) + Context Hints + Anna-AI'})
