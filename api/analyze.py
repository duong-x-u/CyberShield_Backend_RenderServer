import json
import asyncio
import os
import random
import gc
import smtplib
from email.mime.text import MIMEText
from flask import Blueprint, request, jsonify
import aiohttp
import threading # <<< THÊM MỚI

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
        print(f"🔴 [URL Check] Failed: {e}")
        return []

# --- LUỒNG 1: GỌI DB-AI QUA GOOGLE APPS SCRIPT ---
async def call_gas_db_ai(text: str):
    if not APPS_SCRIPT_URL:
        print("🔴 [GAS] APPS_SCRIPT_URL is not set. Skipping DB-AI.")
        return {"need_more_analyze": True, "reason": "GAS URL not configured."}
    payload = {"text": text}
    try:
        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(APPS_SCRIPT_URL, json=payload) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    error_text = await resp.text()
                    print(f"🔴 [GAS] Error. Status: {resp.status}, Response: {error_text}")
                    return {"need_more_analyze": True, "reason": f"GAS returned status {resp.status}"}
    except Exception as e:
        print(f"🔴 [GAS] Exception: {e}")
        return {"need_more_analyze": True, "reason": f"Exception: {str(e)}"}

# --- LUỒNG 2: ANNA-AI & FEEDBACK LOOP ---

def create_anna_ai_prompt(text: str) -> str:
    """Prompt đã được nâng cấp để xử lý các ca vùng xám."""
    return f"""
Bạn là hệ thống phân tích an toàn thông minh, chuyên phân tích các tin nhắn được gửi đến người dùng. Tên của bạn là Anna. Nhiệm vụ của bạn là phát hiện các nguy cơ, bao gồm cả những nguy cơ ẩn sau các từ ngữ đa nghĩa và ngữ cảnh phức tạp. 
⚡ Khi nào flag ("is_dangerous": true):
1. Lừa đảo/phishing: Ưu đãi "quá tốt để tin", kêu gọi hành động khẩn cấp, yêu cầu cung cấp thông tin cá nhân.
2. Quấy rối/toxic: Ngôn ngữ thô tục, xúc phạm, đe dọa trực tiếp.
3. Nội dung nhạy cảm/chính trị: Kích động bạo lực, phát tán tin sai lệch.
⚡ CẢNH BÁO NGỮ CẢNH & TỪ ĐA NGHĨA (QUAN TRỌNG):
Bạn phải cực kỳ nhạy cảm với những từ ngữ có vẻ trong sáng nhưng được dùng với ý định xấu. Hãy tìm kiếm dấu hiệu của sự mỉa mai, công kích, hạ thấp hoặc thao túng.
- VÍ DỤ 1 (Body Shaming): Một từ như "chubby" (mũm mĩm) là vô hại, nhưng nếu được dùng trong ngữ cảnh chê bai ("Dạo này trông chubby quá, ăn lắm vào rồi lăn nhé") thì đó là hành vi độc hại.
- VÍ DỤ 2 ("Brainrot"): Một nội dung có vẻ "vô tri", "giải trí" nhưng lại lặp đi lặp lại các hình ảnh, âm thanh phi logic một cách ám ảnh, không có tính giáo dục và có thể gây sai lệch nhận thức cho trẻ em thì phải được gắn cờ là có hại.
⚡ Safe-case (không flag):
- Meme, châm biếm vui, không có ý công kích cá nhân.
- Link từ domain chính thống.
- Các từ "chubby", "mập mạp" được dùng với ý nghĩa tích cực, khen ngợi.
⚡ Output JSON (ngắn gọn, chỉ trả lời bằng Tiếng Việt):
- "is_dangerous" (boolean)
- "reason" (string, ≤ 2 câu, đưa ra lý do bạn đánh giá nó nguy hiểm)
- "types" (string, có thể bao gồm nhiều loại. Ví dụ: "xúc phạm", "miệt thị ngoại hình", "nội dung nguy hiểm", "thối não", "không có tính giáo dục")
- "score" (0-5, đánh dấu là 0 nếu an toàn, đánh dấu từ 1-5 tuỳ theo mức nguy hiểm)
- "recommend" (string, đưa ra gợi ý cho người dùng nên làm gì tiếp theo)
Sau đây là đoạn tin nhắn người dùng đã nhận được: {text}
"""

async def analyze_with_anna_ai_http(text: str):
    api_key = random.choice(GOOGLE_API_KEYS)
    gemini_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key={api_key}"
    prompt = create_anna_ai_prompt(text[:2500])
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.2, "maxOutputTokens": 400, "responseMimeType": "application/json",
        }
    }
    try:
        timeout = aiohttp.ClientTimeout(total=25)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(gemini_url, json=payload) as resp:
                if resp.status == 200:
                    response_json = await resp.json()
                    json_text = response_json['candidates'][0]['content']['parts'][0]['text']
                    result = json.loads(json_text)
                    print("✅ [Anna-AI] Analysis successful via HTTP.")
                    return result
                else:
                    error_text = await resp.text()
                    print(f"🔴 [Anna-AI] HTTP Error! Status: {resp.status}, Response: {error_text}")
                    return {"error": f"Anna-AI API Error {resp.status}", "status_code": 500}
    except Exception as e:
        print(f"🔴 [Anna-AI] HTTP Exception: {e}")
        return {"error": "Anna-AI analysis failed due to exception.", "status_code": 500}

# *** THAY ĐỔI LỚN NẰM Ở CÁCH GỌI HÀM NÀY ***
def _send_sync_email(original_text, analysis_result):
    """Hàm này giờ sẽ được chạy trong một thread riêng biệt."""
    print("➡️ [Email Thread] Starting email sending process...")
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        print("🟡 [Email Thread] Credentials not set. Skipping notification.")
        return
    
    subject = "[CyberShield Report] Yêu cầu bổ sung CSDL"
    body = f"""Một tin nhắn mới đã được Anna-AI phân tích.
Vui lòng xem xét và bổ sung vào Google Sheets nếu cần thiết.
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
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        server.sendmail(GMAIL_USER, to_email, msg.as_string())
        server.quit()
        print("✅ [Email Thread] Feedback email sent successfully.")
    except Exception as e:
        print(f"🔴 [Email Thread] Failed to send feedback email: {e}")

# --- HÀM ĐIỀU PHỐI CHÍNH ---
async def perform_full_analysis(text: str, urls: list):
    final_result = None
    is_new_case = False
    
    print("➡️ [Flow] Starting Luồng 1: Calling Simple GAS DB-AI...")
    gas_result = await call_gas_db_ai(text)

    # Quay lại logic kiểm tra "found" đơn giản
    if gas_result and gas_result.get("found"):
        print("✅ [Flow] Luồng 1 successful. Found direct match in database.")
        final_result = gas_result.get("data")
    else:
        reason = "Unknown"
        if gas_result:
            reason = gas_result.get('reason', 'Not found in DB')
        print(f"🟡 [Flow] Luồng 1 negative (Reason: {reason}). Starting Luồng 2: Anna-AI...")
        is_new_case = True
        final_result = await analyze_with_anna_ai_http(text)
        if 'error' in final_result:
            return final_result

    if urls:
        url_matches = await check_urls_safety_optimized(urls)
        if url_matches:
            final_result.update({'url_analysis': url_matches, 'is_dangerous': True, 'score': max(final_result.get('score', 0), 4), 'reason': (final_result.get('reason', '') + " + Unsafe URLs")[:100]})

    if is_new_case:
        print("➡️ [Flow] Scheduling feedback email for new case via Thread.")
        email_thread = threading.Thread(target=_send_sync_email, args=(text, final_result))
        email_thread.start()
    
    gc.collect()
    return final_result


# --- ENDPOINTS ---
@analyze_endpoint.route('/analyze', methods=['POST'])
async def analyze_text():
    try:
        data = request.get_json(silent=True)
        if not data or 'text' not in data: return jsonify({'error': 'Invalid request format'}), 400
        text = data.get('text', '').strip()
        
        print(f"--------------------\n📬 [Input] Received text: '{text}...'")
        if not text: return jsonify({'error': 'No text to analyze'}), 400
        
        result = await perform_full_analysis(text[:3000], data.get('urls', []))
        
        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status_code', 500)
        
        print("✅ [Response] Sent result back to client.")
        return jsonify({'result': result})
    except Exception as e:
        print(f"🔴 [FATAL] Server error in analyze_text: {e}")
        gc.collect()
        return jsonify({'error': 'Internal server error'}), 500

@analyze_endpoint.route('/health', methods=['GET'])
async def health_check():
    return jsonify({'status': 'healthy', 'architecture': 'GAS + Anna-AI (Threaded Feedback)'})
