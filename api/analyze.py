import json
import asyncio
import os
import random
import gc
import smtplib
from email.mime.text import MIMEText
from flask import Blueprint, request, jsonify
import aiohttp

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
        return {"found": False, "reason": "GAS URL not configured."}
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
                    return {"found": False, "reason": f"GAS returned status {resp.status}"}
    except Exception as e:
        print(f"🔴 [GAS] Exception: {e}")
        return {"found": False, "reason": f"Exception: {str(e)}"}

# --- LUỒNG 2: ANNA-AI & FEEDBACK LOOP ---

# *** PROMPT MỚI ĐƯỢC CẬP NHẬT Ở ĐÂY ***
def create_anna_ai_prompt(text: str) -> str:
    """Tạo prompt chi tiết cho Anna, dựa trên yêu cầu mới của người dùng."""
    # Ghi chú: Phần {keywords} đã được lược bỏ để giữ cho server Render nhẹ nhất có thể.
    return f"""
Bạn là hệ thống phân tích an toàn thông minh. Nhiệm vụ: phát hiện và phân loại đa loại (multi-type) các nguy cơ trong tin nhắn.

⚡ Khi nào flag ("is_dangerous": true):
1. Lừa đảo/phishing:
   - Ưu đãi "quá tốt để tin"
   - Kêu gọi hành động khẩn cấp, tạo áp lực
   - Yêu cầu cung cấp thông tin cá nhân (tài khoản, OTP, mật khẩu) qua link lạ
   - URL/domain đáng ngờ, giả mạo thương hiệu
2. Quấy rối/toxic:
   - Ngôn ngữ thô tục, xúc phạm, đe dọa, khủng bố tinh thần
3. Nội dung nhạy cảm/chính trị:
   - Kích động bạo lực, nổi loạn, chống phá chính quyền
   - Phát tán tin sai lệch gây hoang mang
4. Khác:
   - Spam hàng loạt, quảng cáo rác
   - Nội dung có tính ép buộc hoặc thao túng tâm lý

⚡ Safe-case (không flag):
- Meme, châm biếm vui, không hại ai
- Link từ domain chính thống (vd: *.gov.vn, *.google.com)
- Thảo luận chính trị trung lập, không kêu gọi hành động
- Thông báo dịch vụ hợp pháp, minh bạch
- Nội dung lịch sử, trích dẫn văn học, bài hát, tài liệu giáo dục chính thống.

⚡ Output JSON (ngắn gọn):
- "is_dangerous" (boolean)
- "reason" (string, ≤ 2 câu, tóm rõ nhất vì sao flag/không flag)
- "types" (string, nhiều loại cách nhau bằng dấu phẩy, ví dụ: "scam, phishing, toxic")
- "score" (0-5)  # 0 = an toàn, 5 = rất nguy hiểm
- "recommend" (string, hành động cụ thể: vd "xoá tin", "bỏ qua", "cảnh giác với link")

Đoạn tin nhắn: {text}
"""

async def analyze_with_anna_ai_http(text: str):
    """Phân tích chuyên sâu với Anna qua HTTP Request trực tiếp (siêu nhẹ)."""
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

def _send_sync_email(original_text, analysis_result):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        print("🟡 [Email] Credentials not set. Skipping notification.")
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
        print("✅ [Email] Feedback email sent successfully.")
    except Exception as e:
        print(f"🔴 [Email] Failed to send feedback email: {e}")

async def send_email_notification(original_text, analysis_result):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _send_sync_email, original_text, analysis_result)

# --- HÀM ĐIỀU PHỐI CHÍNH ---
async def perform_full_analysis(text: str, urls: list):
    final_result = None
    is_new_case = False
    
    print("➡️ [Flow] Starting Luồng 1: Calling GAS DB-AI...")
    gas_result = await call_gas_db_ai(text)

    if gas_result.get("found"):
        print("✅ [Flow] Luồng 1 successful. Found match in database.")
        final_result = gas_result.get("data")
    else:
        print(f"🟡 [Flow] Luồng 1 negative (Reason: {gas_result.get('reason', 'Unknown')}). Starting Luồng 2: Anna-AI...")
        is_new_case = True
        final_result = await analyze_with_anna_ai_http(text)

    if 'error' in final_result:
        return final_result

    if urls:
        url_matches = await check_urls_safety_optimized(urls)
        if url_matches:
            final_result.update({'url_analysis': url_matches, 'is_dangerous': True, 'score': max(final_result.get('score', 0), 4), 'reason': (final_result.get('reason', '') + " + Unsafe URLs")[:100]})

    if is_new_case:
        print("➡️ [Flow] Scheduling feedback email for new case.")
        asyncio.create_task(send_email_notification(text, final_result))
    
    gc.collect()
    return final_result

# --- ENDPOINTS ---
@analyze_endpoint.route('/analyze', methods=['POST'])
async def analyze_text():
    try:
        data = request.get_json(silent=True)
        if not data or 'text' not in data: return jsonify({'error': 'Invalid request format'}), 400
        text = data.get('text', '').strip()
        
        print(f"--------------------\n📬 [Input] Received text: '{text[:100]}...'")
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
    return jsonify({'status': 'healthy', 'architecture': 'GAS + Anna-AI (HTTP)'})
