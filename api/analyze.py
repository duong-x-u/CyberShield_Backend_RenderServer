import json
import asyncio
import os
import random
import time
import gc
from flask import Blueprint, request, jsonify
import aiohttp
import smtplib
from email.mime.text import MIMEText

# --- Lazy imports ---
def lazy_import_genai():
    import google.generativeai as genai
    return genai

# Blueprint
analyze_endpoint = Blueprint('analyze_endpoint', __name__)

# --- Cấu hình MỚI ---
# API Keys cho Anna-AI
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
if not GOOGLE_API_KEYS_STR:
    raise ValueError("Biến môi trường GOOGLE_API_KEYS là bắt buộc.")
GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]

# URL của Google Apps Script Web App (DB-AI)
APPS_SCRIPT_URL = os.environ.get('APPS_SCRIPT_URL')

# Email Credentials cho Feedback Loop
GMAIL_USER = os.environ.get('GMAIL_USER') # Vẫn giữ lại để gửi mail
GMAIL_APP_PASSWORD = os.environ.get('GMAIL_APP_PASSWORD')

# --- HÀM HỖ TRỢ ---

async def check_urls_safety_optimized(urls: list):
    """Kiểm tra độ an toàn của URL (Không thay đổi)"""
    if not SAFE_BROWSING_API_KEY or not urls: return []
    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {"threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url} for url in urls[:5]]}}
    try:
        timeout = aiohttp.ClientTimeout(total=15) # Tăng timeout một chút
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(safe_browsing_url, json=payload) as resp:
                if resp.status == 200: return (await resp.json()).get("matches", [])
                return []
    except Exception as e:
        print(f"ERROR: URL safety check failed: {e}")
        return []

# --- LUỒNG 1: GỌI DB-AI QUA GOOGLE APPS SCRIPT ---

async def call_gas_db_ai(text: str):
    """Gọi đến Web App Google Apps Script để thực hiện tìm kiếm ngữ nghĩa."""
    if not APPS_SCRIPT_URL:
        print("🔴 [GAS] APPS_SCRIPT_URL is not set. Skipping DB-AI.")
        return {"found": False, "reason": "GAS URL not configured."}

    payload = {"text": text}
    try:
        timeout = aiohttp.ClientTimeout(total=20) # Cho GAS tối đa 20s để phản hồi
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(APPS_SCRIPT_URL, json=payload) as resp:
                if resp.status == 200:
                    return await resp.json()
                else:
                    # Log lỗi từ GAS nếu có
                    error_text = await resp.text()
                    print(f"🔴 [GAS] Error calling GAS. Status: {resp.status}, Response: {error_text}")
                    return {"found": False, "reason": f"GAS returned status {resp.status}"}
    except asyncio.TimeoutError:
        print("🔴 [GAS] Timeout error when calling GAS.")
        return {"found": False, "reason": "GAS call timed out."}
    except Exception as e:
        print(f"🔴 [GAS] Exception when calling GAS: {e}")
        return {"found": False, "reason": f"Exception: {str(e)}"}

# --- LUỒNG 2: ANNA-AI & FEEDBACK LOOP (Không thay đổi nhiều) ---

def create_anna_ai_prompt(text: str) -> str:
    return f"""
Bạn là hệ thống phân tích an toàn thông minh tên là Anna. Nhiệm vụ: phát hiện và phân loại đa loại (multi-type) các nguy cơ trong tin nhắn.
⚡ Khi nào flag ("is_dangerous": true):
1. Lừa đảo/phishing: Ưu đãi "quá tốt để tin", kêu gọi hành động khẩn cấp, yêu cầu cung cấp thông tin cá nhân qua link lạ.
2. Quấy rối/toxic: Ngôn ngữ thô tục, xúc phạm, đe dọa, khủng bố tinh thần.
3. Nội dung nhạy cảm/chính trị: Kích động bạo lực, phát tán tin sai lệch.
⚡ Safe-case (không flag): Meme vui, link từ domain chính thống (vd: *.gov.vn), thảo luận trung lập.
⚡ Output JSON (ngắn gọn):
- "is_dangerous" (boolean)
- "reason" (string, ≤ 2 câu)
- "types" (string, ví dụ: "scam, phishing, toxic")
- "score" (0-5)
- "recommend" (string, vd "xoá tin", "cảnh giác với link")
Đoạn tin nhắn: {text}
"""

async def analyze_with_anna_ai(text: str):
    genai = lazy_import_genai()
    for attempt in range(min(3, len(GOOGLE_API_KEYS))):
        try:
            api_key = random.choice(GOOGLE_API_KEYS)
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash-latest")
            prompt = create_anna_ai_prompt(text[:2000])
            response = await model.generate_content_async(
                prompt,
                generation_config=genai.types.GenerationConfig(temperature=0.2, max_output_tokens=400)
            )
            json_text = response.text.strip().replace('```json', '').replace('```', '').strip()
            result = json.loads(json_text)
            print(f"✅ [Anna-AI] Analysis successful.")
            return result
        except Exception as e:
            print(f"🔴 [Anna-AI] Analysis failed (attempt {attempt + 1}): {e}")
            await asyncio.sleep(1)
            continue
    return {"error": "Anna-AI analysis failed.", "status_code": 500}

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

    # Luồng 1: Gọi DB-AI qua GAS
    print("➡️ [Flow] Starting Luồng 1: Calling GAS DB-AI...")
    gas_result = await call_gas_db_ai(text)

    if gas_result.get("found"):
        print("✅ [Flow] Luồng 1 successful. Found match in database.")
        final_result = gas_result.get("data")
    else:
        # Fallback hoặc không tìm thấy -> Chuyển sang Luồng 2
        print(f"🟡 [Flow] Luồng 1 did not find a match (Reason: {gas_result.get('reason')}). Starting Luồng 2: Anna-AI...")
        is_new_case = True
        final_result = await analyze_with_anna_ai(text)

    # Xử lý lỗi từ các luồng
    if 'error' in final_result:
        return final_result

    # Bổ sung kiểm tra URL vào kết quả cuối cùng
    if urls:
        url_matches = await check_urls_safety_optimized(urls)
        if url_matches:
            final_result.update({
                'url_analysis': url_matches, 'is_dangerous': True,
                'score': max(final_result.get('score', 0), 4),
                'reason': (final_result.get('reason', '') + " + Unsafe URLs")[:100]
            })

    # Feedback Loop: Chỉ gửi mail cho trường hợp mới do Anna phân tích
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
    # Health check không cần cache nữa
    return jsonify({'status': 'healthy', 'architecture': 'GAS + Anna-AI'})
