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

def lazy_import_google_services():
    import google.auth
    from googleapiclient.discovery import build
    return google.auth, build

# Blueprint
analyze_endpoint = Blueprint('analyze_endpoint', __name__)

# --- Cấu hình ---
# API Keys
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
if not GOOGLE_API_KEYS_STR:
    raise ValueError("Biến môi trường GOOGLE_API_KEYS là bắt buộc.")
GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]

# Google Sheets
GOOGLE_SHEET_ID = os.environ.get('GOOGLE_SHEET_ID')
GOOGLE_SHEET_RANGE = os.environ.get('GOOGLE_SHEET_RANGE', 'Sheet1!A2:F')
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

# Email Credentials
GMAIL_USER = os.environ.get('GMAIL_USER')
GMAIL_APP_PASSWORD = os.environ.get('GMAIL_APP_PASSWORD')

# --- Cache ---
g_sheets_service = None
g_cached_sheet_data = []
g_sheet_data_last_fetched = 0
CACHE_DURATION_SECONDS = 900
MAX_CACHE_SIZE = 100

# --- CÁC HÀM HỖ TRỢ (Giữ nguyên, không thay đổi) ---
async def get_sheets_service():
    global g_sheets_service
    if g_sheets_service: return g_sheets_service
    try:
        google_auth, build_func = lazy_import_google_services()
        creds, _ = google_auth.default(scopes=SCOPES)
        loop = asyncio.get_running_loop()
        g_sheets_service = await loop.run_in_executor(
            None, lambda: build_func('sheets', 'v4', credentials=creds, cache_discovery=False)
        )
        return g_sheets_service
    except Exception as e:
        print(f"ERROR: Failed to create Sheets service: {e}")
        return None

async def fetch_sheet_data_optimized():
    global g_cached_sheet_data, g_sheet_data_last_fetched
    current_time = time.time()
    if g_cached_sheet_data and (current_time - g_sheet_data_last_fetched < CACHE_DURATION_SECONDS):
        return g_cached_sheet_data
    service = await get_sheets_service()
    if not service or not GOOGLE_SHEET_ID: return []
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None, lambda: service.spreadsheets().values().get(
                spreadsheetId=GOOGLE_SHEET_ID, range=GOOGLE_SHEET_RANGE
            ).execute()
        )
        values = result.get('values', [])
        if not values: return []
        processed_data = []
        for i, row in enumerate(values[:MAX_CACHE_SIZE]):
            if len(row) >= 6:
                processed_data.append({
                    'id': i, 'text': row[0][:200], 'is_dangerous': row[1].lower() == 'true',
                    'types': row[2], 'reason': row[3][:100],
                    'score': int(row[4]) if row[4].isdigit() else 0, 'recommend': row[5][:100]
                })
        g_cached_sheet_data, g_sheet_data_last_fetched = processed_data, current_time
        gc.collect()
        return processed_data
    except Exception as e:
        print(f"ERROR: Failed to fetch sheet data: {e}")
        return []

async def check_urls_safety_optimized(urls: list):
    if not SAFE_BROWSING_API_KEY or not urls: return []
    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"], "threatEntries": [{"url": url} for url in urls[:5]]
        }
    }
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(safe_browsing_url, json=payload) as resp:
                if resp.status == 200: return (await resp.json()).get("matches", [])
                return []
    except Exception as e:
        print(f"ERROR: URL safety check failed: {e}")
        return []

# --- LUỒNG 1: DB-AI (Cỗ máy đối chiếu ngữ nghĩa) ---

def create_db_ai_prompt(input_text: str, known_data: list) -> str:
    known_texts_str = "\n".join([f'ID {item["id"]}: "{item["text"]}"' for item in known_data])
    return f"""
    VAI TRÒ: Bạn là một cỗ máy đối chiếu ngữ nghĩa siêu chính xác.
    MỤC ĐÍCH: So sánh "TIN NHẮN CẦN KIỂM TRA" với một "CƠ SỞ DỮ LIỆU" các mẫu câu đã biết.
    NHIỆM VỤ: Tìm ra MỘT và CHỈ MỘT mẫu câu trong "CƠ SỞ DỮ LIỆU" có ý nghĩa và ngữ cảnh trùng khớp với "TIN NHẮN CẦN KIỂM TRA" ở mức độ chắc chắn 90% trở lên.

    CƠ SỞ DỮ LIỆU:
    ---
    {known_texts_str}
    ---

    TIN NHẮN CẦN KIỂM TRA:
    ---
    "{input_text}"
    ---

    HƯỚNG DẪN TRẢ VỀ:
    - Nếu tìm thấy một sự trùng khớp rõ ràng (trên 90%), hãy trả về CHỈ SỐ ID của mẫu đó. (Ví dụ: 4)
    - Nếu có nhiều mẫu hơi giống nhưng không có mẫu nào đạt 90% chắc chắn, hoặc hoàn toàn không có mẫu nào giống, hãy trả về CHỈ SỐ -1.
    - CÂU TRẢ LỜI CỦA BẠN CHỈ ĐƯỢC PHÉP LÀ MỘT CON SỐ DUY NHẤT.

    Ví dụ:
    - Tin nhắn: "Chúc mừng bạn đã nhận được 1 voucher 500k, bấm vào link để nhận thưởng."
    - Cơ sở dữ liệu có: ID 15: "Bạn đã trúng thưởng, vui lòng bấm vào đây"
    - Kết quả trả về phải là: 15

    - Tin nhắn: "Chào bạn, cuối tuần đi cà phê không?"
    - Cơ sở dữ liệu không có mẫu nào tương tự.
    - Kết quả trả về phải là: -1
    """

async def semantic_search_with_db_ai(input_text: str, cached_data: list):
    if not cached_data: return None
    genai = lazy_import_genai()
    try:
        api_key = random.choice(GOOGLE_API_KEYS)
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-1.0-pro-latest")
        prompt = create_db_ai_prompt(input_text, cached_data)
        response = await model.generate_content_async(
            prompt,
            generation_config=genai.types.GenerationConfig(temperature=0.0, max_output_tokens=10)
        )
        match_id = int(response.text.strip())
        if match_id != -1:
            for item in cached_data:
                if item['id'] == match_id:
                    # LOG
                    print(f"✅ [DB-AI] Found match! Input text is similar to cached item with ID {match_id}.")
                    return item
        # LOG
        print(f"🟡 [DB-AI] No high-confidence match found. Proceeding to Anna.")
        return None
    except Exception as e:
        print(f"🔴 [DB-AI] Search failed: {e}")
        return None

# --- LUỒNG 2: Anna-AI (Phân tích chuyên sâu) & FEEDBACK LOOP ---

def create_anna_ai_prompt(text: str) -> str:
    return f"""
Bạn là hệ thống phân tích an toàn thông minh tên là Anna. Nhiệm vụ: phát hiện và phân loại đa loại (multi-type) các nguy cơ trong tin nhắn.

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
            
            # LOG
            print(f"✅ [Anna-AI] Analysis successful. Result: {json.dumps(result)}")
            
            required_fields = ['is_dangerous', 'reason', 'types', 'score', 'recommend']
            if all(field in result for field in required_fields):
                return result
        except Exception as e:
            print(f"🔴 [Anna-AI] Analysis failed (attempt {attempt + 1}): {e}")
            continue
    return {"error": "Anna-AI analysis failed after multiple attempts.", "status_code": 500}

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
        # LOG
        print("✅ [Email] Feedback email sent successfully.")
    except Exception as e:
        print(f"🔴 [Email] Failed to send feedback email: {e}")

async def send_email_notification(original_text, analysis_result):
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, _send_sync_email, original_text, analysis_result)

# --- HÀM ĐIỀU PHỐI CHÍNH ---

async def perform_full_analysis(text: str, urls: list):
    # Luồng 1
    cached_data = await fetch_sheet_data_optimized()
    semantic_result = await semantic_search_with_db_ai(text, cached_data)
    
    if semantic_result:
        semantic_result.pop('id', None)
        if urls:
            url_matches = await check_urls_safety_optimized(urls)
            if url_matches:
                semantic_result.update({
                    'url_analysis': url_matches, 'is_dangerous': True,
                    'score': max(semantic_result.get('score', 0), 4),
                    'reason': (semantic_result.get('reason', '') + " + Unsafe URLs")[:100]
                })
        return semantic_result

    # Luồng 2
    anna_ai_task = analyze_with_anna_ai(text)
    urls_task = check_urls_safety_optimized(urls) if urls else asyncio.sleep(0)
    
    anna_ai_result, url_matches = await asyncio.gather(anna_ai_task, urls_task)

    if 'error' in anna_ai_result:
        return anna_ai_result
    
    final_result = anna_ai_result.copy()
    if url_matches:
        final_result.update({
            'url_analysis': url_matches, 'is_dangerous': True,
            'score': max(final_result.get('score', 0), 4),
            'reason': (final_result.get('reason', '') + " + Unsafe URLs")[:100]
        })

    # Feedback Loop
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
        
        # LOG
        print(f"-------------------- NEW REQUEST --------------------")
        print(f"📬 [Input] Received text: '{text[:200]}...'")

        if not text: return jsonify({'error': 'No text to analyze'}), 400
        
        result = await perform_full_analysis(text[:5000], data.get('urls', []))
        
        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status_code', 500)
        
        # LOG
        print("✅ [Response] Sent result back to client successfully.")
        print(f"-----------------------------------------------------\n")
        
        return jsonify({'result': result})
    except Exception as e:
        print(f"🔴 [FATAL] Server error in analyze_text: {e}")
        gc.collect()
        return jsonify({'error': 'Internal server error'}), 500

@analyze_endpoint.route('/health', methods=['GET'])
async def health_check():
    return jsonify({
        'status': 'healthy', 'cache_size': len(g_cached_sheet_data),
        'last_fetch_timestamp': g_sheet_data_last_fetched
    })
