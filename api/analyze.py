import json
import asyncio
import os
import random
import hashlib
import redis
import aiohttp
from flask import Blueprint, request, jsonify
import google.generativeai as genai
import google.auth
from googleapiclient.discovery import build

# Khởi tạo Blueprint
analyze_endpoint = Blueprint('analyze_endpoint', __name__)

# --- Cấu hình Redis ---
try:
    REDIS_URL = os.environ.get('REDIS_URL')
    if not REDIS_URL:
        print("Cảnh báo: REDIS_URL không được thiết lập. Tính năng cache sẽ bị vô hiệu hóa.")
        redis_client = None
    else:
        redis_client = redis.from_url(REDIS_URL)
        redis_client.ping()
        print("Kết nối Redis thành công.")
except redis.exceptions.ConnectionError as e:
    print(f"Lỗi kết nối Redis: {e}. Tính năng cache sẽ bị vô hiệu hóa.")
    redis_client = None

# --- Cấu hình Google APIs ---
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')

# Cấu hình Google Sheets - các biến này sẽ được đọc từ môi trường của Render
GOOGLE_SHEET_ID = os.environ.get('GOOGLE_SHEET_ID')
GOOGLE_SHEET_RANGE = os.environ.get('GOOGLE_SHEET_RANGE')
SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']

if not GOOGLE_API_KEYS_STR:
    raise ValueError("Biến môi trường GOOGLE_API_KEYS là bắt buộc.")
GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]
if not GOOGLE_API_KEYS:
    raise ValueError("GOOGLE_API_KEYS phải chứa ít nhất một key hợp lệ.")
if not SAFE_BROWSING_API_KEY:
    print("Cảnh báo: SAFE_BROWSING_API_KEY không được thiết lập. Tính năng quét URL sẽ bị vô hiệu hóa.")

# --- Logic Phân tích ---
UNIFIED_PROMPT = lambda text, keywords: f"""
Bạn là hệ thống phân tích an toàn thông minh. Nhiệm vụ: phát hiện và phân loại đa loại (multi-type) các nguy cơ trong tin nhắn.

⚡ Khi nào flag ("is_scam": true):
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

⚡ HƯỚNG DẪN BỔ SUNG: Dưới đây là các từ khóa và mẫu câu đáng ngờ do người dùng cung cấp để bạn tham khảo. Hãy xem chúng như những ví dụ giúp bạn nhận diện các chiêu trò mới. Nhiệm vụ chính của bạn vẫn là phải tự phân tích sâu toàn bộ nội dung tin nhắn, ngay cả khi nó không chứa các từ khóa này.
- {keywords}

⚡ Output JSON (ngắn gọn):
- "is_scam" (boolean)
- "reason" (string, ≤ 2 câu, tóm rõ nhất vì sao flag/không flag)
- "types" (string, nhiều loại cách nhau bằng dấu phẩy, ví dụ: "scam, phishing, toxic")
- "score" (0-5)  # 0 = an toàn, 5 = rất nguy hiểm
- "recommend" (string, hành động cụ thể: vd "xoá tin", "bỏ qua", "cảnh giác với link")

Đoạn tin nhắn: {text}
"""

async def fetch_keywords_from_sheet():
    """Lấy danh sách từ khóa từ Google Sheet một cách tự động qua biến môi trường."""
    if not GOOGLE_SHEET_ID or not GOOGLE_SHEET_RANGE:
        print("Cảnh báo: GOOGLE_SHEET_ID hoặc GOOGLE_SHEET_RANGE chưa được thiết lập. Bỏ qua việc lấy keyword.")
        return ""
    try:
        # Tự động tìm credentials từ biến môi trường GOOGLE_APPLICATION_CREDENTIALS
        creds, _ = google.auth.default(scopes=SCOPES)
        
        loop = asyncio.get_running_loop()
        service = await loop.run_in_executor(None, lambda: build('sheets', 'v4', credentials=creds))
        
        sheet = service.spreadsheets()
        result = await loop.run_in_executor(None, lambda: sheet.values().get(spreadsheetId=GOOGLE_SHEET_ID, range=GOOGLE_SHEET_RANGE).execute())
        
        values = result.get('values', [])

        if not values:
            print("Không tìm thấy từ khóa nào trong Google Sheet.")
            return ""
        else:
            keywords = "\n- ".join([item for sublist in values for item in sublist if item])
            print(f"Đã lấy thành công {len(values)} từ khóa từ Google Sheet.")
            return keywords
    except Exception as e:
        print(f"Lỗi khi lấy dữ liệu từ Google Sheet: {e}")
        return ""

async def analyze_with_gemini(text, keywords):
    """Phân tích văn bản với Gemini, sử dụng các từ khóa được cung cấp."""
    for _ in range(len(GOOGLE_API_KEYS)):
        try:
            selected_api_key = random.choice(GOOGLE_API_KEYS)
            genai.configure(api_key=selected_api_key)
            model = genai.GenerativeModel("gemini-1.5-pro-latest")
            prompt = UNIFIED_PROMPT(text, keywords)
            response = await model.generate_content_async(prompt)
            json_text = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(json_text)
        except Exception as e:
            print(f"Lỗi với key {selected_api_key[:12]}...: {e}")
            continue
    return None

async def check_urls_safety(urls: list):
    if not SAFE_BROWSING_API_KEY or not urls:
        return []

    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": u} for u in urls]
        }
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(safe_browsing_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get("matches", [])
                else:
                    print(f"Lỗi API Safe Browsing: {response.status} - {await response.text()}")
                    return []
    except Exception as e:
        print(f"Lỗi khi gọi Safe Browsing API: {e}")
        return []

async def perform_full_analysis(text, urls):
    print(f"DEBUG: Start Analysis with text = {text}")

    keywords_task = fetch_keywords_from_sheet()
    urls_task = check_urls_safety(urls)
    
    keywords = await keywords_task
    gemini_task = analyze_with_gemini(text, keywords)

    gemini_result, url_matches = await asyncio.gather(gemini_task, urls_task)

    print(f"DEBUG: Gemini Result: {gemini_result}")
    print(f"DEBUG: URL Matches: {url_matches}")

    if not gemini_result:
        return {'error': 'Phân tích với Gemini thất bại', 'status_code': 500}

    final_result = gemini_result
    final_result['url_analysis'] = url_matches

    if url_matches:
        final_result['is_scam'] = True
        final_result['reason'] += " Ngoài ra, một hoặc nhiều URL trong tin nhắn được xác định là không an toàn."
        final_result['score'] = max(final_result['score'], 4)

    print(f"DEBUG: Final Result: {final_result}")
    return final_result

@analyze_endpoint.route('/analyze', methods=['POST'])
def analyze_text():
    try:
        data = request.get_json(silent=True)
        if data is None or 'text' not in data:
            return jsonify({'error': 'Yêu cầu không hợp lệ'}), 400

        text = data.get('text', '')
        urls = data.get('urls', [])

        if not text:
            return jsonify({'error': 'Không có văn bản để phân tích'}), 400

        result = asyncio.run(perform_full_analysis(text, urls))

        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status_code', 500)

        return jsonify({'result': result})

    except Exception as e:
        print(f"Lỗi không xác định trong endpoint /api/analyze: {e}")
        return jsonify({'error': 'Lỗi máy chủ nội bộ'}), 500