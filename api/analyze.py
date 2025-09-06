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
        redis_client = None
    else:
        redis_client = redis.from_url(REDIS_URL)
        redis_client.ping()
except redis.exceptions.ConnectionError:
    redis_client = None

# --- Cấu hình Google APIs ---
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
GOOGLE_SHEET_ID = os.environ.get('GOOGLE_SHEET_ID')
GOOGLE_SHEET_RANGE = os.environ.get('GOOGLE_SHEET_RANGE', 'Sheet1!A2:A') # Mặc định là Sheet1!A2:A

# Thay đổi scope để cho phép đọc và GHI
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

if not GOOGLE_API_KEYS_STR:
    raise ValueError("Biến môi trường GOOGLE_API_KEYS là bắt buộc.")
GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]

# --- Logic Phân tích ---
UNIFIED_PROMPT = lambda text, keywords: f"""
Bạn là một hệ thống phân tích an ninh mạng, nhiệm vụ của bạn là phân tích tin nhắn và xác định các mối nguy hiểm tiềm tàng.

# HƯỚNG DẪN PHÂN TÍCH:
1.  **Phân tích nội dung:** Đọc và hiểu đoạn tin nhắn được cung cấp.
2.  **So sánh với từ khóa tham khảo:** Dưới đây là danh sách các từ khóa và mẫu lừa đảo đã biết. Hãy dùng chúng làm thông tin tham khảo để nâng cao khả năng phán đoán. Nhiệm vụ chính của bạn vẫn là phải tự phân tích sâu toàn bộ nội dung, ngay cả khi nó không chứa các từ khóa này.
    - {keywords}
3.  **Đánh giá và cho điểm:** Dựa trên phân tích, hãy xác định mức độ nguy hiểm.

# HƯỚM DẪN TRÍCH XUẤT TỪ KHÓA:
- Từ "Đoạn tin nhắn" được cung cấp, nếu bạn xác định đó là lừa đảo, hãy trích xuất các cụm từ khóa ngắn (3-7 từ) mà bạn cho rằng là dấu hiệu lừa đảo và có thể tái sử dụng để nhận diện các tin nhắn tương tự trong tương lai.
- Chỉ trích xuất những cụm từ trực tiếp có trong văn bản.
- Nếu tin nhắn an toàn, hãy trả về một danh sách rỗng [].

# ĐỊNH DẠNG OUTPUT (JSON):
Bạn PHẢI trả lời bằng một đối tượng JSON duy nhất có cấu trúc như sau:
{{
    "is_scam": (boolean, true nếu là lừa đảo, ngược lại false),
    "reason": (string, giải thích ngắn gọn, súc tích lý do tại sao bạn đưa ra kết luận đó, <= 2 câu),
    "types": (string, một hoặc nhiều loại lừa đảo, cách nhau bằng dấu phẩy, ví dụ: "scam, phishing, financial_fraud"),
    "score": (integer, điểm nguy hiểm từ 0 đến 5, 0 = an toàn, 5 = rất nguy hiểm),
    "recommend": (string, đề xuất hành động cụ thể cho người dùng, ví dụ: "Xoá tin nhắn, không cung cấp thông tin."),
    "suggested_keywords": (list of strings, danh sách các cụm từ khóa mới bạn trích xuất được, ví dụ: ["tuyển dụng các bạn sinh viên", "đóng khoản phí 119k"])
}}

# ĐOẠN TIN NHẮN CẦN PHÂN TÍCH:
{text}
"""

async def fetch_keywords_from_sheet():
    if not GOOGLE_SHEET_ID:
        return []
    try:
        creds, _ = google.auth.default(scopes=SCOPES)
        loop = asyncio.get_running_loop()
        service = await loop.run_in_executor(None, lambda: build('sheets', 'v4', credentials=creds))
        sheet = service.spreadsheets()
        result = await loop.run_in_executor(None, lambda: sheet.values().get(spreadsheetId=GOOGLE_SHEET_ID, range=GOOGLE_SHEET_RANGE).execute())
        values = result.get('values', [])
        if not values:
            return []
        else:
            raw_keywords = [item for sublist in values for item in sublist if item]
            print(f"DEBUG: Đã đọc thành công {len(raw_keywords)} từ khóa hiện có từ Google Sheet.")
            return raw_keywords
    except Exception as e:
        print(f"Lỗi khi đọc từ Google Sheet: {e}")
        return []

async def append_keywords_to_sheet(keywords_to_add: list):
    if not keywords_to_add:
        return
    print(f"DEBUG: Bắt đầu quá trình ghi {len(keywords_to_add)} từ khóa mới vào Google Sheet...")
    try:
        creds, _ = google.auth.default(scopes=SCOPES)
        loop = asyncio.get_running_loop()
        service = await loop.run_in_executor(None, lambda: build('sheets', 'v4', credentials=creds))
        values_to_append = [[keyword] for keyword in keywords_to_add]
        body = {'values': values_to_append}
        result = await loop.run_in_executor(None, lambda:
            service.spreadsheets().values().append(
                spreadsheetId=GOOGLE_SHEET_ID,
                range=GOOGLE_SHEET_RANGE,
                valueInputOption='USER_ENTERED',
                body=body
            ).execute()
        )
        print(f"DEBUG: Ghi thành công! {result.get('updates').get('updatedCells')} ô đã được cập nhật.")
    except Exception as e:
        print(f"Lỗi khi ghi vào Google Sheet: {e}")

async def analyze_with_gemini(text, keywords_str):
    for _ in range(len(GOOGLE_API_KEYS)):
        try:
            selected_api_key = random.choice(GOOGLE_API_KEYS)
            genai.configure(api_key=selected_api_key)
            model = genai.GenerativeModel("gemini-1.5-pro-latest")
            prompt = UNIFIED_PROMPT(text, keywords_str)
            response = await model.generate_content_async(prompt)
            json_text = response.text.replace("```json", "").replace("```", "").strip()
            return json.loads(json_text)
        except Exception as e:
            print(f"Lỗi với Gemini key {selected_api_key[:12]}...: {e}")
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
                    return []
    except Exception:
        return []

async def perform_full_analysis(text, urls):
    # 1. Đọc các từ khóa hiện có
    existing_keywords_list = await fetch_keywords_from_sheet()
    existing_keywords_str_for_prompt = "\n- ".join(existing_keywords_list)

    # 2. Chạy song song việc phân tích của Gemini và kiểm tra URL
    gemini_task = analyze_with_gemini(text, existing_keywords_str_for_prompt)
    urls_task = check_urls_safety(urls)
    gemini_result, url_matches = await asyncio.gather(gemini_task, urls_task)

    if not gemini_result:
        return {'error': 'Phân tích với Gemini thất bại', 'status_code': 500}

    # 3. Xử lý và ghi các từ khóa mới (không cần chờ)
    suggested_keywords = gemini_result.get('suggested_keywords', [])
    if suggested_keywords:
        existing_keywords_set = {kw.strip().lower() for kw in existing_keywords_list}
        unique_new_keywords = []
        for kw in suggested_keywords:
            if kw.strip().lower() not in existing_keywords_set:
                unique_new_keywords.append(kw.strip())
                existing_keywords_set.add(kw.strip().lower())
        
        if unique_new_keywords:
            asyncio.create_task(append_keywords_to_sheet(unique_new_keywords))

    # 4. Chuẩn bị kết quả cuối cùng để gửi về cho người dùng
    gemini_result.pop('suggested_keywords', None) # Xóa trường này khỏi kết quả trả về
    final_result = gemini_result
    final_result['url_analysis'] = url_matches

    if url_matches:
        final_result['is_scam'] = True
        final_result['reason'] += " Ngoài ra, một hoặc nhiều URL trong tin nhắn được xác định là không an toàn."
        final_result['score'] = max(final_result.get('score', 0), 4)

    return final_result

@analyze_endpoint.route('/analyze', methods=['POST'])
def analyze_text():
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