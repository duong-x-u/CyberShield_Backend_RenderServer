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
- Đọc và hiểu đoạn tin nhắn được cung cấp.
- Dựa vào cả khả năng phân tích của bạn và các từ khóa tham khảo dưới đây, hãy xác định xem tin nhắn có phải là một "mối nguy" hay không.
- Từ khóa tham khảo: {keywords}

# ĐỊNH NGHĨA "MỐI NGUY":
Một tin nhắn được coi là "mối nguy" và bạn PHẢI đặt `"is_scam": true` nếu nó chứa BẤT KỲ yếu tố nào sau đây:
1.  **Lừa đảo & Phishing:** Yêu cầu thông tin cá nhân, dụ dỗ bằng phần thưởng lớn, việc nhẹ lương cao, giả mạo thương hiệu/cơ quan chức năng để lừa tiền.
2.  **Đe dọa & Xúc phạm:** Chứa ngôn ngữ đe dọa, khủng bố tinh thần, bắt nạt, hoặc các từ ngữ thô tục, lăng mạ, xúc phạm nghiêm trọng đến người khác.
3.  **Nội dung cực đoan:** Kích động bạo lực, chia rẽ, chống phá nhà nước, hoặc lan truyền thông tin sai sự thật có chủ đích gây hoang mang.

# HƯỚM DẪN TRÍCH XUẤT TỪ KHÓA:
- Nếu bạn xác định tin nhắn là một "mối nguy", hãy trích xuất các cụm từ khóa ngắn (3-7 từ) đặc trưng nhất gây ra mối nguy đó.
- Nếu tin nhắn an toàn, trả về danh sách rỗng [].

# ĐỊNH DẠNG OUTPUT (JSON):
Bạn PHẢI trả lời bằng một đối tượng JSON duy nhất có cấu trúc như sau:
{{
    "is_scam": (boolean, đặt là true nếu tin nhắn là một "mối nguy" như định nghĩa ở trên),
    "reason": (string, giải thích ngắn gọn tại sao nó là một mối nguy, <= 2 câu),
    "types": (string, một hoặc nhiều loại mối nguy, ví dụ: "scam, phishing", "threatening, toxic_language", "hate_speech"),
    "score": (integer, điểm nguy hiểm từ 0 đến 5, với 0 = an toàn, 3-5 = rất nguy hiểm),
    "recommend": (string, đề xuất hành động cụ thể cho người dùng),
    "suggested_keywords": (list of strings, danh sách các cụm từ khóa mới bạn trích xuất được)
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
    if not GOOGLE_API_KEYS:
        print("--- LỖI CẤU HÌNH: Danh sách GOOGLE_API_KEYS bị trống. Vui lòng kiểm tra biến môi trường. ---")
        return None
    for _ in range(len(GOOGLE_API_KEYS)):
        try:
            selected_api_key = random.choice(GOOGLE_API_KEYS)
            genai.configure(api_key=selected_api_key)
            model = genai.GenerativeModel("gemini-1.5-flash-latest")
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
    print("DEBUG: === BẮT ĐẦU perform_full_analysis ===")
    print(f"DEBUG: Nội dung gửi đến AI: {text}") # Dòng log mới
    try:
        # 1. Đọc các từ khóa hiện có
        print("DEBUG: Bước 1: Chuẩn bị gọi fetch_keywords_from_sheet...")
        existing_keywords_list = await fetch_keywords_from_sheet()
        print(f"DEBUG: Bước 1a: Đã gọi xong fetch_keywords_from_sheet. {len(existing_keywords_list)} từ khóa được trả về.")

        existing_keywords_str_for_prompt = "\n- ".join(existing_keywords_list)
        print("DEBUG: Bước 1b: Đã nối chuỗi từ khóa cho prompt.")

        # 2. Chạy song song việc phân tích của Gemini và kiểm tra URL
        print("DEBUG: Bước 2: Chuẩn bị tạo gemini_task...")
        gemini_task = analyze_with_gemini(text, existing_keywords_str_for_prompt)
        print("DEBUG: Bước 2a: Đã tạo gemini_task.")

        print("DEBUG: Bước 2b: Chuẩn bị tạo urls_task...")
        urls_task = check_urls_safety(urls)
        print("DEBUG: Bước 2c: Đã tạo urls_task.")

        print("DEBUG: Bước 2d: Chuẩn bị gọi asyncio.gather...")
        gemini_result, url_matches = await asyncio.gather(gemini_task, urls_task)
        print("DEBUG: Bước 2e: Đã gọi xong asyncio.gather.")
        print(f"DEBUG: Kết quả JSON thô từ AI: {gemini_result}") # Dòng log mới

        if not gemini_result:
            print("DEBUG: Lỗi - gemini_result rỗng. Trả về lỗi.")
            return {'error': 'Phân tích với Gemini thất bại', 'status_code': 500}
        
        print("DEBUG: Bước 3: Bắt đầu xử lý từ khóa đề xuất...")
        # 3. Xử lý và ghi các từ khóa mới (không cần chờ)
        suggested_keywords = gemini_result.get('suggested_keywords', [])
        if suggested_keywords:
            print(f"DEBUG: AI đề xuất {len(suggested_keywords)} từ khóa.")
            existing_keywords_set = {kw.strip().lower() for kw in existing_keywords_list}
            
            unique_new_keywords = []
            for kw in suggested_keywords:
                if kw.strip().lower() not in existing_keywords_set:
                    unique_new_keywords.append(kw.strip())
                    existing_keywords_set.add(kw.strip().lower())
            
            if unique_new_keywords:
                print(f"DEBUG: Tìm thấy {len(unique_new_keywords)} từ khóa mới. Chuẩn bị ghi vào sheet...")
                asyncio.create_task(append_keywords_to_sheet(unique_new_keywords))
            else:
                print("DEBUG: Không có từ khóa mới nào để ghi.")
        else:
            print("DEBUG: AI không đề xuất từ khóa nào.")

        # 4. Chuẩn bị kết quả cuối cùng để gửi về cho người dùng
        print("DEBUG: Bước 4: Chuẩn bị kết quả cuối cùng...")
        gemini_result.pop('suggested_keywords', None)
        final_result = gemini_result
        final_result['url_analysis'] = url_matches

        if url_matches:
            print("DEBUG: Có URL độc hại, cập nhật kết quả cuối cùng.")
            final_result['is_dangerous'] = True
            final_result['reason'] += " Ngoài ra, một hoặc nhiều URL trong tin nhắn được xác định là không an toàn."
            final_result['score'] = max(final_result.get('score', 0), 4)

        print("DEBUG: === KẾT THÚC perform_full_analysis thành công ===")
        return final_result
    except Exception as e:
        print(f"--- LỖI KHÔNG XÁC ĐỊNH BÊN TRONG perform_full_analysis: {e} ---")
        import traceback
        print(traceback.format_exc())
        raise


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