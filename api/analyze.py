import json
import asyncio
import os
import random
from flask import Blueprint, request, jsonify
import google.generativeai as genai
import google.auth
from googleapiclient.discovery import build
import aiohttp

# Khởi tạo Blueprint
analyze_endpoint = Blueprint('analyze_endpoint', __name__)

# --- Cấu hình Google APIs ---
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
GOOGLE_SHEET_ID = os.environ.get('GOOGLE_SHEET_ID')
GOOGLE_SHEET_RANGE = os.environ.get('GOOGLE_SHEET_RANGE', 'Sheet1!A2:A')
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

if not GOOGLE_API_KEYS_STR:
    raise ValueError("Biến môi trường GOOGLE_API_KEYS là bắt buộc.")
GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]

# --- Biến global cache Google Sheets service ---
g_sheets_service = None

async def get_sheets_service():
    """Tạo hoặc trả về service object đã được cache của Google Sheets."""
    global g_sheets_service
    if g_sheets_service:
        return g_sheets_service
    
    try:
        creds, _ = google.auth.default(scopes=SCOPES)
        loop = asyncio.get_running_loop()
        g_sheets_service = await loop.run_in_executor(
            None,
            lambda: build('sheets', 'v4', credentials=creds)
        )
        print("DEBUG: Đã tạo và cache service object của Google Sheets.")
        return g_sheets_service
    except Exception as e:
        print(f"Lỗi khi tạo Google Sheets service: {e}")
        return None

# --- Prompt cho AI ---
UNIFIED_PROMPT = lambda text, keywords: f"""
Bạn là một hệ thống phân tích an ninh mạng, nhiệm vụ của bạn là phân tích tin nhắn và xác định các mối nguy hiểm tiềm tàng.

# HƯỚNG DẪN PHÂN TÍCH:
- Đọc và hiểu đoạn tin nhắn được cung cấp.
- Dựa vào cả khả năng phân tích của bạn và các từ khóa tham khảo dưới đây, hãy xác định xem tin nhắn có phải là một "mối nguy" hay không.
- Từ khóa tham khảo: {keywords}

# ĐỊNH NGHĨA "MỐI NGUY":
Một tin nhắn được coi là "mối nguy" và bạn PHẢI đặt "is_dangerous": true nếu nó chứa BẤT KỲ yếu tố nào sau đây:
1.  **Lừa đảo & Phishing:** Yêu cầu thông tin cá nhân, dụ dỗ bằng phần thưởng lớn, việc nhẹ lương cao, giả mạo thương hiệu/cơ quan chức năng để lừa tiền.
2.  **Đe dọa & Xúc phạm:** Chứa ngôn ngữ đe dọa, khủng bố tinh thần, bắt nạt, hoặc các từ ngữ thô tục, lăng mạ, xúc phạm nghiêm trọng đến người khác.
3.  **Nội dung cực đoan:** Kích động bạo lực, chia rẽ, chống phá nhà nước, hoặc lan truyền thông tin sai sự thật có chủ đích gây hoang mang.

# HƯỚNG DẪN TRÍCH XUẤT TỪ KHÓA:
- Nếu bạn xác định tin nhắn là một "mối nguy", hãy trích xuất các cụm từ khóa ngắn (3-7 từ) đặc trưng nhất gây ra mối nguy đó.
- Nếu tin nhắn an toàn, trả về danh sách rỗng [].

# ĐỊNH DẠNG OUTPUT (JSON):
Bạn PHẢI trả lời bằng một đối tượng JSON duy nhất có cấu trúc như sau:
{{
    "is_dangerous": (boolean),
    "reason": (string, <= 2 câu),
    "types": (string),
    "score": (integer, 0-5),
    "recommend": (string),
    "suggested_keywords": (list of strings)
}}

# ĐOẠN TIN NHẮN CẦN PHÂN TÍCH:
{text}
"""

async def fetch_keywords_from_sheet():
    service = await get_sheets_service()
    if not service or not GOOGLE_SHEET_ID:
        return []
    try:
        sheet = service.spreadsheets()
        result = await asyncio.get_running_loop().run_in_executor(
            None,
            lambda: sheet.values().get(
                spreadsheetId=GOOGLE_SHEET_ID,
                range=GOOGLE_SHEET_RANGE
            ).execute()
        )
        values = result.get('values', [])
        return [item for sublist in values for item in sublist if item] if values else []
    except Exception as e:
        print(f"Lỗi đọc Google Sheet: {e}")
        return []

async def append_keywords_to_sheet(keywords_to_add: list):
    if not keywords_to_add: 
        return
    service = await get_sheets_service()
    if not service:
        print("Không thể ghi vào Sheet (service object fail).")
        return
    try:
        values_to_append = [[kw] for kw in keywords_to_add]
        body = {'values': values_to_append}
        result = await asyncio.get_running_loop().run_in_executor(
            None,
            lambda: service.spreadsheets().values().append(
                spreadsheetId=GOOGLE_SHEET_ID,
                range=GOOGLE_SHEET_RANGE,
                valueInputOption='USER_ENTERED',
                body=body
            ).execute()
        )
        print(f"DEBUG: Append {result.get('updates',{}).get('updatedCells')} ô vào Google Sheet.")
    except Exception as e:
        print(f"Lỗi ghi Google Sheet: {e}")

async def analyze_with_gemini(text, keywords_str):
    if not GOOGLE_API_KEYS:
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
        except json.JSONDecodeError:
            print(f"JSON parse fail từ Gemini. Raw: {response.text}")
            return {
                "is_dangerous": False,
                "reason": "Gemini trả về JSON không hợp lệ.",
                "types": "",
                "score": 0,
                "recommend": "Bỏ qua tin nhắn này.",
                "suggested_keywords": []
            }
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
            async with session.post(safe_browsing_url, json=payload) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get("matches", [])
                return []
    except Exception:
        return []

async def perform_full_analysis(text, urls):
    existing_keywords_list = await fetch_keywords_from_sheet()
    gemini_task = analyze_with_gemini(text, "\n- ".join(existing_keywords_list))
    urls_task = check_urls_safety(urls)
    gemini_result, url_matches = await asyncio.gather(gemini_task, urls_task)

    if not gemini_result:
        return {'error': 'Gemini fail', 'status_code': 500}

    # keywords mới
    suggested_keywords = gemini_result.get('suggested_keywords', [])
    if suggested_keywords:
        existing_set = {kw.strip().lower() for kw in existing_keywords_list}
        unique_new = [kw.strip() for kw in suggested_keywords if kw.strip().lower() not in existing_set]
        if unique_new:
            await append_keywords_to_sheet(unique_new)

    gemini_result.pop('suggested_keywords', None)
    final_result = gemini_result
    final_result['url_analysis'] = url_matches

    if url_matches:
        final_result['is_dangerous'] = True
        cur_reason = final_result.get("reason", "") or "Phát hiện mối nguy."
        final_result["reason"] = cur_reason + " Ngoài ra, có URL không an toàn."
        final_result['score'] = max(final_result.get('score', 0), 4)

    return final_result

@analyze_endpoint.route('/analyze', methods=['POST'])
def analyze_text():
    try:
        data = request.get_json(silent=True)
        if not data or 'text' not in data:
            return jsonify({'error': 'Yêu cầu không hợp lệ'}), 400

        text = data.get('text', '').strip()
        urls = data.get('urls', [])

        if not text:
            return jsonify({'error': 'Không có văn bản để phân tích'}), 400

        # tạo loop mới an toàn cho Flask
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(perform_full_analysis(text, urls))
        loop.close()

        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status_code', 500)

        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': f'Lỗi server: {str(e)}'}), 500
