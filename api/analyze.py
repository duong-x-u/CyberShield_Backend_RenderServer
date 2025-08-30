import json
import asyncio
import os
import random
import hashlib
import redis
import aiohttp
from flask import Blueprint, request, jsonify
import google.generativeai as genai

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

# --- Cấu hình APIs ---
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')

if not GOOGLE_API_KEYS_STR:
    raise ValueError("Biến môi trường GOOGLE_API_KEYS là bắt buộc.")
GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]
if not GOOGLE_API_KEYS:
    raise ValueError("GOOGLE_API_KEYS phải chứa ít nhất một key hợp lệ.")
if not SAFE_BROWSING_API_KEY:
    print("Cảnh báo: SAFE_BROWSING_API_KEY không được thiết lập. Tính năng quét URL sẽ bị vô hiệu hóa.")

# --- Logic Phân tích ---

UNIFIED_PROMPT = lambda text: f"""
Bạn là một hệ thống phân tích an toàn thông minh, chuyên phát hiện mọi hành vi có nguy cơ lừa đảo, đe dọa, quấy rối, kích động bạo lực hoặc chống phá Nhà nước Việt Nam, gây tổn hại đến người nhận hoặc xã hội.

Nếu tin nhắn có bất kỳ dấu hiệu sau, dù không trực tiếp lừa đảo tài chính, hãy đánh dấu "is_scam": true để bảo vệ toàn diện:
- Ngôn từ thô tục, xúc phạm cá nhân hoặc nhóm người
- Đe dọa, ép buộc, khủng bố tinh thần
- Kích động bạo lực, nổi loạn, chống phá chính quyền
- Phát tán thông tin sai lệch gây hoang mang
- Gây ảnh hưởng tiêu cực đến an ninh trật tự xã hội

Trả lời dưới dạng JSON với các key:
- "is_scam" (boolean)
- "reason" (string)
- "types" (string)
- "score" (number 0-5)  # 0 là không nguy hiểm, 5 là rất nguy hiểm
- "recommend" (string)

Đoạn tin nhắn: {text}
"""


async def analyze_with_gemini(text):
    # ... (Nội dung hàm này không đổi)
    try:
        selected_api_key = random.choice(GOOGLE_API_KEYS)
        genai.configure(api_key=selected_api_key)
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        response = await model.generate_content_async(UNIFIED_PROMPT(text))
        json_text = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(json_text)
    except Exception as e:
        print(f"Lỗi API Gemini: {e}")
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
    cache_key = f"analysis:{hashlib.sha256(text.encode()).hexdigest()}"
    # if redis_client:
    #     try:
    #         cached_result = redis_client.get(cache_key)
    #         if cached_result:
    #             print(f"Cache hit cho key: {cache_key}")
    #             return json.loads(cached_result)
    #     except redis.exceptions.RedisError as e:
    #         print(f"Lỗi truy cập Redis: {e}")

    # Chạy song song cả hai tác vụ
    gemini_task = analyze_with_gemini(text)
    urls_task = check_urls_safety(urls)
    gemini_result, url_matches = await asyncio.gather(gemini_task, urls_task)

    print(f"DEBUG: Gemini Result: {gemini_result}")
    print(f"DEBUG: URL Matches: {url_matches}")

    if not gemini_result:
        return {'error': 'Phân tích với Gemini thất bại', 'status_code': 500}

    # Tổng hợp kết quả
    final_result = gemini_result
    final_result['url_analysis'] = url_matches

    if url_matches:
        final_result['is_scam'] = True
        final_result['reason'] += " Ngoài ra, một hoặc nhiều URL trong tin nhắn được xác định là không an toàn."
        # Tăng điểm nguy hiểm nếu có URL độc hại
        final_result['score'] = max(final_result['score'], 4)

    # if redis_client:
    #     try:
    #         redis_client.setex(cache_key, 86400, json.dumps(final_result))
    #     except redis.exceptions.RedisError as e:
    #         print(f"Lỗi lưu vào Redis: {e}")

    print(f"DEBUG: Final Result: {final_result}")
    return final_result

@analyze_endpoint.route('/analyze', methods=['POST'])
def analyze_text():
    try:
        data = request.get_json(silent=True)
        if data is None or 'text' not in data:
            return jsonify({'error': 'Yêu cầu không hợp lệ'}), 400

        text = data.get('text', '')
        urls = data.get('urls', []) # Lấy danh sách URLs
        if not text:
            return jsonify({'error': 'Không có văn bản để phân tích'}), 400

        result = asyncio.run(perform_full_analysis(text, urls))

        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status_code', 500)

        return jsonify({'result': result})

    except Exception as e:
        print(f"Lỗi không xác định trong endpoint /api/analyze: {e}")
        return jsonify({'error': 'Lỗi máy chủ nội bộ'}), 500