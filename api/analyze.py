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
Bạn là hệ thống AI phân tích an toàn toàn diện, nhiệm vụ là phát hiện và đánh giá mọi nguy cơ trong tin nhắn. 
Bạn KHÔNG được trung lập hay bỏ qua. Nếu có yếu tố nguy hiểm thì phải flag ngay, kể cả khi tin nhắn ngắn gọn, dùng từ lóng, emoji hoặc biến thể chữ viết.

Một tin nhắn sẽ bị coi là nguy hiểm và đánh dấu "is_scam": true nếu có bất kỳ yếu tố sau:
- **Lừa đảo / phishing**: link giả, app giả, khuyến mãi ảo, dụ chuyển tiền, dụ cung cấp OTP/thông tin.
- **Ngôn từ độc hại**: chửi bậy, xúc phạm, phân biệt vùng miền (ví dụ: "bắc kỳ", "nam ngố", "trẩu miền núi", "dân rau má", "parky", "vin nô", "Namki", "Namkiki"), từ lóng mang nghĩa miệt thị.
- **Đe dọa / ép buộc**: hăm dọa, khủng bố tinh thần, ép buộc làm điều không mong muốn.
- **Kích động bạo lực / phản động**: chống phá chính quyền, xuyên tạc chính trị, lôi kéo biểu tình, tuyên truyền cực đoan, khủng bố.
- **Spam / gây nhiễu**: quảng cáo rác, tin nhắn lặp lại nhiều lần, dụ dỗ trái phép.
- **Thông tin nhạy cảm**: phát tán tin sai lệch, lộ dữ liệu cá nhân (CMND, số thẻ, mật khẩu).
- **Nguy hiểm khác**: dụ dỗ trẻ em, hướng dẫn phạm pháp, khuyến khích tự hại.
- ...v.v...

Yêu cầu đặc biệt:
- Luôn giải thích lý do phát hiện trong "reason", không được để trống.
- Luôn phân loại đúng nhóm trong "types" (ví dụ: "scam", "toxic", "discrimination", "threat", "violence", "political_violation", "spam", "sensitive", "illegal").
- Nếu có nhiều nguy cơ, chọn nhóm NGHIÊM TRỌNG NHẤT.
- "score": đánh giá 0–5 (0 = an toàn, 5 = cực kỳ nguy hiểm).
- "recommend": lời khuyên ngắn gọn (vd: "Không trả lời, không bấm link", "Báo cáo cho quản trị viên", "Bỏ qua tin nhắn độc hại",...v.v..).

Đầu ra chỉ được phép là JSON với các key cố định:
- "is_scam" (boolean)
- "reason" (string)
- "types" (string)
- "score" (number 0-5)
- "recommend" (string)

Tin nhắn cần phân tích: {text}
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
    if redis_client:
        try:
            cached_result = redis_client.get(cache_key)
            if cached_result:
                print(f"Cache hit cho key: {cache_key}")
                return json.loads(cached_result)
        except redis.exceptions.RedisError as e:
            print(f"Lỗi truy cập Redis: {e}")

    # Chạy song song cả hai tác vụ
    gemini_task = analyze_with_gemini(text)
    urls_task = check_urls_safety(urls)
    gemini_result, url_matches = await asyncio.gather(gemini_task, urls_task)

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

    if redis_client:
        try:
            redis_client.setex(cache_key, 86400, json.dumps(final_result))
        except redis.exceptions.RedisError as e:
            print(f"Lỗi lưu vào Redis: {e}")

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
