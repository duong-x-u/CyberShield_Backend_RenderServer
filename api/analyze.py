import json
import asyncio
import os
import random
import hashlib
import redis
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
        redis_client.ping() # Kiểm tra kết nối
        print("Kết nối Redis thành công.")
except redis.exceptions.ConnectionError as e:
    print(f"Lỗi kết nối Redis: {e}. Tính năng cache sẽ bị vô hiệu hóa.")
    redis_client = None

# --- Cấu hình Gemini API ---
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
if not GOOGLE_API_KEYS_STR:
    raise ValueError("Biến môi trường GOOGLE_API_KEYS là bắt buộc.")
GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]
if not GOOGLE_API_KEYS:
    raise ValueError("GOOGLE_API_KEYS phải chứa ít nhất một key hợp lệ.")

UNIFIED_PROMPT = lambda text: f'''
Bạn là một hệ thống phân tích an toàn thông minh. Hãy phân tích đoạn tin nhắn sau và trả lời dưới dạng JSON với các key:
- "is_scam" (boolean)
- "reason" (string)
- "types" (string)
- "score" (number 1-5)
- "recommend" (string)

Đoạn tin nhắn: {text}
'''

async def analyze_with_gemini(text):
    try:
        selected_api_key = random.choice(GOOGLE_API_KEYS)
        genai.configure(api_key=selected_api_key)
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        response = await model.generate_content_async(UNIFIED_PROMPT(text))
        json_text = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(json_text)
    except json.JSONDecodeError as e:
        print(f"Lỗi giải mã JSON từ Gemini: {e}. Phản hồi: {response.text}")
        return None
    except Exception as e:
        print(f"Lỗi API Gemini: {e}")
        return None

async def perform_full_analysis(text):
    cache_key = f"analysis:{hashlib.sha256(text.encode()).hexdigest()}"

    # 1. Kiểm tra cache trước
    if redis_client:
        try:
            cached_result = redis_client.get(cache_key)
            if cached_result:
                print(f"Cache hit cho key: {cache_key}")
                return json.loads(cached_result)
        except redis.exceptions.RedisError as e:
            print(f"Lỗi truy cập Redis: {e}. Bỏ qua cache.")

    # 2. Nếu không có trong cache, gọi Gemini
    print(f"Cache miss cho key: {cache_key}. Gọi API Gemini.")
    final_result = await analyze_with_gemini(text)

    if not final_result:
        return {'error': 'Phân tích với Gemini thất bại', 'status_code': 500}

    # 3. Lưu kết quả vào cache
    if redis_client:
        try:
            redis_client.setex(cache_key, 86400, json.dumps(final_result)) # Cache trong 24 giờ
        except redis.exceptions.RedisError as e:
            print(f"Lỗi lưu vào Redis: {e}")

    return final_result

@analyze_endpoint.route('/analyze', methods=['POST'])
def analyze_text():
    try:
        data = request.get_json(silent=True)
        if data is None or 'text' not in data:
            return jsonify({'error': 'Yêu cầu không hợp lệ, thiếu key "text" hoặc JSON sai định dạng'}), 400

        text = data.get('text', '')
        if not text:
            return jsonify({'error': 'Không có văn bản để phân tích'}), 400

        result = asyncio.run(perform_full_analysis(text))

        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status_code', 500)

        return jsonify({'result': result})

    except Exception as e:
        print(f"Lỗi không xác định trong endpoint /api/analyze: {e}")
        return jsonify({'error': 'Lỗi máy chủ nội bộ'}), 500
