import json
import asyncio
import os
from flask import Blueprint, request, jsonify
import google.generativeai as genai

# Khởi tạo Blueprint
analyze_endpoint = Blueprint('analyze_endpoint', __name__)

# Cấu hình API keys từ environment variables
GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')

# Validate API key
if not GOOGLE_API_KEY:
    raise ValueError("GOOGLE_API_KEY environment variable is required")

# Cấu hình client
genai.configure(api_key=GOOGLE_API_KEY)

# Prompt chuẩn
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
        model = genai.GenerativeModel('gemini-1.5-flash-latest')
        response = await model.generate_content_async(UNIFIED_PROMPT(text))
        # Cẩn thận hơn khi parse JSON
        json_text = response.text.replace('```json', '').replace('```', '').strip()
        return json.loads(json_text)
    except json.JSONDecodeError as e:
        print(f"Gemini JSON Decode Error: {str(e)}. Response text: {response.text}")
        return None
    except Exception as e:
        print(f"Gemini API Error: {str(e)}")
        return None

async def perform_full_analysis(text):
    """
    Hàm điều phối chính, chỉ chạy phân tích với Gemini.
    """
    final_result = await analyze_with_gemini(text)

    if not final_result:
        return {'error': 'Gemini analysis failed', 'status_code': 500}

    return final_result


@analyze_endpoint.route('/analyze', methods=['POST'])
def analyze_text():
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({'error': 'Invalid request body, missing "text" key'}), 400

        text = data.get('text', '')
        if not text:
            return jsonify({'error': 'No text provided'}), 400

        # Chạy toàn bộ quy trình bất đồng bộ trong một event loop duy nhất
        result = asyncio.run(perform_full_analysis(text))

        # Kiểm tra xem kết quả có phải là lỗi không
        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status_code', 500)

        return jsonify(result)

    except Exception as e:
        # Bắt các lỗi không mong muốn ở tầng cao nhất
        print(f"Unhandled error in /api/analyze endpoint: {str(e)}")
        return jsonify({'error': 'An internal server error occurred'}), 500
