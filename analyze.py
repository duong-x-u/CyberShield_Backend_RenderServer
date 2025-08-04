import json
import asyncio
import aiohttp
import os
from flask import Flask, request, jsonify
from openai import AsyncOpenAI, OpenAIError
import google.generativeai as genai

# Khởi tạo Flask app
app = Flask(__name__)

# Cấu hình API keys từ environment variables
GOOGLE_API_KEY = os.environ.get('GOOGLE_API_KEY')
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
OPENROUTER_API_KEY = os.environ.get('OPENROUTER_API_KEY')

# Validate API keys
if not GOOGLE_API_KEY:
    raise ValueError("GOOGLE_API_KEY environment variable is required")
if not OPENAI_API_KEY:
    raise ValueError("OPENAI_API_KEY environment variable is required")
if not OPENROUTER_API_KEY:
    raise ValueError("OPENROUTER_API_KEY environment variable is required")

# Cấu hình clients
genai.configure(api_key=GOOGLE_API_KEY)
openai_client = AsyncOpenAI(api_key=OPENAI_API_KEY)

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

async def analyze_with_openai(text):
    try:
        response = await openai_client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": UNIFIED_PROMPT(text)}]
        )
        content = response.choices[0].message.content
        return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"OpenAI JSON Decode Error: {str(e)}. Response content: {content}")
        return None
    except OpenAIError as e:
        print(f"OpenAI API Error: {str(e)}")
        return None

async def synthesize_results_with_claude(analyses):
    try:
        prompt = f'''
Bạn là chuyên gia an ninh, hãy tổng hợp các phân tích sau thành một kết quả JSON cuối cùng và chính xác nhất với các key:
- "is_scam", "reason", "types", "score", "recommend".

--- CÁC PHÂN TÍCH ---
{json.dumps(analyses, ensure_ascii=False, indent=2)}
'''.strip()

        async with aiohttp.ClientSession() as session:
            async with session.post(
                'https://openrouter.ai/api/v1/chat/completions',
                headers={
                    'Authorization': f'Bearer {OPENROUTER_API_KEY}',
                    'Content-Type': 'application/json'
                },
                json={
                    "model": "anthropic/claude-3-sonnet",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.2
                }
            ) as resp:
                resp.raise_for_status()  # Sẽ raise lỗi cho status codes 4xx/5xx
                result = await resp.json()
                content = result["choices"][0]["message"]["content"]
                return json.loads(content)
    except json.JSONDecodeError as e:
        print(f"Claude JSON Decode Error: {str(e)}. Response content: {content}")
        return None
    except aiohttp.ClientError as e:
        print(f"Claude (aiohttp) Error: {str(e)}")
        return None
    except Exception as e:
        # Bắt các lỗi không mong muốn khác
        print(f"Claude Synthesizer Unexpected Error: {str(e)}")
        return None

async def perform_full_analysis(text):
    """
    Hàm điều phối chính, chạy tất cả các tác vụ bất đồng bộ.
    """
    # Chạy các phân tích ban đầu song song
    analyses = await asyncio.gather(
        analyze_with_gemini(text),
        analyze_with_openai(text)
    )
    successful_analyses = [a for a in analyses if a is not None]

    if not successful_analyses:
        # Trả về một dict lỗi để hàm route có thể xử lý
        return {'error': 'All primary analysis AIs failed', 'status_code': 500}

    # Tổng hợp kết quả
    final_result = await synthesize_results_with_claude(successful_analyses)

    if not final_result:
        return {'error': 'Synthesis AI failed', 'status_code': 500}

    return final_result


@app.route('/api/analyze', methods=['POST'])
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

# Chạy local
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=3000)