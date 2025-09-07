import json
import asyncio
import os
import random
import time
import gc  # Garbage collector
from flask import Flask, Blueprint, request, jsonify
import aiohttp
from functools import lru_cache

# Lazy imports để giảm memory footprint ban đầu
def lazy_import_genai():
    import google.generativeai as genai
    return genai

def lazy_import_google_services():
    import google.auth
    from googleapiclient.discovery import build
    return google.auth, build

# Telegram lazy import
def lazy_import_telegram():
    import telegram
    return telegram

# --- Blueprint ---
analyze_endpoint = Blueprint('analyze_endpoint', __name__)

# --- Config environment ---
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
GOOGLE_SHEET_ID = os.environ.get('GOOGLE_SHEET_ID')
GOOGLE_SHEET_RANGE = os.environ.get('GOOGLE_SHEET_RANGE', 'Sheet1!A2:F')
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID')
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

if not GOOGLE_API_KEYS_STR:
    raise ValueError("GOOGLE_API_KEYS required")

GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]

# --- Cache ---
g_sheets_service = None
g_cached_sheet_data = []
g_sheet_data_last_fetched = 0
CACHE_DURATION_SECONDS = 900
MAX_CACHE_SIZE = 100

# --- Text similarity ---
@lru_cache(maxsize=50)
def simple_text_similarity(text1: str, text2: str) -> float:
    text1_lower = text1.lower().strip()
    text2_lower = text2.lower().strip()
    
    if text1_lower == text2_lower:
        return 1.0
    if text1_lower in text2_lower or text2_lower in text1_lower:
        return 0.8
    
    words1 = set(text1_lower.split())
    words2 = set(text2_lower.split())
    if not words1 or not words2:
        return 0.0
    intersection = len(words1.intersection(words2))
    union = len(words1.union(words2))
    return intersection / union if union > 0 else 0.0

# --- Google Sheets service ---
async def get_sheets_service():
    global g_sheets_service
    if g_sheets_service:
        return g_sheets_service
    try:
        google_auth, build_func = lazy_import_google_services()
        creds, _ = google_auth.default(scopes=SCOPES)
        loop = asyncio.get_running_loop()
        g_sheets_service = await loop.run_in_executor(
            None,
            lambda: build_func('sheets', 'v4', credentials=creds, cache_discovery=False)
        )
        return g_sheets_service
    except Exception as e:
        print(f"ERROR: Google Sheets service: {e}")
        return None

# --- Fetch Sheet data ---
async def fetch_sheet_data_optimized():
    global g_cached_sheet_data, g_sheet_data_last_fetched
    current_time = time.time()
    if g_cached_sheet_data and (current_time - g_sheet_data_last_fetched < CACHE_DURATION_SECONDS):
        return g_cached_sheet_data
    service = await get_sheets_service()
    if not service or not GOOGLE_SHEET_ID:
        return []
    try:
        loop = asyncio.get_running_loop()
        result = await loop.run_in_executor(
            None,
            lambda: service.spreadsheets().values().get(
                spreadsheetId=GOOGLE_SHEET_ID,
                range=GOOGLE_SHEET_RANGE
            ).execute()
        )
        values = result.get('values', [])
        processed_data = []
        for row in values[:MAX_CACHE_SIZE]:
            if len(row) >= 6:
                processed_data.append({
                    'text': row[0][:200],
                    'is_dangerous': row[1].lower() == 'true',
                    'types': row[2],
                    'reason': row[3][:100],
                    'score': int(row[4]) if row[4].isdigit() else 0,
                    'recommend': row[5][:100]
                })
        g_cached_sheet_data = processed_data
        g_sheet_data_last_fetched = current_time
        gc.collect()
        return processed_data
    except Exception as e:
        print(f"ERROR: fetch_sheet_data: {e}")
        return []

# --- Lightweight search ---
async def perform_lightweight_search(input_text: str):
    cached_data = await fetch_sheet_data_optimized()
    best_match = None
    highest_similarity = 0
    threshold = 0.7
    for item in cached_data:
        sim = simple_text_similarity(input_text, item['text'])
        if sim > highest_similarity:
            highest_similarity = sim
            best_match = item
    if best_match and highest_similarity >= threshold:
        return {
            'is_dangerous': best_match['is_dangerous'],
            'reason': best_match['reason'],
            'types': best_match['types'],
            'score': best_match['score'],
            'recommend': best_match['recommend'],
        }
    return None

# --- Gemini analysis ---
async def analyze_with_gemini_optimized(text: str, keywords_str: str):
    if not GOOGLE_API_KEYS:
        return {"is_dangerous": False, "reason": "System error", "score": 0}
    genai = lazy_import_genai()
    text_trunc = text[:1000]
    keywords_trunc = keywords_str[:300]
    for attempt in range(min(3, len(GOOGLE_API_KEYS))):
        try:
            api_key = random.choice(GOOGLE_API_KEYS)
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel("gemini-1.5-flash-latest")
            prompt = f"Phân tích tin nhắn:\n{ text_trunc }\nKeywords:\n{ keywords_trunc }"
            response = await model.generate_content_async(prompt)
            json_text = response.text.strip()
            if json_text.startswith('```json'):
                json_text = json_text[7:]
            if json_text.endswith('```'):
                json_text = json_text[:-3]
            result = json.loads(json_text)
            return result
        except Exception:
            continue
    return {"is_dangerous": False, "reason": "Analysis failed", "score": 0}

# --- URL check ---
async def check_urls_safety_optimized(urls: list):
    if not SAFE_BROWSING_API_KEY or not urls:
        return []
    limited_urls = urls[:5]
    url_api = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {"threatInfo":{"threatTypes":["MALWARE","SOCIAL_ENGINEERING"],"platformTypes":["ANY_PLATFORM"],"threatEntryTypes":["URL"],"threatEntries":[{"url":u} for u in limited_urls]}}
    try:
        timeout = aiohttp.ClientTimeout(total=10)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url_api, json=payload) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    return result.get("matches", [])
                return []
    except Exception:
        return []

# --- Telegram alert ---
async def send_telegram_alert(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    async with aiohttp.ClientSession() as session:
        await session.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": message})

# --- Full analysis ---
async def perform_full_analysis_optimized(text: str, urls: list):
    result = await perform_lightweight_search(text)
    if result:
        if urls:
            matches = await check_urls_safety_optimized(urls)
            if matches:
                result['url_analysis'] = matches
                result['is_dangerous'] = True
        return result

    # AI analysis
    cached_data = await fetch_sheet_data_optimized()
    keywords_str = '\n'.join([item['text'] for item in cached_data[:20]])
    gemini_task = analyze_with_gemini_optimized(text, keywords_str)
    urls_task = check_urls_safety_optimized(urls) if urls else asyncio.sleep(0)
    gemini_result, url_matches = await asyncio.gather(gemini_task, urls_task)

    final_result = gemini_result.copy()
    if url_matches:
        final_result['url_analysis'] = url_matches
        final_result['is_dangerous'] = True

    # Telegram notify
    msg = f"🚨 New AI Analysis 🚨\nText: {text[:200]}...\nResult: {json.dumps(final_result, ensure_ascii=False)}"
    asyncio.create_task(send_telegram_alert(msg))
    gc.collect()
    return final_result

# --- Flask endpoint ---
@analyze_endpoint.route('/analyze', methods=['POST'])
async def analyze_text():
    try:
        data = request.get_json(silent=True)
        if not data or 'text' not in data:
            return jsonify({'error': 'Invalid request'}), 400
        text = data.get('text','').strip()
        urls = data.get('urls', [])
        result = await perform_full_analysis_optimized(text, urls)
        return jsonify({'result': result})
    except Exception as e:
        gc.collect()
        return jsonify({'error': 'Internal server error', 'detail': str(e)}), 500

@analyze_endpoint.route('/health', methods=['GET'])
async def health_check():
    return jsonify({'status': 'healthy', 'cache_size': len(g_cached_sheet_data)})

# --- Flask app ---
app = Flask(__name__)
app.register_blueprint(analyze_endpoint)
