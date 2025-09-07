import json
import asyncio
import os
import random
import time
import gc  # Garbage collector
from flask import Blueprint, request, jsonify
import aiohttp
import hashlib
from functools import lru_cache

# Lazy imports để giảm memory footprint ban đầu
def lazy_import_genai():
    import google.generativeai as genai
    return genai

def lazy_import_google_services():
    import google.auth
    from googleapiclient.discovery import build
    return google.auth, build

def lazy_import_email():
    from email.mime.text import MIMEText
    import base64
    return MIMEText, base64

# Blueprint
analyze_endpoint = Blueprint('analyze_endpoint', __name__)

# --- Cấu hình tối ưu cho Render Free ---
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
GOOGLE_SHEET_ID = os.environ.get('GOOGLE_SHEET_ID')
GOOGLE_SHEET_RANGE = os.environ.get('GOOGLE_SHEET_RANGE', 'Sheet1!A2:F')
SCOPES = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/gmail.send']

if not GOOGLE_API_KEYS_STR:
    raise ValueError("Biến môi trường GOOGLE_API_KEYS là bắt buộc.")
GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]

# --- Cache tối ưu với giới hạn memory ---
g_sheets_service = None
g_cached_sheet_data = []
g_sheet_data_last_fetched = 0
CACHE_DURATION_SECONDS = 900  # Tăng cache time để giảm API calls
MAX_CACHE_SIZE = 100  # Giới hạn số lượng records
EMAIL_RECIPIENTS = os.environ.get('EMAIL_RECIPIENTS', 'quoctrieu581 @gmail.com,duongpham18210 @gmail.com').split(',')
SERVICE_ACCOUNT_EMAIL = os.environ.get('SERVICE_ACCOUNT_EMAIL', 'cyber-shield-server @fluent-plate-465614-b0.iam.gserviceaccount.com')

# --- Memory-efficient text similarity ---
@lru_cache(maxsize=50)  # Cache kết quả similarity
def simple_text_similarity(text1: str, text2: str) -> float:
    """
    Thay thế SentenceTransformer bằng similarity đơn giản nhưng hiệu quả
    """
    text1_lower = text1.lower().strip()
    text2_lower = text2.lower().strip()
    
    # Exact match
    if text1_lower == text2_lower:
        return 1.0
    
    # Substring match
    if text1_lower in text2_lower or text2_lower in text1_lower:
        return 0.8
    
    # Word-based Jaccard similarity
    words1 = set(text1_lower.split())
    words2 = set(text2_lower.split())
    
    if not words1 or not words2:
        return 0.0
    
    intersection = len(words1.intersection(words2))
    union = len(words1.union(words2))
    
    return intersection / union if union > 0 else 0.0

async def get_sheets_service():
    """Tạo service với connection pooling tối ưu"""
    global g_sheets_service
    if g_sheets_service:
        return g_sheets_service
    
    try:
        google_auth, build_func = lazy_import_google_services()
        creds, _ = google_auth.default(scopes=SCOPES)
        
        # Tạo service trong executor để không block
        loop = asyncio.get_running_loop()
        g_sheets_service = await loop.run_in_executor(
            None, 
            lambda: build_func('sheets', 'v4', credentials=creds, cache_discovery=False)
        )
        print("DEBUG: Google Sheets service created")
        return g_sheets_service
    except Exception as e:
        print(f"ERROR: Failed to create Sheets service: {e}")
        return None

async def get_gmail_service():
    """Tạo Gmail service khi cần thiết"""
    try:
        google_auth, build_func = lazy_import_google_services()
        creds, _ = google_auth.default(scopes=SCOPES)
        
        if creds and creds.valid:
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(
                None,
                lambda: build_func('gmail', 'v1', credentials=creds, cache_discovery=False)
            )
        return None
    except Exception as e:
        print(f"ERROR: Failed to create Gmail service: {e}")
        return None

# --- Optimized prompt with memory-conscious structure ---
def create_analysis_prompt(text: str, keywords: str) -> str:
    """Tạo prompt tối ưu với kích thước nhỏ hơn"""
    return f"""Bạn là CyberShield Guardian, chuyên gia phân tích an ninh tin nhắn.

NHIỆM VỤ: Phân tích tin nhắn và xác định mối nguy hiểm.

MỐI NGUY bao gồm:
1. Lừa đảo: Yêu cầu thông tin cá nhân, phần thưởng giả, việc nhẹ lương cao
2. Đe dọa: Ngôn ngữ đe dọa, bắt nạt, từ ngữ thô tục
3. Cực đoan: Kích động bạo lực, thông tin sai lệch

TỪ KHÓA THAM KHẢO:
{keywords[:500]}...

PHÂN TÍCH: {text}

Trả về JSON:
{{
    "is_dangerous": boolean,
    "reason": "string (max 100 chars)",
    "types": "string",
    "score": integer (0-5),
    "recommend": "string",
    "suggested_keywords": []
}} """

async def fetch_sheet_data_optimized():
    """Fetch data với memory optimization"""
    global g_cached_sheet_data, g_sheet_data_last_fetched
    
    current_time = time.time()
    if (g_cached_sheet_data and 
        (current_time - g_sheet_data_last_fetched < CACHE_DURATION_SECONDS)):
        print("DEBUG: Using cached sheet data")
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
        if not values:
            return []

        # Process với memory limit
        processed_data = []
        for i, row in enumerate(values[:MAX_CACHE_SIZE]):  # Limit số records
            if len(row) >= 6:
                processed_data.append({
                    'text': row[0][:200],  # Truncate text để tiết kiệm memory
                    'is_dangerous': row[1].lower() == 'true',
                    'types': row[2],
                    'reason': row[3][:100],  # Limit reason length
                    'score': int(row[4]) if row[4].isdigit() else 0,
                    'recommend': row[5][:100]  # Limit recommend length
                })

        g_cached_sheet_data = processed_data
        g_sheet_data_last_fetched = current_time
        
        # Force garbage collection
        gc.collect()
        
        print(f"DEBUG: Cached {len(processed_data)} records")
        return processed_data
        
    except Exception as e:
        print(f"ERROR: Failed to fetch sheet data: {e}")
        return []

async def perform_lightweight_search(input_text: str):
    """Tìm kiếm với thuật toán nhẹ thay thế SentenceTransformer"""
    cached_data = await fetch_sheet_data_optimized()
    if not cached_data:
        return None

    best_match = None
    highest_similarity = 0
    similarity_threshold = 0.7  # Lowered threshold

    for item in cached_data:
        similarity = simple_text_similarity(input_text, item['text'])
        
        if similarity > highest_similarity:
            highest_similarity = similarity
            best_match = item

    if best_match and highest_similarity >= similarity_threshold:
        print(f"DEBUG: Found match with similarity: {highest_similarity:.3f}")
        return {
            'is_dangerous': best_match['is_dangerous'],
            'reason': best_match['reason'],
            'types': best_match['types'],
            'score': best_match['score'],
            'recommend': best_match['recommend'],
            'suggested_keywords': []
        }
    
    return None

async def analyze_with_gemini_optimized(text: str, keywords_str: str):
    """Gemini analysis với retry logic tối ưu"""
    if not GOOGLE_API_KEYS:
        return {"is_dangerous": False, "reason": "System error", "score": 0}
    
    genai = lazy_import_genai()
    
    # Truncate input để tiết kiệm tokens
    text_truncated = text[:1000]  # Limit input size
    keywords_truncated = keywords_str[:300]  # Limit keywords
    
    for attempt in range(min(3, len(GOOGLE_API_KEYS))):  # Max 3 attempts
        try:
            api_key = random.choice(GOOGLE_API_KEYS)
            genai.configure(api_key=api_key)
            
            model = genai.GenerativeModel("gemini-1.5-flash-latest")
            prompt = create_analysis_prompt(text_truncated, keywords_truncated)
            
            response = await model.generate_content_async(
                prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,  # Lower temperature for consistency
                    max_output_tokens=300  # Limit output size
                )
            )
            
            # Clean and parse JSON
            json_text = response.text.strip()
            if json_text.startswith('```json'):
                json_text = json_text[7:]
            if json_text.endswith('```'):
                json_text = json_text[:-3]
            
            result = json.loads(json_text.strip())
            
            # Validate required fields
            required_fields = ['is_dangerous', 'reason', 'types', 'score', 'recommend']
            if all(field in result for field in required_fields):
                return result
            else:
                print(f"WARNING: Missing required fields in Gemini response")
                
        except json.JSONDecodeError as e:
            print(f"JSON parse error: {e}")
            continue
        except Exception as e:
            print(f"Gemini error (attempt {attempt + 1}): {e}")
            continue
    
    # Fallback response
    return {
        "is_dangerous": False,
        "reason": "Analysis failed",
        "types": "system_error",
        "score": 0,
        "recommend": "Manual review required",
        "suggested_keywords": []
    }

async def check_urls_safety_optimized(urls: list):
    """URL safety check với timeout và limit"""
    if not SAFE_BROWSING_API_KEY or not urls:
        return []
    
    # Limit số URLs để avoid timeout
    limited_urls = urls[:5]
    
    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],  # Reduced types
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url} for url in limited_urls]
        }
    }
    
    try:
        timeout = aiohttp.ClientTimeout(total=10)  # 10s timeout
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(safe_browsing_url, json=payload) as resp:
                if resp.status == 200:
                    result = await resp.json()
                    return result.get("matches", [])
                return []
    except asyncio.TimeoutError:
        print("WARNING: URL safety check timeout")
        return []
    except Exception as e:
        print(f"ERROR: URL safety check failed: {e}")
        return []

async def send_analysis_email_optimized(original_text: str, analysis_result: dict):
    """Gửi email với error handling tốt hơn"""
    try:
        service = await get_gmail_service()
        if not service:
            print("WARNING: Cannot send email - no Gmail service")
            return

        MIMEText, base64 = lazy_import_email()
        
        sender = SERVICE_ACCOUNT_EMAIL
        recipients = ', '.join(EMAIL_RECIPIENTS)
        subject = "CyberShield: New Analysis Result"

        # Truncate text for email
        truncated_text = original_text[:500] + "..." if len(original_text) > 500 else original_text
        
        body = f"""
Analysis Result:

Text: {truncated_text}
Dangerous: {analysis_result.get('is_dangerous')}
Score: {analysis_result.get('score')}
Type: {analysis_result.get('types')}
Reason: {analysis_result.get('reason')}

Best regards,
CyberShield System
        """

        message = MIMEText(body, 'plain', 'utf-8')
        message['to'] = recipients
        message['from'] = sender
        message['subject'] = subject

        raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
        
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(
            None,
            lambda: service.users().messages().send(
                userId='me',
                body={'raw': raw_message}
            ).execute()
        )
        
        print(f"DEBUG: Email sent to {recipients}")
        
    except Exception as e:
        print(f"ERROR: Failed to send email: {e}")

async def perform_full_analysis_optimized(text: str, urls: list):
    """Main analysis với memory và performance optimization"""
    
    # 1. Quick similarity search first
    semantic_result = await perform_lightweight_search(text)
    if semantic_result:
        print("DEBUG: Using cached analysis result")
        
        # Add URL analysis if needed
        if urls:
            url_matches = await check_urls_safety_optimized(urls)
            if url_matches:
                semantic_result['url_analysis'] = url_matches
                semantic_result['is_dangerous'] = True
                semantic_result['score'] = max(semantic_result.get('score', 0), 4)
                semantic_result['reason'] = (semantic_result.get('reason', '') + " + Unsafe URLs")[:100]
        
        return semantic_result

    # 2. Gemini analysis for new content
    print("DEBUG: Performing new Gemini analysis")
    
    # Get keywords for context (limited)
    cached_data = await fetch_sheet_data_optimized()
    keywords_list = [item['text'] for item in cached_data[:20]]  # Limit keywords
    keywords_str = '\n- '.join(keywords_list)

    # Concurrent analysis
    gemini_task = analyze_with_gemini_optimized(text, keywords_str)
    urls_task = check_urls_safety_optimized(urls) if urls else asyncio.sleep(0)

    gemini_result, url_matches = await asyncio.gather(gemini_task, urls_task)

    if 'error' in gemini_result:
        return gemini_result

    # 3. Send email notification (non-blocking)
    asyncio.create_task(send_analysis_email_optimized(text, gemini_result))

    # 4. Combine results
    final_result = gemini_result.copy()
    
    if url_matches:
        final_result['url_analysis'] = url_matches
        final_result['is_dangerous'] = True
        final_result['score'] = max(final_result.get('score', 0), 4)
        current_reason = final_result.get('reason', '')
        final_result['reason'] = (current_reason + " + Unsafe URLs")[:100]

    # Remove unused fields to save bandwidth
    final_result.pop('suggested_keywords', None)
    
    # Force garbage collection after analysis
    gc.collect()
    
    return final_result

@analyze_endpoint.route('/analyze', methods=['POST'])
async def analyze_text():
    """API endpoint với comprehensive error handling"""
    try:
        data = request.get_json(silent=True)
        
        if not data or 'text' not in data:
            return jsonify({'error': 'Invalid request format'}), 400
        
        text = data.get('text', '').strip()
        urls = data.get('urls', [])
        
        if not text:
            return jsonify({'error': 'No text to analyze'}), 400
        
        if len(text) > 5000:  # Limit input size
            text = text[:5000]
            
        result = await perform_full_analysis_optimized(text, urls)
        
        if 'error' in result:
            return jsonify({'error': result['error']}), result.get('status_code', 500)
        
        return jsonify({'result': result})
        
    except Exception as e:
        print(f"ERROR: Server error in analyze_text: {e}")
        # Force garbage collection on error
        gc.collect()
        return jsonify({'error': 'Internal server error'}), 500

# Health check endpoint
@analyze_endpoint.route('/health', methods=['GET'])
async def health_check():
    """Health check cho Render deployment"""
    try:
        # Quick system check
        memory_info = {
            'cache_size': len(g_cached_sheet_data),
            'last_fetch': g_sheet_data_last_fetched
        }
        return jsonify({
            'status': 'healthy',
            'memory_info': memory_info
        })
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500
