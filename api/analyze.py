import json
import asyncio
import os
import random
import time
from flask import Blueprint, request, jsonify
import google.generativeai as genai
import google.auth
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from email.mime.text import MIMEText
import base64
import aiohttp
from sentence_transformers import SentenceTransformer
from scipy.spatial.distance import cosine

# Khởi tạo Blueprint
analyze_endpoint = Blueprint('analyze_endpoint', __name__)

# --- Cấu hình Google APIs ---
GOOGLE_API_KEYS_STR = os.environ.get('GOOGLE_API_KEYS')
SAFE_BROWSING_API_KEY = os.environ.get('SAFE_BROWSING_API_KEY')
GOOGLE_SHEET_ID = os.environ.get('GOOGLE_SHEET_ID')
GOOGLE_SHEET_RANGE = os.environ.get('GOOGLE_SHEET_RANGE', 'Sheet1!A2:F') # Updated range to include all columns
SCOPES = ['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/gmail.send'] # Added gmail.send scope

if not GOOGLE_API_KEYS_STR:
    raise ValueError("Biến môi trường GOOGLE_API_KEYS là bắt buộc.")
GOOGLE_API_KEYS = [key.strip() for key in GOOGLE_API_KEYS_STR.split(',') if key.strip()]

# --- Cache và các biến toàn cục ---
g_sheets_service = None
g_cached_sheet_data = [] # To store full sheet data (text, is_dangerous, types, reason, score, recommend)
g_sheet_data_last_fetched = 0
g_embedding_model = None # Sentence Transformer model
CACHE_DURATION_SECONDS = 600 # Cache data trong 10 phút
SEMANTIC_SIMILARITY_THRESHOLD = 0.8 # Ngưỡng độ tương đồng ngữ nghĩa
EMAIL_RECIPIENTS = os.environ.get('EMAIL_RECIPIENTS', 'quoctrieu581@gmail.com,duongpham18210@gmail.com').split(',')
SERVICE_ACCOUNT_EMAIL = os.environ.get('SERVICE_ACCOUNT_EMAIL', 'cyber-shield-server@fluent-plate-465614-b0.iam.gserviceaccount.com')
TOKEN_PATH = 'token.json' # Path to store the service account token

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

# --- Cache và các biến toàn cục ---
g_sheets_service = None
g_cached_keywords = None
g_keywords_last_fetched = 0
CACHE_DURATION_SECONDS = 600 # Cache từ khóa trong 10 phút

async def get_sheets_service():
    """Tạo hoặc trả về service object đã được cache của Google Sheets."""
    global g_sheets_service
    if g_sheets_service:
        return g_sheets_service
    try:
        # Use service account for authentication
        creds, project_id = google.auth.default(scopes=SCOPES)
        loop = asyncio.get_running_loop()
        g_sheets_service = await loop.run_in_executor(None, lambda: build('sheets', 'v4', credentials=creds))
        print("DEBUG: Đã tạo và cache service object của Google Sheets.")
        return g_sheets_service
    except Exception as e:
        print(f"Lỗi nghiêm trọng khi tạo Google Sheets service: {e}")
        return None

async def get_gmail_service():
    """Tạo hoặc trả về service object đã được cache của Gmail."""
    try:
        creds, project_id = google.auth.default(scopes=SCOPES)
        if creds and creds.valid:
            return build('gmail', 'v1', credentials=creds)
        else:
            print("DEBUG: Không thể lấy thông tin xác thực hợp lệ cho Gmail service.")
            return None
    except Exception as e:
        print(f"Lỗi nghiêm trọng khi tạo Gmail service: {e}")
        return None

def load_embedding_model():
    """Tải mô hình SentenceTransformer."""
    global g_embedding_model
    if g_embedding_model is None:
        print("DEBUG: Đang tải mô hình SentenceTransformer...")
        hf_token = os.environ.get('HUGGINGFACE_API_KEY')
        g_embedding_model = SentenceTransformer('paraphrase-multilingual-MiniLM-L12-v2', use_auth_token=hf_token)
        print("DEBUG: Đã tải mô hình SentenceTransformer.")
    return g_embedding_model

# --- Prompt "2.5 Pro" cho AI ---
UNIFIED_PROMPT = lambda text, keywords: f"""<ROLE>
Bạn là \"CyberShield Guardian\", một chuyên gia phân tích an ninh và ngôn ngữ cấp cao. Nhiệm vụ của bạn là đánh giá các đoạn tin nhắn và xác định các mối nguy hiểm tiềm tàng với độ chính xác tuyệt đối. Hãy hành động một cách logic, có phương pháp, và tuân thủ nghiêm ngặt các hướng dẫn dưới đây.
</ROLE>

<THINKING_PROCESS>
Trước khi đưa ra kết quả JSON cuối cùng, hãy thực hiện các bước suy luận sau trong đầu (không cần in ra):
1.  **Phân tích ngữ nghĩa:** Đọc kỹ đoạn tin nhắn. Xác định chủ đề, giọng văn (nghiêm túc, đùa cợt, giận dữ), và mục đích của người gửi.
2.  **Đối chiếu định nghĩa \"Mối Nguy\":** So sánh nội dung tin nhắn với từng loại \"Mối Nguy\" được định nghĩa trong <INSTRUCTIONS>. Tin nhắn có dấu hiệu lừa đảo không? Có chứa lời đe dọa không? Có ngôn ngữ xúc phạm không?
3.  **Đối chiếu từ khóa tham khảo:** Rà soát các từ khóa tham khảo được cung cấp. Việc một từ khóa xuất hiện không có nghĩa tin nhắn đó chắc chắn nguy hiểm, nhưng nó là một tín hiệu cần xem xét cẩn thận.
4.  **Tổng hợp và quyết định:** Dựa trên tất cả các phân tích trên, đưa ra quyết định cuối cùng về `is_dangerous`, `types`, `score`, và `reason`.
5.  **Trích xuất bằng chứng:** Nếu quyết định là nguy hiểm, quay lại đoạn tin nhắn và trích xuất những cụm từ nguyên văn, không diễn giải, làm bằng chứng.
</THINKING_PROCESS>

<INSTRUCTIONS>
# ĐỊNH NGHĨA \"MỐI NGUY\"
Một tin nhắn được coi là \"mối nguy\" và bạn PHẢI đặt \"is_dangerous\": true nếu nó chứa BẤT KỲ yếu tố nào sau đây:
1.  **Lừa đảo & Phishing:** Yêu cầu thông tin cá nhân, dụ dỗ bằng phần thưởng lớn, việc nhẹ lương cao, giả mạo thương hiệu/cơ quan chức năng để lừa tiền.
2.  **Đe dọa & Xúc phạm:** Chứa ngôn ngữ đe dọa, khủng bố tinh thần, bắt nạt, hoặc các từ ngữ thô tục, lăng mạ, xúc phạm nghiêm trọng đến người khác.
3.  **Nội dung cực đoan:** Kích động bạo lực, chia rẽ, chống phá nhà nước, hoặc lan truyền thông tin sai sự thật có chủ đích gây hoang mang.

# HƯỚNG DẪN TRÍCH XUẤT TỪ KHÓA:
- **Mục tiêu:** Trích xuất những cụm từ \"bằng chứng\" nguyên văn từ tin nhắn, giúp người quản lý hiểu được tại sao tin nhắn này lại nguy hiểm.
- **Yêu cầu:**
    - Chỉ trích xuất nếu tin nhắn được xác định là nguy hiểm.
    - Cụm từ phải có độ dài tối thiểu 5 từ và tối đa 20 từ.
    - Cụm từ phải được lấy **nguyên văn**, không diễn giải, không tóm tắt.
- **Ví dụ TỐT:** Nếu tin nhắn là \"Tan học đợi tao ở cổng trường nhé, mày chết chắc\", bạn có thể trích xuất `[\"đợi tao ở cổng trường\", \"mày chết chắc\"]`.
- **Ví dụ XẤU (KHÔNG LÀM):** Không trích xuất các từ đơn lẻ, mang tính trừu tượng như `[\"đe dọa\", \"bạo lực\", \"xúc phạm\"]`.
- Nếu tin nhắn an toàn, trả về danh sách rỗng `[]`.

# TỪ KHÓA THAM KHẢO
Dưới đây là các từ khóa do cộng đồng cung cấp để bạn tham khảo:
{keywords}
</INSTRUCTIONS>

<OUTPUT_FORMAT>
Bạn PHẢI trả lời bằng một đối tượng JSON duy nhất, không có bất kỳ giải thích nào bên ngoài. Cấu trúc JSON phải như sau:
{{{{
    \"is_dangerous\": (boolean),
    \"reason\": (string, \"<={{ 2 }}> câu\"),
    \"types\": (string),
    \"score\": (integer, 0-5),
    \"recommend\": (string),
    \"suggested_keywords\": (list of strings)
}}}}
</OUTPUT_FORMAT>

<TEXT_TO_ANALYZE>
{text}
</TEXT_TO_ANALYZE>
"""

async def fetch_sheet_data_and_embed():
    """Lấy toàn bộ dữ liệu từ Google Sheet, tạo embeddings và cache."""
    global g_cached_sheet_data, g_sheet_data_last_fetched
    current_time = time.time()
    if g_cached_sheet_data and (current_time - g_sheet_data_last_fetched < CACHE_DURATION_SECONDS):
        print("DEBUG: Trả về dữ liệu sheet từ cache.")
        return g_cached_sheet_data

    print("DEBUG: Cache dữ liệu sheet hết hạn hoặc trống. Fetching mới từ Google Sheet...")
    service = await get_sheets_service()
    if not service or not GOOGLE_SHEET_ID:
        print("ERROR: Không thể lấy service hoặc GOOGLE_SHEET_ID.")
        return []

    try:
        sheet = service.spreadsheets()
        result = await asyncio.get_running_loop().run_in_executor(None, lambda: sheet.values().get(spreadsheetId=GOOGLE_SHEET_ID, range=GOOGLE_SHEET_RANGE).execute())
        values = result.get('values', [])

        if not values:
            print("DEBUG: Không có dữ liệu trong Google Sheet.")
            g_cached_sheet_data = []
            g_sheet_data_last_fetched = current_time
            return []

        # Load embedding model
        model = load_embedding_model()

        processed_data = []
        for row in values:
            if len(row) >= 6: # Ensure row has enough columns
                text = row[0]
                is_dangerous = row[1].lower() == 'true'
                types = row[2]
                reason = row[3]
                score = int(row[4]) if row[4].isdigit() else 0
                recommend = row[5]
                
                embedding = model.encode(text).tolist() # Convert to list for JSON serialization
                processed_data.append({
                    'text': text,
                    'is_dangerous': is_dangerous,
                    'types': types,
                    'reason': reason,
                    'score': score,
                    'recommend': recommend,
                    'embedding': embedding
                })
            else:
                print(f"WARNING: Hàng không đủ cột, bỏ qua: {row}")

        g_cached_sheet_data = processed_data
        g_sheet_data_last_fetched = current_time
        print(f"DEBUG: Đã cache {len(processed_data)} hàng dữ liệu từ sheet.")
        return processed_data
    except Exception as e:
        print(f"Lỗi khi đọc hoặc xử lý dữ liệu từ Google Sheet: {e}")
        return []

async def perform_semantic_search(input_text):
    """Thực hiện tìm kiếm ngữ nghĩa trong dữ liệu đã cache."""
    cached_data = await fetch_sheet_data_and_embed()
    if not cached_data: return None

    model = load_embedding_model()
    input_embedding = model.encode(input_text).tolist()

    best_match = None
    highest_similarity = -1

    for item in cached_data:
        sheet_embedding = item['embedding']
        similarity = 1 - cosine(input_embedding, sheet_embedding)
        
        if similarity > highest_similarity:
            highest_similarity = similarity
            best_match = item

    if best_match and highest_similarity >= SEMANTIC_SIMILARITY_THRESHOLD:
        print(f"DEBUG: Tìm thấy match ngữ nghĩa với độ tương đồng: {highest_similarity:.4f}")
        # Return the relevant fields, excluding the embedding
        return {
            'is_dangerous': best_match['is_dangerous'],
            'reason': best_match['reason'],
            'types': best_match['types'],
            'score': best_match['score'],
            'recommend': best_match['recommend'],
            'suggested_keywords': [] # No new keywords from cached data
        }
    print(f"DEBUG: Không tìm thấy match ngữ nghĩa. Độ tương đồng cao nhất: {highest_similarity:.4f}")
    return None

async def append_keywords_to_sheet(keywords_to_add: list):
    if not keywords_to_add: return
    service = await get_sheets_service()
    if not service: return
    try:
        values_to_append = [[kw] for kw in keywords_to_add]
        body = {'values': values_to_append}
        result = await asyncio.get_running_loop().run_in_executor(None, lambda: 
            service.spreadsheets().values().append(spreadsheetId=GOOGLE_SHEET_ID, range=GOOGLE_SHEET_RANGE, valueInputOption='USER_ENTERED', body=body).execute())
        print(f"DEBUG: Ghi thành công {result.get('updates',{}).get('updatedCells')} ô.")
    except Exception as e:
        print(f"Lỗi khi ghi vào Google Sheet: {e}")

async def send_analysis_email(original_text, analysis_result):
    """Gửi email chứa văn bản gốc và kết quả phân tích."""
    service = await get_gmail_service()
    if not service:
        print("ERROR: Không thể gửi email, không có Gmail service.")
        return

    sender = SERVICE_ACCOUNT_EMAIL
    recipients = ', '.join(EMAIL_RECIPIENTS)
    subject = "CyberShield: Kết quả phân tích tin nhắn mới"

    body = f"""
    Kính gửi,

    Hệ thống CyberShield đã phân tích một tin nhắn mới chưa có trong cơ sở dữ liệu.

    --- Tin nhắn gốc ---
    {original_text}

    --- Kết quả phân tích ---
    Is Dangerous: {analysis_result.get('is_dangerous')}
    Types: {analysis_result.get('types')}
    Score: {analysis_result.get('score')}
    Reason: {analysis_result.get('reason')}
    Recommend: {analysis_result.get('recommend')}

    Trân trọng,
    Hệ thống CyberShield
    """

    message = MIMEText(body, 'plain', 'utf-8')
    message['to'] = recipients
    message['from'] = sender
    message['subject'] = subject

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    try:
        await asyncio.get_running_loop().run_in_executor(None, lambda: service.users().messages().send(userId='me', body={'raw': raw_message}).execute())
        print(f"DEBUG: Đã gửi email kết quả phân tích đến {recipients}")
    except Exception as e:
        print(f"ERROR: Lỗi khi gửi email: {e}")

async def analyze_with_gemini(text, keywords_str):
    if not GOOGLE_API_KEYS:
        return {"is_dangerous": False, "reason": "Lỗi hệ thống: GOOGLE_API_KEYS không được cấu hình.", "score": 0}
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
            return {"is_dangerous": False, "reason": "Gemini trả về JSON không hợp lệ.", "types": "analysis_error", "score": 0, "recommend": "Bỏ qua tin nhắn này.", "suggested_keywords": []}
        except Exception as e:
            print(f"Lỗi với Gemini key {selected_api_key[:12]}...: {e}")
            continue
    return None

async def check_urls_safety(urls: list):
    if not SAFE_BROWSING_API_KEY or not urls: return []
    safe_browsing_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={SAFE_BROWSING_API_KEY}"
    payload = {"threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in urls]}}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(safe_browsing_url, json=payload) as resp:
                if resp.status == 200:
                    return (await resp.json()).get("matches", [])
                return []
    except Exception: return []

async def perform_full_analysis(text, urls):
    # 1. Perform semantic search
    semantic_match_result = await perform_semantic_search(text)
    if semantic_match_result:
        print("DEBUG: Trả về kết quả từ semantic cache.")
        # Add URL analysis to cached result if any URLs are present
        if urls:
            url_matches = await check_urls_safety(urls)
            if url_matches:
                semantic_match_result['url_analysis'] = url_matches
                cur_reason = semantic_match_result.get("reason", "") or "Phát hiện mối nguy." # Ensure reason is not None
                semantic_match_result["reason"] = cur_reason + " Ngoài ra, có URL không an toàn."
                semantic_match_result['is_dangerous'] = True
                semantic_match_result['score'] = max(semantic_match_result.get('score', 0), 4)
        return semantic_match_result

    # 2. If no semantic match, proceed with Gemini analysis
    print("DEBUG: Không tìm thấy semantic match, tiến hành phân tích bằng Gemini.")
    existing_keywords_list = [item['text'] for item in await fetch_sheet_data_and_embed()] # Get keywords for Gemini
    gemini_task = analyze_with_gemini(text, "\n- ".join(existing_keywords_list))
    urls_task = check_urls_safety(urls)

    gemini_result, url_matches = await asyncio.gather(gemini_task, urls_task)

    if not gemini_result: return {'error': 'Gemini fail', 'status_code': 500}

    # 3. Send email with analysis result
    await send_analysis_email(text, gemini_result) # Send email for new analysis

    final_result = gemini_result
    final_result['url_analysis'] = url_matches

    if url_matches:
        final_result['is_dangerous'] = True
        cur_reason = final_result.get("reason", "") or "Phát hiện mối nguy."
        final_result["reason"] = cur_reason + " Ngoài ra, có URL không an toàn."
        final_result['score'] = max(final_result.get('score', 0), 4)
    
    # Remove suggested_keywords as they are not being appended to sheet anymore
    final_result.pop('suggested_keywords', None)

    return final_result

@analyze_endpoint.route('/analyze', methods=['POST'])
async def analyze_text():
    try:
        data = request.get_json(silent=True)
        if not data or 'text' not in data: return jsonify({'error': 'Yêu cầu không hợp lệ'}), 400
        text = data.get('text', '').strip()
        urls = data.get('urls', [])
        if not text: return jsonify({'error': 'Không có văn bản để phân tích'}), 400
        
        result = await perform_full_analysis(text, urls)
        
        if 'error' in result: return jsonify({'error': result['error']}), result.get('status_code', 500)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': f'Lỗi server: {str(e)}'}), 500