const axios = require('axios');

// !!! CẢNH BÁO: ĐIỀN API KEY THẬT CỦA BẠN VÀO ĐÂY !!!
const GOOGLE_API_KEY = 'YOUR_GEMINI_API_KEY';
const OPENAI_API_KEY = 'YOUR_OPENAI_API_KEY';
const OPENROUTER_API_KEY = 'YOUR_OPENROUTER_API_KEY';

const unifiedPrompt = (text) => `
Bạn là một hệ thống phân tích an toàn thông minh. Hãy phân tích đoạn tin nhắn sau và trả lời dưới dạng JSON với các key:

- "is_scam" (boolean): Đây có phải nội dung lừa đảo, độc hại, hoặc nguy hiểm không (vd:true, false)?
- "reason" (string): Giải thích ngắn gọn vì sao bị đánh giá như vậy.
- "types" (string): Các loại rủi ro tiềm ẩn (vd: "Lừa đảo", "bạo lực", v.v.).
- "score" (number 1-5): Mức độ nghiêm trọng (1 là nhẹ, 5 là cực kỳ nguy hiểm).
- "recommend" (string): Gợi ý hành động nên làm (vd: báo cáo, xoá, bỏ qua, cảnh giác, v.v.).

Đoạn tin nhắn: ${text}
`;

async function analyzeWithGemini(text) {
    const prompt = unifiedPrompt(text);
    try {
        const response = await axios.post(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${GOOGLE_API_KEY}`,
            { contents: [{ parts: [{ text: prompt }] }] }
        );
        const jsonText = response.data.candidates[0].content.parts[0].text
            .replace(/```json/g, '')
            .replace(/```/g, '')
            .trim();
        return JSON.parse(jsonText);
    } catch (e) {
        console.error("Gemini API Error:", e.message);
        return null;
    }
}

async function analyzeWithOpenAI(text) {
    const prompt = unifiedPrompt(text);
    try {
        const response = await axios.post(
            'https://api.openai.com/v1/chat/completions',
            {
                model: 'gpt-3.5-turbo',
                messages: [{ role: 'user', content: prompt }],
                response_format: { type: 'json_object' },
            },
            { headers: { 'Authorization': `Bearer ${OPENAI_API_KEY}` } }
        );
        return JSON.parse(response.data.choices[0].message.content || '{}');
    } catch (e) {
        console.error("OpenAI API Error:", e.message);
        return null;
    }
}

async function synthesizeResultsWithClaude(analyses) {
    const prompt = `
Bạn là chuyên gia an ninh, hãy tổng hợp các phân tích sau thành một kết quả JSON cuối cùng và chính xác nhất với các key:
- "is_scam", "reason", "types", "score", "recommend".

--- CÁC PHÂN TÍCH ---
${JSON.stringify(analyses, null, 2)}
`.trim();
    try {
        const response = await axios.post(
            'https://openrouter.ai/api/v1/chat/completions',
            {
                model: 'anthropic/claude-3.5-sonnet',
                messages: [{ role: 'user', content: prompt }],
                response_format: { type: 'json_object' },
            },
            { headers: { 'Authorization': `Bearer ${OPENROUTER_API_KEY}` } }
        );
        return JSON.parse(response.data.choices[0].message.content || null);
    } catch (e) {
        console.error("Claude Synthesizer Error:", e.message);
        return null;
    }
}

async function performAdvancedAnalysis(text) {
    const promises = [analyzeWithGemini(text), analyzeWithOpenAI(text)];
    const results = await Promise.allSettled(promises);

    const successfulAnalyses = results
        .filter(r => r.status === 'fulfilled' && r.value)
        .map(r => r.value);

    if (successfulAnalyses.length === 0) {
        throw new Error('All primary analysis AIs failed.');
    }

    const finalResult = await synthesizeResultsWithClaude(successfulAnalyses);
    if (!finalResult) {
        throw new Error('Synthesis AI failed.');
    }
    return finalResult;
}

module.exports = { performAdvancedAnalysis };
