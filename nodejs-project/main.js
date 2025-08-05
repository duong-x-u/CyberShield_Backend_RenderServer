const rn_bridge = require('rn-bridge');
const { performAdvancedAnalysis } = require('./analyzer.js');

rn_bridge.channel.on('message', async (messageString) => {
    let messageId = null;
    try {
        const message = JSON.parse(messageString);
        messageId = message.id;
        const textToAnalyze = message.text;

        if (!textToAnalyze) {
            throw new Error('No text to analyze was provided.');
        }

        console.log(`[Node.js] Received job ${messageId}: Analyzing text...`);
        const result = await performAdvancedAnalysis(textToAnalyze);
        console.log(`[Node.js] Job ${messageId} complete. Sending result back.`);
        rn_bridge.channel.send(JSON.stringify({ id: messageId, payload: result }));

    } catch (error) {
        console.error('[Node.js] An error occurred:', error.message);
        if (messageId) {
            rn_bridge.channel.send(JSON.stringify({ id: messageId, error: error.message }));
        }
    }
});

rn_bridge.channel.send("Node.js engine has started and is ready.");