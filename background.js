// background.js
// The service worker listens for messages from content scripts requesting
// AI‑powered email analysis.  When invoked it retrieves the user’s
// configured API endpoint and key from storage and issues a fetch
// request with a system prompt instructing the LLM to analyse the
// email.  Results are returned to the sender via the callback.

self.addEventListener('install', () => {
  // Ensure the service worker does not get terminated before we
  // complete asynchronous operations.
  self.skipWaiting();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message && message.action === 'analyzeEmail') {
    const { body, header } = message;
    // Retrieve API configuration from storage
    chrome.storage.sync.get(['apiEndpoint', 'apiKey', 'model'], async (cfg) => {
      const endpoint = cfg.apiEndpoint;
      const apiKey = cfg.apiKey;
      const model = cfg.model || 'gpt-4o-mini';
      if (!endpoint || !apiKey) {
        console.log('AI analysis skipped: API configuration missing', { endpoint: !!endpoint, apiKey: !!apiKey });
        sendResponse({ error: 'API configuration missing' });
        return;
      }
      
      console.log('Starting AI analysis with config:', { endpoint, model, hasApiKey: !!apiKey });
      try {
        const systemPrompt =
          'You are a cybersecurity assistant trained to detect phishing emails. Given the email headers and body, analyse the content for indicators of phishing such as mismatched sender domains, urgent or threatening language, requests for personal information, and suspicious links. Respond in JSON with two keys: "score" (an integer 0–100 where higher values indicate a greater likelihood of phishing) and "explanation" (a concise sentence explaining the reasoning). If the email appears legitimate, use a low score such as below 40; if it appears malicious use a high score such as above 80.';
        const userContent =
          'Headers:\n' + JSON.stringify(header) + '\n\nBody:\n' + body;
        const payload = {
          model: model,
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: userContent }
          ],
          temperature: 0
        };
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${apiKey}`
          },
          body: JSON.stringify(payload)
        });
        if (!res.ok) {
          const errorText = await res.text();
          console.error('LLM request failed', {
            status: res.status,
            statusText: res.statusText,
            error: errorText
          });
          sendResponse({ error: `LLM request failed: ${res.status} ${res.statusText}` });
          return;
        }
        const data = await res.json();
        // OpenAI style responses include an array of choices
        let content;
        if (data.choices && data.choices.length > 0) {
          content = data.choices[0].message.content.trim();
        } else if (data.message) {
          content = data.message.content.trim();
        } else {
          sendResponse({ error: 'Invalid LLM response format' });
          return;
        }
        console.log('Raw AI response content:', content);
        
        // Strip markdown code blocks if present
        let cleanContent = content;
        if (content.includes('```json')) {
          // Extract JSON from markdown code blocks
          const jsonMatch = content.match(/```json\s*([\s\S]*?)\s*```/);
          if (jsonMatch && jsonMatch[1]) {
            cleanContent = jsonMatch[1].trim();
            console.log('Extracted JSON from markdown:', cleanContent);
          }
        } else if (content.includes('```')) {
          // Handle generic code blocks
          const codeMatch = content.match(/```\s*([\s\S]*?)\s*```/);
          if (codeMatch && codeMatch[1]) {
            cleanContent = codeMatch[1].trim();
            console.log('Extracted content from code block:', cleanContent);
          }
        }
        
        let parsed;
        try {
          parsed = JSON.parse(cleanContent);
          console.log('Successfully parsed AI JSON:', parsed);
        } catch (err) {
          console.error('Failed to parse LLM JSON content', err, content);
          // Attempt to extract score and explanation from non-JSON response
          const numMatch = content.match(/(\d{1,3})/);
          const score = numMatch ? parseInt(numMatch[1], 10) : NaN;
          
          // Try to extract a meaningful explanation from the raw text
          let explanation = content;
          // Remove any JSON-like artifacts
          explanation = explanation.replace(/[{}"]/g, '').trim();
          // If it's too long, truncate it
          if (explanation.length > 200) {
            explanation = explanation.substring(0, 200) + '...';
          }
          
          sendResponse({ score: score, explanation: explanation });
          return;
        }
        
        const score = typeof parsed.score === 'number' ? parsed.score : NaN;
        const explanation = parsed.explanation || parsed.reasoning || null;
        console.log('Sending AI analysis result:', { score, explanation });
        sendResponse({ score, explanation });
      } catch (err) {
        console.error('Error contacting LLM', err);
        sendResponse({ error: 'Error contacting LLM' });
      }
    });
    // Indicate that we will respond asynchronously
    return true;
  }
});