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
    chrome.storage.sync.get(['apiEndpoint', 'apiKey', 'model', 'enableAI', 'endpointType'], async (cfg) => {
      const endpoint = cfg.apiEndpoint;
      const apiKey = cfg.apiKey;
      const model = cfg.model || '';
      console.error('[DEBUG] Retrieved model from storage:', JSON.stringify(model), 'Length:', model.length);
      const enableAI = cfg.enableAI;
      const endpointType = cfg.endpointType || 'openai';
      
      console.log('[PHISHING-EXT] AI analysis request received', { enableAI, endpointType, hasEndpoint: !!endpoint, hasApiKey: !!apiKey });
      console.error('[DEBUG] AI analysis request received', { enableAI, endpointType, hasEndpoint: !!endpoint, hasApiKey: !!apiKey });
      
      // Check if AI is enabled
      if (!enableAI) {
        console.log('[PHISHING-EXT] AI analysis disabled in settings');
        sendResponse({ error: 'AI analysis disabled' });
        return;
      }
      
      // Check endpoint configuration based on type
      if (!endpoint) {
        console.log('[PHISHING-EXT] AI analysis skipped: No endpoint configured');
        sendResponse({ error: 'API endpoint missing' });
        return;
      }
      
      // For OpenAI endpoints, require API key
      if (endpointType === 'openai' && !apiKey) {
        console.log('[PHISHING-EXT] AI analysis skipped: API key missing for OpenAI endpoint');
        sendResponse({ error: 'API key missing' });
        return;
      }
      
      console.log('[PHISHING-EXT] Starting AI analysis with config:', { endpoint, endpointType, model, hasApiKey: !!apiKey });
      try {
        const systemPrompt =
          'You are a cybersecurity assistant trained to detect phishing emails. Given the email headers and body, analyse the content for indicators of phishing such as mismatched sender domains, urgent or threatening language, requests for personal information, and suspicious links. Respond in JSON with two keys: "score" (an integer 0–100 where higher values indicate a greater likelihood of phishing) and "explanation" (a concise sentence explaining the reasoning). If the email appears legitimate, use a low score such as below 40; if it appears malicious use a high score such as above 80.';
        const userContent =
          'Headers:\n' + JSON.stringify(header) + '\n\nBody:\n' + body;
        
        let res;
        if (endpointType === 'fastapi') {
          // For FastAPI endpoints, use OpenAI-compatible format but without API key
          const payload = {
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: userContent }
            ],
            temperature: 0
          };
          
          // Only include model if one is specified
          console.error('[DEBUG] Model check - model:', JSON.stringify(model), 'trimmed:', JSON.stringify(model.trim()), 'will include:', !!(model && model.trim()));
          if (model && model.trim()) {
            payload.model = model.trim();
            console.log('[PHISHING-EXT] Including model in payload:', model.trim());
            console.error('[DEBUG] Including model in payload:', model.trim());
          } else {
            console.log('[PHISHING-EXT] No model specified, using server default');
            console.error('[DEBUG] No model specified, using server default');
          }
          
          console.log('[PHISHING-EXT] Making FastAPI request to:', endpoint + '/v1/chat/completions');
          console.log('[PHISHING-EXT] FastAPI payload:', JSON.stringify(payload, null, 2));
          console.error('[DEBUG] Making FastAPI request to:', endpoint + '/v1/chat/completions');
          console.error('[DEBUG] FastAPI payload:', JSON.stringify(payload, null, 2));
          
          res = await fetch(endpoint + '/v1/chat/completions', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
          });
          
          console.log('[PHISHING-EXT] FastAPI response status:', res.status, res.statusText);
        } else {
          // For OpenAI-style APIs
          const isResponsesApi = /\/v1\/responses\b/.test(endpoint);
          // Use a safe default model if none provided or whitespace
          const selectedModel = (model && typeof model === 'string' && model.trim()) ? model.trim() : 'gpt-4o-mini';
          let payload;
          if (isResponsesApi) {
            // OpenAI Responses API format
            payload = {
              model: selectedModel,
              input: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userContent }
              ],
              temperature: 0
            };
          } else {
            // Chat Completions format (default)
            payload = {
              model: selectedModel,
              messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userContent }
              ],
              temperature: 0
            };
          }

          console.log('[PHISHING-EXT] Making OpenAI request to:', endpoint);
          console.log('[PHISHING-EXT] OpenAI payload:', payload);

          res = await fetch(endpoint, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${apiKey}`
            },
            body: JSON.stringify(payload)
          });

          console.log('[PHISHING-EXT] OpenAI response status:', res.status, res.statusText);
        }
        if (!res.ok) {
          const errorText = await res.text();
          console.error('[PHISHING-EXT] LLM request failed', {
            status: res.status,
            statusText: res.statusText,
            error: errorText
          });
          // Surface body back for easier debugging
          sendResponse({ error: `LLM request failed: ${res.status} ${res.statusText}`, detail: errorText });
          return;
        }
        const data = await res.json();
        console.log('[PHISHING-EXT] Raw API response:', data);
        
        // Handle OpenAI-style responses
        let content;
        if (data.choices && data.choices.length > 0 && data.choices[0].message?.content) {
          // Chat Completions style
          content = (data.choices[0].message.content || '').trim();
        } else if (Array.isArray(data.output) && data.output.length) {
          // Responses API: concatenate text items
          const parts = [];
          for (const item of data.output) {
            if (item.type === 'output_text' && item.text) parts.push(item.text);
            if (item.type === 'message' && Array.isArray(item.content)) {
              for (const c of item.content) { if (c.type === 'output_text' && c.text) parts.push(c.text); }
            }
          }
          content = parts.join('\n').trim();
          if (!content && typeof data.output_text === 'string') content = data.output_text.trim();
        } else if (typeof data.output_text === 'string') {
          // Some Responses variants return output_text directly
          content = data.output_text.trim();
        } else if (data.message && data.message.content) {
          content = String(data.message.content).trim();
        } else {
          console.error('[PHISHING-EXT] Invalid LLM response format:', data);
          sendResponse({ error: 'Invalid LLM response format' });
          return;
        }
        console.log('[PHISHING-EXT] Raw AI response content:', content);
        
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
          const result = JSON.parse(cleanContent);
          console.log('[PHISHING-EXT] Parsed AI result:', result);
          sendResponse({ score: result.score, explanation: result.explanation });
        } catch (parseErr) {
          console.error('[PHISHING-EXT] Failed to parse AI response as JSON:', parseErr, 'Content:', cleanContent);
          sendResponse({ error: 'Invalid JSON response from AI' });
        }
      } catch (err) {
        console.error('[PHISHING-EXT] AI analysis error:', err);
        sendResponse({ error: 'AI analysis failed' });
      }
    });
    return true; // Keep the message channel open for async response
  }
  
  // Handle auto-reporting of high-risk phishing emails via backend webhook
  if (message && message.action === 'autoReportPhishing') {
    const payload = message.report || {};
    // Allow overriding endpoint via storage; default to provided VPN address
    chrome.storage.sync.get(['reportEndpoint'], async (cfg) => {
      const endpoint = (cfg && cfg.reportEndpoint) ? cfg.reportEndpoint : 'http://10.1.141.6:8005/report-phishing';
      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json().catch(() => ({}));
        if (!res.ok) {
          console.error('[PHISHING-EXT] Report POST failed', res.status, res.statusText, data);
          sendResponse({ ok: false, status: res.status, error: data?.detail || res.statusText });
          return;
        }
        console.log('[PHISHING-EXT] Report POST success', data);
        sendResponse({ ok: true, data });
      } catch (err) {
        console.error('[PHISHING-EXT] Report POST error', err);
        sendResponse({ ok: false, error: String(err) });
      }
    });
    return true; // async response
  }
});