// Test script to verify AI configuration
// Run this in the Chrome DevTools console on any Gmail page after loading the extension

console.log('Testing AI configuration...');

// Check if extension is loaded
if (typeof chrome !== 'undefined' && chrome.storage) {
  chrome.storage.sync.get(['apiEndpoint', 'apiKey', 'model', 'enableAI'], (cfg) => {
    console.log('Current AI configuration:');
    console.log('- AI Analysis Enabled:', cfg.enableAI !== false ? 'YES' : 'NO');
    console.log('- API Endpoint:', cfg.apiEndpoint || 'NOT SET');
    console.log('- API Key:', cfg.apiKey ? 'SET (length: ' + cfg.apiKey.length + ')' : 'NOT SET');
    console.log('- Model:', cfg.model || 'gpt-4o-mini (default)');
    
    if (!cfg.apiEndpoint || !cfg.apiKey) {
      console.warn('⚠️ AI analysis will not work - missing configuration!');
      console.log('To fix:');
      console.log('1. Click the extension icon');
      console.log('2. Click "Settings"');
      console.log('3. Enter your OpenAI API endpoint and key');
    } else {
      console.log('✅ AI configuration appears complete');
      
      // Test a simple API call
      console.log('Testing API connection...');
      fetch(cfg.apiEndpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${cfg.apiKey}`
        },
        body: JSON.stringify({
          model: cfg.model || 'gpt-4o-mini',
          messages: [
            { role: 'system', content: 'You are a test assistant.' },
            { role: 'user', content: 'Respond with just "API test successful"' }
          ],
          max_tokens: 10
        })
      })
      .then(response => {
        console.log('API Response Status:', response.status);
        if (response.ok) {
          console.log('✅ API connection successful!');
        } else {
          console.error('❌ API connection failed:', response.status, response.statusText);
        }
        return response.text();
      })
      .then(data => {
        console.log('API Response:', data);
      })
      .catch(error => {
        console.error('❌ API test failed:', error);
      });
    }
  });
} else {
  console.error('❌ Extension not loaded or no access to chrome.storage');
}
