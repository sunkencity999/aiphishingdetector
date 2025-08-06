#!/usr/bin/env node

/**
 * Debug Extension Settings
 * 
 * This script helps debug what settings the extension is actually using
 * and tests the exact same request format the extension would send.
 */

console.log('🔍 Extension Settings Debugger');
console.log('This script simulates exactly what the extension should be sending.\n');

// Simulate the extension's storage values
const extensionConfig = {
  apiEndpoint: 'http://10.1.141.6:8002',
  apiKey: '', // Should be empty for FastAPI
  model: '', // Should be empty for server default
  enableAI: true,
  endpointType: 'fastapi'
};

console.log('📋 Extension Configuration:');
console.log(JSON.stringify(extensionConfig, null, 2));

// Simulate the exact payload the extension creates
const systemPrompt = 'You are a cybersecurity assistant trained to detect phishing emails. Given the email headers and body, analyse the content for indicators of phishing such as mismatched sender domains, urgent or threatening language, requests for personal information, and suspicious links. Respond in JSON with two keys: "score" (an integer 0–100 where higher values indicate a greater likelihood of phishing) and "explanation" (a concise sentence explaining the reasoning). If the email appears legitimate, use a low score such as below 40; if it appears malicious use a high score such as above 80.';

const testHeader = {
  from: "admin@corp-internal.com",
  subject: "IMPORTANT: View Your Urgent Document",
  authentication: {
    dkim: { status: "unknown", details: "" },
    spf: { status: "unknown", details: "" },
    dmarc: { status: "unknown", details: "" }
  }
};

const testBody = `Hello Christopher,

You have an urgent Company policy document that needs your attention.
View it now by clicking the secure link below:
www.Joby.aero/sharepoint/2025NewPolicy

Review this document by Thursday, July 31, 2025 to avoid losing access to your accounts.

Thank you,
Admin Team

Security Warning:
This message is intended only for the user. If you have received this by mistake, delete it now.
Do not share or forward this message.`;

// Create payload exactly like the extension does
const payload = {
  messages: [
    { role: 'system', content: systemPrompt },
    { role: 'user', content: `Headers:\n${JSON.stringify(testHeader)}\n\nBody:\n${testBody}` }
  ],
  temperature: 0
};

// Only include model if one is specified (like the extension logic)
if (extensionConfig.model && extensionConfig.model.trim()) {
  payload.model = extensionConfig.model.trim();
  console.log('\n✅ Including model in payload:', extensionConfig.model.trim());
} else {
  console.log('\n✅ No model specified, using server default');
}

console.log('\n📤 Request Details:');
console.log(`URL: ${extensionConfig.apiEndpoint}/v1/chat/completions`);
console.log(`Method: POST`);
console.log(`Headers: Content-Type: application/json`);
console.log(`Payload:\n${JSON.stringify(payload, null, 2)}`);

async function testExtensionRequest() {
  try {
    console.log('\n🚀 Sending request (simulating extension)...');
    
    const response = await fetch(`${extensionConfig.apiEndpoint}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
        // Note: No Authorization header for FastAPI
      },
      body: JSON.stringify(payload)
    });

    console.log(`\n📥 Response: ${response.status} ${response.statusText}`);
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error('❌ Request failed:', errorText);
      
      // Try to diagnose the issue
      if (response.status === 404) {
        console.log('\n🔍 404 Diagnosis:');
        console.log('- The endpoint might not exist');
        console.log('- The model might be required (even though our test works without it)');
        console.log('- There might be a difference in request format');
        
        // Try with a model
        console.log('\n🔄 Trying with model "gpt-3.5-turbo"...');
        const payloadWithModel = { ...payload, model: 'gpt-3.5-turbo' };
        
        const retryResponse = await fetch(`${extensionConfig.apiEndpoint}/v1/chat/completions`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payloadWithModel)
        });
        
        console.log(`Retry response: ${retryResponse.status} ${retryResponse.statusText}`);
        if (retryResponse.ok) {
          console.log('✅ Success with model! The extension should include a model.');
        } else {
          const retryError = await retryResponse.text();
          console.log('❌ Still failed:', retryError);
        }
      }
      return;
    }

    const data = await response.json();
    console.log('\n✅ Success! Response:');
    console.log(JSON.stringify(data, null, 2));
    
    if (data.choices && data.choices[0] && data.choices[0].message) {
      const content = data.choices[0].message.content;
      console.log('\n📊 AI Analysis Content:');
      console.log(content);
      
      try {
        const parsed = JSON.parse(content);
        console.log('\n✅ Parsed AI Result:');
        console.log(`Score: ${parsed.score}`);
        console.log(`Explanation: ${parsed.explanation}`);
      } catch (e) {
        console.log('⚠️ Could not parse AI response as JSON');
      }
    }

  } catch (error) {
    console.error('\n❌ Network error:', error.message);
  }
}

// Run the test
testExtensionRequest();
