#!/usr/bin/env node

/**
 * FastAPI Endpoint Test Script
 * 
 * This script tests the FastAPI endpoint to ensure it's compatible with our extension.
 * It sends a request in the same format that the extension uses and verifies the response.
 * 
 * Usage: node test-fastapi-endpoint.js [endpoint_url]
 * Example: node test-fastapi-endpoint.js http://10.1.141.6:8002
 */

const endpoint = process.argv[2] || 'http://10.1.141.6:8002';

console.log(`[TEST] Testing FastAPI endpoint: ${endpoint}`);
console.log(`[TEST] Full URL: ${endpoint}/v1/chat/completions`);

// Test email data (similar to what the extension would send)
const testEmailBody = `
Dear Customer,

Your account has been temporarily suspended due to suspicious activity. 
Please verify your identity immediately by clicking the link below:

http://verify-account-security.com/login

Failure to verify within 24 hours will result in permanent account closure.

Best regards,
Security Team
`;

const testEmailHeader = {
  from: "security@paypal.com",
  subject: "Urgent: Account Verification Required",
  authentication: {
    dkim: { status: "fail", details: "signature verification failed" },
    spf: { status: "fail", details: "sender IP not authorized" },
    dmarc: { status: "fail", details: "DMARC policy violation" }
  }
};

// Try different approaches: no model first, then common model names
const modelOptions = [
  { name: "no model (server default)", model: null },
  { name: "gpt-3.5-turbo", model: "gpt-3.5-turbo" },
  { name: "gpt-4", model: "gpt-4" },
  { name: "llama", model: "llama" },
  { name: "default", model: "default" }
];

const basePayload = {
  messages: [
    {
      role: "system",
      content: "You are a cybersecurity assistant trained to detect phishing emails. Given the email headers and body, analyse the content for indicators of phishing such as mismatched sender domains, urgent or threatening language, requests for personal information, and suspicious links. Respond in JSON with two keys: \"score\" (an integer 0–100 where higher values indicate a greater likelihood of phishing) and \"explanation\" (a concise sentence explaining the reasoning). If the email appears legitimate, use a low score such as below 40; if it appears malicious use a high score such as above 80."
    },
    {
      role: "user",
      content: `Headers:\n${JSON.stringify(testEmailHeader)}\n\nBody:\n${testEmailBody}`
    }
  ],
  temperature: 0
};

console.log('[TEST] Base request payload (model will be added if specified):');
console.log(JSON.stringify(basePayload, null, 2));

async function testEndpoint() {
  // Try different model approaches
  for (const option of modelOptions) {
    console.log(`\n[TEST] Trying: ${option.name}`);
    
    const testPayload = { ...basePayload };
    if (option.model) {
      testPayload.model = option.model;
    }
    
    try {
      console.log('[TEST] Sending request...');
      
      const response = await fetch(`${endpoint}/v1/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(testPayload)
      });

      console.log(`[TEST] Response status: ${response.status} ${response.statusText}`);
      
      if (!response.ok) {
        const errorText = await response.text();
        console.error(`[TEST] ❌ Request failed with ${option.name}:`, errorText);
        
        // If it's a model not found error, try the next option
        if (response.status === 404 && errorText.includes('model')) {
          console.log(`[TEST] ${option.name} not supported, trying next...`);
          continue;
        }
        
        // For other errors, don't continue
        return;
      }

      const data = await response.json();
      console.log('\n[TEST] Raw response:');
      console.log(JSON.stringify(data, null, 2));

      // Verify response format (OpenAI-compatible)
      if (data.choices && data.choices.length > 0) {
      const content = data.choices[0].message.content.trim();
      console.log('\n[TEST] ✅ Response format is correct (OpenAI-compatible)');
      console.log('[TEST] AI response content:');
      console.log(content);

      // Try to parse the JSON response
      try {
        const aiResult = JSON.parse(content);
        console.log('\n[TEST] ✅ JSON parsing successful');
        console.log(`[TEST] Score: ${aiResult.score}`);
        console.log(`[TEST] Explanation: ${aiResult.explanation}`);
        
        if (typeof aiResult.score === 'number' && aiResult.score >= 0 && aiResult.score <= 100) {
          console.log('\n[TEST] ✅ Score is valid (0-100 range)');
        } else {
          console.log('\n[TEST] ⚠️  Score is not in valid range (0-100)');
        }
        
        if (aiResult.explanation && typeof aiResult.explanation === 'string') {
          console.log('[TEST] ✅ Explanation is present and valid');
        } else {
          console.log('[TEST] ⚠️  Explanation is missing or invalid');
        }
        
        console.log('\n[TEST] 🎉 FastAPI endpoint test PASSED!');
        console.log(`[TEST] The endpoint is compatible with the extension using: ${option.name}`);
        if (option.model) {
          console.log(`[TEST] 💡 Recommendation: Use model "${option.model}" in the extension settings.`);
        } else {
          console.log(`[TEST] 💡 Recommendation: Leave the model field empty in the extension settings.`);
        }
        return; // Success, exit the function
        
      } catch (parseError) {
        console.error('\n[TEST] ❌ JSON parsing failed:', parseError);
        console.log('[TEST] Raw content that failed to parse:', content);
        return; // Parsing failed, exit
      }
      
    } else {
      console.error('\n[TEST] ❌ Invalid response format - missing choices array');
      console.log('[TEST] Expected OpenAI-compatible format with choices[0].message.content');
      return; // Invalid format, exit
    }

    } catch (error) {
      console.error(`\n[TEST] ❌ Network error with ${option.name}:`, error.message);
      
      if (error.code === 'ECONNREFUSED') {
        console.log('\n[TEST] 💡 Troubleshooting tips:');
        console.log('1. Make sure the FastAPI server is running');
        console.log('2. Check if the endpoint URL is correct');
        console.log('3. Verify the server is accessible from this machine');
        return; // Network error, exit
      }
    }
  }
  
  console.log('\n[TEST] ❌ All attempts failed');
  console.log('[TEST] The FastAPI server may not be compatible or may require a different configuration.');
}

// Run the test
testEndpoint();
