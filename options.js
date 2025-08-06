// options.js
// Handles loading and saving user configuration for the AI integration.

document.addEventListener('DOMContentLoaded', () => {
  const enableAICheckbox = document.getElementById('enableAI');
  const aiSettingsDiv = document.getElementById('aiSettings');
  const endpointInput = document.getElementById('apiEndpoint');
  const keyInput = document.getElementById('apiKey');
  const modelInput = document.getElementById('model');
  const status = document.getElementById('status');
  const endpointTypeRadios = document.querySelectorAll('input[name="endpointType"]');
  const endpointNote = document.getElementById('endpointNote');
  const apiKeyNote = document.getElementById('apiKeyNote');
  
  // Function to toggle AI settings visibility
  function toggleAISettings() {
    aiSettingsDiv.style.display = enableAICheckbox.checked ? 'block' : 'none';
  }
  
  // Function to update UI based on endpoint type
  function updateEndpointTypeUI() {
    const selectedType = document.querySelector('input[name="endpointType"]:checked').value;
    if (selectedType === 'fastapi') {
      endpointNote.textContent = 'For FastAPI endpoints, provide the base URL (e.g., http://localhost:8000)';
      apiKeyNote.textContent = 'Not needed for local FastAPI endpoints.';
      keyInput.disabled = true;
      modelInput.disabled = true;
    } else {
      endpointNote.textContent = 'For OpenAI-style APIs, provide the full endpoint URL (e.g., https://api.openai.com/v1/chat/completions)';
      apiKeyNote.textContent = 'Required for OpenAI-style APIs.';
      keyInput.disabled = false;
      modelInput.disabled = false;
    }
  }
  
  // Load existing values
  chrome.storage.sync.get(['apiEndpoint', 'apiKey', 'model', 'enableAI', 'endpointType'], (cfg) => {
    if (cfg.apiEndpoint) endpointInput.value = cfg.apiEndpoint;
    if (cfg.apiKey) keyInput.value = cfg.apiKey;
    if (cfg.model) modelInput.value = cfg.model;
    
    // Set AI enabled state (default to true if not set)
    enableAICheckbox.checked = cfg.enableAI !== false;
    toggleAISettings();
    
    // Set endpoint type (default to openai if not set)
    const endpointType = cfg.endpointType || 'openai';
    document.querySelector(`input[name="endpointType"][value="${endpointType}"]`).checked = true;
    updateEndpointTypeUI();
  });
  
  // Add event listeners
  enableAICheckbox.addEventListener('change', toggleAISettings);
  endpointTypeRadios.forEach(radio => {
    radio.addEventListener('change', updateEndpointTypeUI);
  });
  
  document.getElementById('optionsForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const endpoint = endpointInput.value.trim();
    const key = keyInput.value.trim();
    const model = modelInput.value.trim();
    const enableAI = enableAICheckbox.checked;
    const endpointType = document.querySelector('input[name="endpointType"]:checked').value;
    
    // For FastAPI endpoints, we don't need an API key
    const apiKey = endpointType === 'fastapi' ? '' : key;
    
    chrome.storage.sync.set({ 
      apiEndpoint: endpoint, 
      apiKey: apiKey, 
      model: model,
      enableAI: enableAI,
      endpointType: endpointType
    }, () => {
      status.textContent = 'Saved!';
      setTimeout(() => { status.textContent = ''; }, 1500);
    });
  });
});