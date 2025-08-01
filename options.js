// options.js
// Handles loading and saving user configuration for the AI integration.

document.addEventListener('DOMContentLoaded', () => {
  const enableAICheckbox = document.getElementById('enableAI');
  const aiSettingsDiv = document.getElementById('aiSettings');
  const endpointInput = document.getElementById('apiEndpoint');
  const keyInput = document.getElementById('apiKey');
  const modelInput = document.getElementById('model');
  const status = document.getElementById('status');
  
  // Function to toggle AI settings visibility
  function toggleAISettings() {
    aiSettingsDiv.style.display = enableAICheckbox.checked ? 'block' : 'none';
  }
  
  // Load existing values
  chrome.storage.sync.get(['apiEndpoint', 'apiKey', 'model', 'enableAI'], (cfg) => {
    if (cfg.apiEndpoint) endpointInput.value = cfg.apiEndpoint;
    if (cfg.apiKey) keyInput.value = cfg.apiKey;
    if (cfg.model) modelInput.value = cfg.model;
    
    // Set AI enabled state (default to true if not set)
    enableAICheckbox.checked = cfg.enableAI !== false;
    toggleAISettings();
  });
  
  // Add event listener for checkbox
  enableAICheckbox.addEventListener('change', toggleAISettings);
  document.getElementById('optionsForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const endpoint = endpointInput.value.trim();
    const key = keyInput.value.trim();
    const model = modelInput.value.trim();
    const enableAI = enableAICheckbox.checked;
    
    chrome.storage.sync.set({ 
      apiEndpoint: endpoint, 
      apiKey: key, 
      model: model,
      enableAI: enableAI
    }, () => {
      status.textContent = 'Saved!';
      setTimeout(() => { status.textContent = ''; }, 1500);
    });
  });
});