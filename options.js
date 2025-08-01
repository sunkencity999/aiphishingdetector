// options.js
// Handles loading and saving user configuration for the AI integration.

document.addEventListener('DOMContentLoaded', () => {
  const endpointInput = document.getElementById('apiEndpoint');
  const keyInput = document.getElementById('apiKey');
  const modelInput = document.getElementById('model');
  const status = document.getElementById('status');
  // Load existing values
  chrome.storage.sync.get(['apiEndpoint', 'apiKey', 'model'], (cfg) => {
    if (cfg.apiEndpoint) endpointInput.value = cfg.apiEndpoint;
    if (cfg.apiKey) keyInput.value = cfg.apiKey;
    if (cfg.model) modelInput.value = cfg.model;
  });
  document.getElementById('optionsForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const endpoint = endpointInput.value.trim();
    const key = keyInput.value.trim();
    const model = modelInput.value.trim();
    chrome.storage.sync.set({ apiEndpoint: endpoint, apiKey: key, model: model }, () => {
      status.textContent = 'Saved!';
      setTimeout(() => { status.textContent = ''; }, 1500);
    });
  });
});