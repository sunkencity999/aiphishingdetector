# Joby Security Extension

A Chrome extension that analyzes email headers and bodies directly within your browser to provide a phishing confidence score and highlights suspicious elements. Uses advanced heuristics and optional AI integration via OpenAI-compatible APIs (including local FastAPI endpoints) to improve accuracy.

This extension has been comprehensively enhanced with robust heuristic detection, flexible AI integration, comprehensive logging, detailed documentation, unit tests, and improved error handling to ensure reliable phishing detection and easier maintenance.

## Features

- **Real-time Analysis**: Automatically analyzes emails when you open them in Gmail
- **Visual Indicators**: Displays a color-coded banner with phishing confidence score (0-100)
- **Advanced Heuristic Detection**: Uses sophisticated techniques to identify phishing patterns:
  - **Comprehensive Keyword Analysis**: Detects urgent, action, security, and financial keywords
  - **Deceptive Link Detection**: Identifies mismatched display text vs actual URLs
  - **Suspicious Domain Patterns**: Detects fake domains resembling legitimate services
  - **Email Authentication Analysis**: DKIM, SPF, and DMARC verification results
    - Failed DKIM authentication: +15 points
    - Failed SPF authentication: +12 points
    - Failed DMARC authentication: +18 points
    - Multiple authentication failures: additional +10 points
    - All three authentication failures: additional +15 points
    - Passed authentication slightly reduces phishing scores
  - **Generic/Impersonal Greetings**: Detects non-personalized salutations
  - **Dangerous Combinations**: Higher scores for multiple suspicious indicators
- **Flexible AI Integration**: Optional integration with multiple AI providers:
  - **OpenAI API**: Full OpenAI GPT model support
  - **Local FastAPI Endpoints**: Support for local AI models (no API key required)
  - **Automatic Model Selection**: Uses server default models when not specified
- **Link Highlighting**: Suspicious links are highlighted in red
- **Safe List**: Mark emails as safe to skip future analysis
- **Detailed Reports**: Expandable details section showing exactly what was detected
- **Comprehensive Logging**: Detailed debug logging for troubleshooting and development
- **Unit Tests**: Comprehensive test suite for heuristic functions
- **Enhanced Error Handling**: Robust error handling throughout the codebase

## Installation

1. Clone or download this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top right corner
4. Click "Load unpacked" and select the extension directory

## Configuration

1. Click the extension icon in the toolbar and select "Settings"
2. Choose your analysis mode:
   - **Enable AI Analysis**: Toggle on/off to use AI-powered analysis
   - When disabled, only fast heuristic analysis is used (more private, no API required)
3. If AI analysis is enabled, select your endpoint type:
   - **OpenAI-style API**: For OpenAI or compatible cloud services
   - **Local FastAPI Endpoint**: For local AI models (recommended for privacy)
4. Configure based on your endpoint type:
   
   **For OpenAI-style API:**
   - **API Endpoint**: URL (e.g., `https://api.openai.com/v1/chat/completions`)
   - **API Key**: Your API key for authentication (required)
   - **Model**: Model name (e.g., `gpt-4o-mini`, `gpt-3.5-turbo`)
   
   **For Local FastAPI Endpoint:**
   - **API Endpoint**: Local server URL (e.g., `http://localhost:8002`, `http://10.1.141.6:8002`)
   - **API Key**: Not required (field disabled)
   - **Model**: Optional (leave empty to use server default, recommended)
5. Click "Save" to store your settings

## Usage

1. Navigate to Gmail and open an email
2. The extension will automatically analyze the email and display a banner at the top with:
   - Phishing confidence score (0-100)
   - Risk assessment (Low/Moderate/High)
   - "Details" button to see heuristic findings
   - "Mark as Safe" button to skip future analysis of this email
3. Suspicious links in the email body will be highlighted in red

## How It Works

The extension uses two layers of analysis:

1. **Heuristic Analysis**: Client-side analysis that checks for common phishing indicators:
   - Suspicious sender domains and email addresses
   - Generic greetings and impersonal salutations
   - Mismatched or deceptive links
   - Urgent/action-required language
   - Email authentication failures (DKIM, SPF, DMARC)
   - Suspicious URL patterns and domains
   - Excessive use of capital letters and punctuation
   - Common phishing keywords and phrases

2. **AI Analysis**: Optional server-side analysis using an LLM to provide context-aware scoring:
   - Analyzes email content for sophisticated social engineering
   - Detects subtle phishing patterns that rules might miss
   - Provides detailed reasoning for its assessment
   - Considers the relationship between different elements of the email

## Detection Capabilities

### Sender Analysis

- Detects spoofed or suspicious sender domains
- Identifies lookalike domains (e.g., micros0ft.com)
- Flags generic or suspicious sender names

### Link Analysis

- Highlights links where the display text doesn't match the actual URL
- Detects URL shorteners and redirects
- Identifies links to suspicious or mismatched domains
- Warns about links to IP addresses

### Content Analysis

- Identifies urgent/action-required language
- Detects generic greetings and impersonal salutations
- Flags requests for sensitive information
- Identifies threats or consequences for inaction

### Authentication Checks

- Verifies DKIM, SPF, and DMARC authentication
- Detects email spoofing attempts
- Checks for missing or failed authentication

## Customization

### Heuristic Sensitivity

You can adjust the sensitivity of the heuristic analysis by modifying the weights in `contentScript.js`. Look for the `computeHeuristics` function to customize scoring.

### Custom Keywords

Add your own keywords to the detection lists in `contentScript.js`:

- `urgentKeywords`
- `actionKeywords`
- `securityKeywords`
- `financialKeywords`

### Safe List Management

Emails can be marked as safe through the UI, which adds them to Chrome's local storage. To manage the safe list:

1. Open Chrome Developer Tools (F12)
2. Go to Application > Local Storage > chrome-extension://[extension-id]/
3. Look for the `safeList` key

## Troubleshooting

### Common Issues

#### AI Analysis Not Working

- Verify your API key and endpoint are correct
- Check the browser console for error messages (F12 > Console)
- Ensure your API key has sufficient permissions and quota

#### False Positives/Negatives

- Mark false positives as safe using the "Mark as Safe" button
- For persistent issues, adjust the heuristic weights in `contentScript.js`
- Consider enabling AI analysis for more accurate results

#### Extension Not Loading

- Make sure you've enabled Developer Mode in Chrome
- Try reloading the extension from `chrome://extensions/`
- Check for error messages in the browser console

### Viewing Logs

For debugging purposes, you can view detailed logs in the Chrome DevTools console (F12 > Console). The extension logs various events and analysis results.

## Privacy

### Data Collection

- The extension processes all email content locally in your browser
- When AI analysis is enabled, email content is sent to your configured API endpoint
- No data is collected or stored by the extension itself

### Safe Mode

For maximum privacy, you can disable AI analysis in the settings to ensure all processing happens locally in your browser.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Running Tests

To run the unit tests:

1. Open `tests/test-runner.html` in a browser, or
2. Run `node tests/run-tests.js` from the command line

All tests should pass before submitting any changes.

### Testing Tools

The extension includes several testing and debugging tools:

- **`test-fastapi-endpoint.js`**: Tests FastAPI endpoint compatibility and model support
- **`debug-extension-settings.js`**: Simulates extension requests for debugging API issues
- **`tests/heuristic-tests.js`**: Comprehensive unit tests for all heuristic functions
- **`tests/test-runner.html`**: Browser-based test runner with visual results

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

The final score is a weighted combination of both analyses (40% heuristics, 60% AI).

## Privacy

- All heuristic analysis happens locally in your browser
- Email content is only sent to the configured AI endpoint when AI analysis is enabled
- API keys are stored locally using Chrome's secure storage

## Development

This extension is built with:
- JavaScript
- HTML/CSS
- Chrome Extension APIs

### Files

- `manifest.json`: Extension configuration
- `contentScript.js`: Gmail integration and analysis logic
- `background.js`: AI service communication
- `popup.html/js`: Extension popup interface
- `options.html/js`: Configuration interface
- `tests/`: Unit tests and test runner for heuristic functions

### Code Quality

- Comprehensive JSDoc documentation for all functions
- Detailed logging for debugging and monitoring
- Unit tests with 100% pass rate for core functionality
- Robust error handling with meaningful error messages
- Well-structured, maintainable codebase

## License

Copyright (c) 2025 Christopher Bradford. All rights reserved.

This project is closed source and proprietary.

## Author

Christopher Bradford

For support, please contact the repository owner.
