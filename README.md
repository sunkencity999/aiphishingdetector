# Email Phishing Confidence Extension

A Chrome extension that analyzes email headers and bodies directly within your browser to provide a phishing confidence score and highlights suspicious elements. Uses heuristics and an optional AI integration via an OpenAI-style API endpoint to improve accuracy.

## Features

- **Real-time Analysis**: Automatically analyzes emails when you open them in Gmail
- **Visual Indicators**: Displays a color-coded banner with phishing confidence score (0-100)
- **Heuristic Detection**: Uses multiple heuristic techniques to identify suspicious patterns:
  - Suspicious keywords (urgent, verify, password, etc.)
  - Excessive links
  - Domain mismatches between sender and links
  - All-caps sentences and excessive exclamation marks
  - **Email Authentication Analysis**: DKIM, SPF, and DMARC verification results
    - Failed DKIM authentication: +15 points
    - Failed SPF authentication: +12 points
    - Failed DMARC authentication: +18 points
    - Multiple authentication failures: additional +10 points
    - Passed authentication slightly reduces phishing scores
- **AI-Powered Analysis**: Optional integration with OpenAI-style APIs for advanced detection
- **Link Highlighting**: Suspicious links are highlighted in red
- **Safe List**: Mark emails as safe to skip future analysis
- **Detailed Reports**: Expandable details section showing exactly what was detected

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
3. If AI analysis is enabled, configure:
   - **API Endpoint**: URL for the OpenAI-style API (e.g., `https://api.openai.com/v1/chat/completions`)
   - **API Key**: Your API key for authentication
   - **Model**: Optional model specification (defaults to `gpt-4o-mini`)
4. Click "Save" to store your settings

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

## License

Copyright (c) 2025 Christopher Bradford. All rights reserved.

This project is closed source and proprietary.

## Author

Christopher Bradford

For support, please contact the repository owner.
