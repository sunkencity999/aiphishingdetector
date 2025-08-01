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
2. Configure the API endpoint and key for AI-powered analysis:
   - **API Endpoint**: URL for the OpenAI-style API (e.g., `https://api.openai.com/v1/chat/completions`)
   - **API Key**: Your API key for authentication
   - **Model**: Optional model specification (defaults to `gpt-4o-mini`)
3. Click "Save" to store your settings

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

1. **Heuristic Analysis**: Client-side analysis that checks for common phishing indicators
2. **AI Analysis**: Optional server-side analysis using an LLM to provide context-aware scoring

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
