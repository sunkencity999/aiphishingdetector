// contentScript.js
// This file runs in the context of the Gmail webpage.  It scans the
// displayed messages, extracts email headers and body text, performs
// heuristic analysis to detect signs of phishing and calls an optional
// AI service via the background service worker to obtain a more
// sophisticated score.  A visual indicator is injected directly into
// the Gmail UI summarising the phishing confidence score and
// highlighting suspicious elements.

 (function () {
  /**
   * Logging utility for debugging purposes.
   * Provides consistent logging format with timestamp and context.
   * @param {string} level - Log level (debug, info, warn, error)
   * @param {string} message - Log message
   * @param {any} [data] - Optional data to log
   */
  function log(level, message, data) {
    const timestamp = new Date().toISOString();
    const prefix = `[PhishingExtension:${level.toUpperCase()}][${timestamp}]`;
    
    if (data !== undefined) {
      console[level](`${prefix} ${message}`, data);
    } else {
      console[level](`${prefix} ${message}`);
    }
  }
  
  // Convenience logging functions
  const logDebug = (message, data) => log('debug', message, data);
  const logInfo = (message, data) => log('info', message, data);
  const logWarn = (message, data) => log('warn', message, data);
  const logError = (message, data) => log('error', message, data);
  const ANALYZED_FLAG = 'data-phishing-analyzed';
  const SAFE_FLAG = 'data-phishing-safe';
  // In-memory safe list of message IDs
  let safeList = [];

  /**
   * Get the unique message identifier for a Gmail message container.
   * Uses the data-message-id attribute if present.
   * @param {HTMLElement} container
   * @returns {string|null}
   */
  /**
   * Extracts the unique message identifier from a Gmail message container.
   * Uses the data-message-id attribute which is unique per message.
   *
   * @param {HTMLElement} container - The Gmail message container element
   * @returns {string|null} The message ID or null if not found
   */
  function getMessageId(container) {
    return container.getAttribute('data-message-id') || null;
  }

  /**
   * Compute a simple heuristic‑based score between 0 and 100.  A higher
   * score indicates a greater likelihood that the email is a phishing
   * attempt.  The heuristics are intentionally lightweight and run
   * entirely on the client.  Additional AI analysis may adjust this
   * score in the background.
   *
   * @param {string} body Plain text content of the email body.
   * @param {object} header Parsed header information including authentication results.
   * @returns {{score: number, details: string[], suspiciousElements: string[]}}
   */
  /**
   * Computes a phishing likelihood score based on various heuristic checks.
   * Analyzes email body and header information for common phishing indicators.
   *
   * Scoring system:
   * - Keyword hits: +1-5 points each
   * - Suspicious domains: +10-25 points
   * - Sender-link domain mismatches: +5-25 points
   * - Authentication failures: +12-18 points each
   * - Generic greetings: +10 points
   * - Excessive links: +5-15 points
   * - Urgent language: +5-10 points
   *
   * @param {string} body - The email body text
   * @param {Object} header - The email header information
   * @param {string} header.from - The sender email address
   * @param {string} header.subject - The email subject
   * @param {Object} header.authentication - Authentication results
   * @returns {Object} Results object containing score, details, and suspicious elements
   * @returns {number} return.score - The computed phishing likelihood score
   * @returns {string[]} return.details - Detailed explanations for the score
   * @returns {string[]} return.suspiciousElements - Elements flagged as suspicious
   */
  function computeHeuristics(body, header) {
    let score = 0;
    const details = [];
    const suspiciousElements = [];
    
    // Initialize suspicious domains - will be populated via API in the future
    // Format: { domain: string, riskLevel: 'high'|'medium'|'low', lastUpdated: number }
    const suspiciousDomains = [
      'paypal.com.security.login.com',
      'amazon.account.security.com',
      'microsoft-office.com',
      'appleid.apple.com.security.check.com',
      'irs.gov.tax.refund.com',
      'bankofamerica.com.login.verify.com',
      'wellsfargo.security.verify.com',
      'chase.com.security.alert.com',
      'facebook.password.reset.com',
      'gmail.login.verify.com',
      'outlook.login.verify.com',
      'linkedin.security.verify.com',
      'dropbox.login.verify.com',
      'icloud.verify.account.com',
      'netflix.billing.verify.com'
    ];

    // Lowercase version for case‑insensitive matching
    const lowerBody = (body || '').toLowerCase();

    // Enhanced keyword list for phishing detection
    const urgentKeywords = [
      'urgent', 'immediate', 'asap', 'expires', 'deadline', 'time sensitive',
      'act now', 'limited time', 'expires today', 'final notice', 'last chance',
      'needs your attention', 'requires immediate', 'must be completed',
      'avoid losing', 'will result in', 'by thursday', 'by friday', 'by monday',
      'within 24 hours', 'within 48 hours', 'before', 'review this document by'
    ];
    
    const actionKeywords = [
      'verify', 'confirm', 'update', 'validate', 'activate', 'click here',
      'click below', 'click link', 'download', 'open attachment', 'view document',
      'view it now', 'click the', 'access your', 'review this', 'complete this',
      'take action', 'respond immediately', 'sign in', 'log in', 'login now'
    ];
    
    const securityKeywords = [
      'password', 'account', 'login', 'security', 'suspended', 'locked',
      'compromised', 'unauthorized', 'breach', 'violation', 'alert',
      'policy document', 'security warning', 'access to your accounts',
      'losing access', 'account closure', 'account suspension'
    ];
    
    const financialKeywords = [
      'bank', 'payment', 'invoice', 'refund', 'credit card', 'wire transfer',
      'tax', 'irs', 'paypal', 'amazon', 'apple', 'microsoft', 'google',
      'accounts', 'billing', 'financial'
    ];
    
    // Enhanced keyword scoring with different weights for different categories
    let urgentHits = 0, actionHits = 0, securityHits = 0, financialHits = 0;
    
    urgentKeywords.forEach(kw => {
      if (lowerBody.includes(kw)) urgentHits++;
    });
    actionKeywords.forEach(kw => {
      if (lowerBody.includes(kw)) actionHits++;
    });
    securityKeywords.forEach(kw => {
      if (lowerBody.includes(kw)) securityHits++;
    });
    financialKeywords.forEach(kw => {
      if (lowerBody.includes(kw)) financialHits++;
    });
    
    // Score based on keyword categories (higher weights for more dangerous combinations)
    if (urgentHits > 0) {
      score += Math.min(15, urgentHits * 8); // Urgent language is highly suspicious
      details.push(`Contains ${urgentHits} urgent keyword${urgentHits > 1 ? 's' : ''}`);
    }
    if (actionHits > 0) {
      score += Math.min(12, actionHits * 6); // Action requests are suspicious
      details.push(`Contains ${actionHits} action keyword${actionHits > 1 ? 's' : ''}`);
    }
    if (securityHits > 0) {
      score += Math.min(10, securityHits * 5); // Security-related terms
      details.push(`Contains ${securityHits} security keyword${securityHits > 1 ? 's' : ''}`);
    }
    if (financialHits > 0) {
      score += Math.min(8, financialHits * 4); // Financial terms
      details.push(`Contains ${financialHits} financial keyword${financialHits > 1 ? 's' : ''}`);
    }
    
    // Bonus points for dangerous combinations
    if (urgentHits > 0 && actionHits > 0) {
      score += 10;
      details.push('Dangerous combination: urgent language + action request');
    }
    if (securityHits > 0 && actionHits > 0) {
      score += 8;
      details.push('Suspicious combination: security alert + action request');
    }

    // Count number of hyperlinks in the email body.  A high number of links can be a sign of spam/phishing.
    const linkCount = (body.match(/https?:\/\//gi) || []).length;
    if (linkCount > 5) {
      const linkScore = Math.min(20, (linkCount - 5) * 2);
      score += linkScore;
      details.push(`Contains many links (${linkCount})`);
    }

    // Enhanced deceptive link detection - check for links where display text doesn't match actual URL
    const deceptiveLinkPatterns = [
      // Pattern: display text shows one domain but URL goes to another
      /\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<]*?)\b[^<]*<[^>]*href=["']https?:\/\/([^"'>\/]+)/gi,
      // Pattern: text that looks like a URL but links elsewhere
      /(https?:\/\/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<]*)[^<]*<[^>]*href=["']https?:\/\/([^"'>\/]+)/gi,
      // Pattern: simple text-based links (www.domain.com/path style)
      /\b(www\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\s<]*?)\b/gi
    ];
    
    let deceptiveLinks = [];
    
    // Helper function to extract base domain
    const getBaseDomain = (domain) => {
      const parts = domain.replace(/^www\./i, '').split('.');
      return parts.length >= 2 ? parts.slice(-2).join('.') : domain;
    };
    
    // Check for HTML-style deceptive links
    deceptiveLinkPatterns.slice(0, 2).forEach(pattern => {
      let match;
      while ((match = pattern.exec(body)) !== null) {
        const displayDomain = match[1].replace(/^https?:\/\//i, '').replace(/^www\./i, '');
        const actualDomain = match[2];
        
        const displayBase = getBaseDomain(displayDomain.toLowerCase());
        const actualBase = getBaseDomain(actualDomain.toLowerCase());
        
        if (displayBase !== actualBase) {
          deceptiveLinks.push({ display: displayDomain, actual: actualDomain });
        }
      }
    });
    
    // Check for suspicious domain patterns in display text (like www.Joby.aero/sharepoint/)
    // This catches cases where the display text looks legitimate but may be deceptive
    const suspiciousDisplayPatterns = [
      /\bwww\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\/[^\s<]*/gi,  // www.domain.com/path patterns
      /\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\/[a-zA-Z0-9._-]+/gi  // domain.com/path patterns
    ];
    
    suspiciousDisplayPatterns.forEach(pattern => {
      let match;
      while ((match = pattern.exec(body)) !== null) {
        const displayText = match[0];
        const domain = displayText.split('/')[0].replace(/^www\./i, '');
        
        // Check if this looks like a legitimate domain being spoofed
        const legitimateDomains = ['joby.aero', 'paypal.com', 'amazon.com', 'microsoft.com', 'google.com', 'apple.com'];
        const isLegitimatePattern = legitimateDomains.some(legit => domain.toLowerCase().includes(legit.toLowerCase()));
        
        if (isLegitimatePattern) {
          // This is suspicious - looks like a legitimate domain with a path that could be deceptive
          deceptiveLinks.push({ display: displayText, actual: 'potentially deceptive link pattern', type: 'suspicious_pattern' });
        }
      }
    });
    
    // Also check for markdown-style links [text](url) where text looks like a different domain
    const markdownLinkRegex = /\[([^\]]*\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^\]]*)\]\(https?:\/\/([^)>\/]+)[^)]*\)/gi;
    let markdownMatch;
    while ((markdownMatch = markdownLinkRegex.exec(body)) !== null) {
      const displayText = markdownMatch[1];
      const actualDomain = markdownMatch[2];
      
      // Extract domain from display text
      const domainInText = displayText.match(/\b([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/);
      if (domainInText) {
        const displayDomain = domainInText[1];
        const getBaseDomain = (domain) => {
          const parts = domain.split('.');
          return parts.length >= 2 ? parts.slice(-2).join('.') : domain;
        };
        
        const displayBase = getBaseDomain(displayDomain.toLowerCase());
        const actualBase = getBaseDomain(actualDomain.toLowerCase());
        
        if (displayBase !== actualBase) {
          deceptiveLinks.push({ display: displayDomain, actual: actualDomain });
        }
      }
    }
    
    // Score deceptive links
    if (deceptiveLinks.length > 0) {
      const deceptiveScore = Math.min(25, deceptiveLinks.length * 15);
      score += deceptiveScore;
      const linkDescriptions = deceptiveLinks.map(link => `"${link.display}" → ${link.actual}`).slice(0, 3);
      details.push(`Deceptive links detected (display text ≠ actual URL): ${linkDescriptions.join(', ')}${deceptiveLinks.length > 3 ? ` and ${deceptiveLinks.length - 3} more` : ''}`);
      suspiciousElements.push(...deceptiveLinks.map(link => link.actual));
    }

    // Enhanced generic greeting detection with pattern matching
    const genericGreetingPatterns = [
      /^\s*(dear|hello|hi|greetings|good\s+(morning|afternoon|evening)|attention|to whom it may concern|valued customer|dear (customer|user|sir|madam|sir\/madam|account holder|client|member|valued member|valued client|account team|support team|it team|security team|billing department|payroll|hr|human resources|administrator))(\s+[^\s,]+)?[,\s]*$/i,
      /^\s*(dear|hello|hi)\s+[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\s*,?\s*$/i,  // Email address as name
      /^\s*(dear|hello|hi)\s+[a-z]+\s*[0-9]+/i,  // Generic name with number (e.g., "User123")
      /^\s*(dear|hello|hi)\s+[a-z]+\s*(department|team|support|helpdesk)/i
    ];
  
    const emailBodyLower = body.toLowerCase();
    const firstLine = emailBodyLower.split('\n')[0].trim();
  
    // Check for generic greetings in first line
    const isGenericGreeting = genericGreetingPatterns.some(pattern => pattern.test(firstLine));
  
    // Also check common second-line greetings if first line is just a name
    let secondLineGreeting = false;
    if (!isGenericGreeting && emailBodyLower.split('\n').length > 1) {
      const secondLine = emailBodyLower.split('\n')[1].trim();
      secondLineGreeting = genericGreetingPatterns.some(pattern => pattern.test(secondLine));
    }
  
    if (isGenericGreeting || secondLineGreeting) {
      const detectedGreeting = isGenericGreeting ? firstLine : emailBodyLower.split('\n')[1].trim();
      score += 10;
      details.push(`Generic/impersonal greeting detected: "${detectedGreeting.substring(0, 30)}${detectedGreeting.length > 30 ? '...' : ''}"`);
    }

    // Enhanced sender domain analysis
    const senderDomain = header.from.split('@')[1] || '';
    const suspiciousDomainPatterns = [
      /^[a-f0-9]+\.(com|net|org)$/i,  // Random-looking domains
      /^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$/,  // IP address as domain
      /^mail\d*\./i,  // mail1., mail2., etc.
      /^smtp\d*\./i,  // smtp1., smtp2., etc.
      /^no[-_]?reply\b/i,  // no-reply, no_reply, noreply
      /^notification/i,
      /^alert/i,
      /^security/i,
      /^update/i,
      /^verify/i,
      /^account/i,
      /^service/i,
      /^support/i,
      /^billing/i,
      /^payment/i,
      /^corp[-_]?internal/i
    ];
  
    // Check for suspicious domain patterns
    const isSuspiciousDomain = suspiciousDomainPatterns.some(pattern => 
      pattern.test(senderDomain) || 
      senderDomain.split('.').some(part => part.length > 30)  // Long subdomains
    );
  
    if (isSuspiciousDomain) {
      score += 15;
      details.push(`Suspicious sender domain pattern: ${senderDomain}`);
    } else if (suspiciousDomains.some(domain => senderDomain.includes(domain))) {
      score += 10;
      details.push(`Suspicious sender domain: ${senderDomain}`);
    }

    // Check for mismatched sender domain vs. display name or reply-to.
    if (header && header.from && header.from.includes('@')) {
      try {
        const domain = header.from.split('@')[1].toLowerCase();
        // Find all domains from links in the body
        const domainRegex = /https?:\/\/(?:www\.)?([^\/'\"\s]+)/gi;
        const domainsInBody = [];
        let match;
        while ((match = domainRegex.exec(lowerBody)) !== null) {
          domainsInBody.push(match[1]);
        }
        const uniqueDomains = [...new Set(domainsInBody)];
        const mismatches = uniqueDomains.filter(d => !d.endsWith(domain));
        if (mismatches.length > 0) {
          const mismatchScore = Math.min(25, mismatches.length * 5);
          score += mismatchScore;
          details.push(`Links point to domains that differ from sender (${mismatches.join(', ')})`);
          suspiciousElements.push(...mismatches);
        }
      } catch (err) {
        console.warn('Error checking sender domain mismatch:', err);
      }
    }

    // Check for all caps lines or exclamation points indicating urgency.
    const exclamations = (body.match(/!/g) || []).length;
    if (exclamations > 3) {
      score += 5;
      details.push('Contains many exclamation marks');
    }
    const lines = body.split(/\n+/);
    let shoutCount = 0;
    lines.forEach(line => {
      if (line.trim() && line === line.toUpperCase() && line.length > 10) {
        shoutCount++;
      }
    });
    if (shoutCount > 0) {
      score += 5;
      details.push('Contains all‑caps sentences');
    }

    // Check email authentication results (DKIM, SPF, DMARC)
    if (header && header.authentication) {
      const auth = header.authentication;
      let authFailures = 0;
      const authDetails = [];
      
      // DKIM check
      if (auth.dkim && auth.dkim.status === 'fail') {
        authFailures++;
        authDetails.push('DKIM authentication failed');
        score += 15;
      } else if (auth.dkim && auth.dkim.status === 'pass') {
        authDetails.push('DKIM authentication passed');
        // Slight reduction for passed DKIM
        score = Math.max(0, score - 2);
      }
      
      // SPF check
      if (auth.spf && auth.spf.status === 'fail') {
        authFailures++;
        authDetails.push('SPF authentication failed');
        score += 12;
      } else if (auth.spf && auth.spf.status === 'pass') {
        authDetails.push('SPF authentication passed');
        score = Math.max(0, score - 2);
      }
      
      // DMARC check
      if (auth.dmarc && auth.dmarc.status === 'fail') {
        authFailures++;
        authDetails.push('DMARC authentication failed');
        score += 18; // DMARC failure is more serious
      } else if (auth.dmarc && auth.dmarc.status === 'pass') {
        authDetails.push('DMARC authentication passed');
        score = Math.max(0, score - 3);
      }
      
      // Multiple authentication failures are very suspicious
      if (authFailures >= 2) {
        score += 10;
        details.push(`Multiple authentication failures (${authFailures})`);
      }
      
      // Add authentication details to the report
      if (authDetails.length > 0) {
        details.push(...authDetails);
      }
      
      // If all three authentication methods fail, it's highly suspicious
      if (authFailures >= 3) {
        score += 15;
        details.push('All email authentication methods failed - high phishing risk');
      }
    }

    // Normalize final score within 0–70 range for heuristics.  AI analysis may bring it closer to 100.
    score = Math.min(70, score);

    return { score, details, suspiciousElements };
  }

  /**
   * Combine the heuristic score with the LLM score.  We weight the LLM
   * score slightly higher because it considers context and subtle
   * patterns.  Heuristics are internally 0-70, LLM is 0-100.
   *
   * @param {number} heuristics Heuristic score (0-70 range)
   * @param {number} llm LLM score (0-100 range)
   * @returns {number} Combined score (0-100 range)
   */
  /**
   * Combines heuristic and AI scores using weighted averaging.
   * Heuristic score weight: 40%, AI score weight: 60%
   *
   * @param {number} heuristics - Normalized heuristic score (0-100)
   * @param {number} llm - AI analysis score (0-100) or NaN if unavailable
   * @returns {number} Combined phishing confidence score (0-100)
   */
  function combineScores(heuristics, llm) {
    // If the LLM score is unavailable (NaN), return the heuristics score.
    if (typeof llm !== 'number' || isNaN(llm)) return heuristics;
    return Math.round((heuristics * 0.4) + (llm * 0.6));
  }

  /**
   * Create and insert a banner into the Gmail UI to display the phishing
   * score and related details.  The banner is inserted above the email
   * header area, near where Gmail displays the sender and subject.
   *
   * @param {HTMLElement} container A DOM element associated with the email being analysed.
   * @param {number} score Final combined phishing confidence score.
   * @param {Array<string>} details List of heuristic findings.
   * @param {Array<string>} suspiciousElements List of suspicious domains or strings.
   */
  /**
   * Inserts a visual phishing indicator banner into the Gmail message container.
   * The banner displays the phishing confidence score and detailed analysis.
   * Color-coded based on risk level (green=low, yellow=medium, red=high).
   *
   * @param {HTMLElement} container - The Gmail message container element
   * @param {number} score - The phishing confidence score (0-100)
   * @param {string[]} details - Detailed analysis explanations
   * @param {string[]} suspiciousElements - Elements flagged as suspicious
   */
  function insertIndicator(container, score, details, suspiciousElements) {
    // Avoid inserting multiple indicators
    if (container.querySelector('.phishing-indicator')) return;

    const banner = document.createElement('div');
    banner.className = 'phishing-indicator';
    banner.style.display = 'flex';
    banner.style.alignItems = 'center';
    banner.style.padding = '8px';
    banner.style.margin = '8px 0';
    banner.style.borderRadius = '6px';
    banner.style.fontFamily = 'Arial, sans-serif';
    banner.style.fontSize = '14px';

    // Determine colour based on score
    let bgColor;
    if (score >= 80) {
      bgColor = '#ffebee'; // light red
    } else if (score >= 40) {
      bgColor = '#fffde7'; // light yellow
    } else {
      bgColor = '#e8f5e9'; // light green
    }
    banner.style.backgroundColor = bgColor;

    // Text container
    const textDiv = document.createElement('div');
    textDiv.style.flex = '1';
    textDiv.style.display = 'flex';
    textDiv.style.flexDirection = 'column';

    const title = document.createElement('div');
    title.style.fontWeight = 'bold';
    title.textContent = `Phishing Score: ${score}/100`;
    textDiv.appendChild(title);
    const desc = document.createElement('div');
    desc.textContent = score >= 80 ?
      'High risk of phishing – proceed with caution.' :
      score >= 40 ? 'Moderate risk – review carefully.' :
      'Low risk – likely legitimate.';
    textDiv.appendChild(desc);

    // Create expandable details sections
    const detailsBtn = document.createElement('button');
    detailsBtn.textContent = 'Analysis Details';
    detailsBtn.style.marginLeft = '8px';
    detailsBtn.style.cursor = 'pointer';
    detailsBtn.style.padding = '4px 12px';
    detailsBtn.style.border = '1px solid #ccc';
    detailsBtn.style.borderRadius = '4px';
    detailsBtn.style.background = '#f0f7ff';
    detailsBtn.style.fontWeight = '500';

    const markSafeBtn = document.createElement('button');
    markSafeBtn.textContent = 'Mark as Safe';
    markSafeBtn.style.marginLeft = '8px';
    markSafeBtn.style.cursor = 'pointer';
    markSafeBtn.style.padding = '4px 12px';
    markSafeBtn.style.border = '1px solid #ccc';
    markSafeBtn.style.borderRadius = '4px';
    markSafeBtn.style.background = '#f7f7f7';
    markSafeBtn.style.fontWeight = '500';

    // Create collapsible details panel
    const detailsPanel = document.createElement('div');
    detailsPanel.style.display = 'none';
    detailsPanel.style.marginTop = '12px';
    detailsPanel.style.padding = '0';
    detailsPanel.style.fontSize = '13px';
    detailsPanel.style.whiteSpace = 'pre-line';
    detailsPanel.style.borderTop = '1px solid #e0e0e0';

    // Helper function to create a section in the details panel
    const createSection = (title, content, isAI = false) => {
      const section = document.createElement('div');
      section.style.padding = '12px';
      section.style.borderBottom = '1px solid #f0f0f0';
      section.style.backgroundColor = isAI ? '#f8f9ff' : '#ffffff';
      
      const titleEl = document.createElement('div');
      titleEl.textContent = title;
      titleEl.style.fontWeight = 'bold';
      titleEl.style.marginBottom = '8px';
      titleEl.style.color = isAI ? '#2c5282' : '#2d3748';
      section.appendChild(titleEl);
      
      const contentEl = document.createElement('div');
      contentEl.innerHTML = content;
      contentEl.style.lineHeight = '1.5';
      contentEl.style.color = '#4a5568';
      section.appendChild(contentEl);
      
      return section;
    };

    // Process and separate heuristic and AI analysis
    const heuristicDetails = [];
    const aiAnalysis = [];
    const suspiciousItems = [];

    if (details && details.length) {
      details.forEach(detail => {
        if (detail.includes('AI Analysis:')) {
          // Clean up AI analysis text
          const aiText = detail.replace('AI Analysis:', '').trim();
          // Format AI explanation with proper line breaks and bullet points
          const formattedText = aiText
            .replace(/\n\s*\n/g, '<br><br>') // Double newlines to paragraphs
            .replace(/\n\s*•/g, '<br>•')     // Bullet points
            .replace(/\n/g, ' ');             // Single newlines to spaces
          aiAnalysis.push(formattedText);
        } else if (detail.includes('Final Score:') || detail.includes('AI Status:')) {
          // Skip these as they're handled separately
        } else {
          heuristicDetails.push(detail);
        }
      });
    }

    // Add heuristic findings section if available
    if (heuristicDetails.length > 0) {
      const formattedHeuristics = heuristicDetails
        .map(d => d.replace(/^•\s*/, ''))
        .map(d => `• ${d}`)
        .join('<br>');
      detailsPanel.appendChild(
        createSection(
          '🔍 Heuristic Analysis Findings',
          formattedHeuristics
        )
      );
    }

    // Add AI analysis section if available
    if (aiAnalysis.length > 0) {
      detailsPanel.appendChild(
        createSection(
          '🤖 AI Analysis Results',
          aiAnalysis.join('<br><br>'),
          true
        )
      );
    }

    // Add suspicious elements section if any
    if (suspiciousElements && suspiciousElements.length > 0) {
      const formattedSuspicious = suspiciousElements
        .map(s => `• ${s}`)
        .join('<br>');
      detailsPanel.appendChild(
        createSection(
          '⚠️ Suspicious Elements Detected',
          formattedSuspicious
        )
      );
    }

    detailsBtn.addEventListener('click', () => {
      const isHidden = detailsPanel.style.display === 'none';
      detailsPanel.style.display = isHidden ? 'block' : 'none';
      detailsBtn.textContent = isHidden ? 'Hide Details' : 'Analysis Details';
      detailsBtn.style.background = isHidden ? '#e1f0ff' : '#f0f7ff';
    });

    markSafeBtn.addEventListener('click', () => {
      // Mark this message as safe: use its data-message-id for persistence.
      const msgId = getMessageId(container);
      container.setAttribute(SAFE_FLAG, 'true');
      if (msgId) {
        if (!safeList.includes(msgId)) {
          safeList.push(msgId);
          chrome.storage.local.set({ safeList });
        }
      }
      // Remove banner and skip future analysis
      banner.remove();
    });

    const buttonsDiv = document.createElement('div');
    buttonsDiv.style.display = 'flex';
    buttonsDiv.appendChild(detailsBtn);
    buttonsDiv.appendChild(markSafeBtn);

    banner.appendChild(textDiv);
    banner.appendChild(buttonsDiv);
    banner.appendChild(detailsPanel);

    // Insert banner at the top of the container
    container.insertBefore(banner, container.firstChild);
  }

  /**
   * Extract DKIM, SPF, and DMARC authentication results from email headers.
   * This function attempts to find and parse authentication-results headers
   * from the raw email source when available.
   *
   * @param {HTMLElement} messageContainer
   * @returns {Promise<object>} Authentication results object
   */
  /**
   * Extracts email authentication results (DKIM, SPF, DMARC) from Gmail UI elements.
   * Attempts to parse authentication information from various Gmail UI patterns.
   * Uses multiple selector strategies and regex patterns for robust parsing.
   *
   * @param {HTMLElement} messageContainer - The Gmail message container element
   * @returns {Promise<Object>} Authentication results object
   * @returns {Object} return.dkim - DKIM authentication result
   * @returns {string} return.dkim.status - DKIM status ('pass', 'fail', 'neutral', 'unknown')
   * @returns {string} return.dkim.details - DKIM details if available
   * @returns {Object} return.spf - SPF authentication result
   * @returns {string} return.spf.status - SPF status ('pass', 'fail', 'neutral', 'unknown')
   * @returns {string} return.spf.details - SPF details if available
   * @returns {Object} return.dmarc - DMARC authentication result
   * @returns {string} return.dmarc.status - DMARC status ('pass', 'fail', 'neutral', 'unknown')
   * @returns {string} return.dmarc.details - DMARC details if available
   */
  async function extractAuthenticationResults(messageContainer) {
    const authResults = {
      dkim: { status: 'unknown', details: '' },
      spf: { status: 'unknown', details: '' },
      dmarc: { status: 'unknown', details: '' }
    };

    try {
      // Enhanced approach: try multiple selectors for authentication information
      // Look for Gmail's authentication indicators in message details
      const authElements = messageContainer.querySelectorAll('.aVW, .aVY, [data-tooltip*="authentication"], [aria-label*="authentication"]');
      
      let authText = '';
      authElements.forEach(el => {
        const text = el.innerText || el.textContent || '';
        authText += ' ' + text.toLowerCase();
      });
      
      // If we found authentication text, parse it
      if (authText) {
        // Enhanced parsing with multiple regex patterns for different Gmail formats
        
        // Pattern 1: Standard authentication-results format
        const dkimPatterns = [
          /dkim=([a-z]+)(?:\s*\(([^)]+)\))?/i,
          /dkim\s+([a-z]+)/i,
          /domainkeys\s+([a-z]+)/i
        ];
        
        const spfPatterns = [
          /spf=([a-z]+)(?:\s*\(([^)]+)\))?/i,
          /spf\s+([a-z]+)/i
        ];
        
        const dmarcPatterns = [
          /dmarc=([a-z]+)(?:\s*\(([^)]+)\))?/i,
          /dmarc\s+([a-z]+)/i
        ];
        
        // Try DKIM patterns
        for (const pattern of dkimPatterns) {
          const match = authText.match(pattern);
          if (match) {
            authResults.dkim.status = match[1].toLowerCase();
            authResults.dkim.details = match[2] || '';
            break;
          }
        }
        
        // Try SPF patterns
        for (const pattern of spfPatterns) {
          const match = authText.match(pattern);
          if (match) {
            authResults.spf.status = match[1].toLowerCase();
            authResults.spf.details = match[2] || '';
            break;
          }
        }
        
        // Try DMARC patterns
        for (const pattern of dmarcPatterns) {
          const match = authText.match(pattern);
          if (match) {
            authResults.dmarc.status = match[1].toLowerCase();
            authResults.dmarc.details = match[2] || '';
            break;
          }
        }
        
        // Fallback: look for general indicators
        if (authResults.dkim.status === 'unknown' && authResults.spf.status === 'unknown' && authResults.dmarc.status === 'unknown') {
          if (authText.includes('failed') || authText.includes('not authenticated')) {
            // If we see failure indicators but no specific protocol, mark all as potentially failed
            if (authText.includes('dkim')) authResults.dkim.status = 'fail';
            if (authText.includes('spf')) authResults.spf.status = 'fail';
            if (authText.includes('dmarc')) authResults.dmarc.status = 'fail';
          } else if (authText.includes('pass') || authText.includes('verified') || authText.includes('signed')) {
            // If we see success indicators but no specific protocol, mark as potentially passed
            if (authText.includes('dkim')) authResults.dkim.status = 'pass';
            if (authText.includes('spf')) authResults.spf.status = 'pass';
            if (authText.includes('dmarc')) authResults.dmarc.status = 'pass';
          }
        }
      }
      
      // Additional fallback: check for security warnings in the message
      const warningElements = messageContainer.querySelectorAll('.yO, .adv, .adn');
      warningElements.forEach(el => {
        const warningText = (el.innerText || el.textContent || '').toLowerCase();
        
        // Look for specific warning indicators
        if (warningText.includes('suspicious') || warningText.includes('phishing') || 
            warningText.includes('fraud') || warningText.includes('scam')) {
          // If there are security warnings, assume authentication likely failed
          if (authResults.dkim.status === 'unknown') authResults.dkim.status = 'fail';
          if (authResults.spf.status === 'unknown') authResults.spf.status = 'fail';
          if (authResults.dmarc.status === 'unknown') authResults.dmarc.status = 'fail';
        }
      });
      
    } catch (err) {
      console.warn('Error extracting authentication results:', err);
      // Return default unknown results rather than failing
    }
    
    return authResults;
  }

  /**
   * Analyse a specific email container element if it hasn't been
   * processed yet.  Extracts the body and header, computes the
   * heuristic score and requests AI analysis if configured.  Finally
   * inserts the visual indicator.
   *
   * @param {HTMLElement} messageContainer
   */
  /**
   * Analyse a specific email container element if it hasn't been
   * processed yet.  Extracts the body and header, computes the
   * heuristic score and requests AI analysis if configured.  Finally
   * inserts the visual indicator.
   *
   * @param {HTMLElement} messageContainer
   */
  async function analyseMessage(messageContainer) {
    if (!messageContainer ||
        messageContainer.getAttribute(ANALYZED_FLAG) ||
        messageContainer.getAttribute(SAFE_FLAG) === 'true') {
      return;
    }
    
    // Log the start of message analysis
    logDebug('Starting analysis of message container', { 
      messageId: getMessageId(messageContainer),
      containerId: messageContainer.id,
      containerClass: messageContainer.className
    });
    // Check persisted safe list by message ID
    const messageId = getMessageId(messageContainer);
    if (messageId && safeList.includes(messageId)) {
      messageContainer.setAttribute(SAFE_FLAG, 'true');
      return;
    }
    // Mark as analysed to avoid reprocessing
    messageContainer.setAttribute(ANALYZED_FLAG, 'true');

    // Extract body text from Gmail.  We query for the `.a3s` element which
    // holds the rendered message.  Use innerText to extract plain text.
    const bodyEl = messageContainer.querySelector('div.a3s');
    if (!bodyEl) {
      logDebug('No body element found in message container');
      return;
    }
    const emailBody = bodyEl.innerText || bodyEl.textContent || '';
    if (!emailBody.trim()) {
      logDebug('Email body is empty');
      return;
    }
    
    // Log basic email information for debugging
    logDebug('Extracted email body', { 
      bodyLength: emailBody.length,
      first100Chars: emailBody.substring(0, 100)
    });

    // Extract header information: from, to, subject, and authentication results
    const header = {};
    try {
      const fromEl = messageContainer.querySelector('span.gD');
      if (fromEl) {
        header.from = fromEl.getAttribute('email') || fromEl.innerText;
        logDebug('Extracted sender information', { from: header.from });
      }
      const toEl = messageContainer.querySelector('span.g2');
      if (toEl) {
        header.to = toEl.getAttribute('email') || toEl.innerText;
        logDebug('Extracted recipient information', { to: header.to });
      }
      const subjectEl = messageContainer.querySelector('h2');
      if (subjectEl) {
        header.subject = subjectEl.innerText;
        logDebug('Extracted subject', { subject: header.subject.substring(0, 100) });
      }
      
      // Extract authentication results from raw headers
      logDebug('Starting authentication results extraction');
      const authResults = await extractAuthenticationResults(messageContainer);
      header.authentication = authResults;
      logDebug('Authentication results extracted', { 
        dkim: authResults.dkim.status,
        spf: authResults.spf.status,
        dmarc: authResults.dmarc.status
      });
    } catch (err) {
      // header extraction failure is non‑fatal
      console.warn('Header extraction error:', err);
    }

    // Compute heuristic score
    logDebug('Computing heuristic score');
    const heuristics = computeHeuristics(emailBody, header);
    logDebug('Heuristic analysis completed', { 
      score: heuristics.score,
      detailsCount: heuristics.details.length
    });
    
    // Function to finish by inserting indicator once we have final score
    function finishWithScore(llmScore, explanation) {
      logDebug('Finishing analysis with score', { llmScore, explanation });
      
      // Normalize heuristic score to 0-100 scale
      // Use a more realistic maximum of 120 points for normalization
      const normalizedHeuristic = Math.min(100, Math.round((heuristics.score / 120) * 100));
      
      // If no AI score available, use normalized heuristic directly
      const finalScore = (typeof llmScore === 'number' && !isNaN(llmScore)) 
        ? combineScores(normalizedHeuristic, llmScore)
        : normalizedHeuristic;
      
      logDebug('Score combination results', { 
        heuristicScore: heuristics.score,
        normalizedHeuristic,
        llmScore,
        finalScore
      });
      
      // Prepare detailed analysis for display
      const analysisDetails = [...heuristics.details];
      
      // Add scoring breakdown
      analysisDetails.push(`Heuristic score: ${heuristics.score} (normalized: ${normalizedHeuristic})`);
      if (typeof llmScore === 'number' && !isNaN(llmScore)) {
        analysisDetails.push(`AI score: ${llmScore}`);
        analysisDetails.push(`Final Score: ${finalScore}/100 (combined)`);
      } else {
        analysisDetails.push(`Final Score: ${finalScore}/100 (heuristics only)`);
      }
      
      // Process AI explanation if available
      if (explanation && explanation.trim()) {
        try {
          let aiExplanation = '';
          const trimmedExplanation = explanation.trim();
          
          // Try to parse as JSON if it looks like JSON
          if (trimmedExplanation.startsWith('{') && trimmedExplanation.endsWith('}')) {
            try {
              const parsed = JSON.parse(trimmedExplanation);
              
              // Extract explanation or reasoning
              if (parsed.explanation) {
                aiExplanation = parsed.explanation;
              } else if (parsed.reasoning) {
                aiExplanation = parsed.reasoning;
              }
              
              // Format structured response if available
              const formattedParts = [];
              if (parsed.risk_factors && parsed.risk_factors.length) {
                formattedParts.push(
                  'Risk Factors:\n• ' + parsed.risk_factors.join('\n• ')
                );
              }
              if (parsed.recommendations && parsed.recommendations.length) {
                formattedParts.push(
                  'Recommendations:\n• ' + parsed.recommendations.join('\n• ')
                );
              }
              
              if (formattedParts.length > 0) {
                aiExplanation = formattedParts.join('\n\n');
              }
            } catch (e) {
              console.warn('Error parsing AI explanation as JSON:', e);
              aiExplanation = trimmedExplanation;
            }
          } else {
            // If not JSON, clean up the text
            aiExplanation = trimmedExplanation
              .replace(/^AI Analysis:/i, '')
              .replace(/^[\s\n]+|[\s\n]+$/g, ''); // Trim whitespace
          }
          
          // Add the formatted AI analysis
          if (aiExplanation) {
            analysisDetails.push(`\nAI Analysis:\n${aiExplanation}`);
          }
        } catch (e) {
          console.warn('Error processing AI explanation:', e);
          // Fallback to showing the raw explanation
          analysisDetails.push(`\nAI Analysis: ${explanation}`);
        }
      } else if (explanation && explanation.includes('Error')) {
        // Show error status if no explanation but there's an error
        analysisDetails.push(`\nAI Status: ${explanation}`);
      } else if (llmScore === undefined || isNaN(llmScore)) {
        // Only show "Not available" if AI was supposed to run but didn't
        analysisDetails.push('AI Analysis: Not available');
      }
      
      logDebug('Inserting phishing indicator', { 
        finalScore, 
        detailsCount: analysisDetails.length,
        suspiciousElementsCount: heuristics.suspiciousElements.length 
      });
      
      insertIndicator(messageContainer, finalScore, analysisDetails, heuristics.suspiciousElements);
      logDebug('Phishing indicator inserted successfully');
    }

    // Retrieve AI settings and call AI if enabled and configured
    chrome.storage.sync.get(['apiEndpoint', 'apiKey', 'enableAI', 'endpointType'], (cfg) => {
      const endpoint = cfg.apiEndpoint;
      const key = cfg.apiKey;
      const enableAI = cfg.enableAI !== false; // Default to true if not set
      const endpointType = cfg.endpointType || 'openai';
      
      logDebug('AI analysis configuration check', { enableAI, hasEndpoint: !!endpoint, hasApiKey: !!key, endpointType });
      
      if (!enableAI) {
        logInfo('AI analysis disabled by user setting');
        finishWithScore(NaN, 'AI analysis disabled in settings');
        return;
      }
      
      if (!endpoint) {
        logInfo('AI analysis skipped: No endpoint configured');
        finishWithScore(NaN, null);
        return;
      }
      
      // For OpenAI endpoints, require API key; for FastAPI, it's optional
      if (endpointType === 'openai' && !key) {
        logInfo('AI analysis skipped: API key required for OpenAI endpoint');
        finishWithScore(NaN, 'API key required for OpenAI endpoint');
        return;
      }
      // Send message to background to perform AI analysis
      logInfo('Requesting AI analysis for email...', { emailSubject: header.subject });
      chrome.runtime.sendMessage({
        action: 'analyzeEmail',
        body: emailBody,
        header
      }, (response) => {
        if (chrome.runtime.lastError) {
          logError('AI analysis error', chrome.runtime.lastError);
          finishWithScore(NaN, `AI Error: ${chrome.runtime.lastError.message}`);
          return;
        }
        logDebug('AI analysis response received', response);
        if (response && response.error) {
          logWarn('AI analysis failed', response.error);
          finishWithScore(NaN, `AI Error: ${response.error}`);
        } else if (response && typeof response.score === 'number') {
          logInfo('AI analysis successful', { score: response.score });
          finishWithScore(response.score, response.explanation || null);
        } else {
          logWarn('Invalid AI response format', response);
          finishWithScore(NaN, 'AI Error: Invalid response format');
        }
      });
    });
  }

  /**
   * Highlight links that point to suspicious domains or where the
   * displayed text doesn’t match the link.  Suspicious links are
   * underlined and coloured red to draw user attention.
   *
   * @param {HTMLElement} bodyEl The body element containing the email markup.
   * @param {Array<string>} suspiciousDomains Domains considered suspicious.
   */
  function highlightSuspiciousLinks(bodyEl, suspiciousDomains) {
    const anchors = bodyEl.querySelectorAll('a[href]');
    anchors.forEach(a => {
      const href = a.getAttribute('href');
      if (!href) return;
      const linkHost = (() => {
        try {
          const url = new URL(href);
          return url.host.toLowerCase();
        } catch (err) {
          return '';
        }
      })();
      const text = (a.innerText || '').trim().toLowerCase();
      const hostMismatch = text && text.includes('.') && !text.includes(linkHost);
      const domainSuspicious = suspiciousDomains.some(dom => linkHost.endsWith(dom));
      if (hostMismatch || domainSuspicious) {
        a.style.color = '#c62828';
        a.style.textDecoration = 'underline';
        a.style.borderBottom = '2px dashed #c62828';
        a.title = 'Suspicious link: text does not match destination or domain flagged by heuristics.';
      }
    });
  }

  /**
   * Observe the DOM for new message containers and analyse them.
   */
  function observeMessages() {
    const observer = new MutationObserver(() => {
      // Gmail nests each message thread inside a `.adn` element; we
      // broaden our search to `.adn` and `.a3s` for robustness.
      const messageContainers = document.querySelectorAll('div.adn, div[data-message-id]');
      messageContainers.forEach(async (mc) => {
        await analyseMessage(mc);
      });
    });
    observer.observe(document.body, { childList: true, subtree: true });
    // Run initial scan
    const initialContainers = document.querySelectorAll('div.adn, div[data-message-id]');
    initialContainers.forEach(async (mc) => await analyseMessage(mc));
  }

  // Wait until Gmail is fully loaded, then begin observing messages.
  function waitForGmail() {
    const checkInterval = setInterval(() => {
      if (document.querySelector('div.adn') || document.querySelector('div.a3s')) {
        clearInterval(checkInterval);
        observeMessages();
      }
    }, 1000);
  }

  // Load persisted safe list, then start Gmail observer
  chrome.storage.local.get({ safeList: [] }, (res) => {
    safeList = Array.isArray(res.safeList) ? res.safeList : [];
    waitForGmail();
  });
})();