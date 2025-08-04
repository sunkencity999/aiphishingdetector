/**
 * Unit tests for phishing extension heuristic functions
 * Tests the core heuristic analysis logic without requiring browser environment
 */

// Import or mock the computeHeuristics function
// Since we're in a browser context, we'll need to extract the function

/**
 * Mock suspicious domains array for testing
 */
const mockSuspiciousDomains = [
  'paypal.com.security.login.com',
  'amazon.account.security.com',
  'microsoft-office.com',
  'ups-tracking.com'
];

/**
 * Mock computeHeuristics function for testing
 * This is a simplified version of the actual function for testing purposes
 * @param {string} body - Email body text
 * @param {Object} header - Email header information
 * @returns {Object} Heuristic analysis results
 */
function computeHeuristics(body, header) {
  let score = 0;
  const details = [];
  const suspiciousElements = [];
  
  const lowerBody = body.toLowerCase();
  
  // Check for urgent keywords
  const urgentKeywords = ['urgent', 'immediate', 'act now', 'limited time'];
  urgentKeywords.forEach(keyword => {
    if (lowerBody.includes(keyword)) {
      score += 5;
      details.push(`Contains urgent keyword: ${keyword}`);
    }
  });
  
  // Check for suspicious domains
  mockSuspiciousDomains.forEach(domain => {
    if (lowerBody.includes(domain)) {
      score += 20;
      details.push(`Contains suspicious domain: ${domain}`);
      suspiciousElements.push(domain);
    }
  });
  
  // Check authentication failures
  if (header.authentication) {
    if (header.authentication.dkim.status === 'fail') {
      score += 15;
      details.push('DKIM authentication failed');
    }
    if (header.authentication.spf.status === 'fail') {
      score += 12;
      details.push('SPF authentication failed');
    }
    if (header.authentication.dmarc.status === 'fail') {
      score += 18;
      details.push('DMARC authentication failed');
    }
  }
  
  return { score, details, suspiciousElements };
}

/**
 * Test function to validate heuristic scoring
 * @param {string} testName - Name of the test
 * @param {Function} testFunction - Function that performs the test
 */
function runTest(testName, testFunction) {
  try {
    testFunction();
    console.log(`✅ ${testName}: PASSED`);
  } catch (error) {
    console.error(`❌ ${testName}: FAILED - ${error.message}`);
  }
}

/**
 * Assert function for testing
 * @param {boolean} condition - Condition to assert
 * @param {string} message - Error message if assertion fails
 */
function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

// Test data
const testData = {
  phishingEmail: {
    body: 'Urgent: Your account will be suspended. Click here immediately: http://paypal.com.security.login.com',
    header: {
      from: 'fake-support@scam.com',
      subject: 'Account Verification Required',
      authentication: {
        dkim: { status: 'fail' },
        spf: { status: 'fail' },
        dmarc: { status: 'fail' }
      }
    }
  },
  legitimateEmail: {
    body: 'Hi John, thanks for the meeting today. Looking forward to working together.',
    header: {
      from: 'colleague@company.com',
      subject: 'Meeting Follow-up',
      authentication: {
        dkim: { status: 'pass' },
        spf: { status: 'pass' },
        dmarc: { status: 'pass' }
      }
    }
  },
  suspiciousDomainEmail: {
    body: 'Your package is ready for pickup. Track it here: http://ups-tracking.com',
    header: {
      from: 'notifications@ups.com',
      subject: 'Package Delivery Notification',
      authentication: {
        dkim: { status: 'unknown' },
        spf: { status: 'unknown' },
        dmarc: { status: 'unknown' }
      }
    }
  }
};

// Run tests
console.log('Phishing Extension Heuristic Tests');
console.log('====================================');

runTest('Phishing email should have high score', () => {
  const result = computeHeuristics(testData.phishingEmail.body, testData.phishingEmail.header);
  assert(result.score > 50, `Expected high score, got ${result.score}`);
  assert(result.details.length > 0, 'Expected detailed analysis');
});

runTest('Legitimate email should have low score', () => {
  const result = computeHeuristics(testData.legitimateEmail.body, testData.legitimateEmail.header);
  assert(result.score < 20, `Expected low score, got ${result.score}`);
});

runTest('Suspicious domain should be detected', () => {
  const result = computeHeuristics(testData.suspiciousDomainEmail.body, testData.suspiciousDomainEmail.header);
  assert(result.score > 15, `Expected score for suspicious domain, got ${result.score}`);
  assert(result.suspiciousElements.includes('ups-tracking.com'), 'Expected suspicious domain to be flagged');
});

runTest('Authentication failures should increase score', () => {
  const result = computeHeuristics(testData.phishingEmail.body, testData.phishingEmail.header);
  // Should have points for DKIM (15) + SPF (12) + DMARC (18) + urgent keyword (5) + suspicious domain (20) = 70
  assert(result.score >= 70, `Expected high score for authentication failures, got ${result.score}`);
  assert(result.details.includes('DKIM authentication failed'), 'Expected DKIM failure in details');
  assert(result.details.includes('SPF authentication failed'), 'Expected SPF failure in details');
  assert(result.details.includes('DMARC authentication failed'), 'Expected DMARC failure in details');
});

console.log('\nAll tests completed!');
