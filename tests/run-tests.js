#!/usr/bin/env node

// Simple Node.js test runner for heuristic tests
// This simulates the browser environment for testing

global.console = console;

// Run the tests
require('./heuristic-tests.js');

console.log('\nTest execution completed.');
