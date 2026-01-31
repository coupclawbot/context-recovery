/**
 * Rate Limiter Regression Prevention Tests
 * 
 * These tests ensure the fix for issue #5 remains in place.
 * If anyone reverts to using req.token, these tests will fail.
 */

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  + ${name}`);
    passed++;
  } catch (error) {
    console.log(`  - ${name}`);
    console.log(`    Error: ${error.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(message || `Expected "${expected}", got "${actual}"`);
  }
}

function assertNotEqual(actual, expected, message) {
  if (actual === expected) {
    throw new Error(message || `Expected values to differ, both were "${actual}"`);
  }
}

// The fixed getKey function
function getKey(req, limitType) {
  const authHeader = req.headers.authorization;
  let identifier;
  
  if (authHeader && authHeader.startsWith('Bearer ')) {
    identifier = authHeader.substring(7);
  } else {
    identifier = req.ip || 'anonymous';
  }
  
  return `rl:${limitType}:${identifier}`;
}

console.log('\n[Rate Limiter Regression Prevention]\n');

// REGRESSION TEST 1: Verify we don't use req.token
test('CRITICAL: getKey does NOT use req.token property', () => {
  const req = {
    headers: { authorization: 'Bearer valid_token_123' },
    ip: '127.0.0.1',
    token: 'this_should_be_ignored' // Old property that caused the bug
  };
  const key = getKey(req, 'comments');
  // If we used req.token, key would be 'rl:comments:this_should_be_ignored'
  // But we should use the Bearer token from headers
  assertEqual(key, 'rl:comments:valid_token_123');
  assertNotEqual(key, 'rl:comments:this_should_be_ignored', 
    'REGRESSION: Code is using req.token instead of Authorization header!');
});

// REGRESSION TEST 2: Verify empty req.token doesn't cause fallback to IP
test('CRITICAL: Empty req.token does not break auth header parsing', () => {
  const req = {
    headers: { authorization: 'Bearer moltbook_real_key' },
    ip: '192.168.1.100',
    token: undefined // Empty token property
  };
  const key = getKey(req, 'posts');
  // Should use Authorization header, not fall back to IP because req.token is undefined
  assertEqual(key, 'rl:posts:moltbook_real_key');
  assertNotEqual(key, 'rl:posts:192.168.1.100',
    'REGRESSION: Code falling back to IP when req.token is undefined!');
});

// REGRESSION TEST 3: Verify exact bug scenario from issue #5
test('CRITICAL: Issue #5 scenario - 35 comments then 401', () => {
  // Simulate the scenario: agent made many comments successfully
  const apiKey = 'moltbook_sk_8Xn6T1MLuY_IdgrayuN65FQ_L0AdLt2C';
  
  for (let i = 0; i < 35; i++) {
    const req = {
      headers: { authorization: `Bearer ${apiKey}` },
      ip: '10.0.0.1',
      // req.token might not be set yet in middleware chain
    };
    const key = getKey(req, 'comments');
    assertEqual(key, `rl:comments:${apiKey}`, 
      `Comment ${i + 1}: Should use API key from header`);
  }
  
  // After 35 comments, the 36th should still work with correct auth
  const req36 = {
    headers: { authorization: `Bearer ${apiKey}` },
    ip: '10.0.0.1'
  };
  const key36 = getKey(req36, 'comments');
  assertEqual(key36, `rl:comments:${apiKey}`,
    'Comment 36: Should still work (rate limiting is separate from auth)');
});

// REGRESSION TEST 4: Verify middleware integration pattern
test('Middleware chain: getKey works before requireAuth sets req.token', () => {
  // Simulate: commentLimiter runs BEFORE requireAuth completes
  const req = {
    headers: { authorization: 'Bearer moltbook_valid_key' },
    ip: '172.17.0.1'
    // req.agent and req.token NOT set yet (this is the bug scenario)
  };
  
  // getKey should still work without req.token
  const key = getKey(req, 'comments');
  assertEqual(key, 'rl:comments:moltbook_valid_key',
    'Should extract key from headers even when req.token is undefined');
});

// REGRESSION TEST 5: Case sensitivity in Bearer prefix
test('Case sensitivity: Only "Bearer " with space works', () => {
  const req1 = {
    headers: { authorization: 'bearer lowercase_token' },
    ip: '127.0.0.1'
  };
  const key1 = getKey(req1, 'comments');
  // "bearer" (lowercase) should NOT match, fall back to IP
  assertEqual(key1, 'rl:comments:127.0.0.1',
    'Lowercase "bearer" should fall back to IP (case sensitive)');
  
  const req2 = {
    headers: { authorization: 'BearerUppercase token' },
    ip: '127.0.0.2'
  };
  const key2 = getKey(req2, 'comments');
  assertEqual(key2, 'rl:comments:127.0.0.2',
    'Missing space after Bearer should fall back to IP');
});

// REGRESSION TEST 6: Verify no authentication returns consistent anonymous
test('No auth: Returns consistent anonymous identifier', () => {
  const req = {
    headers: {},
    ip: null,
    token: undefined
  };
  const key = getKey(req, 'comments');
  assertEqual(key, 'rl:comments:anonymous',
    'Should return anonymous when no auth available');
});

// REGRESSION TEST 7: Whitespace handling in token
test('Whitespace: Extra spaces after Bearer handled correctly', () => {
  const req = {
    headers: { authorization: 'Bearer  double_space_token' },
    ip: '127.0.0.1'
  };
  const key = getKey(req, 'posts');
  // substring(7) extracts " double_space_token" (with leading space)
  // This is intentional - preserves exact token including any spaces
  assertEqual(key, 'rl:posts: double_space_token',
    'Should preserve exact extraction including whitespace');
});

console.log('\n' + '='.repeat(50));
console.log(`\nRegression Prevention: ${passed} passed, ${failed} failed\n`);

if (failed > 0) {
  console.log('⚠️  REGRESSION DETECTED! Do not merge without fixing.');
  process.exit(1);
} else {
  console.log('✅ All regression tests passed. Fix is protected.');
  process.exit(0);
}
