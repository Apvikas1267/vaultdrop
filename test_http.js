const http = require('http');

async function testHttpEndpoints() {
  console.log('Testing VaultDrop Express endpoints...');

  // Start server on a test port
  process.env.PORT = '3899';
  const server = require('./server');

  // Wait 500ms for server to bind
  await new Promise(r => setTimeout(r, 600));

  try {
    // 1. Test GET / (Landing page)
    const landingRes = await fetch('http://localhost:3899/');
    console.log(`Landing Page Status: ${landingRes.status}`);
    if (landingRes.status !== 200) throw new Error('Landing page failed');
    const landingHtml = await landingRes.text();
    if (!landingHtml.includes('VaultDrop')) throw new Error('Landing page missing VaultDrop title');
    console.log('✅ Landing Page OK');

    // 2. Test GET /share/non-existent-id/meta (Expect 404)
    const metaRes = await fetch('http://localhost:3899/api/share/00000000-0000-0000-0000-000000000000/meta');
    console.log(`Missing File Meta Status: ${metaRes.status}`);
    if (metaRes.status !== 404) throw new Error('Expected 404 for missing file');
    const metaData = await metaRes.json();
    if (metaData.code !== 'NOT_FOUND') throw new Error('Expected NOT_FOUND code');
    console.log('✅ 404 Meta Handling OK');

    // 3. Test Security Headers on responses
    const headers = landingRes.headers;
    const nosniff = headers.get('x-content-type-options');
    const frameOptions = headers.get('x-frame-options');
    if (nosniff !== 'nosniff') throw new Error('Missing x-content-type-options: nosniff');
    if (frameOptions !== 'DENY') throw new Error('Missing x-frame-options: DENY');
    console.log('✅ Strict Security Headers Verified (nosniff, DENY)');

    // 4. Test User Signup via API
    const testEmail = `http_test_${Date.now()}@test.com`;
    const signupRes = await fetch('http://localhost:3899/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testEmail, password: 'password123' })
    });
    console.log(`Signup Status: ${signupRes.status}`);
    if (signupRes.status !== 201) throw new Error('Signup failed');
    const signupData = await signupRes.json();
    console.log(`✅ User Signup OK: ${signupData.user.email}, quota: ${signupData.user.storage_limit} bytes`);

    // Extract cookie
    const setCookie = signupRes.headers.get('set-cookie');
    if (!setCookie || !setCookie.includes('token=')) throw new Error('Missing authentication cookie');
    console.log('✅ Authentication Cookie Set Successfully');

    // 5. Test Authenticated /api/auth/me
    const meRes = await fetch('http://localhost:3899/api/auth/me', {
      headers: { 'Cookie': setCookie }
    });
    if (meRes.status !== 200) throw new Error('Authenticated me failed');
    const meData = await meRes.json();
    if (meData.user.email !== testEmail) throw new Error('User email mismatch');
    console.log('✅ /api/auth/me Endpoint OK');

    console.log('\n🎉 ALL HTTP ENDPOINTS & SECURITY CHECKS PASSED PERFECTLY!\n');
    process.exit(0);
  } catch (err) {
    console.error('❌ HTTP Test Error:', err);
    process.exit(1);
  }
}

testHttpEndpoints();
