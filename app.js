// Import Express.js
const express = require('express');

let nodeCrypto;
try {
  nodeCrypto = require('crypto');
} catch (e) {
  nodeCrypto = undefined;
}

// Create an Express app
const app = express();

// Debug: print which crypto implementation is available
console.log('==== STARTUP CRYPTO DEBUG ====');
console.log('nodeCrypto present:', !!nodeCrypto);
console.log('nodeCrypto.createHmac type:', nodeCrypto ? typeof nodeCrypto.createHmac : 'n/a');
console.log('globalThis.crypto present:', !!globalThis.crypto);
if (globalThis.crypto && globalThis.crypto.subtle) {
  console.log('globalThis.crypto.subtle available (WebCrypto)');
}
console.log('==============================\n');

// Set port and verify_token
const port = process.env.PORT || 3000;
const verifyToken = process.env.VERIFY_TOKEN;
const appToken = process.env.APP_TOKEN;

// Capture raw body for HMAC
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

// Route for GET requests
app.get('/', (req, res) => {
  const { 'hub.mode': mode, 'hub.challenge': challenge, 'hub.verify_token': token } = req.query;

  if (mode === 'subscribe' && token === verifyToken) {
    console.log('WEBHOOK VERIFIED');
    res.status(200).send(challenge);
  } else {
    res.status(403).end();
  }
});


// POST: print headers + body, and try to verify signature if present
app.post('/', (req, res) => {
  const timestamp = new Date().toISOString().replace('T', ' ').slice(0, 19);
  console.log(`\n\nWebhook received ${timestamp}\n`);

  // Print headers (pretty)
  console.log('--- HEADERS ---');
  console.log(JSON.stringify(req.headers, null, 2));

  // Print body (pretty)
  console.log('--- BODY ---');
  try {
    console.log(JSON.stringify(req.body, null, 2));
  } catch (err) {
    console.log('Could not stringify body:', err);
  }

  const validation = validateMetaHmac(req);
  console.log('--- SIGNATURE VALIDATION ---');
  console.log(validation);

  res.status(200).end();
});

// Start the server
app.listen(port, () => {
  console.log(`\nListening on port ${port}\n`);
});

/**
 * Validate Meta HMAC signature.
 * Always returns a Promise resolving to { valid: boolean, reason: string }.
 * Uses Node crypto if available, otherwise WebCrypto.
 */
async function validateMetaHmac(req) {
  if (!appToken) return { valid: false, reason: 'APP_TOKEN not set' };

  const sigHeader = req.headers['x-hub-signature-256'] || req.headers['x-hub-signature'];
  if (!sigHeader) return { valid: false, reason: 'Missing signature header' };

  // Prefer Node sync HMAC if available
  if (nodeCrypto && typeof nodeCrypto.createHmac === 'function') {
    try {
      const hmac = nodeCrypto.createHmac('sha256', appToken);
      // req.rawBody is a Buffer from express.json verify hook
      hmac.update(req.rawBody || Buffer.from(''));
      const digest = `sha256=${hmac.digest('hex')}`;

      // timing-safe compare using Node if available
      if (nodeCrypto.timingSafeEqual) {
        const a = Buffer.from(digest);
        const b = Buffer.from(String(sigHeader));
        if (a.length !== b.length) {
          return { valid: false, reason: 'HMAC length mismatch' };
        }
        const ok = nodeCrypto.timingSafeEqual(a, b);
        return { valid: ok, reason: ok ? 'OK' : 'HMAC mismatch' };
      } else {
        // fallback to JS constant time string compare
        const ok = constantTimeEqualStr(digest, String(sigHeader));
        return { valid: ok, reason: ok ? 'OK' : 'HMAC mismatch (fallback compare)' };
      }
    } catch (err) {
      return { valid: false, reason: `Node crypto error: ${err.message}` };
    }
  }

  // Fallback: use WebCrypto (async)
  if (globalThis.crypto && globalThis.crypto.subtle) {
    try {
      const keyData = new TextEncoder().encode(appToken);
      const key = await globalThis.crypto.subtle.importKey(
        'raw',
        keyData,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
      );

      const data = req.rawBody ? new Uint8Array(req.rawBody) : new Uint8Array();
      const signature = await globalThis.crypto.subtle.sign('HMAC', key, data);
      const hex = Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
      const expected = `sha256=${hex}`;

      const ok = constantTimeEqualStr(expected, String(sigHeader));
      return { valid: ok, reason: ok ? 'OK (WebCrypto)' : 'HMAC mismatch (WebCrypto)' };
    } catch (err) {
      return { valid: false, reason: `WebCrypto error: ${err.message}` };
    }
  }

  return { valid: false, reason: 'No HMAC capability in runtime' };
}