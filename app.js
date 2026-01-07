// Import Express.js
const express = require('express');

// Create an Express app
const app = express();

// Middleware to parse JSON bodies
app.use(express.json());

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

function validateMetaHmac(req) {
  if (!appToken) {
    return { valid: false, reason: 'APP_TOKEN not set' };
  }

  const sig256 = req.headers['x-hub-signature-256'];
  if (!sig256) {
    return { valid: false, reason: 'Missing x-hub-signature-256' };
  }

  try {
    const hmac = crypto.createHmac('sha256', appToken);
    hmac.update(req.rawBody || Buffer.from(''));
    const expected = `sha256=${hmac.digest('hex')}`;

    const valid =
      Buffer.byteLength(expected) === Buffer.byteLength(sig256) &&
      crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(sig256));

    return { valid, reason: valid ? 'OK' : 'HMAC mismatch' };
  } catch (err) {
    return { valid: false, reason: err.message };
  }
}