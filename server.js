require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');

const app = express();
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
}));

const REDIRECT_URI = 'http://localhost:3000/callback';
let config; // will hold Google's discovery document

// Stage 1: discovery
async function loadConfig() {
  const res = await fetch('https://accounts.google.com/.well-known/openid-configuration');
  config = await res.json();
  console.log('authorization_endpoint:', config.authorization_endpoint);
  console.log('token_endpoint:', config.token_endpoint);
  console.log('jwks_uri:', config.jwks_uri);
  console.log('issuer:', config.issuer);
}

app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/profile');
  res.send('<a href="/login">Log in with Google</a>');
});

// Stage 2: login
app.get('/login', (req, res) => {
  const state = crypto.randomBytes(32).toString('base64url');
  const nonce = crypto.randomBytes(32).toString('base64url');
  const codeVerifier = crypto.randomBytes(32).toString('base64url');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64url');

  req.session.state = state;
  req.session.nonce = nonce;
  req.session.codeVerifier = codeVerifier;

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: process.env.GOOGLE_CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid email profile',
    state: state,
    nonce: nonce,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  });

  req.session.authParams = Object.fromEntries(params);
  res.redirect(`${config.authorization_endpoint}?${params}`);
});

// Stage 3 + 4: callback
app.get('/callback', async (req, res) => {
  
  const { code, state } = req.query;

  // Reject if state doesn't match
  if (!state || state !== req.session.state) {
    return res.status(400).send('State mismatch');
  }

  // Exchange the code for tokens
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: REDIRECT_URI,
    client_id: process.env.GOOGLE_CLIENT_ID,
    client_secret: process.env.GOOGLE_CLIENT_SECRET,
    code_verifier: req.session.codeVerifier,
  });

  const tokenRes = await fetch(config.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  });
  const tokens = await tokenRes.json();

  // Validate the ID token
  const client = jwksClient({ jwksUri: config.jwks_uri });

  function getKey(header, callback) {
    client.getSigningKey(header.kid, (err, key) => {
      if (err) return callback(err);
      callback(null, key.getPublicKey());
    });
  }

  jwt.verify(
  
    tokens.id_token,
    getKey,
    {
      algorithms: ['RS256'],
      issuer: config.issuer,
     audience: process.env.GOOGLE_CLIENT_ID,
    },
    (err, claims) => {
      if (err) return res.status(401).send('Invalid ID token: ' + err.message);

      // Check the nonce yourself. jwt.verify doesn't do this.
      if (claims.nonce !== req.session.nonce) {
        return res.status(401).send('Nonce mismatch');
      }

      req.session.user = claims;
      req.session.accessToken = tokens.access_token;
      req.session.idToken = tokens.id_token;
      req.session.tokenInfo = {
        token_type: tokens.token_type,
        scope: tokens.scope,
        expires_in: tokens.expires_in,
        has_refresh_token: !!tokens.refresh_token,
      };
      res.redirect('/profile');
    }
  );
});

// Stage 5: profile + logout
app.get('/profile', async (req, res) => {
  if (!req.session.user) return res.redirect('/');

  // Ask Google's userinfo endpoint who this is, using the access token
  const infoRes = await fetch(config.userinfo_endpoint, {
    headers: { Authorization: `Bearer ${req.session.accessToken}` },
  });
  const userinfo = await infoRes.json();

  res.send(`
    <h1>Hello, ${userinfo.name}</h1>
    <img src="${userinfo.picture}" width="80" referrerpolicy="no-referrer">
    <p>Email: ${userinfo.email}</p>
    <h3>ID token claims (what your app verified)</h3>
    <pre>${JSON.stringify(req.session.user, null, 2)}</pre>
    <h3>Userinfo response (what the access token fetched)</h3>
    <pre>${JSON.stringify(userinfo, null, 2)}</pre>
    <p><a href="/debug">Debug</a> | <a href="/logout">Log out</a></p>
  `);
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

// Stage 6: debug
app.get('/debug', (req, res) => {
  if (!req.session.user) return res.redirect('/');

  const [h, p] = req.session.idToken.split('.');
  const decode = (part) => JSON.parse(Buffer.from(part, 'base64url').toString());

  const header = decode(h);
  const payload = decode(p);

  const show = (obj) => `<pre>${JSON.stringify(obj, null, 2)}</pre>`;

  res.send(`
    <h2>1. Authorization request params</h2>
    ${show(req.session.authParams)}
    <h2>2. Token response (metadata only)</h2>
    ${show(req.session.tokenInfo)}
    <h2>3. ID token header</h2>
    ${show(header)}
    <h2>4. ID token payload</h2>
    ${show(payload)}
    <p><a href="/profile">Profile</a> | <a href="/logout">Log out</a></p>
  `);
});

loadConfig().then(() => {
  app.listen(3000, () => console.log('Running at http://localhost:3000'));
});