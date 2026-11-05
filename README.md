# OAuth 2.0 and OIDC Identity Flow Demo

A small Node/Express app that implements the **OpenID Connect Authorization Code flow with PKCE** by hand, using Google as the identity provider. No auth libraries (like Passport) handle the flow: every redirect, token exchange, and validation step is written out so the flow is easy to read and explain.

## What it demonstrates

- OIDC **discovery** (`/.well-known/openid-configuration`)
- **Authorization Code flow with PKCE** (S256)
- **CSRF protection** with the `state` parameter
- **Replay protection** with the `nonce` claim
- **ID token validation**: signature (via Google's JWKS), issuer, audience, expiry
- Calling the **userinfo endpoint** with an access token
- A `/debug` page that shows what happened at each step

## The flow

```
Browser            This app (client)            Google (authorization + token server)
   |                      |                                  |
   |-- GET /login ------->|                                  |
   |                      | create state, nonce, verifier    |
   |                      | challenge = SHA-256(verifier)    |
   |<-- 302 to Google ----|                                  |
   |-- authorization request (state, nonce, code_challenge) -->|
   |<-- user signs in, consents; 302 to /callback?code&state --|
   |-- GET /callback ---->|                                  |
   |                      | check state matches session      |
   |                      |-- POST token endpoint ---------->|
   |                      |   code + code_verifier + secret  |
   |                      |<-- access_token + id_token ------|
   |                      | verify signature, iss, aud, exp  |
   |                      | check nonce matches session      |
   |<-- 302 to /profile --|                                  |
   |                      |-- GET userinfo (Bearer token) -->|
```

## Setup

### 1. Google Cloud

1. Create a project in the [Google Cloud Console](https://console.cloud.google.com/).
2. Configure the OAuth consent screen (External) and add your Google account under **Audience → Test users**.
3. Create an **OAuth client ID** of type **Web application**.
4. Add `http://localhost:3000/callback` as an authorized redirect URI.

No billing account is required for this.

### 2. Install

```bash
npm install express express-session dotenv jsonwebtoken jwks-rsa
```

Requires Node 18 or newer (uses the built-in `fetch`).

### 3. Environment variables

Create a `.env` file in the project root:

```
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-client-secret
SESSION_SECRET=a-long-random-string
```

Generate a session secret with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Make sure `.env` is listed in `.gitignore`. Never commit it.

### 4. Run

```bash
node server.js
```

Open <http://localhost:3000> and log in with a test-user account.

## Routes

| Route | Purpose |
|---|---|
| `/` | Login link, or redirect to `/profile` if already signed in |
| `/login` | Generates `state`, `nonce`, and the PKCE verifier/challenge, then redirects to Google |
| `/callback` | Verifies `state`, exchanges the code for tokens, validates the ID token and nonce |
| `/profile` | Shows the verified ID token claims and the userinfo response |
| `/debug` | Shows the authorization request params, token response metadata, and the decoded ID token header and payload |
| `/logout` | Destroys the session |

## Security notes


| Mechanism | Where | What it protects against |
|---|---|---|
| `state` | `/login` sets it, `/callback` checks it | Cross-site request forgery: an attacker cannot make you finish a login you did not start |
| PKCE (`code_challenge` / `code_verifier`) | `/login` sends the hash, `/callback` sends the original | Authorization code interception: a stolen code is useless without the verifier |
| `nonce` | `/login` sends it, `/callback` compares it to the ID token claim | ID token replay: a token minted for a different login attempt is rejected |
| Signature check (JWKS, RS256) | `/callback` | Forged or tampered ID tokens |
| `iss`, `aud`, `exp` checks | `/callback` | Tokens from another issuer, tokens meant for another app, expired tokens |
| Client secret in `.env` | Server only | Secrets stay out of source code and the browser |

### Tests I ran
Successful test: <img width="1673" height="855" alt="02-profile" src="https://github.com/user-attachments/assets/f4dfe598-2f2c-402e-9f8c-c74bd54dde90" />


Each test breaks one defense on purpose to confirm it works. Fill in the results as you run them.

| Test | How | Expected result | Actual result |
|---|---|---|---|
| Wrong `state` | Edit `state` in the `/callback` URL | `State mismatch` |  <img width="1381" height="931" alt="test-wrong-state" src="https://github.com/user-attachments/assets/a93b3b05-8419-42c7-960d-f72f77e96174" /> |
|

| Reused code | Reload the `/callback` URL after a successful login | Token request fails (codes are single-use) | |

| Wrong audience | Temporarily set `audience: 'wrong'` | `Invalid ID token` | <img width="1374" height="719" alt="test-wrong-audience" src="https://github.com/user-attachments/assets/0c4b2a30-d59b-4b30-bfbe-7ab7514cab7d" /> |

| Wrong nonce | Temporarily compare against `'wrong'` | `Nonce mismatch` |  <img width="1377" height="729" alt="test-wrong-nonce" src="https://github.com/user-attachments/assets/5c1f9674-58b8-432b-95ab-6c2c87f7c19a" /> |


| Missing verifier | Temporarily remove `code_verifier` from the token request | Google rejects the exchange | <img width="1353" height="724" alt="test-missing-verifier" src="https://github.com/user-attachments/assets/784a0370-feec-4b3c-b77a-1e58df59684c" /> |


## Limitations

This is a learning demo, not production code.

- Sessions use the default in-memory store, which loses sessions on restart and does not scale. Use a persistent store in production.
- The session cookie is not marked `secure` because the app runs over plain HTTP on localhost. Serve over HTTPS and set `cookie: { secure: true, httpOnly: true, sameSite: 'lax' }` in production.
- User-supplied values (name, email, picture URL) are inserted into HTML without escaping. Escape them in a real app.
- Network errors and token endpoint errors (such as a reused code) are not handled gracefully.
- Refresh tokens are not requested or used.
- Tokens are stored in the server-side session only for the life of the session.

## Stack

Node.js, Express, `express-session`, `jsonwebtoken`, `jwks-rsa`, `dotenv`. Identity provider: Google.

## Files

```
.
├── server.js     # the whole app
├── .env          # secrets (not committed)
├── .gitignore
└── package.json
```
