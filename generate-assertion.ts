import { SignJWT } from 'jose';
import { readFileSync } from 'fs';
import crypto from 'crypto';  // For jti

// Load your private key from JSON
const keyJson = JSON.parse(readFileSync('./340445481815506947.json', 'utf8'));
const privateKeyPem = keyJson.key;  // The full PEM string
const clientId = keyJson.clientId;  // "340442431583485955"
const keyId = keyJson.keyId;  // "340445481815506947"
const issuerUrl = 'https://auth.sabanus.site';  // Your Zitadel

// Import the private key for signing
import { importPKCS8 } from 'jose/util';
const privateKey = await importPKCS8(privateKeyPem, 'RS256');

async function generateAssertion() {
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({
    // Claims for client_assertion (RFC 7523)
    iss: clientId,  // Client authenticating itself
    sub: clientId,
    aud: `${issuerUrl}/oauth/v2/token`,  // Token endpoint
    iat: now,
    exp: now + 300,  // 5 min expiry
    jti: crypto.randomUUID(),  // Unique ID
  })
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'JWT',
      kid: keyId,  // Matches your key
    })
    .sign(privateKey);

  console.log('Client Assertion (copy to Postman):');
  console.log(assertion);
}

generateAssertion();
