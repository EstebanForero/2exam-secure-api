import { SignJWT } from 'jose';
import { readFileSync } from 'fs';
import crypto from 'crypto';

const keyJson = JSON.parse(readFileSync('./340445481815506947.json', 'utf8'));
const privateKeyPem = keyJson.key;
const clientId = keyJson.clientId;
const keyId = keyJson.keyId;
const issuerUrl = 'https://auth.sabanus.site';

import { importPKCS8 } from 'jose/util';
const privateKey = await importPKCS8(privateKeyPem, 'RS256');

async function generateAssertion() {
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({
    iss: clientId,
    sub: clientId,
    aud: `${issuerUrl}/oauth/v2/token`,
    iat: now,
    exp: now + 300,
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({
      alg: 'RS256',
      typ: 'JWT',
      kid: keyId,
    })
    .sign(privateKey);

  console.log('Client Assertion (copy to Postman):');
  console.log(assertion);
}

generateAssertion();
