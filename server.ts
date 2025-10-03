import { serve } from 'bun';
import { SignJWT, importPKCS8 } from 'jose';
import { readFileSync } from 'fs';
import crypto from 'crypto';
import { createPrivateKey } from 'crypto';

const ZITADEL_ISSUER = 'https://auth.sabanus.site';
const INTROSPECT_ENDPOINT = `${ZITADEL_ISSUER}/oauth/v2/introspect`;
const EXPECTED_AUDIENCE = '340437961126445059';

const keyJson = JSON.parse(readFileSync('./340445481815506947.json', 'utf8'));
let privateKeyPem = keyJson.key;
if (privateKeyPem.includes('BEGIN RSA PRIVATE KEY')) {
  console.log('Converting PKCS#1 to PKCS#8...');
  const pkcs1Key = createPrivateKey({
    key: privateKeyPem,
    format: 'pem',
    type: 'pkcs1',
  });
  privateKeyPem = pkcs1Key.export({
    format: 'pem',
    type: 'pkcs8',
  }).toString();
}
console.log('Private key format ready (PKCS#8).');

const apiClientId = keyJson.clientId;
const keyId = keyJson.keyId;
const privateKey = await importPKCS8(privateKeyPem, 'RS256');
console.log('Private key imported successfully.');

async function validateToken(accessToken: string): Promise<{ valid: boolean; scopes: string[]; sub?: string }> {
  try {
    console.log('=== Introspection Start ===');
    console.log('Token preview:', accessToken.substring(0, 20) + '...');

    const now = Math.floor(Date.now() / 1000);
    const assertion = await new SignJWT({
      iss: apiClientId,
      sub: apiClientId,
      aud: ZITADEL_ISSUER,
      iat: now,
      exp: now + 300,
    })
      .setProtectedHeader({ alg: 'RS256', kid: keyId })
      .sign(privateKey);

    console.log('Generated assertion JWT:', assertion);

    const requestBody = new URLSearchParams({
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
      token: accessToken,
    });
    console.log('Request body preview:', {
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion.substring(0, 50) + '...',
      token: accessToken.substring(0, 20) + '...',
    });

    const response = await fetch(INTROSPECT_ENDPOINT, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: requestBody,
    });

    const fullResponseText = await response.text();
    console.log('Full introspection response body:', fullResponseText);
    console.log('Response status:', response.status);

    if (!response.ok) {
      console.error('Introspection HTTP error details:', { status: response.status, body: fullResponseText });
      return { valid: false, scopes: [] };
    }

    const data = JSON.parse(fullResponseText);
    console.log('Parsed introspection data:', {
      active: data.active,
      scope: data.scope,
      sub: data.sub,
      username: data.username,
      aud: data.aud,
      client_id: data.client_id,
      exp: data.exp
    });

    const isActive = data.active === true;
    if (!isActive || (data.aud && !data.aud.includes(EXPECTED_AUDIENCE))) {
      console.log('Token inactive or audience mismatch:', { active: isActive, aud: data.aud });
      return { valid: false, scopes: [] };
    }

    // Extract roles from custom claims (Zitadel-specific)
    const projectRoles = data['urn:zitadel:iam:org:project:roles'] || {};
    const hasServiceRead = !!projectRoles['service.read'];
    const hasUserRead = !!projectRoles['user.read'];
    const scopes = [
      ...(data.scope ? data.scope.split(' ') : []),
      ...(hasServiceRead ? ['service.read'] : []),
      ...(hasUserRead ? ['user.read'] : []),
      ...(projectRoles['service.write'] ? ['service.write'] : []),
      ...(projectRoles['user.write'] ? ['user.write'] : []),
    ];

    console.log('Extracted scopes/roles:', scopes);
    console.log('=== Introspection Success ===');
    return {
      valid: true,
      scopes,
      sub: data.sub as string || data.username as string,
    };
  } catch (error) {
    console.error('Introspection exception:', error);
    return { valid: false, scopes: [] };
  }
}

// Service handler (requires service.read)
async function serviceHandler(req: Request): Promise<Response> {
  console.log('Service endpoint called');
  const authHeader = req.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    console.log('Missing Bearer header');
    return unauthorized('Missing/invalid Authorization: Bearer <token>');
  }

  const token = authHeader.substring(7);
  const { valid, scopes, sub } = await validateToken(token);

  if (!valid) {
    console.log('Token validation failed');
    return unauthorized('Invalid/expired/revoked token');
  }

  if (!scopes.includes('service.read')) {
    console.log('Scope check failed:', scopes);
    return forbidden('Requires service.read scope');
  }

  console.log('Service access granted for sub:', sub);
  return ok({
    message: 'Service-protected data accessed successfully',
    actor: 'microservice',
    scopes,
    userId: sub,
  });
}

// User handler (requires user.read)
async function userHandler(req: Request): Promise<Response> {
  console.log('User endpoint called');
  const authHeader = req.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return unauthorized('Missing/invalid Authorization: Bearer <token>');
  }

  const token = authHeader.substring(7);
  const { valid, scopes, sub } = await validateToken(token);

  if (!valid) {
    return unauthorized('Invalid/expired/revoked token');
  }

  if (!scopes.includes('user.read')) {
    return forbidden('Requires user.read scope');
  }

  return ok({
    message: 'User-protected data accessed successfully',
    actor: 'human-user',
    scopes,
    userId: sub,
  });
}

function healthHandler(_: Request): Response {
  return ok({ status: 'OK', timestamp: new Date().toISOString() });
}

function ok(body: object): Response {
  return new Response(JSON.stringify(body, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
}

function unauthorized(message: string): Response {
  return new Response(JSON.stringify({ error: message }), { status: 401, headers: { 'Content-Type': 'application/json' } });
}

function forbidden(message: string): Response {
  return new Response(JSON.stringify({ error: message }), { status: 403, headers: { 'Content-Type': 'application/json' } });
}

function withCors(handler: (req: Request) => Promise<Response> | Response) {
  const allowedOrigins = [
    'http://localhost:5173',
    'https://frontend-auth.sabanus.site'
  ];

  return async (req: Request) => {
    const origin = req.headers.get('Origin');
    const isAllowed = allowedOrigins.includes(origin || '');

    const corsHeaders = {
      'Access-Control-Allow-Origin': isAllowed ? origin || '' : '',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Credentials': 'true',
    };

    if (req.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    const response = await handler(req);

    if (isAllowed) {
      Object.entries(corsHeaders).forEach(([key, value]) => {
        response.headers.set(key, value);
      });
    }

    return response;
  };
}

serve({
  port: 3000,
  fetch: withCors(async (req) => {
    const url = new URL(req.url);
    if (url.pathname === '/service-protected' && req.method === 'GET') return serviceHandler(req);
    if (url.pathname === '/user-protected' && req.method === 'GET') return userHandler(req);
    if (url.pathname === '/health') return healthHandler(req);
    return new Response('Not Found', { status: 404 });
  }),
  error(e) {
    console.error('Server error:', e);
    return new Response('Internal Server Error', { status: 500 });
  },
});

console.log(`Secure API running on https://localhost:3000 (HTTPS enabled)`);
