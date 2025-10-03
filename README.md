# Secure Backend API with ZITADEL

This backend provides secure endpoints for both microservices and human users, relying on **ZITADEL** as the identity and authorization provider.

The API validates **Access Tokens** via ZITADEL’s [OAuth 2.0 Introspection](https://zitadel.com/docs/apis/openidoauth/introspection) endpoint, ensuring that only valid and authorized clients can access protected resources.

---

## Overview

* **Identity Provider**: [ZITADEL](https://zitadel.com)
* **Auth Flow**: Access Tokens issued by ZITADEL are validated via token introspection.
* **Endpoints**:

  * `/service-protected` → accessible to microservices with `service.read`
  * `/user-protected` → accessible to human users with `user.read`
  * `/health` → public health check

---

## Token Validation Flow

1. Client (microservice or user) calls the API with an `Authorization: Bearer <access_token>` header.
2. The backend creates a **JWT client assertion**, signed with its private key:

   ```ts
   const assertion = await new SignJWT({ iss, sub, aud, iat, exp })
     .setProtectedHeader({ alg: 'RS256', kid })
     .sign(privateKey);
   ```
3. The backend sends the access token and client assertion to ZITADEL’s introspection endpoint:

   ```
   POST /oauth/v2/introspect
   ```
4. ZITADEL responds with token validity, scopes, roles, and claims.
5. The backend enforces role/scope checks before returning data.

---

## Roles and Scopes

ZITADEL attaches custom claims for project roles. This backend extracts them into usable scopes:

| Role/Claim      | Grants Access To                |
| --------------- | ------------------------------- |
| `service.read`  | `/service-protected` endpoint   |
| `service.write` | (future: service modifications) |
| `user.read`     | `/user-protected` endpoint      |
| `user.write`    | (future: user modifications)    |

Example of extracted scopes after introspection:

```json
["openid", "profile", "service.read", "user.read"]
```

---

## Endpoints

### Health Check

```bash
GET /health
```

Always returns `200 OK` with status and timestamp.

---

### Service-Protected

```bash
GET /service-protected
Authorization: Bearer <access_token>
```

Requires scope: `service.read`
Returns JSON with protected microservice data.

---

### User-Protected

```bash
GET /user-protected
Authorization: Bearer <access_token>
```

Requires scope: `user.read`
Returns JSON with protected user data.

---

## CORS Policy

Allowed origins:

* `http://localhost:5173` (local development)
* `https://frontend-auth.sabanus.site` (production frontend)

Other origins are blocked.

---

## Interaction Model

* **Microservices**

  * Use the client credentials flow with ZITADEL.
  * Receive an access token containing `service.read`.
  * Call `/service-protected` with the token.

* **Human Users**

  * Authenticate via ZITADEL login (OIDC).
  * Receive an access token containing `user.read`.
  * Call `/user-protected` with the token.

Both flows rely on **introspection** for runtime validation.
Tokens can be revoked, expired, or restricted at any time by ZITADEL.

---

## Security Considerations

* Private key is stored in a `.json` file provided by ZITADEL.
* PKCS#1 keys are automatically converted to PKCS#8 for JOSE compatibility.
* All introspection requests are authenticated with **signed JWT assertions**.
* Only active tokens with the correct **audience** and **scopes** are accepted.

---

## Running Locally

```bash
bun install
bun run index.ts
```

The API runs at:

```
https://localhost:3000
```
