# 🏆 @bepalo/jwt

[![npm version](https://img.shields.io/npm/v/@bepalo/jwt.svg)](https://www.npmjs.com/package/@bepalo/jwt)
[![jsr](https://img.shields.io/badge/jsr-%40bepalo%2Fjwt-blue?logo=deno&label=jsr)](https://jsr.io/@bepalo/jwt)
[![github](https://img.shields.io/badge/github-bepalo%2Fjwt-181717?logo=github)](https://github.com/bepalo/jwt)
[![GitHub Repo stars](https://img.shields.io/github/stars/bepalo/jwt?style=social)](https://github.com/bepalo/jwt)

[![license](https://img.shields.io/npm/l/@bepalo/jwt.svg)](LICENSE)
![Node.js](https://img.shields.io/badge/Node.js-%5E18%E2%9C%94-brightgreen?logo=nodedotjs&logoColor=white)
![Bun](https://img.shields.io/badge/Bun-%E2%9C%94-green?logo=bun&logoColor=white)
![Deno](https://img.shields.io/badge/Deno-%E2%9C%94-black?logo=deno&logoColor=white)
[![CI](https://img.shields.io/github/actions/workflow/status/bepalo/jwt/ci.yaml?label=CI)](https://github.com/bepalo/jwt/actions/workflows/ci.yaml)
[![Tests](https://img.shields.io/github/actions/workflow/status/bepalo/jwt/testing.yaml?label=tests)](https://github.com/bepalo/jwt/actions/workflows/testing.yaml)
[![Vitest](https://img.shields.io/badge/vitest-6E9F18?style=for-the-badge&logo=vitest&logoColor=white)](test-result.md)

A secure and tested json-web-token class-based utility library for generating keys, signing, verifying, and decoding JWT payloads for use with your high-security demanding projects.

## Table of Contents

- [✨ Features](#-features)
- [📥 Installation](#-installation)
- [🚀 Quick Start](#-quick-start)
- [✅ Usage](#-usage)
  - [🔑 Key Creation](#-key-creation)
  - [🏗️ JWT Instance Creation](#️-jwt-instance-creation)
  - [✍️ Signing](#️-signing)
  - [🔎 Verification](#-verification)
  - [⚙️ Verify Options](#️-verify-options)
- [📚 Quick Docs](#-quick-docs)
- [🛡️ Supported Algorithms](#️-supported-algorithms)
- [🔗 Links](#-links)
- [🕊️ Thanks, Stay Safe and Enjoy](#️-thanks-stay-safe-and-enjoy)

## ✨ Features

- 🎯 JWT sign and verify with HMAC, ECDSA, RSA, RSA-PSS algorithms.
- 🗝️ Easy key generation support.
- ♻️ Synchronous by default, with asynchronous alternatives.
- ⌚ Time helper functions from [@bepalo/time](#bepalotime).
- 📄 Written in modern TypeScript.
- 📢 Available for both ESM and CommonJS.
- 📢 Works with Node, Bun, and Deno.
- 📢 Built on the crypto API.

## 🚀 Get Started

### 📥 Installation

**Node.js / Bun (npm / pnpm / yarn)**

```sh
bun add @bepalo/jwt
# or
pnpm add @bepalo/jwt
# or
npm install @bepalo/jwt
# or
yarn add @bepalo/jwt
```

**Deno**

```ts
Import directly using the URL:

import { JWT } from "npm:@bepalo/jwt";
// or
import { JWT } from "jsr:@bepalo/jwt";
```

## 🚀 Quick Start

**Simple Symmetric HMAC:**

```ts
import { JWT } from "@bepalo/jwt";

// 1. Generate a key
const secret = JWT.genHmac("HS256");

// 2. Store the generated key somewhere safe like in a .env file
console.log(secret);

// 3. Load that key from where it was stored
const signKey = process.env.SECRET;
const verifyKey = process.env.SECRET;

// 4. Create a JWT instance for signing
const jwtSign = JWT.createSymmetric(signKey, "HS256");

// 5. Sign a payload
const token = jwtSign.signSync({ 
  userId: 123, 
  role: "admin", 
  jti: "tid-1234",
  iat: JWT.now(), 
  // exp: JWT.on("2026"),
  // nbf: JWT.after(5).Minutes,
  // ...
});

// 6. Create another JWT instance for verifying. *optional*
const jwtVerify = JWT.createSymmetric(verifyKey, "HS256");

// 7. Verify and decode the token
const { valid, payload, error } = jwtVerify.verifySync(token, {
  jti: "tid-1234",
  nbfLeeway: JWT.for(5).Seconds
});

// 8. Deal with errors or use the payload
console.log(valid);    // true
console.log(payload);  // { userId: 123, role: "admin", ... }
console.log(error);    // undefined
```

**Generic:**

```ts
import { JWT } from "@bepalo/jwt";

// 1. Generate a key
const key = JWT.genKey("ES256");

// 2. Store the generated key somewhere safe like in a .env file
const { alg, publicKey, privateKey } = key;
console.log(JSON.stringify({ alg, publicKey }));
console.log(JSON.stringify({ alg, privateKey }));

// 3. Load that key from where it was stored
const signKey = JSON.parse(process.env.PRIVATE_KEY ?? "null");
const verifyKey = JSON.parse(process.env.PUBLIC_KEY ?? "null");

// 4. Create a JWT instance for signing
const jwtSign = JWT.create(signKey);

// 5. Sign a payload
const token = jwtSign.signSync({ 
  userId: 123, 
  role: "admin", 
  jti: "tid-1234",
  iat: JWT.now(), 
  // exp: JWT.on("2026"),
  // nbf: JWT.after(5).Minutes,
  // ...
});

// 6. Create a JWT instance for verifying
const jwtVerify = JWT.create(verifyKey);

// 7. Verify and decode the token
const { valid, payload, error } = jwtVerify.verifySync(token, {
  jti: "tid-1234",
  nbfLeeway: JWT.for(5).Seconds
});

// 8. Deal with errors or use the payload
console.log(valid);    // true
console.log(payload);  // { userId: 123, role: "admin", ... }
console.log(error);    // undefined

```


## ✅ Usage

### 🔑 Key Creation

```ts
import { JWT } from "@bepalo/jwt";

// 📢 Symmetric HMAC key generation. returns string
const secret = JWT.genHmac("HS256");

// 📢 Generic way of generating any key. returns JwtKey
const key = JWT.genKey("none");
const key = JWT.genKey("HS512"); 
const key = JWT.genKey("ES384"); 
const key = JWT.genKey("RS256"); 
const key = JWT.genKey("PS256"); 

```

### 🏗️ JWT Instance Creation

```ts
import { JWT } from "@bepalo/jwt";

type Payload = { userId: number, role: "admin" | "user" };

const secret = JWT.genHmac("HS256");
// 📢 Symmetric only way of creating a JWT instance.
const jwt = JWT.createSymmetric<Payload>(secret, "HS256");

const key = JWT.genKey("ES256"); 
// 📢 Generic way of creating a JWT instance
const jwt = JWT.create<Payload>(key);
```

### ✍️ Signing

**Synchronous:**

```ts
import { JWT } from "@bepalo/jwt";

type Payload = { userId: number, role: "admin" | "user" };

const key = JWT.genKey("HS256"); 
const jwt = JWT.create<Payload>(key);

// 📢 Sign synchronously
const token = jwt.signSync({ userId: 123, role: "admin", iat: JWT.now() });
```

**Asynchronous:**

```ts
import { JWT } from "@bepalo/jwt";

type Payload = { userId: number, role: "admin" | "user" };

const key = JWT.genKey("HS256"); 
const jwt = JWT.create<Payload>(key);

// 📢 Sign asynchronously
const token = await jwt.sign({ userId: 123, role: "admin", iat: JWT.now() });
```

### 🔎 Verification

**Synchronous:**

```ts
import { JWT } from "@bepalo/jwt";

type Payload = { userId: number, role: "admin" | "user" };

const key = JWT.genKey("HS256"); 
const jwt = JWT.create<Payload>(key);

const token = jwt.signSync({ userId: 123, role: "admin", iat: JWT.now() });

// 📢 Verify synchronously
const { valid, payload, error } = jwt.verifySync(token);

// 📢 Verify signature synchronously
const { valid, error } = jwt.verifySignatureSync(token);
```

**Asynchronous:**

```ts
import { JWT } from "@bepalo/jwt";

type Payload = { userId: number, role: "admin" | "user" };

const key = JWT.genKey("HS256"); 
const jwt = JWT.create<Payload>(key);

const token = await jwt.sign({ userId: 123, role: "admin", iat: JWT.now() });

// 📢 Verify asynchronously
const payload = await jwt.verify(token);

// 📢 Verify signature asynchronously
const valid = await jwt.verifySignature(token);
```

### ⚙️ Verify Options

```ts
import { JWT } from "@bepalo/jwt";

type Payload = { userId: number, role: "admin" | "user" };

const key = JWT.genKey("HS256"); 
const jwt = JWT.create<Payload>(key);

const token = await jwt.sign({
  userId: 123, 
  role: "admin", 
  iat: JWT.now(),
  nbf: JWT.after(5).Minutes,
  exp: JWT.on("2026"),
  jti: "jti-1234",
  iss: "auth-server",
  sub: "session",
  aud: ["auth-client-a", "auth-client-b"],
});

const payload = await jwt.verify(token, {
  strict: false, // default: true
  iss: "auth-server",
  aud: "auth-client-a", // or ["auth-client-a", "auth-client-c"]
  sub: "session",
  jti: "jti-1234",
  exp: true, // default: true
  nbf: false, // default: true
  expLeeway: JWT.for(5).Seconds,
  nbfLeeway: JWT.for(5).Seconds,
});

const valid = await jwt.verifySignature(token, { strict: false });
```

## 📚 Quick Docs

> All errors thrown or returned by this library are instances of `JwtError` 
> with a descriptive message and a smart error code.

<details>
<summary>JWT class</summary>

```ts
// Using Time and RelativeTime for fluent time expression feature.
import type { Time, RelativeTime } from "@bepalo/time";

/**
 * JWT class providing utility function and methods to generate keys, and sign, verify and decode tokens.
 */
class JWT<Payload> {

  // Get the current time in seconds.
  static now(): number;
  
  // Get the given date-time in seconds.
  static on(date): number;

  // Fluently define absolute time in seconds. 
  // eg. `JWT.for(1).Day`
  static for(): Time;
  
  // Fluently define the relative time in seconds. 
  // eg. `JWT.in(10).Hours`
  static in(): RelativeTime;
  
  // Fluently define the relative time in seconds. 
  // eg. `JWT.after(5).Minutes`
  static after(): RelativeTime;

  // Fluently define the relative time in seconds. 
  // eg. `JWT.before(1).Week`
  static before(): RelativeTime;


  // Generate a random key for HMAC
  static genHmac(alg): string;

  // Generate a generic jwt key based on algorithm and optional parameters
  static genKey(alg, options?): Key;

  // Create a JWT instance using a symmetric algorithm.
  static createSymmetric<Payload>(secret, alg): JWT<Payload>;

  // Create a JWT instance using an asymmetric JwtKey.
  static createAsymmetric<Payload>(key): JWT<Payload>;

  // Create a JWT instance using a generic JwtKey.
  static create<Payload>(key): JWT<Payload>;


  // Synchronously sign a payload and return a JWT token string.
  signSync(payload): string

  // Asynchronously sign a payload and return a JWT token string.
  sign(payload): Promise<string>


  // Synchronously verify only the token and the signature (no payload or claims are checked).
  verifySignatureSync(token, verifyJwtStrict?): JwtResult<Payload> 

  // Asynchronously verify only the signature of the token (no claims checked).
  verifySignature(token, verifyJwtStrict?): Promise<boolean>;


  // Synchronously verify a token, signature, payload and claims.
  verifySync(token, verifyJwt?): JwtResult<Payload>;

  // Asynchronously verify a token, signature, payload and claims.
  verify(token, verifyJwt?): Promise<JwtPayload<Payload>>;

}
```

</details>

<details>
<summary>JWT Error class</summary>

```ts
/**
 * Error class for use with this JWT library
 */
class JwtError extends Error {
  code: JwtErrorCode;
}
```

</details>

<details>
<summary>JWT Result type</summary>

```ts
/**
 * JWT verify result type
 */
type JwtResult<Payload> = {
  valid: boolean;
  payload?: JwtPayload<Payload>;
  error?: JwtError;
};
```

</details>

<details>
<summary>JWT Key type</summary>

```ts
/**
 * JWT Key type
 */
type JwtKey = { 
  alg: JwtAlgorithm, 
  publicKey: string; 
  privateKey: string 
};
```

</details>

<details>
<summary>JWT Verify Options type</summary>

```ts
/**
 * Optional parameters for verifying a JWT.
 */
type JwtVerifyOptions = {
  // Decoded algorithm must match the stored algorithm. default: true
  strict?: boolean;
  // Expected issuer
  iss?: string;
  // Expected audience/s
  aud?: string | string[];
  // Expected subject
  sub?: string;
  // Expected token id
  jti?: string;
  // Enable/disable expiration time check. default: true
  exp?: boolean;
  // Enable/disable not-before time check. default: true
  nbf?: boolean;
  // Leeway in seconds for expiration time
  expLeeway?: number;
  // Leeway in seconds for not-before time
  nbfLeeway?: number;
};
```

</details>

<details>
<summary>JWT Algorithm types</summary>

```ts
// Supported symmetric algorithms
type JwtSymmetricAlgorithm = "HS256" | "HS384" | "HS512";

// Supported asymmetric algorithms
type JwtAsymmetricAlgorithm =
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES384"
  | "ES512"
  | "PS256"
  | "PS384"
  | "PS512";

// All supported JWT algorithms
type JwtAlgorithm =
  | JwtSymmetricAlgorithm
  | JwtAsymmetricAlgorithm
  | "none";
```

</details>

<details>
<summary>JWT Error codes</summary>

```ts
/**
 * Smart Error codes for use with this JWT library
 */
enum JwtErrorCode {
  internalError = 0,

  invalid = 100,

  tokenInvalid = 110,
  tokenTypeInvalid = 111,

  tokenHeaderInvalid = 120,

  algorithmInvalid = 130,
  algorithmMismatch = 131,

  signatureInvalid = 140,
  signatureMismatch = 141,

  payloadInvalid = 150,

  // for use with your custom validation errors
  claimInvalid = 200,
  claimMismatch = 201,

  jti = 210,
  jtiMismatch = 210,
  jtId = 210,
  jtIdMismatch = 210,

  iss = 220,
  issMismatch = 220,
  issuer = 220,
  issuerMismatch = 220,

  sub = 230,
  subMismatch = 230,
  subjet = 230,
  subjectMismatch = 230,

  aud = 240,
  audMismatch = 240,
  audience = 240,
  audienceMismatch = 240,

  exp = 250,
  expired = 250,

  nbf = 260,
  notValidYet = 260,
  notYetValid = 260,
  notBefore = 260,

  keyInvalid = 300,
  privateKeyInvalid = 301,
  publicKeyInvalid = 302,
};
```

</details>

### 🛡️ Supported Algorithms

> *📕* The `ES512`(`P-521`) algorithm is less common and might not be supported on the runtime of your preference.
But you can use `ES256` or `ES384`, or switch to a runtime that supports it.

<details>
<summary><b>HMAC-Based (Symmetric, Fast):</b> Used for shared-key authentication.</summary>

  - HS256: Most common and secure.
  - HS384: Slightly stronger but less common.
  - HS512: High-security option for robust applications.

</details>

<details>

<summary><b>ECDSA-Based (Asymmetric, Efficient):</b> Faster than RSA, great for modern applications.</summary>

  - ES256: Recommended alternative to RSA.
  - ES384: Stronger cryptographic security.
  - ES512: Best for ultra-secure environments. **NOTE: May not be supported/implemented in all runtimes.**

</details>

<details>

<summary><b>RSA-Based (Asymmetric):</b> Used for OAuth, OpenID, and other key-based authentication.</summary>

  - RS256: Widely used.
  - RS384: Stronger but heavier.
  - RS512: Computationally expensive but highly secure.

</details>

<details>

<summary><b>RSA-PSS (Asymmetric): RSA-PSS variants.</b></summary>

  - PS256: RSA-PSS variant with SHA-256.
  - PS384: RSA-PSS variant with SHA-384.
  - PS512: RSA-PSS variant with SHA-512.

</details>

For more details, see [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) and [IANA JWT Algorithms](https://www.iana.org/assignments/jose/jose.xhtml#web-signature-encryption-algorithms).


## 🔗 Links

### @bepalo/time

[![npm](https://img.shields.io/npm/v/@bepalo/time?&label=npm)](https://www.npmjs.com/package/@bepalo/time)
[![jsr](https://img.shields.io/badge/jsr-%40bepalo%2Ftime-blue?logo=deno&label=jsr)](https://jsr.io/@bepalo/time)
[![github](https://img.shields.io/badge/github-bepalo%2Ftime-181717?logo=github)](https://github.com/bepalo/time)
## 🕊️ Thanks, Stay Safe and Enjoy

If you like this library and want to support then please give a star on [GitHub ![GitHub Repo stars](https://img.shields.io/github/stars/bepalo/jwt?style=social)](https://github.com/bepalo/jwt)

## 💖 Be a Sponsor

Fund me so I can give more attention to the products and services you liked.

<p align="left">
  <a href="https://ko-fi.com/natieshzed" target="_blank">
    <img height="32" src="https://img.shields.io/badge/Ko--fi-donate-orange?style=for-the-badge&logo=ko-fi&logoColor=white" alt="Ko-fi Badge"> 
  </a>
  <br/> 
  <a href="https://bybit.com" target="_blank"> 
    <img height="32" src="https://img.shields.io/badge/ByBit-UID%3A%20225636163-blueviolet?style=for-the-badge&logo=bitcoin&logoColor=white" alt="ByBit UID"> 
  </a> 
  <br/>
  <a href="https://www.blockchain.com/btc/address/16wLsJMVC9znDrFQCYFhVfpHwLofx8foqS" target="_blank"> 
    <img height="32" src="https://img.shields.io/badge/BTC-16wLsJMVC9znDrFQCYFhVfpHwLofx8foqS-orange?style=for-the-badge&logo=bitcoin&logoColor=white" alt="BTC Wallet"> 
  </a> 
</p>
