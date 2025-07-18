/**
 * A secure and tested json-web-token class-based utility library for generating keys, signing,
 * verifying, and decoding JWT payloads for use with your high-security projects.
 *
 * @module @bepalo/jwt
 * @exports JWT class
 * @exports JwtKey type
 * @exports JwtVerifyOptions type
 * @exports JwtHeader type
 * @exports JwtPayload type
 * @exports JwtResult type
 * @exports JwtErrorCode enum
 * @exports JwtError class
 * @exports validJwtSymmetricAlgorithms
 * @exports validJwtAsymmetricAlgorithms
 * @exports validJwtAlgorithms
 * @exports JwtSymmetricAlgorithm type
 * @exports JwtAsymmetricAlgorithm type
 * @exports JwtAlgorithm type
 * @exports SURecord type
 */
import {
  constants,
  createHmac,
  createSign,
  createVerify,
  generateKeyPairSync,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} from "node:crypto";
import { RelativeTime, Time } from "@bepalo/time";
import { Buffer } from "node:buffer";

export type SURecord = Record<string, unknown>;

/**
 * Smart Error codes for use with this JWT library
 */
export enum JwtErrorCode {
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
}

/**
 * Error class for use with this JWT library
 */
export class JwtError extends Error {
  constructor(message: string, public code: JwtErrorCode = JwtErrorCode.internalError) {
    super(message);
  }
}

// Supported symmetric algorithms
export type JwtSymmetricAlgorithm = "HS256" | "HS384" | "HS512";

// Supported asymmetric algorithms
export type JwtAsymmetricAlgorithm =
  | "RS256"
  | "RS384"
  | "RS512"
  | "ES256"
  | "ES384"
  | "ES512"
  | "PS256"
  | "PS384"
  | "PS512";

/**
 * JWT-supported symmetric and asymmetric algorithms.
 *
 * - **HMAC-Based (Symmetric, Fast)**: Used for shared-key authentication.
 *   - HS256: Most common and secure.
 *   - HS384: Slightly stronger but less common.
 *   - HS512: High-security option for robust applications.
 *
 * - **ECDSA-Based (Asymmetric, Efficient)**: Faster than RSA, great for modern applications.
 *   - ES256: Recommended alternative to RSA.
 *   - ES384: Stronger cryptographic security.
 *   - ES512: Best for ultra-secure environments. **NOTE: May not be supported/implemented in all runtimes.**
 *
 * - **RSA-Based (Asymmetric, Public-Private Key)**: Used for OAuth, OpenID, and other key-based authentication.
 *   - RS256: Widely used.
 *   - RS384: Stronger but heavier.
 *   - RS512: Computationally expensive but highly secure.
 *
 * - **RSA-PSS (Asymmetric, Public-Private Key): RSA-PSS variants.**
 *   - PS256: RSA-PSS variant with SHA-256.
 *   - PS384: RSA-PSS variant with SHA-384.
 *   - PS512: RSA-PSS variant with SHA-512.
 */
export type JwtAlgorithm =
  | JwtSymmetricAlgorithm
  | JwtAsymmetricAlgorithm
  | "none";

/**
 * Internal mapping of algorithms to Node.js crypto identifiers.
 */
enum JwtAlgorithmEnum {
  HS256 = "sha256",
  HS384 = "sha384",
  HS512 = "sha512",
  RS256 = "RSA-SHA256",
  RS384 = "RSA-SHA384",
  RS512 = "RSA-SHA512",
  PS256 = "RSA-PSS-SHA256",
  PS384 = "RSA-PSS-SHA384",
  PS512 = "RSA-PSS-SHA512",
  ES256 = "sha256",
  ES384 = "sha384",
  ES512 = "sha512",
  none = "none",
}

/**
 * Internal mapping of algorithms to Node.js crypto hash algorithms.
 */
enum JwtAlgorithmHashEnum {
  HS256 = "sha256",
  HS384 = "sha384",
  HS512 = "sha512",
  RS256 = "sha256",
  RS384 = "sha384",
  RS512 = "sha512",
  PS256 = "sha256",
  PS384 = "sha384",
  PS512 = "sha512",
  ES256 = "sha256",
  ES384 = "sha384",
  ES512 = "sha512",
  none = "none",
}

/**
 * Internal mapping of algorithms to modulus length.
 */
enum JwtAlgorithmModulusLenEnum {
  RS256 = 2048,
  RS384 = 3072,
  RS512 = 4096,
  PS256 = 2048,
  PS384 = 3072,
  PS512 = 4096,
}

/**
 * Valid symmetric jwt algorithm sets for quick lookup
 */
export const validJwtSymmetricAlgorithms: Set<JwtSymmetricAlgorithm> = Object.freeze(
  new Set<JwtSymmetricAlgorithm>(["HS256", "HS384", "HS512"]),
);

/**
 * Valid asymmetric jwt algorithm set for quick lookup
 */
export const validJwtAsymmetricAlgorithms: Set<JwtAsymmetricAlgorithm> = Object.freeze(
  new Set<JwtAsymmetricAlgorithm>([
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
  ]),
);

/**
 * Valid jwt algorithm set for quick lookup
 */
export const validJwtAlgorithms: Set<JwtAlgorithm> = Object.freeze(
  new Set<JwtAlgorithm>([
    "HS256",
    "HS384",
    "HS512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "none",
  ]),
);

/**
 * JWT header standard fields.
 */
export type JwtHeader = {
  alg: JwtAlgorithm;
  typ?: string | "JWT";
  cty?: string;
  crit?: Array<string | Exclude<keyof JwtHeader, "crit">>;
  kid?: string;
  jku?: string;
  x5u?: string | string[];
  "x5t#S256"?: string;
  x5t?: string;
  x5c?: string | string[];
};

/**
 * JWT payload including standard claims and any custom fields.
 */
export type JwtPayload<CustomData extends SURecord> = {
  [key: string]: unknown;
  iss?: string;
  sub?: string;
  aud?: string | string[];
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
} & CustomData;

/**
 * JWT verify result type with `valid`, `payload` and `error` properties.
 */
export type JwtResult<Payload extends SURecord> = {
  valid: boolean;
  payload?: JwtPayload<Payload>;
  error?: JwtError;
};

/**
 * JWT Key type with `alg`, `publicKey`, `privateKey` properties.
 */
export type JwtKey = {
  alg: JwtAlgorithm;
  publicKey?: string;
  privateKey?: string;
};

/**
 * Optional parameters for verifying a JWT.
 */
export type JwtVerifyOptions = {
  /**
   * Decoded algorithm must match the stored algorithm. **(default: true)**
   */
  strict?: boolean;
  /**
   * Expected issuer
   */
  iss?: string;
  /**
   * Expected audience/s
   */
  aud?: string | string[];
  /**
   * Expected subject
   */
  sub?: string;
  /**
   * Expected token id
   */
  jti?: string;
  /**
   * Enable/disable expiration time check **(default: true)**
   */
  exp?: boolean;
  /**
   * Enable/disable not-before time check **(default: true)**
   */
  nbf?: boolean;
  /**
   * Leeway in seconds for expiration time
   */
  expLeeway?: number;
  /**
   * Leeway in seconds for not-before time
   */
  nbfLeeway?: number;
};

const encUtf8 = "utf-8" as const;
const encBase64url = "base64url" as const;

/**
 * JWT class providing utility function and methods to generate keys, and sign, verify and decode tokens.
 */
export class JWT<Payload extends SURecord> {
  #alg: JwtAlgorithm;
  #algorithm: JwtAlgorithmEnum;
  #privateKey?: string;
  #publicKey?: string;
  #isAsymmetric: boolean = false;

  get alg(): JwtAlgorithm {
    return this.#alg;
  }

  get isAsymmetric(): boolean {
    return this.#isAsymmetric;
  }

  /**
   * Get the current time in seconds.
   */
  static now(): number {
    return Math.floor(Date.now() / 1000);
  }

  /**
   * Get the given date-time in seconds.
   */
  static on(date: Date | string | number): number {
    return Math.floor(new Date(date).getTime() / 1000);
  }

  /**
   * Define absolute time in seconds. eg. `JWT.for(1).Day`
   */
  static for(time: number): Time {
    return new Time(time);
  }

  /**
   * Define the future time in seconds. eg. `JWT.in(10).Hours`
   */
  static in(time: number): RelativeTime {
    return new RelativeTime(time, JWT.now());
  }

  /**
   * Define the future time in seconds. eg. `JWT.after(5).Minutes`
   */
  static after(time: number): RelativeTime {
    return new RelativeTime(time, JWT.now());
  }

  /**
   * Define the past time in seconds. eg. `JWT.before(1).Week`
   */
  static before(time: number): RelativeTime {
    return new RelativeTime(-time, JWT.now());
  }

  /**
   * Generate a random HMAC key for HS256 (32 bytes), HS384 (48 bytes), or HS512 (64 bytes) encoded in base64url format.
   *
   * @throws {JwtError} If the algorithm is invalid.
   */
  static genHmac(alg: JwtSymmetricAlgorithm): string {
    switch (alg) {
      case "HS256":
        return randomBytes(32).toString(encBase64url);
      case "HS384":
        return randomBytes(48).toString(encBase64url);
      case "HS512":
        return randomBytes(64).toString(encBase64url);
      default: {
        throw new JwtError("invalid algorithm", JwtErrorCode.algorithmInvalid);
      }
    }
  }

  /**
   * Generate a generic jwt key based on algorithm and optional parameters.
   *
   * HMAC: HS256 (32 bytes), HS384 (48 bytes), or HS512 (64 bytes) encoded in base64url format.
   *
   * Default options: modulusLength of RS256|PS256 (2048), RS384|PS384 (3072), RS512|PS512 (4096).
   *
   * @returns JwtKey { alg, publicKey, privateKey }
   * @throws {JwtError} If the algorithm is invalid.
   */
  static genKey(
    alg: JwtAlgorithm,
    options?: {
      /**
       * Used only for RSA and RSA-PSS
       */
      modulusLength?: number;
    },
  ): JwtKey {
    try {
      switch (alg) {
        case "HS256": {
          const key = randomBytes(32).toString(encBase64url);
          return { alg, privateKey: key, publicKey: key } as JwtKey;
        }
        case "HS384": {
          const key = randomBytes(48).toString(encBase64url);
          return { alg, privateKey: key, publicKey: key } as JwtKey;
        }
        case "HS512": {
          const key = randomBytes(64).toString(encBase64url);
          return { alg, privateKey: key, publicKey: key } as JwtKey;
        }
        case "ES256": {
          const { publicKey, privateKey } = generateKeyPairSync("ec", {
            namedCurve: "P-256",
            publicKeyEncoding: {
              type: "spki",
              format: "pem",
            },
            privateKeyEncoding: {
              type: "pkcs8",
              format: "pem",
            },
          });
          return { alg, publicKey, privateKey } as JwtKey;
        }
        case "ES384": {
          const { publicKey, privateKey } = generateKeyPairSync("ec", {
            namedCurve: "P-384",
            publicKeyEncoding: {
              type: "spki",
              format: "pem",
            },
            privateKeyEncoding: {
              type: "pkcs8",
              format: "pem",
            },
          });
          return { alg, publicKey, privateKey } as JwtKey;
        }
        case "ES512": {
          const { publicKey, privateKey } = generateKeyPairSync("ec", {
            namedCurve: "P-521",
            publicKeyEncoding: {
              type: "spki",
              format: "pem",
            },
            privateKeyEncoding: {
              type: "pkcs8",
              format: "pem",
            },
          });
          return { alg, publicKey, privateKey } as JwtKey;
        }
        case "RS256":
        case "RS384":
        case "RS512":
        case "PS256":
        case "PS384":
        case "PS512": {
          const { publicKey, privateKey } = generateKeyPairSync("rsa", {
            modulusLength: options?.modulusLength ?? JwtAlgorithmModulusLenEnum[alg],
            publicKeyEncoding: {
              type: "spki",
              format: "pem",
            },
            privateKeyEncoding: {
              type: "pkcs8",
              format: "pem",
            },
          });
          return { alg, publicKey, privateKey } as JwtKey;
        }
        case "none": {
          return { alg, publicKey: "", privateKey: "" } as JwtKey;
        }
        default: {
          throw new JwtError("invalid algorithm", JwtErrorCode.algorithmInvalid);
        }
      }
    } catch (error) {
      throw new JwtError(
        error instanceof Error ? error.message : "internal error",
        JwtErrorCode.internalError,
      );
    }
  }

  /**
   * Create a JWT instance using a symmetric algorithm.
   *
   * @throws {JwtError} If the secret is null/empty or the algorithm is invalid.
   */
  static createSymmetric<Payload extends SURecord>(
    secret: string | undefined,
    alg: JwtSymmetricAlgorithm,
  ): JWT<Payload> {
    if (!secret) {
      throw new JwtError("null or empty symmetric secret", JwtErrorCode.keyInvalid);
    }
    if (!validJwtSymmetricAlgorithms.has(alg)) {
      throw new JwtError("invalid symmetric JWT algorithm", JwtErrorCode.algorithmInvalid);
    }
    const key = { alg, privateKey: secret, publicKey: secret };
    return new JWT<Payload>(key, false);
  }

  /**
   * Create a JWT instance using an asymmetric algorithm.
   *
   * @throws {JwtError} If the algorithm is invalid.
   */
  static createAsymmetric<Payload extends SURecord>(
    key: JwtKey,
  ): JWT<Payload> {
    if (!validJwtAsymmetricAlgorithms.has(key.alg as JwtAsymmetricAlgorithm)) {
      throw new JwtError("invalid asymmetric JWT algorithm", JwtErrorCode.algorithmInvalid);
    }
    return new JWT<Payload>(key, true);
  }

  /**
   * Create a JWT instance using a symmetric or asymmetric algorithm.
   *
   * @throws {JwtError} If the algorithm is invalid.
   */
  static create<Payload extends SURecord>(
    key: JwtKey,
  ): JWT<Payload> {
    if (!validJwtAlgorithms.has(key.alg)) {
      throw new JwtError("invalid JWT algorithm", JwtErrorCode.algorithmInvalid);
    }
    const isAsymmetric = validJwtAsymmetricAlgorithms.has(key.alg as JwtAsymmetricAlgorithm);
    return new JWT<Payload>(key, isAsymmetric);
  }

  static #timingSafeEqual(a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView) {
    if (a.byteLength !== b.byteLength) {
      return false;
    }
    return timingSafeEqual(a, b);
  }

  private constructor(
    key: JwtKey,
    isAsymmetric: boolean,
  ) {
    if (key.alg !== "none" && !(key.privateKey || key.publicKey)) {
      throw new JwtError(
        "null or empty JWT private and public key. either are required",
        JwtErrorCode.keyInvalid,
      );
    }

    this.#alg = key.alg;
    this.#algorithm = JwtAlgorithmEnum[key.alg];
    this.#privateKey = key.privateKey;
    this.#publicKey = key.publicKey;
    this.#isAsymmetric = isAsymmetric;
  }

  #signData(
    alg: JwtAlgorithm,
    algorithm: JwtAlgorithmEnum,
    dataToSign: string,
  ): string {
    switch (alg) {
      case "HS256":
      case "HS384":
      case "HS512":
        if (!this.#privateKey) {
          throw new JwtError("null or empty JWT private key", JwtErrorCode.privateKeyInvalid);
        }
        return createHmac(algorithm, this.#privateKey, { encoding: encBase64url })
          .update(dataToSign)
          .digest(encBase64url);
      case "ES256":
      case "ES384":
      case "ES512":
      case "RS256":
      case "RS384":
      case "RS512":
        if (!this.#privateKey) {
          throw new JwtError("null or empty JWT private key", JwtErrorCode.privateKeyInvalid);
        }
        return createSign(algorithm)
          .update(dataToSign)
          .sign(this.#privateKey, encBase64url);
      case "PS256":
      case "PS384":
      case "PS512":
        if (!this.#privateKey) {
          throw new JwtError("null or empty JWT private key", JwtErrorCode.privateKeyInvalid);
        }
        return sign(JwtAlgorithmHashEnum[alg], Buffer.from(dataToSign, encUtf8), {
          key: this.#privateKey,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        }).toString(encBase64url);
      // case "none":
      default:
        return "";
    }
  }

  #verifySignature(
    alg: JwtAlgorithm,
    algorithm: JwtAlgorithmEnum,
    dataToVerify: string,
    signature: string,
  ): boolean {
    switch (alg) {
      case "HS256":
      case "HS384":
      case "HS512":
        if (!this.#publicKey) {
          throw new JwtError("null or empty JWT public key", JwtErrorCode.publicKeyInvalid);
        }
        return JWT.#timingSafeEqual(
          createHmac(algorithm, this.#publicKey, { encoding: encBase64url })
            .update(dataToVerify).digest(),
          Buffer.from(signature, encBase64url),
        );
      case "ES256":
      case "ES384":
      case "ES512":
      case "RS256":
      case "RS384":
      case "RS512":
        if (!this.#publicKey) {
          throw new JwtError("null or empty JWT public key", JwtErrorCode.publicKeyInvalid);
        }
        return createVerify(algorithm)
          .update(dataToVerify)
          .verify(this.#publicKey, signature, encBase64url);
      case "PS256":
      case "PS384":
      case "PS512":
        if (!this.#publicKey) {
          throw new JwtError("null or empty JWT public key", JwtErrorCode.publicKeyInvalid);
        }
        return verify(
          JwtAlgorithmHashEnum[alg],
          Buffer.from(dataToVerify, encUtf8),
          {
            key: this.#publicKey,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
          },
          Buffer.from(signature, encBase64url),
        );
      case "none":
        return signature === "";
      default:
        throw new JwtError("invalid algorithm", JwtErrorCode.algorithmInvalid);
    }
  }

  /**
   * Validates that the token's `aud` (audience) claim matches the expected audience.
   * Supports strings or arrays for both expected and actual values.
   */
  #validateAudience(
    expectedAudience: string | string[],
    audience: string | string[] | undefined,
  ): boolean {
    if (!audience) return false;
    if (Array.isArray(audience)) {
      if (Array.isArray(expectedAudience)) {
        return audience.some((actual) => expectedAudience.includes(actual));
      }
      return audience.includes(expectedAudience);
    }
    if (Array.isArray(expectedAudience)) {
      return expectedAudience.includes(audience);
    }
    return audience === expectedAudience;
  }

  #validateClaims(
    payload: JwtPayload<Payload> & { exp: number; nbf: number },
    verifyJwt: JwtVerifyOptions,
    now: number = JWT.now(),
  ): JwtResult<Payload> {
    if (verifyJwt.jti != null && payload.jti !== verifyJwt.jti) {
      return {
        valid: false,
        error: new JwtError("jti (jwt id) mismatch", JwtErrorCode.jtiMismatch),
      };
    }

    if (verifyJwt.iss != null && payload.iss !== verifyJwt.iss) {
      return {
        valid: false,
        error: new JwtError("iss (issuer) mismatch", JwtErrorCode.issMismatch),
      };
    }

    if (verifyJwt.sub != null && payload.sub !== verifyJwt.sub) {
      return {
        valid: false,
        error: new JwtError("sub (subject) mismatch", JwtErrorCode.subMismatch),
      };
    }

    if (verifyJwt.aud != null && !this.#validateAudience(verifyJwt.aud, payload.aud)) {
      return {
        valid: false,
        error: new JwtError("aud (audience) mismatch", JwtErrorCode.audMismatch),
      };
    }

    if (verifyJwt.exp != null && now > payload.exp + (verifyJwt.expLeeway ?? 0)) {
      return { valid: false, error: new JwtError("token expired", JwtErrorCode.expired) };
    }

    if (verifyJwt.nbf != null && payload.nbf - (verifyJwt.nbfLeeway ?? 0) > now) {
      return {
        valid: false,
        error: new JwtError("token not yet valid (nbf)", JwtErrorCode.notValidYet),
      };
    }

    return { valid: true, payload };
  }

  #safelyParseJson<ObjType extends SURecord>(
    jsonStr: string,
  ): ObjType | undefined {
    try {
      const result = JSON.parse(jsonStr);
      return result;
    } catch (_err) {
      return undefined;
    }
  }

  /**
   * Synchronously sign a payload and return a JWT token string.
   *
   * @throws {JwtError} If signing fails due to an invalid algorithm or key.
   */
  signSync(payload: JwtPayload<Payload>): string {
    const alg = this.#alg;
    const algorithm = this.#algorithm;
    const header = Buffer.from(JSON.stringify({ typ: "JWT", alg }), encUtf8).toString(
      encBase64url,
    );
    const payload_ = Buffer.from(JSON.stringify(payload), encUtf8).toString(encBase64url);
    const dataToSign = `${header}.${payload_}`;
    try {
      const signature = this.#signData(alg, algorithm, dataToSign);
      return `${dataToSign}.${signature}`;
    } catch (error) {
      throw new JwtError(
        error instanceof Error ? error.message : "internal error",
        JwtErrorCode.internalError,
      );
    }
  }

  /**
   * Asynchronously sign a payload and return a JWT token string.
   *
   * @throws {JwtError} If signing fails due to an invalid token.
   */
  sign(payload: JwtPayload<Payload>): Promise<string> {
    return new Promise((resolve, reject) => {
      try {
        const token = this.signSync(payload);
        resolve(token);
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Synchronously verify only the token and the signature (no payload or claims are checked).
   *
   * @returns a JwtResult with only the valid propery set to true on success.
   * @throws {JwtError} If the token is malformed or the signature is invalid.
   */
  verifySignatureSync(
    token: string,
    verifyJwt?: Pick<JwtVerifyOptions, "strict">,
  ): JwtResult<Payload> {
    verifyJwt = { strict: true, ...verifyJwt };
    const [header, body, signature] = token.split(".", 3);
    if (!(header && body)) {
      return { valid: false, error: new JwtError("invalid token", JwtErrorCode.tokenInvalid) };
    }

    const jwtHeader = this.#safelyParseJson<JwtHeader>(
      Buffer.from(header, encBase64url).toString(encUtf8),
    );
    if (!jwtHeader) {
      return {
        valid: false,
        error: new JwtError("invalid token header", JwtErrorCode.tokenHeaderInvalid),
      };
    }
    const { typ, alg } = jwtHeader;
    if (typ !== "JWT") {
      return {
        valid: false,
        error: new JwtError("invalid token type", JwtErrorCode.tokenTypeInvalid),
      };
    }
    if (verifyJwt.strict && this.#alg !== alg) {
      return {
        valid: false,
        error: new JwtError("algorithm mismatch", JwtErrorCode.algorithmMismatch),
      };
    }
    if (!alg || !validJwtAlgorithms.has(alg)) {
      return {
        valid: false,
        error: new JwtError("invalid algorithm", JwtErrorCode.algorithmInvalid),
      };
    }
    if (!signature && alg !== "none") {
      return {
        valid: false,
        error: new JwtError("invalid signature", JwtErrorCode.signatureInvalid),
      };
    }

    const algorithm = JwtAlgorithmEnum[alg as JwtAlgorithm];
    const dataToVerify = `${header}.${body}`;
    try {
      const signaturesMatch = this.#verifySignature(
        alg,
        algorithm,
        dataToVerify,
        signature,
      );
      if (!signaturesMatch) {
        return {
          valid: false,
          error: new JwtError("signature mismatch", JwtErrorCode.signatureMismatch),
        };
      }
    } catch (error) {
      return {
        valid: false,
        error: new JwtError(
          error instanceof Error ? error.message : "internal error",
          JwtErrorCode.internalError,
        ),
      };
    }
    return { valid: true };
  }

  /**
   * Asynchronously verify only the signature of the token (no claims checked).
   *
   * @returns a Promise to a boolean set to true on success.
   * @throws {JwtError} If the token is malformed or the signature is invalid.
   */
  verifySignature(
    token: string,
    verifyJwt?: Pick<JwtVerifyOptions, "strict">,
  ): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const { valid, error } = this.verifySignatureSync(token, verifyJwt);
      if (!valid) {
        return reject(error);
      }
      resolve(valid);
    });
  }

  /**
   * Synchronously verify a token, signature, payload and claims.
   *
   * @returns a JwtResult with a valid payload and the valid propery set to true on success.
   * @throws {JwtError} If the token, payload, signature, or claims are invalid.
   */
  verifySync(token: string, verifyJwt?: JwtVerifyOptions): JwtResult<Payload> {
    verifyJwt = { strict: true, exp: true, nbf: true, ...verifyJwt };
    const [header, body, signature] = token.split(".", 3);
    if (!(header && body)) {
      return { valid: false, error: new JwtError("invalid token", JwtErrorCode.tokenInvalid) };
    }
    const jwtHeader = this.#safelyParseJson<JwtHeader>(
      Buffer.from(header, encBase64url).toString(encUtf8),
    );
    if (!jwtHeader) {
      return {
        valid: false,
        error: new JwtError("invalid token header", JwtErrorCode.tokenHeaderInvalid),
      };
    }
    const { typ, alg } = jwtHeader;
    if (typ !== "JWT") {
      return {
        valid: false,
        error: new JwtError("invalid token type", JwtErrorCode.tokenTypeInvalid),
      };
    }
    if (verifyJwt.strict && this.#alg !== alg) {
      return {
        valid: false,
        error: new JwtError("algorithm mismatch", JwtErrorCode.algorithmMismatch),
      };
    }
    if (!alg || !validJwtAlgorithms.has(alg)) {
      return {
        valid: false,
        error: new JwtError("invalid algorithm", JwtErrorCode.algorithmInvalid),
      };
    }
    if (!signature && alg !== "none") {
      return {
        valid: false,
        error: new JwtError("invalid signature", JwtErrorCode.signatureInvalid),
      };
    }

    const algorithm = JwtAlgorithmEnum[alg as JwtAlgorithm];
    const dataToVerify = `${header}.${body}`;
    try {
      const signaturesMatch = this.#verifySignature(
        alg,
        algorithm,
        dataToVerify,
        signature,
      );
      if (!signaturesMatch) {
        return {
          valid: false,
          error: new JwtError("signature mismatch", JwtErrorCode.signatureMismatch),
        };
      }
      const jwtPayload = this.#safelyParseJson<
        JwtPayload<Payload & { exp: boolean; nbf: boolean }>
      >(Buffer.from(body, encBase64url).toString(encUtf8));
      if (!jwtPayload) {
        return {
          valid: false,
          error: new JwtError("invalid payload", JwtErrorCode.payloadInvalid),
        };
      }
      return this.#validateClaims(jwtPayload, verifyJwt);
    } catch (error) {
      return {
        valid: false,
        error: new JwtError(
          error instanceof Error ? error.message : "internal error",
          JwtErrorCode.internalError,
        ),
      };
    }
  }

  /**
   * Asynchronously verify a token, signature, payload and claims.
   *
   * @returns a Promise to a valid payload on success.
   * @throws {JwtError} If the token, payload, signature, or claims are invalid.
   */
  verify(token: string, verifyJwt?: JwtVerifyOptions): Promise<JwtPayload<Payload>> {
    return new Promise((resolve, reject) => {
      const { valid, payload, error } = this.verifySync(token, verifyJwt);
      if (!(valid && payload)) {
        return reject(error);
      }
      resolve(payload);
    });
  }
}
