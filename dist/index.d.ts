import { RelativeTime, Time } from "@bepalo/time";
export type SURecord = Record<string, unknown>;
/**
 * Smart Error codes for use with this JWT library
 */
export declare enum JwtErrorCode {
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
    publicKeyInvalid = 302
}
/**
 * Error class for use with this JWT library
 */
export declare class JwtError extends Error {
    code: JwtErrorCode;
    constructor(message: string, code?: JwtErrorCode);
}
export type JwtSymmetricAlgorithm = "HS256" | "HS384" | "HS512";
export type JwtAsymmetricAlgorithm = "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "ES512" | "PS256" | "PS384" | "PS512";
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
 *
 */
export type JwtAlgorithm = JwtSymmetricAlgorithm | JwtAsymmetricAlgorithm | "none";
/**
 * Valid symmetric jwt algorithm sets for quick lookup
 */
export declare const validJwtSymmetricAlgorithms: Set<JwtSymmetricAlgorithm>;
/**
 * Valid asymmetric jwt algorithm set for quick lookup
 */
export declare const validJwtAsymmetricAlgorithms: Set<JwtAsymmetricAlgorithm>;
/**
 * Valid jwt algorithm set for quick lookup
 */
export declare const validJwtAlgorithms: Set<JwtAlgorithm>;
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
/**
 * JWT class providing utility function and methods to generate keys, and sign, verify and decode tokens.
 */
export declare class JWT<Payload extends SURecord> {
    #private;
    get alg(): JwtAlgorithm;
    get isAsymmetric(): boolean;
    /**
     * Get the current time in seconds.
     */
    static now(): number;
    /**
     * Get the given date-time in seconds.
     */
    static on(date: Date | string | number): number;
    /**
     * Define absolute time in seconds. eg. `JWT.for(1).Day`
     */
    static for(time: number): Time;
    /**
     * Define the future time in seconds. eg. `JWT.in(10).Hours`
     */
    static in(time: number): RelativeTime;
    /**
     * Define the future time in seconds. eg. `JWT.after(5).Minutes`
     */
    static after(time: number): RelativeTime;
    /**
     * Define the past time in seconds. eg. `JWT.before(1).Week`
     */
    static before(time: number): RelativeTime;
    /**
     * Generate a random HMAC key for HS256 (32 bytes), HS384 (48 bytes), or HS512 (64 bytes) encoded in base64url format.
     *
     * @throws {JwtError} If the algorithm is invalid.
     */
    static genHmac(alg: JwtSymmetricAlgorithm): string;
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
    static genKey(alg: JwtAlgorithm, options?: {
        /**
         * Used only for RSA and RSA-PSS
         */
        modulusLength?: number;
    }): JwtKey;
    /**
     * Create a JWT instance using a symmetric algorithm.
     *
     * @throws {JwtError} If the secret is null/empty or the algorithm is invalid.
     */
    static createSymmetric<Payload extends SURecord>(secret: string | undefined, alg: JwtSymmetricAlgorithm): JWT<Payload>;
    /**
     * Create a JWT instance using an asymmetric algorithm.
     *
     * @throws {JwtError} If the algorithm is invalid.
     */
    static createAsymmetric<Payload extends SURecord>(key: JwtKey): JWT<Payload>;
    /**
     * Create a JWT instance using a symmetric or asymmetric algorithm.
     *
     * @throws {JwtError} If the algorithm is invalid.
     */
    static create<Payload extends SURecord>(key: JwtKey): JWT<Payload>;
    private constructor();
    /**
     * Synchronously sign a payload and return a JWT token string.
     *
     * @throws {JwtError} If signing fails due to an invalid algorithm or key.
     */
    signSync(payload: JwtPayload<Payload>): string;
    /**
     * Asynchronously sign a payload and return a JWT token string.
     *
     * @throws {JwtError} If signing fails due to an invalid token.
     */
    sign(payload: JwtPayload<Payload>): Promise<string>;
    /**
     * Synchronously verify only the token and the signature (no payload or claims are checked).
     *
     * @returns a JwtResult with only the valid propery set to true on success.
     * @throws {JwtError} If the token is malformed or the signature is invalid.
     */
    verifySignatureSync(token: string, verifyJwt?: Pick<JwtVerifyOptions, "strict">): JwtResult<Payload>;
    /**
     * Asynchronously verify only the signature of the token (no claims checked).
     *
     * @returns a Promise to a boolean set to true on success.
     * @throws {JwtError} If the token is malformed or the signature is invalid.
     */
    verifySignature(token: string, verifyJwt?: Pick<JwtVerifyOptions, "strict">): Promise<boolean>;
    /**
     * Synchronously verify a token, signature, payload and claims.
     *
     * @returns a JwtResult with a valid payload and the valid propery set to true on success.
     * @throws {JwtError} If the token, payload, signature, or claims are invalid.
     */
    verifySync(token: string, verifyJwt?: JwtVerifyOptions): JwtResult<Payload>;
    /**
     * Asynchronously verify a token, signature, payload and claims.
     *
     * @returns a Promise to a valid payload on success.
     * @throws {JwtError} If the token, payload, signature, or claims are invalid.
     */
    verify(token: string, verifyJwt?: JwtVerifyOptions): Promise<JwtPayload<Payload>>;
}
