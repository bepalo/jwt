"use strict";
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var _JWT_instances, _a, _JWT_alg, _JWT_algorithm, _JWT_privateKey, _JWT_publicKey, _JWT_isAsymmetric, _JWT_timingSafeEqual, _JWT_signData, _JWT_verifySignature, _JWT_validateAudience, _JWT_validateClaims, _JWT_safelyParseJson;
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWT = exports.validJwtAlgorithms = exports.validJwtAsymmetricAlgorithms = exports.validJwtSymmetricAlgorithms = exports.JwtError = exports.JwtErrorCode = void 0;
/**
 *
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
 *
 */
const node_crypto_1 = require("node:crypto");
const time_1 = require("@bepalo/time");
/**
 * Smart Error codes for use with this JWT library
 */
var JwtErrorCode;
(function (JwtErrorCode) {
    JwtErrorCode[JwtErrorCode["internalError"] = 0] = "internalError";
    JwtErrorCode[JwtErrorCode["invalid"] = 100] = "invalid";
    JwtErrorCode[JwtErrorCode["tokenInvalid"] = 110] = "tokenInvalid";
    JwtErrorCode[JwtErrorCode["tokenTypeInvalid"] = 111] = "tokenTypeInvalid";
    JwtErrorCode[JwtErrorCode["tokenHeaderInvalid"] = 120] = "tokenHeaderInvalid";
    JwtErrorCode[JwtErrorCode["algorithmInvalid"] = 130] = "algorithmInvalid";
    JwtErrorCode[JwtErrorCode["algorithmMismatch"] = 131] = "algorithmMismatch";
    JwtErrorCode[JwtErrorCode["signatureInvalid"] = 140] = "signatureInvalid";
    JwtErrorCode[JwtErrorCode["signatureMismatch"] = 141] = "signatureMismatch";
    JwtErrorCode[JwtErrorCode["payloadInvalid"] = 150] = "payloadInvalid";
    // for use with your custom validation errors
    JwtErrorCode[JwtErrorCode["claimInvalid"] = 200] = "claimInvalid";
    JwtErrorCode[JwtErrorCode["claimMismatch"] = 201] = "claimMismatch";
    JwtErrorCode[JwtErrorCode["jti"] = 210] = "jti";
    JwtErrorCode[JwtErrorCode["jtiMismatch"] = 210] = "jtiMismatch";
    JwtErrorCode[JwtErrorCode["jtId"] = 210] = "jtId";
    JwtErrorCode[JwtErrorCode["jtIdMismatch"] = 210] = "jtIdMismatch";
    JwtErrorCode[JwtErrorCode["iss"] = 220] = "iss";
    JwtErrorCode[JwtErrorCode["issMismatch"] = 220] = "issMismatch";
    JwtErrorCode[JwtErrorCode["issuer"] = 220] = "issuer";
    JwtErrorCode[JwtErrorCode["issuerMismatch"] = 220] = "issuerMismatch";
    JwtErrorCode[JwtErrorCode["sub"] = 230] = "sub";
    JwtErrorCode[JwtErrorCode["subMismatch"] = 230] = "subMismatch";
    JwtErrorCode[JwtErrorCode["subjet"] = 230] = "subjet";
    JwtErrorCode[JwtErrorCode["subjectMismatch"] = 230] = "subjectMismatch";
    JwtErrorCode[JwtErrorCode["aud"] = 240] = "aud";
    JwtErrorCode[JwtErrorCode["audMismatch"] = 240] = "audMismatch";
    JwtErrorCode[JwtErrorCode["audience"] = 240] = "audience";
    JwtErrorCode[JwtErrorCode["audienceMismatch"] = 240] = "audienceMismatch";
    JwtErrorCode[JwtErrorCode["exp"] = 250] = "exp";
    JwtErrorCode[JwtErrorCode["expired"] = 250] = "expired";
    JwtErrorCode[JwtErrorCode["nbf"] = 260] = "nbf";
    JwtErrorCode[JwtErrorCode["notValidYet"] = 260] = "notValidYet";
    JwtErrorCode[JwtErrorCode["notYetValid"] = 260] = "notYetValid";
    JwtErrorCode[JwtErrorCode["notBefore"] = 260] = "notBefore";
    JwtErrorCode[JwtErrorCode["keyInvalid"] = 300] = "keyInvalid";
    JwtErrorCode[JwtErrorCode["privateKeyInvalid"] = 301] = "privateKeyInvalid";
    JwtErrorCode[JwtErrorCode["publicKeyInvalid"] = 302] = "publicKeyInvalid";
})(JwtErrorCode || (exports.JwtErrorCode = JwtErrorCode = {}));
;
/**
 * Error class for use with this JWT library
 */
class JwtError extends Error {
    constructor(message, code = JwtErrorCode.internalError) {
        super(message);
        this.code = code;
    }
}
exports.JwtError = JwtError;
/**
 * Internal mapping of algorithms to Node.js crypto identifiers.
 */
var JwtAlgorithmEnum;
(function (JwtAlgorithmEnum) {
    JwtAlgorithmEnum["HS256"] = "sha256";
    JwtAlgorithmEnum["HS384"] = "sha384";
    JwtAlgorithmEnum["HS512"] = "sha512";
    JwtAlgorithmEnum["RS256"] = "RSA-SHA256";
    JwtAlgorithmEnum["RS384"] = "RSA-SHA384";
    JwtAlgorithmEnum["RS512"] = "RSA-SHA512";
    JwtAlgorithmEnum["PS256"] = "RSA-PSS-SHA256";
    JwtAlgorithmEnum["PS384"] = "RSA-PSS-SHA384";
    JwtAlgorithmEnum["PS512"] = "RSA-PSS-SHA512";
    JwtAlgorithmEnum["ES256"] = "sha256";
    JwtAlgorithmEnum["ES384"] = "sha384";
    JwtAlgorithmEnum["ES512"] = "sha512";
    JwtAlgorithmEnum["none"] = "none";
})(JwtAlgorithmEnum || (JwtAlgorithmEnum = {}));
/**
 * Internal mapping of algorithms to Node.js crypto hash algorithms.
 */
var JwtAlgorithmHashEnum;
(function (JwtAlgorithmHashEnum) {
    JwtAlgorithmHashEnum["HS256"] = "sha256";
    JwtAlgorithmHashEnum["HS384"] = "sha384";
    JwtAlgorithmHashEnum["HS512"] = "sha512";
    JwtAlgorithmHashEnum["RS256"] = "sha256";
    JwtAlgorithmHashEnum["RS384"] = "sha384";
    JwtAlgorithmHashEnum["RS512"] = "sha512";
    JwtAlgorithmHashEnum["PS256"] = "sha256";
    JwtAlgorithmHashEnum["PS384"] = "sha384";
    JwtAlgorithmHashEnum["PS512"] = "sha512";
    JwtAlgorithmHashEnum["ES256"] = "sha256";
    JwtAlgorithmHashEnum["ES384"] = "sha384";
    JwtAlgorithmHashEnum["ES512"] = "sha512";
    JwtAlgorithmHashEnum["none"] = "none";
})(JwtAlgorithmHashEnum || (JwtAlgorithmHashEnum = {}));
/**
 * Internal mapping of algorithms to modulus length.
 */
var JwtAlgorithmModulusLenEnum;
(function (JwtAlgorithmModulusLenEnum) {
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["RS256"] = 2048] = "RS256";
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["RS384"] = 3072] = "RS384";
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["RS512"] = 4096] = "RS512";
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["PS256"] = 2048] = "PS256";
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["PS384"] = 3072] = "PS384";
    JwtAlgorithmModulusLenEnum[JwtAlgorithmModulusLenEnum["PS512"] = 4096] = "PS512";
})(JwtAlgorithmModulusLenEnum || (JwtAlgorithmModulusLenEnum = {}));
/**
 * Valid symmetric jwt algorithm sets for quick lookup
 */
exports.validJwtSymmetricAlgorithms = Object.freeze(new Set(["HS256", "HS384", "HS512"]));
/**
 * Valid asymmetric jwt algorithm set for quick lookup
 */
exports.validJwtAsymmetricAlgorithms = Object.freeze(new Set([
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
]));
/**
 * Valid jwt algorithm set for quick lookup
 */
exports.validJwtAlgorithms = Object.freeze(new Set([
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
    "none"
]));
const encUtf8 = "utf-8";
const encBase64url = "base64url";
/**
 * JWT class providing utility function and methods to generate keys, and sign, verify and decode tokens.
 */
class JWT {
    get alg() {
        return __classPrivateFieldGet(this, _JWT_alg, "f");
    }
    get isAsymmetric() {
        return __classPrivateFieldGet(this, _JWT_isAsymmetric, "f");
    }
    /**
     * Get the current time in seconds.
     */
    static now() {
        return Math.floor(Date.now() / 1000);
    }
    /**
     * Get the given date-time in seconds.
     */
    static on(date) {
        return Math.floor(new Date(date).getTime() / 1000);
    }
    /**
     * Define absolute time in seconds. eg. `JWT.for(1).Day`
     */
    static for(time) {
        return new time_1.Time(time);
    }
    /**
     * Define the future time in seconds. eg. `JWT.in(10).Hours`
     */
    static in(time) {
        return new time_1.RelativeTime(time, _a.now());
    }
    /**
     * Define the future time in seconds. eg. `JWT.after(5).Minutes`
     */
    static after(time) {
        return new time_1.RelativeTime(time, _a.now());
    }
    /**
     * Define the past time in seconds. eg. `JWT.before(1).Week`
     */
    static before(time) {
        return new time_1.RelativeTime(-time, _a.now());
    }
    /**
     * Generate a random HMAC key for HS256 (32 bytes), HS384 (48 bytes), or HS512 (64 bytes) encoded in base64url format.
     *
     * @throws {JwtError} If the algorithm is invalid.
     */
    static genHmac(alg) {
        switch (alg) {
            case "HS256":
                return (0, node_crypto_1.randomBytes)(32).toString(encBase64url);
            case "HS384":
                return (0, node_crypto_1.randomBytes)(48).toString(encBase64url);
            case "HS512":
                return (0, node_crypto_1.randomBytes)(64).toString(encBase64url);
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
    static genKey(alg, options) {
        var _b;
        try {
            switch (alg) {
                case "HS256": {
                    const key = (0, node_crypto_1.randomBytes)(32).toString(encBase64url);
                    return { alg, privateKey: key, publicKey: key };
                }
                case "HS384": {
                    const key = (0, node_crypto_1.randomBytes)(48).toString(encBase64url);
                    return { alg, privateKey: key, publicKey: key };
                }
                case "HS512": {
                    const key = (0, node_crypto_1.randomBytes)(64).toString(encBase64url);
                    return { alg, privateKey: key, publicKey: key };
                }
                case "ES256": {
                    const { publicKey, privateKey } = (0, node_crypto_1.generateKeyPairSync)("ec", {
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
                    return { alg, publicKey, privateKey };
                }
                case "ES384": {
                    const { publicKey, privateKey } = (0, node_crypto_1.generateKeyPairSync)("ec", {
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
                    return { alg, publicKey, privateKey };
                }
                case "ES512": {
                    const { publicKey, privateKey } = (0, node_crypto_1.generateKeyPairSync)("ec", {
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
                    return { alg, publicKey, privateKey };
                }
                case "RS256":
                case "RS384":
                case "RS512":
                case "PS256":
                case "PS384":
                case "PS512": {
                    const { publicKey, privateKey } = (0, node_crypto_1.generateKeyPairSync)("rsa", {
                        modulusLength: (_b = options === null || options === void 0 ? void 0 : options.modulusLength) !== null && _b !== void 0 ? _b : JwtAlgorithmModulusLenEnum[alg],
                        publicKeyEncoding: {
                            type: "spki",
                            format: "pem",
                        },
                        privateKeyEncoding: {
                            type: "pkcs8",
                            format: "pem",
                        },
                    });
                    return { alg, publicKey, privateKey };
                }
                case "none": {
                    return { alg, publicKey: "", privateKey: "" };
                }
                default: {
                    throw new JwtError("invalid algorithm", JwtErrorCode.algorithmInvalid);
                }
            }
        }
        catch (error) {
            throw new JwtError(error instanceof Error ? error.message : "internal error", JwtErrorCode.internalError);
        }
    }
    /**
     * Create a JWT instance using a symmetric algorithm.
     *
     * @throws {JwtError} If the secret is null/empty or the algorithm is invalid.
     */
    static createSymmetric(secret, alg) {
        if (!secret) {
            throw new JwtError("null or empty symmetric secret", JwtErrorCode.keyInvalid);
        }
        if (!exports.validJwtSymmetricAlgorithms.has(alg)) {
            throw new JwtError("invalid symmetric JWT algorithm", JwtErrorCode.algorithmInvalid);
        }
        const key = { alg, privateKey: secret, publicKey: secret };
        return new _a(key, false);
    }
    /**
     * Create a JWT instance using an asymmetric algorithm.
     *
     * @throws {JwtError} If the algorithm is invalid.
     */
    static createAsymmetric(key) {
        if (!exports.validJwtAsymmetricAlgorithms.has(key.alg)) {
            throw new JwtError("invalid asymmetric JWT algorithm", JwtErrorCode.algorithmInvalid);
        }
        return new _a(key, true);
    }
    /**
     * Create a JWT instance using a symmetric or asymmetric algorithm.
     *
     * @throws {JwtError} If the algorithm is invalid.
     */
    static create(key) {
        if (!exports.validJwtAlgorithms.has(key.alg)) {
            throw new JwtError("invalid JWT algorithm", JwtErrorCode.algorithmInvalid);
        }
        const isAsymmetric = exports.validJwtAsymmetricAlgorithms.has(key.alg);
        return new _a(key, isAsymmetric);
    }
    constructor(key, isAsymmetric) {
        _JWT_instances.add(this);
        _JWT_alg.set(this, void 0);
        _JWT_algorithm.set(this, void 0);
        _JWT_privateKey.set(this, void 0);
        _JWT_publicKey.set(this, void 0);
        _JWT_isAsymmetric.set(this, false);
        if (key.alg !== "none" && !(key.privateKey || key.publicKey)) {
            throw new JwtError("null or empty JWT private and public key. either are required", JwtErrorCode.keyInvalid);
        }
        __classPrivateFieldSet(this, _JWT_alg, key.alg, "f");
        __classPrivateFieldSet(this, _JWT_algorithm, JwtAlgorithmEnum[key.alg], "f");
        __classPrivateFieldSet(this, _JWT_privateKey, key.privateKey, "f");
        __classPrivateFieldSet(this, _JWT_publicKey, key.publicKey, "f");
        __classPrivateFieldSet(this, _JWT_isAsymmetric, isAsymmetric, "f");
    }
    /**
     * Synchronously sign a payload and return a JWT token string.
     *
     * @throws {JwtError} If signing fails due to an invalid algorithm or key.
     */
    signSync(payload) {
        const alg = __classPrivateFieldGet(this, _JWT_alg, "f");
        const algorithm = __classPrivateFieldGet(this, _JWT_algorithm, "f");
        const header = Buffer.from(JSON.stringify({ typ: "JWT", alg }), encUtf8).toString(encBase64url);
        const payload_ = Buffer.from(JSON.stringify(payload), encUtf8).toString(encBase64url);
        const dataToSign = `${header}.${payload_}`;
        try {
            const signature = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_signData).call(this, alg, algorithm, dataToSign);
            return `${dataToSign}.${signature}`;
        }
        catch (error) {
            throw new JwtError(error instanceof Error ? error.message : "internal error", JwtErrorCode.internalError);
        }
    }
    /**
     * Asynchronously sign a payload and return a JWT token string.
     *
     * @throws {JwtError} If signing fails due to an invalid token.
     */
    sign(payload) {
        return new Promise((resolve, reject) => {
            try {
                const token = this.signSync(payload);
                resolve(token);
            }
            catch (error) {
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
    verifySignatureSync(token, verifyJwt) {
        verifyJwt = Object.assign({ strict: true }, verifyJwt);
        const [header, body, signature] = token.split(".", 3);
        if (!(header && body)) {
            return { valid: false, error: new JwtError("invalid token", JwtErrorCode.tokenInvalid) };
        }
        const jwtHeader = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_safelyParseJson).call(this, Buffer.from(header, encBase64url).toString(encUtf8));
        if (!jwtHeader) {
            return { valid: false, error: new JwtError("invalid token header", JwtErrorCode.tokenHeaderInvalid) };
        }
        const { typ, alg } = jwtHeader;
        if (typ !== "JWT") {
            return { valid: false, error: new JwtError("invalid token type", JwtErrorCode.tokenTypeInvalid) };
        }
        if (verifyJwt.strict && __classPrivateFieldGet(this, _JWT_alg, "f") !== alg) {
            return { valid: false, error: new JwtError("algorithm mismatch", JwtErrorCode.algorithmMismatch) };
        }
        if (!alg || !exports.validJwtAlgorithms.has(alg)) {
            return { valid: false, error: new JwtError("invalid algorithm", JwtErrorCode.algorithmInvalid) };
        }
        if (!signature && alg !== "none") {
            return { valid: false, error: new JwtError("invalid signature", JwtErrorCode.signatureInvalid) };
        }
        const algorithm = JwtAlgorithmEnum[alg];
        const dataToVerify = `${header}.${body}`;
        try {
            const signaturesMatch = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_verifySignature).call(this, alg, algorithm, dataToVerify, signature);
            if (!signaturesMatch) {
                return { valid: false, error: new JwtError("signature mismatch", JwtErrorCode.signatureMismatch) };
            }
        }
        catch (error) {
            return {
                valid: false,
                error: new JwtError(error instanceof Error ? error.message : "internal error", JwtErrorCode.internalError)
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
    verifySignature(token, verifyJwt) {
        return new Promise((resolve, reject) => {
            const { valid, error } = this.verifySignatureSync(token, verifyJwt);
            if (!valid)
                return reject(error);
            resolve(valid);
        });
    }
    /**
     * Synchronously verify a token, signature, payload and claims.
     *
     * @returns a JwtResult with a valid payload and the valid propery set to true on success.
     * @throws {JwtError} If the token, payload, signature, or claims are invalid.
     */
    verifySync(token, verifyJwt) {
        verifyJwt = Object.assign({ strict: true, exp: true, nbf: true }, verifyJwt);
        const [header, body, signature] = token.split(".", 3);
        if (!(header && body)) {
            return { valid: false, error: new JwtError("invalid token", JwtErrorCode.tokenInvalid) };
        }
        const jwtHeader = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_safelyParseJson).call(this, Buffer.from(header, encBase64url).toString(encUtf8));
        if (!jwtHeader) {
            return { valid: false, error: new JwtError("invalid token header", JwtErrorCode.tokenHeaderInvalid) };
        }
        const { typ, alg } = jwtHeader;
        if (typ !== "JWT") {
            return { valid: false, error: new JwtError("invalid token type", JwtErrorCode.tokenTypeInvalid) };
        }
        if (verifyJwt.strict && __classPrivateFieldGet(this, _JWT_alg, "f") !== alg) {
            return { valid: false, error: new JwtError("algorithm mismatch", JwtErrorCode.algorithmMismatch) };
        }
        if (!alg || !exports.validJwtAlgorithms.has(alg)) {
            return { valid: false, error: new JwtError("invalid algorithm", JwtErrorCode.algorithmInvalid) };
        }
        if (!signature && alg !== "none") {
            return { valid: false, error: new JwtError("invalid signature", JwtErrorCode.signatureInvalid) };
        }
        const algorithm = JwtAlgorithmEnum[alg];
        const dataToVerify = `${header}.${body}`;
        try {
            const signaturesMatch = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_verifySignature).call(this, alg, algorithm, dataToVerify, signature);
            if (!signaturesMatch) {
                return { valid: false, error: new JwtError("signature mismatch", JwtErrorCode.signatureMismatch) };
            }
            const jwtPayload = __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_safelyParseJson).call(this, Buffer.from(body, encBase64url).toString(encUtf8));
            if (!jwtPayload) {
                return { valid: false, error: new JwtError("invalid payload", JwtErrorCode.payloadInvalid) };
            }
            return __classPrivateFieldGet(this, _JWT_instances, "m", _JWT_validateClaims).call(this, jwtPayload, verifyJwt);
        }
        catch (error) {
            return {
                valid: false,
                error: new JwtError(error instanceof Error ? error.message : "internal error", JwtErrorCode.internalError)
            };
        }
    }
    /**
     * Asynchronously verify a token, signature, payload and claims.
     *
     * @returns a Promise to a valid payload on success.
     * @throws {JwtError} If the token, payload, signature, or claims are invalid.
     */
    verify(token, verifyJwt) {
        return new Promise((resolve, reject) => {
            const { valid, payload, error } = this.verifySync(token, verifyJwt);
            if (!(valid && payload))
                return reject(error);
            resolve(payload);
        });
    }
}
exports.JWT = JWT;
_a = JWT, _JWT_alg = new WeakMap(), _JWT_algorithm = new WeakMap(), _JWT_privateKey = new WeakMap(), _JWT_publicKey = new WeakMap(), _JWT_isAsymmetric = new WeakMap(), _JWT_instances = new WeakSet(), _JWT_timingSafeEqual = function _JWT_timingSafeEqual(a, b) {
    if (a.byteLength !== b.byteLength)
        return false;
    return (0, node_crypto_1.timingSafeEqual)(a, b);
}, _JWT_signData = function _JWT_signData(alg, algorithm, dataToSign) {
    switch (alg) {
        case "HS256":
        case "HS384":
        case "HS512":
            if (!__classPrivateFieldGet(this, _JWT_privateKey, "f")) {
                throw new JwtError("null or empty JWT private key", JwtErrorCode.privateKeyInvalid);
            }
            return (0, node_crypto_1.createHmac)(algorithm, __classPrivateFieldGet(this, _JWT_privateKey, "f"), { encoding: encBase64url })
                .update(dataToSign)
                .digest(encBase64url);
        case "ES256":
        case "ES384":
        case "ES512":
        case "RS256":
        case "RS384":
        case "RS512":
            if (!__classPrivateFieldGet(this, _JWT_privateKey, "f")) {
                throw new JwtError("null or empty JWT private key", JwtErrorCode.privateKeyInvalid);
            }
            return (0, node_crypto_1.createSign)(algorithm)
                .update(dataToSign)
                .sign(__classPrivateFieldGet(this, _JWT_privateKey, "f"), encBase64url);
        case "PS256":
        case "PS384":
        case "PS512":
            if (!__classPrivateFieldGet(this, _JWT_privateKey, "f")) {
                throw new JwtError("null or empty JWT private key", JwtErrorCode.privateKeyInvalid);
            }
            return (0, node_crypto_1.sign)(JwtAlgorithmHashEnum[alg], Buffer.from(dataToSign, encUtf8), {
                key: __classPrivateFieldGet(this, _JWT_privateKey, "f"),
                padding: node_crypto_1.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: node_crypto_1.constants.RSA_PSS_SALTLEN_DIGEST,
            }).toString(encBase64url);
        // case "none":
        default:
            return "";
    }
}, _JWT_verifySignature = function _JWT_verifySignature(alg, algorithm, dataToVerify, signature) {
    switch (alg) {
        case "HS256":
        case "HS384":
        case "HS512":
            if (!__classPrivateFieldGet(this, _JWT_publicKey, "f")) {
                throw new JwtError("null or empty JWT public key", JwtErrorCode.publicKeyInvalid);
            }
            return __classPrivateFieldGet(_a, _a, "m", _JWT_timingSafeEqual).call(_a, (0, node_crypto_1.createHmac)(algorithm, __classPrivateFieldGet(this, _JWT_publicKey, "f"), { encoding: encBase64url })
                .update(dataToVerify).digest(), Buffer.from(signature, encBase64url));
        case "ES256":
        case "ES384":
        case "ES512":
        case "RS256":
        case "RS384":
        case "RS512":
            if (!__classPrivateFieldGet(this, _JWT_publicKey, "f")) {
                throw new JwtError("null or empty JWT public key", JwtErrorCode.publicKeyInvalid);
            }
            return (0, node_crypto_1.createVerify)(algorithm)
                .update(dataToVerify)
                .verify(__classPrivateFieldGet(this, _JWT_publicKey, "f"), signature, encBase64url);
        case "PS256":
        case "PS384":
        case "PS512":
            if (!__classPrivateFieldGet(this, _JWT_publicKey, "f")) {
                throw new JwtError("null or empty JWT public key", JwtErrorCode.publicKeyInvalid);
            }
            return (0, node_crypto_1.verify)(JwtAlgorithmHashEnum[alg], Buffer.from(dataToVerify, encUtf8), {
                key: __classPrivateFieldGet(this, _JWT_publicKey, "f"),
                padding: node_crypto_1.constants.RSA_PKCS1_PSS_PADDING,
                saltLength: node_crypto_1.constants.RSA_PSS_SALTLEN_DIGEST,
            }, Buffer.from(signature, encBase64url));
        case "none":
            return signature === "";
        default:
            throw new JwtError("invalid algorithm", JwtErrorCode.algorithmInvalid);
    }
}, _JWT_validateAudience = function _JWT_validateAudience(expectedAudience, audience) {
    if (!audience)
        return false;
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
}, _JWT_validateClaims = function _JWT_validateClaims(payload, verifyJwt, now = _a.now()) {
    var _b, _c;
    if (verifyJwt.jti != null && payload.jti !== verifyJwt.jti) {
        return { valid: false, error: new JwtError("jti (jwt id) mismatch", JwtErrorCode.jtiMismatch) };
    }
    if (verifyJwt.iss != null && payload.iss !== verifyJwt.iss) {
        return { valid: false, error: new JwtError("iss (issuer) mismatch", JwtErrorCode.issMismatch) };
    }
    if (verifyJwt.sub != null && payload.sub !== verifyJwt.sub) {
        return { valid: false, error: new JwtError("sub (subject) mismatch", JwtErrorCode.subMismatch) };
    }
    if (verifyJwt.aud != null && !__classPrivateFieldGet(this, _JWT_instances, "m", _JWT_validateAudience).call(this, verifyJwt.aud, payload.aud)) {
        return { valid: false, error: new JwtError("aud (audience) mismatch", JwtErrorCode.audMismatch) };
    }
    if (verifyJwt.exp != null && now > payload.exp + ((_b = verifyJwt.expLeeway) !== null && _b !== void 0 ? _b : 0)) {
        return { valid: false, error: new JwtError("token expired", JwtErrorCode.expired) };
    }
    if (verifyJwt.nbf != null && payload.nbf - ((_c = verifyJwt.nbfLeeway) !== null && _c !== void 0 ? _c : 0) > now) {
        return { valid: false, error: new JwtError("token not yet valid (nbf)", JwtErrorCode.notValidYet) };
    }
    return { valid: true, payload };
}, _JWT_safelyParseJson = function _JWT_safelyParseJson(jsonStr) {
    try {
        const result = JSON.parse(jsonStr);
        return result;
    }
    catch (_err) {
        return undefined;
    }
};
//# sourceMappingURL=index.js.map