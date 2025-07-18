/**
 * JWT tests
 */
import { describe, expect, test } from "vitest";
import {
  JWT,
  JwtAlgorithm,
  JwtAsymmetricAlgorithm,
  JwtError,
  JwtKey,
  JwtPayload,
  JwtResult,
  JwtSymmetricAlgorithm,
  JwtVerifyOptions,
  SURecord,
  validJwtAlgorithms,
  validJwtAsymmetricAlgorithms,
  validJwtSymmetricAlgorithms,
} from "..";
import { Buffer } from "node:buffer";

type Payload = {
  userId: number;
  role: "admin" | "user";
};

const payload: Payload = { userId: 123, role: "admin" } as const;

const ES512Supported = (() => {
  try {
    JWT.genKey("ES512");
  } catch {
    console.warn("WARN: ES512 algorithm not supported on this runtime.");
    return false;
  }
  return true;
})();

const jwtSymmetricAlgorithms = Object.freeze(new Set(validJwtSymmetricAlgorithms));
const jwtAsymmetricAlgorithms = Object.freeze(new Set(validJwtAsymmetricAlgorithms));
const jwtAlgorithms = Object.freeze(new Set(validJwtAlgorithms));

if (!ES512Supported) {
  jwtAsymmetricAlgorithms.delete("ES512");
  jwtAlgorithms.delete("ES512");
}

describe("JWT Test", () => {
  describe("JWT.genHmac", () => {
    test("generate HMAC secret with HS256 algorithm works", () => {
      const secret = JWT.genHmac("HS256");
      expect(secret).toBeTypeOf("string");
      expect(Buffer.from(secret, "base64url").length).toBe(32);
    });

    test("generate HMAC secret with HS384 algorithm works", () => {
      const secret = JWT.genHmac("HS384");
      expect(secret).toBeTypeOf("string");
      expect(Buffer.from(secret, "base64url").length).toBe(48);
    });

    test("generate HMAC secret with HS512 algorithm works", () => {
      const secret = JWT.genHmac("HS512");
      expect(secret).toBeTypeOf("string");
      expect(Buffer.from(secret, "base64url").length).toBe(64);
    });

    test("generate HMAC secret fails on invalid algorithm", () => {
      expect(() => JWT.genHmac("ES256" as JwtSymmetricAlgorithm))
        .toThrowError(JwtError);
      expect(() => JWT.genHmac("RS256" as JwtSymmetricAlgorithm))
        .toThrowError(JwtError);
      expect(() => JWT.genHmac("PS256" as JwtSymmetricAlgorithm))
        .toThrowError(JwtError);
      expect(() => JWT.genHmac("none" as JwtSymmetricAlgorithm))
        .toThrowError(JwtError);
    });
  });

  describe("Jwt.genKey", () => {
    // genKey none
    test("generate key with none algorithm works", () => {
      const key = JWT.genKey("none");
      expect(key).toBeTypeOf("object");
      expect(key.alg).toBe("none");
      expect(key.publicKey).toBe("");
      expect(key.privateKey).toBe("");
    });

    // genKey HS*
    test("generate key with HS256 algorithm works", () => {
      const key = JWT.genKey("HS256");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("HS256");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey ? Buffer.from(publicKey, "base64url").length : 0).toBe(32);
      expect(privateKey ? Buffer.from(privateKey, "base64url").length : 0).toBe(32);
    });

    test("generate key with HS384 algorithm works", () => {
      const key = JWT.genKey("HS384");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("HS384");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey ? Buffer.from(publicKey, "base64url").length : 0).toBe(48);
      expect(privateKey ? Buffer.from(privateKey, "base64url").length : 0).toBe(48);
    });

    test("generate key with HS512 algorithm works", () => {
      const key = JWT.genKey("HS512");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("HS512");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey ? Buffer.from(publicKey, "base64url").length : 0).toBe(64);
      expect(privateKey ? Buffer.from(privateKey, "base64url").length : 0).toBe(64);
    });

    // genKey ES*
    test("generate key with ES256 algorithm works", () => {
      const key = JWT.genKey("ES256");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("ES256");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey).toMatch(
        /-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----/gs,
      );
      expect(privateKey).toMatch(
        /-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----/gs,
      );
    });

    test("generate key with ES384 algorithm works", () => {
      const key = JWT.genKey("ES384");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("ES384");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey).toMatch(
        /-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----/gs,
      );
      expect(privateKey).toMatch(
        /-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----/gs,
      );
    });

    test("generate key with ES512 algorithm works", () => {
      if (ES512Supported) {
        const key = JWT.genKey("ES512");
        expect(key).toBeTypeOf("object");
        const { alg, publicKey, privateKey } = key;
        expect(alg).toBe("ES512");
        expect(publicKey).toBeTypeOf("string");
        expect(privateKey).toBeTypeOf("string");
        expect(publicKey?.length).toBeGreaterThan(0);
        expect(publicKey?.length).toBeGreaterThan(0);
        expect(publicKey).toMatch(
          /-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----/gs,
        );
        expect(privateKey).toMatch(
          /-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----/gs,
        );
      }
    });

    // genKey RS*
    test("generate key with RS256 algorithm works", () => {
      const key = JWT.genKey("RS256");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("RS256");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey).toMatch(
        /-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----/gs,
      );
      expect(privateKey).toMatch(
        /-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----/gs,
      );
    });

    test("generate key with RS384 algorithm works", () => {
      const key = JWT.genKey("RS384");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("RS384");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey).toMatch(
        /-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----/gs,
      );
      expect(privateKey).toMatch(
        /-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----/gs,
      );
    });

    test("generate key with RS512 algorithm works", () => {
      const key = JWT.genKey("RS512");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("RS512");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey).toMatch(
        /-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----/gs,
      );
      expect(privateKey).toMatch(
        /-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----/gs,
      );
    });

    // genKey PS*
    test("generate key with PS256 algorithm works", () => {
      const key = JWT.genKey("PS256");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("PS256");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey).toMatch(
        /-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----/gs,
      );
      expect(privateKey).toMatch(
        /-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----/gs,
      );
    });

    test("generate key with PS384 algorithm works", () => {
      const key = JWT.genKey("PS384");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("PS384");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(publicKey).toMatch(
        /-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----/gs,
      );
      expect(privateKey).toMatch(
        /-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----/gs,
      );
    });

    test("generate key with PS512 algorithm works", () => {
      const key = JWT.genKey("PS512");
      expect(key).toBeTypeOf("object");
      const { alg, publicKey, privateKey } = key;
      expect(alg).toBe("PS512");
      expect(publicKey).toBeTypeOf("string");
      expect(privateKey).toBeTypeOf("string");
      expect(publicKey?.length).toBeGreaterThan(0);
      expect(privateKey?.length).toBeGreaterThan(0);
      expect(publicKey).toMatch(
        /-----BEGIN PUBLIC KEY-----.+-----END PUBLIC KEY-----/gs,
      );
      expect(privateKey).toMatch(
        /-----BEGIN PRIVATE KEY-----.+-----END PRIVATE KEY-----/gs,
      );
    });

    test("generate key fails on invalid algorithm", () => {
      expect(() => JWT.genKey("HS128" as JwtAlgorithm))
        .toThrowError(JwtError);
    });
  });

  describe("Jwt.createSymmetric", () => {
    for (const alg of jwtSymmetricAlgorithms.keys()) {
      test("create JWT with " + alg + " works", () => {
        const secret = JWT.genHmac(alg);
        const jwt = JWT.createSymmetric<Payload>(secret, alg);
        expect(jwt).toBeInstanceOf(JWT);
        expect(jwt.alg).toBe(alg);
        expect(jwt.isAsymmetric).toBe(false);
      });
    }
  });

  describe("Jwt.createAsymmetric", () => {
    for (const alg of jwtAsymmetricAlgorithms.keys()) {
      test("create JWT with " + alg + " works", () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.createAsymmetric<Payload>(key);
        expect(jwt).toBeInstanceOf(JWT);
        expect(jwt.alg).toBe(alg);
        expect(jwt.isAsymmetric).toBe(true);
      });
    }
  });

  describe("Jwt.create", () => {
    for (const alg of jwtAlgorithms.keys()) {
      test("create JWT with " + alg + " works", () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        expect(jwt).toBeInstanceOf(JWT);
        expect(jwt.alg).toBe(alg);
        expect(jwt.isAsymmetric).toBe(
          jwtAsymmetricAlgorithms.has(jwt.alg as JwtAsymmetricAlgorithm),
        );
      });
    }
  });

  describe("JWT.sign", () => {
    for (const alg of jwtAlgorithms.keys()) {
      test("sign with " + alg + " works", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = await jwt.sign({ ...payload });
        expect(token).toBeTypeOf("string");
        expect(token.length).toBeGreaterThan(0);
        const tokenParts = token.split(".");
        expect(tokenParts.length).toBe(3);
        if (alg === "none") {
          expect(tokenParts[2]).toBe("");
        }
        expect(tokenParts[0]).toBeTypeOf("string");
        expect(tokenParts[1]).toBeTypeOf("string");
        const header = JSON.parse(Buffer.from(tokenParts[0], "base64url").toString("utf-8"));
        expect(header).toBeTypeOf("object");
        expect(header.typ).toBe("JWT");
        expect(header.alg).toBe(alg);
      });

      test("sign with " + alg + " and only private key works", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>({ ...key, publicKey: undefined });
        const token = await jwt.sign({ ...payload });
        expect(token).toBeTypeOf("string");
        expect(token.length).toBeGreaterThan(0);
        const tokenParts = token.split(".");
        expect(tokenParts.length).toBe(3);
        if (alg === "none") {
          expect(tokenParts[2]).toBe("");
        }
        expect(tokenParts[0]).toBeTypeOf("string");
        expect(tokenParts[1]).toBeTypeOf("string");
        const header = JSON.parse(Buffer.from(tokenParts[0], "base64url").toString("utf-8"));
        expect(header).toBeTypeOf("object");
        expect(header.typ).toBe("JWT");
        expect(header.alg).toBe(alg);
      });

      if (alg !== "none") {
        test("sign with " + alg + " and only public key fails", async () => {
          const key = JWT.genKey(alg);
          const jwt = JWT.create<Payload>({ ...key, privateKey: undefined });
          const result: { token?: string; error?: JwtError } = await jwt.sign({ ...payload })
            .then((token) => ({ token }))
            .catch((error) => ({ error }));
          expect(result).toBeTypeOf("object");
          expect(result.token).toBeUndefined();
          expect(result.error).toBeInstanceOf(JwtError);
        });
      }
    }
  });

  describe("JWT.signSync", () => {
    for (const alg of jwtAlgorithms.keys()) {
      test("sign with " + alg + " works", () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = jwt.signSync({ ...payload });
        expect(token).toBeTypeOf("string");
        expect(token.length).toBeGreaterThan(0);
        const tokenParts = token.split(".");
        expect(tokenParts.length).toBe(3);
        if (alg === "none") {
          expect(tokenParts[2]).toBe("");
        }
        expect(tokenParts[0]).toBeTypeOf("string");
        expect(tokenParts[1]).toBeTypeOf("string");
        const header = JSON.parse(Buffer.from(tokenParts[0], "base64url").toString("utf-8"));
        expect(header).toBeTypeOf("object");
        expect(header.typ).toBe("JWT");
        expect(header.alg).toBe(alg);
      });

      if (jwtAsymmetricAlgorithms.has(alg as JwtAsymmetricAlgorithm)) {
        test("sign with " + alg + " and only private key works", () => {
          const key = JWT.genKey(alg);
          const jwt = JWT.create<Payload>({ ...key, publicKey: undefined });
          const token = jwt.signSync({ ...payload });
          expect(token).toBeTypeOf("string");
          expect(token.length).toBeGreaterThan(0);
          const tokenParts = token.split(".");
          expect(tokenParts.length).toBe(3);
          if (alg === "none") {
            expect(tokenParts[2]).toBe("");
          }
          expect(tokenParts[0]).toBeTypeOf("string");
          expect(tokenParts[1]).toBeTypeOf("string");
          const header = JSON.parse(Buffer.from(tokenParts[0], "base64url").toString("utf-8"));
          expect(header).toBeTypeOf("object");
          expect(header.typ).toBe("JWT");
          expect(header.alg).toBe(alg);
        });

        test("sign with " + alg + " and only public key fails", () => {
          const key = JWT.genKey(alg);
          const jwt = JWT.create<Payload>({ ...key, privateKey: undefined });
          expect(() => jwt.signSync({ ...payload }))
            .toThrowError(JwtError);
        });
      }
    }
  });

  describe("JWT.verify", () => {
    for (const alg of jwtAlgorithms.keys()) {
      test("verify with " + alg + " works", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = await jwt.sign({ ...payload });
        expect(token).toBeTypeOf("string");
        const result = await jwt.verify(token)
          .then((payload) => ({ valid: true, payload } as JwtResult<Payload>))
          .catch((error) => ({ valid: false, error } as JwtResult<Payload>));
        expect(result).toBeTypeOf("object");
        const { valid, payload: decoded, error } = result;
        expect(valid).toBe(true);
        expect(error).toBeUndefined();
        expect(decoded).toBeTypeOf("object");
        expect(decoded?.userId).toBe(123);
        expect(decoded?.role).toBe("admin");
      });

      if (jwtAsymmetricAlgorithms.has(alg as JwtAsymmetricAlgorithm)) {
        test("verify with " + alg + " and only public key works", async () => {
          const key = JWT.genKey(alg);
          const jwtA = JWT.create<Payload>({ ...key, publicKey: undefined });
          const jwtB = JWT.create<Payload>({ ...key, privateKey: undefined });
          const token = await jwtA.sign({ ...payload });
          expect(token).toBeTypeOf("string");
          const result = await jwtB.verify(token)
            .then((payload) => ({ valid: true, payload } as JwtResult<Payload>))
            .catch((error) => ({ valid: false, error } as JwtResult<Payload>));
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
          expect(decoded?.userId).toBe(123);
          expect(decoded?.role).toBe("admin");
        });

        test("verify with " + alg + " and only private key fails", async () => {
          const key = JWT.genKey(alg);
          const jwtA = JWT.create<Payload>({ ...key, publicKey: undefined });
          const jwtB = JWT.create<Payload>({ ...key, publicKey: undefined });
          const token = await jwtA.sign({ ...payload });
          expect(token).toBeTypeOf("string");
          const result: { payload?: JwtPayload<Payload>; error?: JwtError } = await jwtB.verify(
            token,
          )
            .then((payload) => ({ payload }))
            .catch((error) => ({ error }));
          expect(result).toBeTypeOf("object");
          expect(result.payload).toBeUndefined();
          expect(result.error).toBeInstanceOf(JwtError);
        });
      }
    }

    test("verify with malformed header fails", async () => {
      const key = JWT.genKey("HS256");
      const jwt = JWT.create<Payload>(key);
      const token = await jwt.sign({ ...payload });
      expect(token).toBeTypeOf("string");
      const [, payload_, signature] = token.split(".", 3);
      const tamperedToken = ["malformed_header", payload_, signature].join(".");
      const result = await jwt.verify(tamperedToken)
        .then((payload) => ({ valid: true, payload } as JwtResult<Payload>))
        .catch((error) => ({ valid: false, error } as JwtResult<Payload>));
      expect(result).toBeTypeOf("object");
      const { valid, payload: decoded, error } = result;
      expect(valid).toBe(false);
      expect(error).toBeInstanceOf(JwtError);
      expect(decoded).toBeUndefined();
    });

    test("verify with malformed payload fails", async () => {
      const key = JWT.genKey("HS256");
      const jwt = JWT.create<Payload>(key);
      const token = await jwt.sign({ ...payload });
      expect(token).toBeTypeOf("string");
      const [header, , signature] = token.split(".", 3);
      const tamperedToken = [header, "malformed_payload", signature].join(".");
      const result = await jwt.verify(tamperedToken)
        .then((payload) => ({ valid: true, payload } as JwtResult<Payload>))
        .catch((error) => ({ valid: false, error } as JwtResult<Payload>));
      expect(result).toBeTypeOf("object");
      const { valid, payload: decoded, error } = result;
      expect(valid).toBe(false);
      expect(error).toBeInstanceOf(JwtError);
      expect(decoded).toBeUndefined();
    });

    test("verify with malformed signature fails", async () => {
      const key = JWT.genKey("HS256");
      const jwt = JWT.create<Payload>(key);
      const token = await jwt.sign({ ...payload });
      expect(token).toBeTypeOf("string");
      const [header, payload_] = token.split(".", 3);
      const tamperedToken = [header, payload_, "malformed_signature"].join(".");
      const result = await jwt.verify(tamperedToken)
        .then((payload) => ({ valid: true, payload } as JwtResult<Payload>))
        .catch((error) => ({ valid: false, error } as JwtResult<Payload>));
      expect(result).toBeTypeOf("object");
      const { valid, payload: decoded, error } = result;
      expect(valid).toBe(false);
      expect(error).toBeInstanceOf(JwtError);
      expect(decoded).toBeUndefined();
    });

    test("verify with bad signature fails", async () => {
      const keyA = JWT.genKey("HS256");
      const keyB = JWT.genKey("HS256");
      const jwtA = JWT.create<Payload>(keyA);
      const jwtB = JWT.create<Payload>(keyB);
      const tokenA = await jwtA.sign({ ...payload, exp: JWT.after(1).Minutes });
      const tokenB = await jwtB.sign({ ...payload, exp: JWT.after(1).Minutes });
      expect(tokenA).toBeTypeOf("string");
      const partsA = tokenA.split(".");
      const partsB = tokenB.split(".");
      partsA[2] = partsB[2];
      const tampered = partsA.join(".");
      const result = await jwtA.verify(tampered)
        .then((payload) => ({ valid: true, payload } as JwtResult<Payload>))
        .catch((error) => ({ valid: false, error } as JwtResult<Payload>));
      expect(result).toBeTypeOf("object");
      const { valid, payload: decoded, error } = result;
      expect(valid).toBe(false);
      expect(error).toBeInstanceOf(JwtError);
      expect(decoded).toBeUndefined();
    });
  });

  describe("JWT.verifySync", () => {
    for (const alg of jwtAlgorithms.keys()) {
      test("verify with " + alg, () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = jwt.signSync({ ...payload });
        expect(token).toBeTypeOf("string");
        const result = jwt.verifySync(token);
        expect(result).toBeTypeOf("object");
        const { valid, payload: decoded, error } = result;
        expect(valid).toBe(true);
        expect(error).toBeUndefined();
        expect(decoded).toBeTypeOf("object");
        expect(decoded?.userId).toBe(123);
        expect(decoded?.role).toBe("admin");
      });

      if (jwtAsymmetricAlgorithms.has(alg as JwtAsymmetricAlgorithm)) {
        test("verify with " + alg + " and only public key works", () => {
          const key = JWT.genKey(alg);
          const jwtA = JWT.create<Payload>({ ...key, publicKey: undefined });
          const jwtB = JWT.create<Payload>({ ...key, privateKey: undefined });
          const token = jwtA.signSync({ ...payload });
          expect(token).toBeTypeOf("string");
          const result = jwtB.verifySync(token);
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
          expect(decoded?.userId).toBe(123);
          expect(decoded?.role).toBe("admin");
        });

        test("verify with " + alg + " and only private key fails", () => {
          const key = JWT.genKey(alg);
          const jwtA = JWT.create<Payload>({ ...key, publicKey: undefined });
          const jwtB = JWT.create<Payload>({ ...key, publicKey: undefined });
          const token = jwtA.signSync({ ...payload });
          expect(token).toBeTypeOf("string");
          const result = jwtB.verifySync(token);
          expect(result).toBeTypeOf("object");
          expect(result.valid).toBe(false);
          expect(result.payload).toBeUndefined();
          expect(result.error).toBeInstanceOf(JwtError);
        });
      }
    }

    test("verify with malformed header fails", () => {
      const key = JWT.genKey("HS256");
      const jwt = JWT.create<Payload>(key);
      const token = jwt.signSync({ ...payload });
      expect(token).toBeTypeOf("string");
      const [, payload_, signature] = token.split(".", 3);
      const tamperedToken = ["malformed_header", payload_, signature].join(".");
      const result = jwt.verifySync(tamperedToken);
      expect(result).toBeTypeOf("object");
      const { valid, payload: decoded, error } = result;
      expect(valid).toBe(false);
      expect(error).toBeInstanceOf(JwtError);
      expect(decoded).toBeUndefined();
    });

    test("verify with malformed payload fails", () => {
      const key = JWT.genKey("HS256");
      const jwt = JWT.create<Payload>(key);
      const token = jwt.signSync({ ...payload });
      expect(token).toBeTypeOf("string");
      const [header, , signature] = token.split(".", 3);
      const tamperedToken = [header, "malformed_payload", signature].join(".");
      const result = jwt.verifySync(tamperedToken);
      expect(result).toBeTypeOf("object");
      const { valid, payload: decoded, error } = result;
      expect(valid).toBe(false);
      expect(error).toBeInstanceOf(JwtError);
      expect(decoded).toBeUndefined();
    });

    test("verify with malformed signature fails", () => {
      const key = JWT.genKey("HS256");
      const jwt = JWT.create<Payload>(key);
      const token = jwt.signSync({ ...payload });
      expect(token).toBeTypeOf("string");
      const [header, payload_] = token.split(".", 3);
      const tamperedToken = [header, payload_, "malformed_signature"].join(".");
      const result = jwt.verifySync(tamperedToken);
      expect(result).toBeTypeOf("object");
      const { valid, payload: decoded, error } = result;
      expect(valid).toBe(false);
      expect(error).toBeInstanceOf(JwtError);
      expect(decoded).toBeUndefined();
    });

    test("verify with bad signature fails", () => {
      const keyA = JWT.genKey("HS256");
      const keyB = JWT.genKey("HS256");
      const jwtA = JWT.create<Payload>(keyA);
      const jwtB = JWT.create<Payload>(keyB);
      const tokenA = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
      const tokenB = jwtB.signSync({ ...payload, exp: JWT.after(1).Minutes });
      expect(tokenA).toBeTypeOf("string");
      const partsA = tokenA.split(".");
      const partsB = tokenB.split(".");
      partsA[2] = partsB[2];
      const tampered = partsA.join(".");
      const result = jwtA.verifySync(tampered);
      expect(result).toBeTypeOf("object");
      const { valid, payload: decoded, error } = result;
      expect(valid).toBe(false);
      expect(error).toBeInstanceOf(JwtError);
      expect(decoded).toBeUndefined();
    });
  });

  for (
    const [tag, verifySignature] of Object.entries({
      verifySignature: async <Payload extends SURecord>(
        jwt: JWT<Payload>,
        token: string,
        verifyJwt?: JwtVerifyOptions,
      ): Promise<JwtResult<Payload>> => {
        return await jwt.verifySignature(token, verifyJwt)
          .then((valid) => ({ valid } as JwtResult<Payload>))
          .catch((error) => ({ valid: false, error } as JwtResult<Payload>));
      },
      verifySignatureSync: <Payload extends SURecord>(
        jwt: JWT<Payload>,
        token: string,
        verifyJwt?: JwtVerifyOptions,
      ): Promise<JwtResult<Payload>> => {
        return new Promise((resolve) => resolve(jwt.verifySignatureSync(token, verifyJwt)));
      },
    })
  ) {
    const alg = "HS256";
    describe("JWT." + tag, () => {
      test("works and returns no payload even if valid or not", async () => {
        const key = JWT.genKey(alg);
        const keyB = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const jwtB = JWT.create<Payload>(keyB);
        const token = jwt.signSync({ ...payload, exp: JWT.before(30).Seconds });
        const tokenB = jwtB.signSync({ ...payload, exp: JWT.before(30).Seconds });
        expect(token).toBeTypeOf("string");
        {
          const result = await verifySignature(jwt, token);
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeUndefined();
        }
        {
          const tamperedToken = [
            ...token.split(".").slice(0, 2),
            tokenB.split(".")[2],
          ].join(".");
          const result = await verifySignature(jwt, tamperedToken);
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
      });

      if (jwtAsymmetricAlgorithms.has(alg as JwtAsymmetricAlgorithm)) {
        test("verifySignature with " + alg + " and only public key works", async () => {
          const key = JWT.genKey(alg);
          const jwtA = JWT.create<Payload>({ ...key, publicKey: undefined });
          const jwtB = JWT.create<Payload>({ ...key, privateKey: undefined });
          const token = await jwtA.sign({ ...payload });
          expect(token).toBeTypeOf("string");
          const result = await verifySignature(jwtB, token);
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeUndefined();
        });

        test("verify with " + alg + " and only private key fails", async () => {
          const key = JWT.genKey(alg);
          const jwtA = JWT.create<Payload>({ ...key, publicKey: undefined });
          const jwtB = JWT.create<Payload>({ ...key, publicKey: undefined });
          const token = await jwtA.sign({ ...payload });
          expect(token).toBeTypeOf("string");
          const result = await verifySignature(jwtB, token);
          expect(result).toBeTypeOf("object");
          expect(result.payload).toBeUndefined();
          expect(result.error).toBeInstanceOf(JwtError);
        });
      }
    });
  }

  for (
    const [tag, verify] of Object.entries({
      verify: async <Payload extends SURecord>(
        jwt: JWT<Payload>,
        token: string,
        verifyJwt?: JwtVerifyOptions,
      ): Promise<JwtResult<Payload>> => {
        const result = await jwt.verify(token, verifyJwt)
          .then((payload) => ({ valid: true, payload } as JwtResult<Payload>))
          .catch((error) => ({ valid: false, error } as JwtResult<Payload>));
        return result;
      },
      verifySync: <Payload extends SURecord>(
        jwt: JWT<Payload>,
        token: string,
        verifyJwt?: JwtVerifyOptions,
      ): Promise<JwtResult<Payload>> => {
        return new Promise((resolve) => resolve(jwt.verifySync(token, verifyJwt)));
      },
    })
  ) {
    const alg = "HS256";

    describe("JWT.verify claims", () => {
      test("returns payload if valid", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = jwt.signSync({ ...payload, exp: JWT.after(1).Minutes });
        expect(token).toBeTypeOf("string");
        const result = await verify(jwt, token);
        expect(result).toBeTypeOf("object");
        const { valid, payload: decoded, error } = result;
        expect(valid).toBe(true);
        expect(error).toBeUndefined();
        expect(decoded).toBeTypeOf("object");
        expect(decoded?.userId).toBe(123);
      });

      test("alg mismatch with strict mode on works", async () => {
        {
          const keyPairA = JWT.genKey("HS256");
          const keyPairB = JWT.genKey("none");
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token, { strict: true });
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
        {
          const keyPairA = JWT.genKey("none");
          const keyPairB = JWT.genKey("HS256");
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token, { strict: true });
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
        {
          const keyPairA = JWT.genKey("HS256");
          const keyPairB = JWT.genKey("HS512");
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token, { strict: true });
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
        {
          const keyPairA = JWT.genKey("ES256");
          const keyPairB = JWT.genKey("ES512");
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token, { strict: true });
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
        {
          const keyPairA = JWT.genKey("RS256");
          const keyPairB = JWT.genKey("PS256");
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token, { strict: true });
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
      });

      test(tag + ": alg accept with strict mode off works", async () => {
        {
          const keyPairA = JWT.genKey("none");
          const keyPairB = JWT.genKey("HS256");
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token, { strict: false });
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
        {
          const keyPairA = JWT.genKey("HS256");
          const keyPairB = JWT.genKey("none");
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token, { strict: false });
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
        {
          const keyPairA = JWT.genKey("ES256");
          const keyPairB = { ...keyPairA, alg: "ES512" } as JwtKey;
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token, { strict: false });
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
        {
          const keyPairA = JWT.genKey("RS256");
          const keyPairB = { ...keyPairA, alg: "PS512" } as JwtKey;
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token, { strict: false });
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
      });

      test(tag + ": strict mode on by default", async () => {
        {
          const keyPairA = JWT.genKey("none");
          const keyPairB = JWT.genKey("HS256");
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token);
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
        {
          const keyPairA = JWT.genKey("HS256");
          const keyPairB = JWT.genKey("none");
          const jwtA = JWT.create<Payload>(keyPairA);
          const jwtB = JWT.create<Payload>(keyPairB);
          const token = jwtA.signSync({ ...payload, exp: JWT.after(1).Minutes });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwtB, token);
          const { valid, payload: decoded, error } = result;
          expect(result).toBeTypeOf("object");
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
      });

      test(tag + ": expiry check works", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        // not expired
        {
          const token = jwt.signSync({ ...payload, exp: JWT.after(5).Seconds });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwt, token);
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
        // expired
        {
          const token = jwt.signSync({ ...payload, exp: JWT.before(1).Seconds });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwt, token);
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
      });

      test(tag + ": expiry leeway works", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = jwt.signSync({ ...payload, exp: JWT.before(10).Seconds });
        expect(token).toBeTypeOf("string");
        {
          const result = await verify(jwt, token, {
            expLeeway: JWT.for(5).Seconds,
          });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
        {
          const result = await verify(jwt, token, {
            expLeeway: JWT.for(15).Seconds,
          });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
      });

      test(tag + ": nbf (not before) check works", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        // after nbf
        {
          const token = jwt.signSync({ ...payload, nbf: JWT.before(3).Seconds });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwt, token);
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
        // before nbf
        {
          const token = jwt.signSync({ ...payload, nbf: JWT.after(3).Seconds });
          expect(token).toBeTypeOf("string");
          const result = await verify(jwt, token);
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
      });

      test(tag + ": not-before leeway works", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = jwt.signSync({ ...payload, nbf: JWT.after(10).Seconds });
        expect(token).toBeTypeOf("string");
        {
          const result = await verify(jwt, token, {
            nbfLeeway: JWT.for(5).Seconds,
          });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
        {
          const result = await verify(jwt, token, {
            nbfLeeway: JWT.for(15).Seconds,
          });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
      });

      test(tag + ": issuer check works", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = jwt.signSync({ ...payload, iss: "iss:abc" });
        expect(token).toBeTypeOf("string");
        {
          const result = await verify(jwt, token, { iss: "iss:abc" });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
        {
          const result = await verify(jwt, token, { iss: "iss:cba" });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
      });

      test(tag + ": subject check works", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = jwt.signSync({ ...payload, sub: "sub:abc" });
        expect(token).toBeTypeOf("string");
        {
          const result = await verify(jwt, token, { sub: "sub:abc" });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
        {
          const result = await verify(jwt, token, { sub: "sub:cba" });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
      });

      test(tag + ": audience check works", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = jwt.signSync({ ...payload, aud: ["aud:abc", "aud:cba"] });
        expect(token).toBeTypeOf("string");
        {
          const result = await verify(jwt, token, { aud: "aud:abc" });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
        {
          const result = await verify(jwt, token, { aud: "aud:cba" });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
        {
          const result = await verify(jwt, token, {
            aud: ["aud:abc", "aud:cba"],
          });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
        {
          const result = await verify(jwt, token, {
            aud: ["aud:def", "aud:cba"],
          });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(true);
          expect(error).toBeUndefined();
          expect(decoded).toBeTypeOf("object");
        }
        {
          const result = await verify(jwt, token, { aud: "aud:def" });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
        {
          const result = await verify(jwt, token, {
            aud: ["aud:def", "aud:fed"],
          });
          expect(result).toBeTypeOf("object");
          const { valid, payload: decoded, error } = result;
          expect(valid).toBe(false);
          expect(error).toBeInstanceOf(JwtError);
          expect(decoded).toBeUndefined();
        }
      });

      test(tag + ": tampered payload invalidates signature", async () => {
        const key = JWT.genKey(alg);
        const jwt = JWT.create<Payload>(key);
        const token = jwt.signSync({ ...payload, exp: JWT.after(1).Minutes });
        expect(token).toBeTypeOf("string");
        const parts = token.split(".");
        parts[1] = Buffer.from(JSON.stringify({ tampered: true })).toString(
          "base64url",
        );
        const tampered = parts.join(".");
        const result = await verify(jwt, tampered);
        expect(result).toBeTypeOf("object");
        const { valid, payload: decoded, error } = result;
        expect(valid).toBe(false);
        expect(error).toBeInstanceOf(JwtError);
        expect(decoded).toBeUndefined();
      });
    });
  }
});
