# Test Report

| 🕙 Start time | ⌛ Duration |
| --- | ---: |
| 7/5/2025, 4:06:48 AM | 52.851 s |

| | ✅ Passed | ❌ Failed | ⏩ Skipped | 🚧 Todo | ⚪ Total |
| --- | ---: | ---: | ---: | ---: | ---: |
|Test Suites|15|0|0|0|15|
|Tests|208|0|0|0|208|

## ✅ <a id="file0" href="#file0">tests/jwt.test.ts</a> [[link](https://github.com/bepalo/jwt/blob/e4626ccfed4456f7f0c9bbef1ce6e47661ddf350/tests/jwt.test.ts)]

208 passed, 0 failed, 0 skipped, 0 todo, done in 52455.880585 s

```
✅ JWT Test › JWT.genHmac
   ✅ generate HMAC secret with HS256 algorithm works
   ✅ generate HMAC secret with HS384 algorithm works
   ✅ generate HMAC secret with HS512 algorithm works
   ✅ generate HMAC secret fails on invalid algorithm
✅ JWT Test › Jwt.genKey
   ✅ generate key with none algorithm works
   ✅ generate key with HS256 algorithm works
   ✅ generate key with HS384 algorithm works
   ✅ generate key with HS512 algorithm works
   ✅ generate key with ES256 algorithm works
   ✅ generate key with ES384 algorithm works
   ✅ generate key with ES512 algorithm works
   ✅ generate key with RS256 algorithm works
   ✅ generate key with RS384 algorithm works
   ✅ generate key with RS512 algorithm works
   ✅ generate key with PS256 algorithm works
   ✅ generate key with PS384 algorithm works
   ✅ generate key with PS512 algorithm works
   ✅ generate key fails on invalid algorithm
✅ JWT Test › Jwt.createSymmetric
   ✅ create JWT with HS256 works
   ✅ create JWT with HS384 works
   ✅ create JWT with HS512 works
✅ JWT Test › Jwt.createAsymmetric
   ✅ create JWT with RS256 works
   ✅ create JWT with RS384 works
   ✅ create JWT with RS512 works
   ✅ create JWT with PS256 works
   ✅ create JWT with PS384 works
   ✅ create JWT with PS512 works
   ✅ create JWT with ES256 works
   ✅ create JWT with ES384 works
   ✅ create JWT with ES512 works
✅ JWT Test › Jwt.create
   ✅ create JWT with HS256 works
   ✅ create JWT with HS384 works
   ✅ create JWT with HS512 works
   ✅ create JWT with RS256 works
   ✅ create JWT with RS384 works
   ✅ create JWT with RS512 works
   ✅ create JWT with PS256 works
   ✅ create JWT with PS384 works
   ✅ create JWT with PS512 works
   ✅ create JWT with ES256 works
   ✅ create JWT with ES384 works
   ✅ create JWT with ES512 works
   ✅ create JWT with none works
✅ JWT Test › JWT.sign
   ✅ sign with HS256 works
   ✅ sign with HS256 and only private key works
   ✅ sign with HS256 and only public key fails
   ✅ sign with HS384 works
   ✅ sign with HS384 and only private key works
   ✅ sign with HS384 and only public key fails
   ✅ sign with HS512 works
   ✅ sign with HS512 and only private key works
   ✅ sign with HS512 and only public key fails
   ✅ sign with RS256 works
   ✅ sign with RS256 and only private key works
   ✅ sign with RS256 and only public key fails
   ✅ sign with RS384 works
   ✅ sign with RS384 and only private key works
   ✅ sign with RS384 and only public key fails
   ✅ sign with RS512 works
   ✅ sign with RS512 and only private key works
   ✅ sign with RS512 and only public key fails
   ✅ sign with PS256 works
   ✅ sign with PS256 and only private key works
   ✅ sign with PS256 and only public key fails
   ✅ sign with PS384 works
   ✅ sign with PS384 and only private key works
   ✅ sign with PS384 and only public key fails
   ✅ sign with PS512 works
   ✅ sign with PS512 and only private key works
   ✅ sign with PS512 and only public key fails
   ✅ sign with ES256 works
   ✅ sign with ES256 and only private key works
   ✅ sign with ES256 and only public key fails
   ✅ sign with ES384 works
   ✅ sign with ES384 and only private key works
   ✅ sign with ES384 and only public key fails
   ✅ sign with ES512 works
   ✅ sign with ES512 and only private key works
   ✅ sign with ES512 and only public key fails
   ✅ sign with none works
   ✅ sign with none and only private key works
✅ JWT Test › JWT.signSync
   ✅ sign with HS256 works
   ✅ sign with HS384 works
   ✅ sign with HS512 works
   ✅ sign with RS256 works
   ✅ sign with RS256 and only private key works
   ✅ sign with RS256 and only public key fails
   ✅ sign with RS384 works
   ✅ sign with RS384 and only private key works
   ✅ sign with RS384 and only public key fails
   ✅ sign with RS512 works
   ✅ sign with RS512 and only private key works
   ✅ sign with RS512 and only public key fails
   ✅ sign with PS256 works
   ✅ sign with PS256 and only private key works
   ✅ sign with PS256 and only public key fails
   ✅ sign with PS384 works
   ✅ sign with PS384 and only private key works
   ✅ sign with PS384 and only public key fails
   ✅ sign with PS512 works
   ✅ sign with PS512 and only private key works
   ✅ sign with PS512 and only public key fails
   ✅ sign with ES256 works
   ✅ sign with ES256 and only private key works
   ✅ sign with ES256 and only public key fails
   ✅ sign with ES384 works
   ✅ sign with ES384 and only private key works
   ✅ sign with ES384 and only public key fails
   ✅ sign with ES512 works
   ✅ sign with ES512 and only private key works
   ✅ sign with ES512 and only public key fails
   ✅ sign with none works
✅ JWT Test › JWT.verify
   ✅ verify with HS256 works
   ✅ verify with HS384 works
   ✅ verify with HS512 works
   ✅ verify with RS256 works
   ✅ verify with RS256 and only public key works
   ✅ verify with RS256 and only private key fails
   ✅ verify with RS384 works
   ✅ verify with RS384 and only public key works
   ✅ verify with RS384 and only private key fails
   ✅ verify with RS512 works
   ✅ verify with RS512 and only public key works
   ✅ verify with RS512 and only private key fails
   ✅ verify with PS256 works
   ✅ verify with PS256 and only public key works
   ✅ verify with PS256 and only private key fails
   ✅ verify with PS384 works
   ✅ verify with PS384 and only public key works
   ✅ verify with PS384 and only private key fails
   ✅ verify with PS512 works
   ✅ verify with PS512 and only public key works
   ✅ verify with PS512 and only private key fails
   ✅ verify with ES256 works
   ✅ verify with ES256 and only public key works
   ✅ verify with ES256 and only private key fails
   ✅ verify with ES384 works
   ✅ verify with ES384 and only public key works
   ✅ verify with ES384 and only private key fails
   ✅ verify with ES512 works
   ✅ verify with ES512 and only public key works
   ✅ verify with ES512 and only private key fails
   ✅ verify with none works
   ✅ verify with malformed header fails
   ✅ verify with malformed payload fails
   ✅ verify with malformed signature fails
   ✅ verify with bad signature fails
✅ JWT Test › JWT.verifySync
   ✅ verify with HS256
   ✅ verify with HS384
   ✅ verify with HS512
   ✅ verify with RS256
   ✅ verify with RS256 and only public key works
   ✅ verify with RS256 and only private key fails
   ✅ verify with RS384
   ✅ verify with RS384 and only public key works
   ✅ verify with RS384 and only private key fails
   ✅ verify with RS512
   ✅ verify with RS512 and only public key works
   ✅ verify with RS512 and only private key fails
   ✅ verify with PS256
   ✅ verify with PS256 and only public key works
   ✅ verify with PS256 and only private key fails
   ✅ verify with PS384
   ✅ verify with PS384 and only public key works
   ✅ verify with PS384 and only private key fails
   ✅ verify with PS512
   ✅ verify with PS512 and only public key works
   ✅ verify with PS512 and only private key fails
   ✅ verify with ES256
   ✅ verify with ES256 and only public key works
   ✅ verify with ES256 and only private key fails
   ✅ verify with ES384
   ✅ verify with ES384 and only public key works
   ✅ verify with ES384 and only private key fails
   ✅ verify with ES512
   ✅ verify with ES512 and only public key works
   ✅ verify with ES512 and only private key fails
   ✅ verify with none
   ✅ verify with malformed header fails
   ✅ verify with malformed payload fails
   ✅ verify with malformed signature fails
   ✅ verify with bad signature fails
✅ JWT Test › JWT.verifySignature
   ✅ works and returns no payload even if valid or not
✅ JWT Test › JWT.verifySignatureSync
   ✅ works and returns no payload even if valid or not
✅ JWT Test › JWT.verify claims
   ✅ returns payload if valid
   ✅ alg mismatch with strict mode on works
   ✅ verify: alg accept with strict mode off works
   ✅ verify: strict mode on by default
   ✅ verify: expiry check works
   ✅ verify: expiry leeway works
   ✅ verify: nbf (not before) check works
   ✅ verify: not-before leeway works
   ✅ verify: issuer check works
   ✅ verify: subject check works
   ✅ verify: audience check works
   ✅ verify: tampered payload invalidates signature
✅ JWT Test › JWT.verify claims
   ✅ returns payload if valid
   ✅ alg mismatch with strict mode on works
   ✅ verifySync: alg accept with strict mode off works
   ✅ verifySync: strict mode on by default
   ✅ verifySync: expiry check works
   ✅ verifySync: expiry leeway works
   ✅ verifySync: nbf (not before) check works
   ✅ verifySync: not-before leeway works
   ✅ verifySync: issuer check works
   ✅ verifySync: subject check works
   ✅ verifySync: audience check works
   ✅ verifySync: tampered payload invalidates signature
✅ JWT Test
```
