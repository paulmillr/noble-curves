# Changelog for noble-curves

## 2.4.0 (2026-08-27)

- Harden FROST distributed key generation against round-one transcript substitution.
    - This is not a vulnerability; it's protection against those who don't follow the FROST spec. Spec wants user to preserve rounds.
- FROST: Enforced RFC 9591 point validation for BLS and BN
- POPRF: replace inversion with const-time version
- Weierstrass: harden public-key boundaries & infinity handling
    - ECDH and ECDSA now reject the identity even for point types whose generic codec permits it
    - Curves that disallow infinity cannot encode it, while opted-in curves use the canonical SEC 1 `0x00` encoding.
- DER: Bounded ECDSA signature and INTEGER sizes before bigint conversion, preventing malformed inputs from causing disproportionate parsing and allocation work
- Snapshot all security-sensitive state (passed arguments) to ensure it can't be mutated

Special thanks to Red Team (Rob Hamilton, CalleBTC, Omer Talip) and 1Password's Off-by-1 Labs.

## 2.3.0 (2026-08-06)

### Security and constant-timeness

- Hardened constant-time execution from best-effort to actual guarantees, with no measurable timing behavior across 200,000 samples. Scalar multiplication now uses secret-scalar blinding via CSPRNG, unprecomputed points use a constant-time fixed-window multiply instead of variable-time fallbacks, and modular arithmetic helpers were hardened. New constant-time benchmarks track timing behavior.
- General hardening across all modules.
- Applied fixes from the Trail of Bits review: recovered ECDSA signatures are now bound to their recovery ID, non-canonical BLS signature encodings are rejected, Edwards-to-Montgomery conversion helpers were corrected, and FROST DKG round-two retry handling was hardened.

#### X25519 hardening

It was possible to execute a remote timing attack on X25519 across many samples and learn up to 4.036 bits of a long-term private key. The other 247 bits were not affected.

The impact is primarily fingerprinting—a key can be recognized across deployments—not key recovery or a break of X25519. The maintainer was also unable to escalate the attack to co-residency (SMT).

Reported and found by:

- George Stergiopoulos, Department of Informatics, Athens University of Economics and Business, Greece (`geostergiop@aueb.gr`).
- Constantinos Patsakis, Department of Informatics, University of Piraeus, 80 Karaoli & Dimitriou Street, 18534 Piraeus, Greece (`kpatsak@unipi.gr`).

### Performance

- Improved ECDSA and EdDSA verification by up to 32%, Weierstrass ECDH by up to 19%, and X25519 `getPublicKey` by 2.7×.
- Improved BLS signature performance by 2×.
- Reduced initialization time for the first `getPublicKey` or `sign` call by approximately 2× for Ed25519, P-256, P-384, and P-521.
- Also improved verification of recovered signatures, pairing tower, FFT, and Pippenger performance, as well as joint-MSM paths in FROST and OPRF.
- `getPublicKey` and `sign` became slower because the window size was decreased from 8 to 6 and constant-time execution was hardened. Long-running applications that prefer 2.2.0-level speed can restore it with `secp256k1.Point.BASE.precompute(8)`, and likewise for other curves.

### Miscellaneous

- Improved tree-shaking for smaller bundles.
- Improved error messages and type checks.
- Upgraded noble-hashes to 2.3.0 for improved performance.
- Reduced on-disk size from 1,831 KB to 1,548 KB by disabling source maps, which have become less relevant.

## 2.2.0 (2026-04-12)

- **March 2026 self-audit** (all files): no major issues found.
  - Audited for specification compliance and security.
  - Updated Ed25519 ZIP 215 verification to match the specification more strictly where its vectors were insufficient.
  - Disabled ZIP 215 mode by default for Ed448 in favor of stricter verification.
  - Changed Schnorr randomness handling to reduce modulo N instead of throwing.
  - Hardened square-root calculations.
  - Corrected the Baby Jubjub curve and its parameters.
  - Improved DER parsing.
  - Improved BLS point decoding.
  - Fixed the Fp6 and Fp12 order for BLS and BN curves.
  - Made empty hash-to-curve DST and count values throw.
  - Applied `Object.freeze` to most primitives.
  - Other minor hardening.
- Fixed all byte-array types to work properly in both TypeScript 5.6 and TypeScript 5.9+.
  - TypeScript 5.6 has `Uint8Array`, while TypeScript 5.9+ made it generic: `Uint8Array<ArrayBuffer>`.
  - This created incompatibilities between TypeScript versions.
  - Previously, usage was difficult and constantly emitted errors similar to `TS2345`.
  - See [TypeScript issue #62240](https://github.com/microsoft/TypeScript/issues/62240) for more context.
- Implemented FROST threshold signatures from RFC 9591.
- Fixed compilation issues on TypeScript 6.
- Improved tree-shaking and reduced bundle sizes.
- Added extensive documentation throughout the codebase.

Version 2.1 was skipped to align with other noble packages.

## 2.0.1 (2025-09-22)

- Disabled extensionless imports. If you used `/ed25519`, switch to `/ed25519.js`. See [2.0.0](https://github.com/paulmillr/noble-curves/releases/tag/2.0.0) for more details.
- Specified exported submodules in `package.json` to ensure TypeScript autocompletion.
- Upgraded hashes to 2.0.1, including the scrypt and `package.json` changes.
- Exported `map_to_curve_elligator2_curve25519` for Ed25519 in [#211](https://github.com/paulmillr/noble-curves/pull/211).
- Added `try`/`catch` around `pairingBatch` in `bls12_381.verify()` by @MegaManSec in [#212](https://github.com/paulmillr/noble-curves/pull/212).
- Exposed extra information through FFT's `rootsOfUnity`.

### New Contributors

- @MegaManSec made their first contribution in [#212](https://github.com/paulmillr/noble-curves/pull/212).

### GitHub Immutable Releases

This GitHub release does not include the standalone `noble-curves.js`; use 2.0.0 until the project upgrades to newly added GitHub Immutable Releases.

## 2.0.0 (2025-08-25)

### High-level changes

Version 2 substantially simplifies internals, improves security, reduces bundle size, and lays a path for the future. To simplify upgrading, first upgrade to curves 1.9.x, which surfaces deprecations in VS Code-like editors.

- The package is now ESM-only. ESM can be loaded from CommonJS on Node.js 20.19+.
  - Node.js 20.19 is now the minimum required version.
  - Package imports now work correctly in bundlerless environments, such as browsers.
  - Reduced NPM package size from 354 KB to 300 KB.
  - Reduced unpacked NPM size from 2.1 MB to 1.2 MB.
- Reduced bundle sizes compared to v1.x: 4 KB smaller for Schnorr, 5.3 KB smaller for Ristretto255, and 9.4 KB smaller for X448.
- The `.js` extension must be used for all modules.
  - Old: `@noble/curves/ed25519`
  - New: `@noble/curves/ed25519.js`
  - This simplifies native browser usage without transpilers.

### New features

- Added a friendly noble-like wrapper around built-in WebCrypto.
- Implemented RFC 9497 OPRFs (oblivious pseudorandom functions).
  - P-256, P-384, P-521, Ristretto255, and Decaf448 are supported.
- Added `isValidSecretKey` and `isValidPublicKey` to Weierstrass and Edwards curves.
- Added the BrainpoolP256r1, BrainpoolP384r1, and BrainpoolP512r1 curves to `misc`.

### Changes

- Most methods now expect `Uint8Array`; hexadecimal string inputs are prohibited.
  - This simplifies reasoning, improves security, and reduces malleability.
  - `Point.fromHex` now expects only hexadecimal strings; use `Point.fromBytes` for `Uint8Array`.
- Breaking ECDSA changes for secp256k1, P-256, P-384, and other curves:
  - `sign` and `verify` now expect unhashed messages instead of message hashes. Use `{ prehash: false }` to restore the old behavior.
  - `sign` and `verify` now use low-S signatures by default. This does not affect secp256k1, which has used low-S from the beginning. Tests against specific signature vectors may fail after upgrading unless `{ lowS: false }` is used to restore the old behavior.
  - `sign` and `verify` now use `Uint8Array` signatures in compact format by default.
  - DER format must now be explicitly selected with `{ format: 'der' }` in `verify`, reducing malleability.
  - `verify` now prohibits `Signature` instances; call `signature.toBytes()` first.
- Breaking BLS signature changes for BLS12-381 and BN254:
  - Moved `getPublicKey`, `sign`, `verify`, `signShortSignature`, and related methods into `bls.longSignatures` for G1 public keys and G2 signatures, and `bls.shortSignatures` for G1 signatures and G2 public keys.
  - `verifyBatch` now expects an array of `{ message, publicKey }` inputs.
- Curve changes:
  - Substantially simplified curve creation and split point creation from signature generator creation.
  - The new methods are `weierstrass() + ecdsa()` and `edwards() + eddsa()`.
  - Weierstrass and Edwards constructors expect simplified curve parameters; `Fp` became `p`.
  - ECDSA and EdDSA constructors expect a `Point` class and hash.
  - Removed the unnecessary `Fn` argument from `pippenger`.
- Modular arithmetic changes:
  - `Field#fromBytes()` now validates elements to be in the range from zero through order minus one.
- Upgraded the TypeScript compilation environment to TypeScript 5.9 and ES2022.
- Made error messages substantially more descriptive.

### Renamings

- Module changes:
  - Moved the `p256`, `p384`, and `p521` modules into `nist`.
  - Moved the `jubjub` module into `misc`.
- Point changes:
  - Renamed `ExtendedPoint` and `ProjectivePoint` to `Point`.
  - Renamed projective and extended point coordinates from `px`/`ex`, `py`/`ey`, `pz`/`ez`, and `et` to `X`, `Y`, `Z`, and `T`.
  - Moved `Point.normalizeZ` and `Point.msm` to separate methods in the `abstract/curve.js` submodule.
  - Removed `Point.fromPrivateKey()`; use `Point.BASE.multiply()` and `Point.Fn.fromBytes(secretKey)`.
  - Renamed `toRawBytes` and `fromRawBytes` to `toBytes` and `fromBytes`.
  - Renamed `RistrettoPoint` to `ristretto255.Point` and `DecafPoint` to `decaf448.Point`.
- ECDSA signature changes:
  - Renamed `toCompactRawBytes` and `toDERRawBytes` to `toBytes('compact')` and `toBytes('der')`.
  - Renamed `toCompactHex` and `toDERHex` to `toHex('compact')` and `toHex('der')`.
  - Renamed `fromCompact` and `fromDER` to `fromBytes(format)` and `fromHex(format)`.
- Utility changes:
  - Renamed `randomPrivateKey` to `randomSecretKey`.
  - Replaced `utils.precompute` and `Point#_setWindowSize` with `Point#precompute`.
  - Renamed `edwardsToMontgomery` to `utils.toMontgomery`.
  - Renamed `edwardsToMontgomeryPriv` to `utils.toMontgomerySecret`.
- Renamed all curve-specific hash-to-curve methods to `*curve*_hasher`; for example, `secp256k1.hashToCurve` became `secp256k1_hasher.hashToCurve()`.
- Renamed and improved many types.

### Removed features

- Removed `Point#multiplyAndAddUnsafe` and `Point#hasEvenY`.
- Removed the `CURVE` property with miscellaneous internals. `Point.CURVE()` replaces it but provides only curve parameters.
- Removed the `pasta` and `bn254_weierstrass` curves; this does not affect the pairing-based BN254 curve.
- Removed `Field.MASK`.
- Removed `utils.normPrivateKeyToScalar`.

## 1.9.7 (2025-08-15)

- Renamed the newly introduced, experimental Edwards method `toMontgomeryPriv` to `toMontgomerySecret`.
- Restored `SignatureConstructor` for Weierstrass curves.
- Added more deprecations and preparations for version 2.

## 1.9.6 (2025-07-30)

- Exposed `nBitLength` and `nByteLength` for Edwards curves.
- Renamed `secret` and `public` to `secretKey` and `publicKey` in the experimental `CurveLengths` interface.
- Began point precomputation earlier, within `weierstrass()`, while retaining lazy calculation until the first call.
- Added the new internal version-2 `tower` implementation to BLS.
- Ensured Ed448 and Decaf448 use separate `Fn` fields with different `BITS` lengths.

## 1.9.5 (2025-07-29)

- Fixed Rollup warnings from #205.
- Restored aliases for `secp256r1`, `secp384r1`, and `secp521r1` from #203.
- Restored `CURVE.nByteLength` from #202.
- Added more preparations and deprecations for the future version-2 release.

## 1.9.4 (2025-07-17)

- Fixed #201, an invalid renaming of `ProjConstructor`.
- Added more deprecations for the upcoming version-2 release.

## 1.9.3 (2025-07-16)

This release contains bug fixes and improvements that pave the way for version 2. Existing code continues to work unchanged, while old APIs are visually flagged as deprecated through JSDoc in TypeScript-aware environments.

- Renamed `*privateKey` to `*secretKey` throughout for consistency with post-quantum and non-noble libraries.
- Added `keygen`, which creates both secret and public keys.
- Made the Weierstrass endomorphism generic for all Koblitz curves.
- Added `fromBytes` and `toBytes` to Weierstrass signatures and deprecated `fromDER`, `fromCompact`, `toDERRawBytes`, and `toCompactRawBytes`.
- Moved Edwards `edwardsToMontgomery` into `utils.toMontgomery`.
- Added a new Decaf and Ristretto interface that is more consistent with other points.
- Added `ED448_TORSION_GROUP` for Ed448.
- Added `curve.info` to all curves for better interoperability.
- Changed the public wNAF API.
- Added `sqrt9mod16` to modular arithmetic.
- Moved all hash-to-curve hashers into `_hasher` properties, such as `secp256k1_hasher`.
- Added ACVP test vectors.

### Sensitive code changes

- Primarily renamed wNAF internals.
- Added field-bound validation for scalar fields (`Fn`) and curve fields (`Fp`).

## 1.9.2 (2025-06-05)

This release contains bug fixes and improvements that pave the way for version 2.

- Substantially refactored Edwards and Weierstrass curves with a simpler ECDSA and EdDSA API in [#192](https://github.com/paulmillr/noble-curves/pull/192).
  - The old code continues to work until version 2.
  - The new API is experimental until the next patch release.
  - Renamed `toRawBytes` to `toBytes`.
  - Renamed `ExtendedPoint` and `ProjectivePoint` to `Point`.
  - Added static `Fp` and `Fn` field properties to `Point`.
- Added support for ECDSA on curves with a cofactor greater than one.
- Added support for points with an x-coordinate of zero in Weierstrass curves.
- Substantially refactored BLS, improved types, and added the new `bls.longSignatures` and `bls.shortSignatures` APIs.
  - The old code continues to work until version 2.
  - The new API is experimental until the next patch release.
- Reused noble-hashes utilities.
- Used `randomBytes` and HMAC from noble-hashes by default.

### Sensitive code changes

- Refactored range-check logic for Edwards and Weierstrass curves.
- Improved Weierstrass `sign()` logic for nonce generation.
- Hardened `multiplyUnsafe` and stopped using `multiplyAndAddUnsafe` for Weierstrass curves.

### New Contributors

- @randombit added a test that BLS12-381 augmented signatures can be verified in [#191](https://github.com/paulmillr/noble-curves/pull/191).

## 1.9.1 (2025-05-14)

- Added an experimental FFT/NTT implementation in `abstract/fft`.
- Verified Edwards curve parameters against the curve equation during initialization.
- Verified Weierstrass curve parameters against the discriminant during initialization.
- Improved `getSharedSecret` argument validation for rare Weierstrass curves.
- Fixed invalid signature-recovery decoding lengths for rare Weierstrass curves.
- Improved modular square-root calculation.
- Allowed X25519 and X448 to accept more valid private- and public-key inputs.
- Improved secp256k1 tree-shaking.

## 1.9.0 (2025-04-23)

This release contains bug fixes and improvements that pave the way for version 2.

- Modules are now available with a `.js` extension.
  - Old: `@noble/curves/ed25519`
  - New: `@noble/curves/ed25519.js`
  - The old path remains available.
  - This simplifies native browser usage without transpilers.
- Added sponge and Grain LFSR support to Poseidon.
- Merged P-256, P-384, and P-521 into the new `nist` module.
- Prohibited y-coordinates of zero during Weierstrass initialization.
- Used `inv0` throughout hash-to-curve to ensure zero elements are returned in exceptional cases.
- Improved modular square-root logic, including Tonelli-Shanks and Legendre calculations.
- Fixed `FpInvertBatch` creating sparse arrays instead of arrays containing `undefined`.
- Deprecated Pasta curves.
- Updated noble-hashes to [1.8.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.8.0).

## 1.8.2 (2025-04-14)

- **Important:** adjusted wNAF scalar multiplication logic.
  - The adjustment is small and deduplicates code, but wNAF is sensitive code that handles private keys.
  - Review the change in [#184](https://github.com/paulmillr/noble-curves/pull/184).
- Made Edwards curves such as Ed25519 and Ed448 always use the complete addition formula.
- Prohibited Edwards points with `z = 0`; zero points have `z = 1`.
- Used a slower but more precise `CURVE.a` definition for Ed25519.
- Froze Weierstrass signatures on creation.
- Fixed Weierstrass curves in the Pale Moon browser (#176).
- Improved the hash-to-curve error for zero in `mapToCurve`.
- Fixed the incorrect `Fp12` fields type in `tower`.
- Added the `misc` module containing Jubjub and Baby Jubjub.
- Updated utils to use built-in `Uint8Array` `toHex` and `fromHex` [when available](https://caniuse.com/mdn-javascript_builtins_uint8array_fromhex), providing a 13× speed-up on 256-byte arrays and a 20× speed-up on 32 KB arrays.

### Other changes

- Updated noble-hashes to [1.7.2](https://github.com/paulmillr/noble-hashes/releases/tag/1.7.2).
- Reduced the standalone build by 500 bytes.
- Standalone build files are now attested in CI. See the README for the verification guide.
- TypeScript source can now be used without compilation in Node.js 24 due to [`erasableSyntaxOnly`](https://devblogs.microsoft.com/typescript/announcing-typescript-5-8/#the---erasablesyntaxonly-option).

### New Contributors

- @tuantran-genetica made their first contribution in [#181](https://github.com/paulmillr/noble-curves/pull/181).
- @kigawas made their first contribution in [#183](https://github.com/paulmillr/noble-curves/pull/183).

### Acknowledgments

Thanks to @ChALkeR for spotting the Edwards bug.

## 1.8.1 (2025-01-18)

- Enabled TypeScript's `verbatimModuleSyntax` to support future Node.js type stripping.
- Updated noble-hashes to [1.7.1](https://github.com/paulmillr/noble-hashes/releases/tag/1.7.1).
- Improved documentation.

## 1.8.0 (2025-01-03)

- The package is now available [on JSR](https://jsr.io/@noble/curves).
- Enabled TypeScript's [`isolatedDeclarations`](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-5-5.html#isolated-declarations) option, which substantially simplifies automatic documentation generation and more.
  - See the JSR page for an example.
- Added extensive comments throughout the codebase to improve autocompletion, LLM code generation, and general code understanding.
- Fixed `isLE` logic and reversed `mapHashToField` in modular arithmetic.
- Upgraded noble-hashes to [1.7.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.7.0).

## 1.7.0 (2024-11-22)

- Added `wnafCachedUnsafe()` and `precomputeMSMUnsafe()` to curves.
  - The new methods speed up MSM when inputs are public.
  - Edwards and Weierstrass `multiplyUnsafe` now use the new wNAF methods.
- Made modular square-root calculation fail on a non-prime P instead of looping.
  - Delayed `sqrtP` calculation until its first use instead of precomputing it at initialization.
- Added support for a strict `format` option in Weierstrass `verify`, selecting between `compact` and `der`.
- Exported additional BLS types to simplify custom curves.
- Improved `isBytes` performance.
- Improved compatibility with parsers and minifiers.
- Upgraded noble-hashes to [1.6.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.6.0).

### New Contributors

- @andreibancioiu made their first contribution in [#156](https://github.com/paulmillr/noble-curves/pull/156).
- @ChALkeR made their first contribution in [#166](https://github.com/paulmillr/noble-curves/pull/166).

## 1.6.0 (2024-09-03)

### What's Changed

- Added multi-scalar multiplication using the Pippenger algorithm to Weierstrass and Edwards curves.
- Improved DER encoding edge cases, fixing P-521 signatures.
- Added more hash-to-curve type checks.
- Exported `abstract/tower` for pairing-friendly curves.
- Added support for Node.js 14.
- Upgraded noble-hashes to [1.5.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.5.0).

## 1.5.0 (2024-08-07)

- Implemented BN254 (also known as alt_bn128) pairings compatible with EVM and ZEC.
  - Point serialization is not implemented because there is no standard representation, but it can be implemented in user space. See the README.
- Refactored and simplified range checks for private keys and signatures.
- Added memoization to `toAffine` and `assertValidity` to speed up BLS.
- Made all points immutable and frozen for improved security.

## 1.4.2 (2024-07-01)

- Reverted the TypeScript build target from ES2022 to ES2020 due to compatibility issues.

## 1.4.1 (2024-07-01)

- Added `mapToCurve` to BLS12-381 and fixed TypeScript types.
- Improved tree-shaking for Ed25519 and utils.
- Emitted separate ESM type declarations from the TypeScript build for improved compatibility.
- Changed the TypeScript build target from ES2020 to ES2022.

### New Contributors

- @carleeto made their first contribution in [#133](https://github.com/paulmillr/noble-curves/pull/133).

## 1.4.0 (2024-03-14)

- Fixed verification of BLS short signatures when using hexadecimal strings.
- Fixed types in hash-to-field and Weierstrass entropy.
- Updated noble-hashes to [1.4.0](https://github.com/paulmillr/noble-hashes/releases/tag/1.4.0), adding support for big-endian platforms.
- Refactored small utilities to reduce code duplication.
- Improved `tsconfig`.

### New Contributors

- @ardislu made their first contribution in [#110](https://github.com/paulmillr/noble-curves/pull/110).
- @dhrubabasu made their first contribution in [#117](https://github.com/paulmillr/noble-curves/pull/117).
- @xrchz made their first contribution in [#129](https://github.com/paulmillr/noble-curves/pull/129).

## 1.3.0 (2023-12-11)

- BLS changes:
  - Added support for short signatures, which use G1 for signatures and G2 for public keys rather than the reverse.
  - Contributed by @randombit in [#74](https://github.com/paulmillr/noble-curves/pull/74).
  - Refactored mask-bit settings and improved encoding resilience.
- Implemented the `Group` interface for Ed25519 and Ed448 `DecafPoint` and `RistrettoPoint` by @sublimator in [#85](https://github.com/paulmillr/noble-curves/pull/85).
- Fixed X448 private keys to be 56 bytes rather than 57 bytes.
- Fixed the missing `CURVE` object in Weierstrass `weierstrassPoints` by @secure12 in [#92](https://github.com/paulmillr/noble-curves/pull/92).
- Utility changes:
  - Sped up `hexToBytes` by 6× and improved error formatting, by @arobsn in [#83](https://github.com/paulmillr/noble-curves/pull/83).
  - Improved `isBytes` reliability in environments such as JSDOM.
  - Improved `concatBytes` safety by checking types early.
  - Made `equalBytes` constant-time.
- Upgraded noble-hashes to [1.3.3](https://github.com/paulmillr/noble-hashes/releases/tag/1.3.3).
- Upgraded the TypeScript build version to 5.3.2.

### New Contributors

- @randombit made their first contribution in [#74](https://github.com/paulmillr/noble-curves/pull/74).
- @arobsn made their first contribution in [#83](https://github.com/paulmillr/noble-curves/pull/83).
- @secure12 made their first contribution in [#92](https://github.com/paulmillr/noble-curves/pull/92).
- @yhc125 made their first contribution in [#93](https://github.com/paulmillr/noble-curves/pull/93).

## 1.2.0 (2023-08-23)

- Added Decaf448 support to Ed448.
- Improved the security of random Weierstrass private keys by reducing bias from `2^-64` to `2^-curve_security_level`.
- Allowed Weierstrass `extraEntropy` to accept any number of bytes.
- Improved Poseidon security by making `sboxPower` mandatory, allowing only 3, 5, or 7, and prohibiting odd `roundsFull` values.
- Allowed string and `Uint8Array` DSTs in hash-to-curve.
- Improved tree-shaking by adding `sideEffects: false` to `package.json` and pure annotations to Ed25519.
- Updated noble-hashes to [1.3.2](https://github.com/paulmillr/noble-hashes/releases/tag/1.3.2).

### New Contributors

- @stknob made their first contribution in [#59](https://github.com/paulmillr/noble-curves/pull/59).
- @mahnunchik made their first contribution in [#56](https://github.com/paulmillr/noble-curves/pull/56).
- @steveluscher made their first contribution in [#62](https://github.com/paulmillr/noble-curves/pull/62).

## 1.1.0 (2023-06-03)

### What's Changed

- Ed25519 and Ed448 `verify` now provide non-repudiation (strongly binding signatures) when `zip215: false` is used.
  - Non-repudiation is useful for e-voting and other systems.
  - See [The Provable Security of Ed25519: Theory and Practice](https://eprint.iacr.org/2020/823).
  - See [Taming the many EdDSAs](https://eprint.iacr.org/2020/1244) and its [NIST presentation](https://csrc.nist.gov/csrc/media/Presentations/2023/crclub-2023-03-08/images-media/20230308-crypto-club-slides--taming-the-many-EdDSAs.pdf).
- Reduced common-case bundle sizes by 20% with pure annotations, helping bundlers eliminate dead code during tree-shaking.
  - secp256k1: 75.4 KB to 62.3 KB.
  - Ed25519: 67.5 KB to 51.1 KB.
  - Ed448: 55.1 KB to 44.0 KB.
  - P-256: 67.8 KB to 59.8 KB.
  - P-384: 75.4 KB to 67.4 KB.
  - P-521: 75.8 KB to 67.8 KB.
- Changed the Weierstrass `sign` return type from `SignatureType` to `RecoveredSignatureType`.
- Renamed Edwards `edwardsToMontgomery` to `edwardsToMontgomeryPub` and added `edwardsToMontgomeryPriv`.
- Made BLS12-381 friendlier to non-compliant compilers by avoiding BigInt literals.
- Improved compatibility with non-compliant compilers by avoiding the exponentiation operator with BigInts.
- Fixed the Ed25519 `ristrettoHash` size typo in `hashToCurve` by @sublimator in [#42](https://github.com/paulmillr/noble-curves/pull/42).
- Harmonized utils with noble-hashes.
- Fixed `utf8ToBytes` in Firefox extension contexts.

### New Contributors

- @mirceanis made their first contribution in [#32](https://github.com/paulmillr/noble-curves/pull/32).
- @legobeat made their first contribution in [#38](https://github.com/paulmillr/noble-curves/pull/38).
- @sublimator made their first contribution in [#42](https://github.com/paulmillr/noble-curves/pull/42).
- Thanks to @Wind4Greg for their involvement in strongly binding signatures.

## 1.0.0 (2023-04-12)

First stable release. The API should now remain stable.

### Ed25519 and Ed448 API changes

- `context` is now an option in `sign` and `verify`.
- `zip215` is a new `verify` option that conforms to RFC 8032 when `false` and matches ZIP 215 when `true`.
- Added `edwardsToMontgomery`.

### BLS12-381 API changes

- `CURVE` is no longer exposed because it was an internal property. Use `G1.CURVE` and `G2.CURVE`.
- Fields moved into the `fields: { Fp, Fp2, Fp6, Fp12, Fr }` property.
- See the README for new usage.

- Improved DER decoding and validated curve creation for Weierstrass curves.
- Updated Wycheproof vectors.
- Restricted hash-to-curve `expand` to `xmd` and `xof`.

## 0.1.0 (2022-12-09)

- Initial release
