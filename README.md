# noble-curves

Minimal, zero-dependency JS implementation of elliptic curve cryptography.

- Short Weierstrass curve with ECDSA signatures
- Twisted Edwards curve with EdDSA signatures
- Montgomery curve for ECDH key agreement

To keep the package minimal, no curve definitions are provided out-of-box. Use `micro-curve-definitions` module:

- It provides P192, P224, P256, P384, P521, secp256k1, stark curve, bn254, pasta (pallas/vesta) short weierstrass curves
- It also provides ed25519 and ed448 twisted edwards curves
- Main reason for separate package is the fact hashing library (like `@noble/hashes`) is required for full functionality
- We may reconsider merging packages in future, when a stable version would be ready

Future plans:

- hash to curve standard
- point indistinguishability
- pairings

### This library belongs to _noble_ crypto

> **noble-crypto** — high-security, easily auditable set of contained cryptographic libraries and tools.

- No dependencies, small files
- Easily auditable TypeScript/JS code
- Supported in all major browsers and stable node.js versions
- All releases are signed with PGP keys
- Check out [homepage](https://paulmillr.com/noble/) & all libraries:
  [secp256k1](https://github.com/paulmillr/noble-secp256k1),
  [ed25519](https://github.com/paulmillr/noble-ed25519),
  [bls12-381](https://github.com/paulmillr/noble-bls12-381),
  [hashes](https://github.com/paulmillr/noble-hashes),
  [curves](https://github.com/paulmillr/noble-curves)

## Usage

Use NPM in node.js / browser, or include single file from
[GitHub's releases page](https://github.com/paulmillr/noble-curves/releases):

## Usage

```sh
npm install @noble/curves
```

```ts
import { weierstrass } from '@noble/curves/weierstrass'; // Short Weierstrass curve
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { concatBytes, randomBytes } from '@noble/hashes/utils';

const secp256k1 = weierstrass({
  a: 0n,
  b: 7n,
  P: 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn,
  n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  Gx: 55066263022277343669578718895168534326250603453777594175500187360389116729240n,
  Gy: 32670510020758816978083085130507043184471273380659243275938904335757337482424n,
  hash: sha256,
  hmac: (k: Uint8Array, ...msgs: Uint8Array[]) => hmac(sha256, key, concatBytes(...msgs)),
  randomBytes
});

secp256k1.getPublicKey(secp256k1.utils.randomPrivateKey());
secp256k1.sign(randomBytes(32), secp256k1.utils.randomPrivateKey());
// secp256k1.verify(sig, msg, pub)

import { twistedEdwards } from '@noble/curves/edwards'; // Twisted Edwards curve
import { sha512 } from '@noble/hashes/sha512';
import { div } from '@noble/curves/modular';

const ed25519 = twistedEdwards({
  a: -1n,
  d: div(-121665n, 121666n, 2n ** 255n - 19n), // -121665n/121666n
  P: 2n ** 255n - 19n,
  n: 2n ** 252n + 27742317777372353535851937790883648493n,
  h: 8n,
  Gx: 15112221349535400772501151409588531511454012693041857206046113283949847762202n,
  Gy: 46316835694926478169428394003475163141307993866256225615783033603165251855960n,
  hash: sha512,
  randomBytes,
  adjustScalarBytes(bytes) { // could be no-op
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    return bytes;
  },
} as const);
ed25519.getPublicKey(ed25519.utils.randomPrivateKey());
```

## Performance

Benchmark results on Apple M2 with node v18.10:

```
==== secp256k1 ====
  - getPublicKey1 (samples: 10000)
    noble_old x 8,131 ops/sec @ 122μs/op
    secp256k1 x 7,374 ops/sec @ 135μs/op
  - getPublicKey255 (samples: 10000)
    noble_old x 7,894 ops/sec @ 126μs/op
    secp256k1 x 7,327 ops/sec @ 136μs/op
  - sign (samples: 5000)
    noble_old x 5,243 ops/sec @ 190μs/op
    secp256k1 x 4,834 ops/sec @ 206μs/op
  - getSharedSecret (samples: 1000)
    noble_old x 653 ops/sec @ 1ms/op
    secp256k1 x 634 ops/sec @ 1ms/op
  - verify (samples: 1000)
    secp256k1_old x 1,038 ops/sec @ 962μs/op
    secp256k1 x 1,009 ops/sec @ 990μs/op
==== ed25519 ====
  - getPublicKey (samples: 10000)
    old x 8,632 ops/sec @ 115μs/op
    noble x 8,390 ops/sec @ 119μs/op
  - sign (samples: 5000)
    old x 4,376 ops/sec @ 228μs/op
    noble x 4,233 ops/sec @ 236μs/op
  - verify (samples: 1000)
    old x 865 ops/sec @ 1ms/op
    noble x 860 ops/sec @ 1ms/op
==== ed448 ====
  - getPublicKey (samples: 5000)
    noble x 3,224 ops/sec @ 310μs/op
  - sign (samples: 2500)
    noble x 1,561 ops/sec @ 640μs/op
  - verify (samples: 500)
    noble x 313 ops/sec @ 3ms/op
==== nist ====
  - getPublicKey (samples: 2500)
    P256 x 7,993 ops/sec @ 125μs/op
    P384 x 3,819 ops/sec @ 261μs/op
    P521 x 2,074 ops/sec @ 481μs/op
  - sign (samples: 1000)
    P256 x 5,327 ops/sec @ 187μs/op
    P384 x 2,728 ops/sec @ 366μs/op
    P521 x 1,594 ops/sec @ 626μs/op
  - verify (samples: 250)
    P256 x 806 ops/sec @ 1ms/op
    P384 x 353 ops/sec @ 2ms/op
    P521 x 171 ops/sec @ 5ms/op
==== stark ====
  - pedersen (samples: 500)
    old x 85 ops/sec @ 11ms/op
    noble x 1,216 ops/sec @ 822μs/op
  - verify (samples: 500)
    old x 302 ops/sec @ 3ms/op
    noble x 698 ops/sec @ 1ms/op
```

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
