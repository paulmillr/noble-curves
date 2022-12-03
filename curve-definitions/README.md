# micro-curve-definitions

Elliptic curves implementations. `@noble/curves` is zero-dependency library for internal arithmetics.

`micro-curve-definitions` is the actual implementations. Current functionality:

- NIST curves: P192, P224, P256, P384, P521 (ECDSA)
- secp256k1 (ECDSA, without Schnorr)
- stark curve
- bn254

Pairings are not implemented.

## Usage

```sh
npm install micro-curve-definitions
```

```ts
import * as nist from 'micro-curve-definitions';

// P192, P224, P256, P384, P521, bn254
```

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
