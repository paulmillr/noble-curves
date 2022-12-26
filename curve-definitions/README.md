# micro-curve-definitions

Elliptic curves implementations. `@noble/curves` is zero-dependency library for internal arithmetics.

`micro-curve-definitions` is the actual implementations. Current functionality:

- NIST curves: P192, P224, P256, P384, P521 (ECDSA)
- secp256k1 (ECDSA, without Schnorr)
- stark curve
- bls12-381
- bn254

## Usage

```sh
npm install micro-curve-definitions
```

## License

MIT (c) Paul Miller [(https://paulmillr.com)](https://paulmillr.com), see LICENSE file.
