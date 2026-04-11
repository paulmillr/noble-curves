import { isBytes } from '@noble/hashes/utils.js';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql } from 'node:assert';
import { randomBytes } from 'node:crypto';
import { sha256 } from '@noble/hashes/sha2.js';
import { DER, ecdh, ecdsa } from '../src/abstract/weierstrass.ts';
import { bls12_381 } from '../src/bls12-381.ts';
import { bn254 } from '../src/bn254.ts';
import {
  ED25519_TORSION_SUBGROUP,
  ed25519,
  ed25519ctx,
  ed25519ph,
  ed25519_FROST,
  ed25519_hasher,
  ristretto255,
  ristretto255_FROST,
  ristretto255_hasher,
  x25519,
} from '../src/ed25519.ts';
import {
  E448,
  ED448_TORSION_SUBGROUP,
  decaf448,
  decaf448_hasher,
  ed448,
  ed448ph,
  ed448_FROST,
  ed448_hasher,
  x448,
} from '../src/ed448.ts';
import {
  babyjubjub,
  brainpoolP256r1,
  brainpoolP384r1,
  brainpoolP512r1,
  jubjub,
} from '../src/misc.ts';
import {
  p256 as secp256r1,
  p256_FROST,
  p256_hasher,
  p384 as secp384r1,
  p384_hasher,
  p521 as secp521r1,
  p521_hasher,
} from '../src/nist.ts';
import { schnorr, secp256k1 } from '../src/secp256k1.ts';
import * as webcrypto from '../src/webcrypto.ts';

const CURVES = {
  secp256k1,
  secp256r1,
  secp384r1,
  secp521r1,
  ed25519,
  x25519,
  ed448,
  x448,
  schnorr,
};
const frozen = (name: string, value: object) => eql(Object.isFrozen(value), true, name);
const blocked = (name: string, obj: Record<string, unknown>, key: string, next: unknown) => {
  const prev = obj[key];
  let changed = false;
  try {
    obj[key] = next;
    changed = Object.is(obj[key], next);
  } catch {}
  try {
    obj[key] = prev;
  } catch {}
  eql(changed, false, `${name}.${key}`);
};

describe('info', () => {
  for (const name in CURVES) {
    const curve = CURVES[name];
    describe(name, () => {
      should('keys', () => {
        const len = curve.lengths;
        const privateKey = curve.utils.randomSecretKey();
        eql(privateKey.length, len.secretKey);
        const publicKey = curve.getPublicKey(privateKey);
        eql(publicKey.length, len.publicKey);
        if (curve.getSharedSecret) {
          const shared = curve.getSharedSecret(privateKey, publicKey);
          eql(shared.length, len.publicKey);
        }
        if (curve.sign) {
          const msg = new Uint8Array([1, 2, 3]);
          let sig = curve.sign(msg, privateKey);
          if (!isBytes(sig)) sig = sig.toBytes();
          eql(sig.length, len.signature);
          curve.verify(sig, msg, publicKey);
        }
        const seed = randomBytes(len.seed);
        eql(curve.utils.randomSecretKey(seed), curve.utils.randomSecretKey(seed));
        curve.getPublicKey(curve.utils.randomSecretKey(seed));
      });
      should('keygen', () => {
        const seed = randomBytes(curve.lengths.seed);
        const keys = curve.keygen(seed);
        eql(keys.secretKey, curve.utils.randomSecretKey(seed));
        eql(keys.publicKey, curve.getPublicKey(curve.utils.randomSecretKey(seed)));
      });
    });
  }

  should('freezes signer-style public bundles', () => {
    const signers = [
      ['ed25519', ed25519],
      ['ed25519ctx', ed25519ctx],
      ['ed25519ph', ed25519ph],
      ['ed448', ed448],
      ['ed448ph', ed448ph],
      ['jubjub', jubjub],
      ['babyjubjub', babyjubjub],
      ['p256', secp256r1],
      ['p384', secp384r1],
      ['p521', secp521r1],
      ['brainpoolP256r1', brainpoolP256r1],
      ['brainpoolP384r1', brainpoolP384r1],
      ['brainpoolP512r1', brainpoolP512r1],
    ] as const;
    for (const [name, curve] of signers) {
      frozen(name, curve);
      frozen(`${name}.Point`, curve.Point);
      frozen(`${name}.utils`, curve.utils);
      frozen(`${name}.lengths`, curve.lengths);
      blocked(name, curve as unknown as Record<string, unknown>, 'Point', class FakePoint {});
      blocked(
        `${name}.Point`,
        curve.Point as unknown as Record<string, unknown>,
        'fromBytes',
        () => 'spoof'
      );
      blocked(
        `${name}.utils`,
        curve.utils as unknown as Record<string, unknown>,
        'randomSecretKey',
        () => Uint8Array.of(7)
      );
      blocked(`${name}.lengths`, curve.lengths as unknown as Record<string, unknown>, 'seed', 1);
    }
  });

  should('freezes secp256k1 and schnorr helper surfaces', () => {
    frozen('secp256k1', secp256k1);
    frozen('secp256k1.Point', secp256k1.Point);
    frozen('secp256k1.utils', secp256k1.utils);
    frozen('secp256k1.lengths', secp256k1.lengths);
    frozen('secp256k1.Signature', secp256k1.Signature);
    frozen('secp256k1.Signature.prototype', secp256k1.Signature.prototype);
    blocked('secp256k1', secp256k1 as unknown as Record<string, unknown>, 'sign', () =>
      Uint8Array.of(7)
    );
    blocked(
      'secp256k1.Signature',
      secp256k1.Signature as unknown as Record<string, unknown>,
      'fromBytes',
      () => 'spoof'
    );
    blocked(
      'secp256k1.Signature.prototype',
      secp256k1.Signature.prototype as unknown as Record<string, unknown>,
      'toBytes',
      () => Uint8Array.of(7)
    );
    blocked(
      'secp256k1.lengths',
      secp256k1.lengths as unknown as Record<string, unknown>,
      'seed',
      1
    );

    frozen('schnorr', schnorr);
    frozen('schnorr.Point', schnorr.Point);
    frozen('schnorr.utils', schnorr.utils);
    frozen('schnorr.lengths', schnorr.lengths);
    blocked('schnorr', schnorr as unknown as Record<string, unknown>, 'sign', () =>
      Uint8Array.of(7)
    );
    blocked(
      'schnorr.utils',
      schnorr.utils as unknown as Record<string, unknown>,
      'pointToBytes',
      () => Uint8Array.of(8)
    );
    blocked('schnorr.lengths', schnorr.lengths as unknown as Record<string, unknown>, 'seed', 1);
  });

  should('freezes montgomery-style public bundles', () => {
    const curves = [
      ['x25519', x25519],
      ['x448', x448],
    ] as const;
    for (const [name, curve] of curves) {
      frozen(name, curve);
      frozen(`${name}.utils`, curve.utils);
      frozen(`${name}.lengths`, curve.lengths);
      blocked(
        `${name}.utils`,
        curve.utils as unknown as Record<string, unknown>,
        'randomSecretKey',
        () => Uint8Array.of(7)
      );
      blocked(`${name}.lengths`, curve.lengths as unknown as Record<string, unknown>, 'seed', 1);
    }
  });

  should('freezes prime-order wrapper bundles', () => {
    const curves = [
      ['ristretto255', ristretto255],
      ['decaf448', decaf448],
    ] as const;
    for (const [name, curve] of curves) {
      frozen(name, curve);
      frozen(`${name}.Point`, curve.Point);
      blocked(name, curve as unknown as Record<string, unknown>, 'Point', class FakePoint {});
      blocked(
        `${name}.Point`,
        curve.Point as unknown as Record<string, unknown>,
        'fromBytes',
        () => 'spoof'
      );
    }
  });

  should('freezes point prototypes and singleton instances', () => {
    const points = [
      ['ed25519.Point', ed25519.Point],
      ['p256.Point', secp256r1.Point],
      ['p384.Point', secp384r1.Point],
      ['p521.Point', secp521r1.Point],
      ['bn254.G1.Point', bn254.G1.Point],
      ['bn254.G2.Point', bn254.G2.Point],
      ['ed448.Point', ed448.Point],
      ['E448', E448],
      ['ristretto255.Point', ristretto255.Point],
      ['decaf448.Point', decaf448.Point],
    ] as const;
    for (const [name, Point] of points) {
      frozen(`${name}.prototype`, Point.prototype);
      blocked(
        `${name}.prototype`,
        Point.prototype as unknown as Record<string, unknown>,
        'toBytes',
        () => Uint8Array.of(7)
      );
    }

    const singletons = [
      ['ed25519.Point.BASE', ed25519.Point.BASE],
      ['ed25519.Point.ZERO', ed25519.Point.ZERO],
      ['p256.Point.BASE', secp256r1.Point.BASE],
      ['p256.Point.ZERO', secp256r1.Point.ZERO],
      ['bn254.G1.Point.BASE', bn254.G1.Point.BASE],
      ['bn254.G1.Point.ZERO', bn254.G1.Point.ZERO],
      ['bn254.G2.Point.BASE', bn254.G2.Point.BASE],
      ['bn254.G2.Point.ZERO', bn254.G2.Point.ZERO],
      ['ed448.Point.BASE', ed448.Point.BASE],
      ['ed448.Point.ZERO', ed448.Point.ZERO],
      ['E448.BASE', E448.BASE],
      ['E448.ZERO', E448.ZERO],
      ['ristretto255.Point.BASE', ristretto255.Point.BASE],
      ['ristretto255.Point.ZERO', ristretto255.Point.ZERO],
      ['decaf448.Point.BASE', decaf448.Point.BASE],
      ['decaf448.Point.ZERO', decaf448.Point.ZERO],
    ] as const;
    for (const [name, point] of singletons) {
      frozen(name, point);
      blocked(name, point as unknown as Record<string, unknown>, 'toBytes', () => Uint8Array.of(7));
    }
  });

  should('freezes hashers', () => {
    const hashers = [
      ['ed25519_hasher', ed25519_hasher],
      ['ed448_hasher', ed448_hasher],
      ['p256_hasher', p256_hasher],
      ['p384_hasher', p384_hasher],
      ['p521_hasher', p521_hasher],
    ] as const;
    for (const [name, hasher] of hashers) {
      frozen(name, hasher);
      blocked(
        name,
        hasher as unknown as Record<string, unknown>,
        'hashToCurve',
        () => hasher.Point.ZERO
      );
      blocked(
        name,
        hasher as unknown as Record<string, unknown>,
        'encodeToCurve',
        () => hasher.Point.ZERO
      );
      blocked(name, hasher as unknown as Record<string, unknown>, 'hashToScalar', () => 7n);
    }
    const older = [
      ['ristretto255_hasher', ristretto255_hasher],
      ['decaf448_hasher', decaf448_hasher],
    ] as const;
    for (const [name, hasher] of older) {
      frozen(name, hasher);
      blocked(
        name,
        hasher as unknown as Record<string, unknown>,
        'hashToCurve',
        () => hasher.Point.ZERO
      );
      blocked(
        name,
        hasher as unknown as Record<string, unknown>,
        'deriveToCurve',
        () => hasher.Point.ZERO
      );
      blocked(name, hasher as unknown as Record<string, unknown>, 'hashToScalar', () => 0n);
    }
  });

  should('freezes FROST bundles and helper namespaces', () => {
    const suites = [
      ['ed25519_FROST', ed25519_FROST],
      ['ed448_FROST', ed448_FROST],
      ['p256_FROST', p256_FROST],
      ['ristretto255_FROST', ristretto255_FROST],
    ] as const;
    for (const [name, frost] of suites) {
      frozen(name, frost);
      frozen(`${name}.Identifier`, frost.Identifier);
      frozen(`${name}.DKG`, frost.DKG);
      frozen(`${name}.utils`, frost.utils);
      blocked(
        `${name}.Identifier`,
        frost.Identifier as unknown as Record<string, unknown>,
        'fromNumber',
        () => 'zz'
      );
      blocked(`${name}.DKG`, frost.DKG as unknown as Record<string, unknown>, 'round1', () => ({
        public: 'bad',
        secret: 'bad',
      }));
      blocked(
        `${name}.utils`,
        frost.utils as unknown as Record<string, unknown>,
        'randomScalar',
        () => Uint8Array.of(7)
      );
    }
  });

  should('freezes pairing bundles and nested namespaces', () => {
    frozen('bls12_381', bls12_381);
    frozen('bls12_381.G1', bls12_381.G1);
    frozen('bls12_381.G2', bls12_381.G2);
    frozen('bls12_381.params', bls12_381.params);
    frozen('bls12_381.utils', bls12_381.utils);
    frozen('bls12_381.fields', bls12_381.fields);
    blocked(
      'bls12_381.G1',
      bls12_381.G1 as unknown as Record<string, unknown>,
      'hashToCurve',
      () => bls12_381.G1.Point.ZERO
    );
    blocked(
      'bls12_381.G2',
      bls12_381.G2 as unknown as Record<string, unknown>,
      'hashToCurve',
      () => bls12_381.G2.Point.ZERO
    );
    blocked(
      'bls12_381.params',
      bls12_381.params as unknown as Record<string, unknown>,
      'twistType',
      'divisive'
    );
    blocked(
      'bls12_381.utils',
      bls12_381.utils as unknown as Record<string, unknown>,
      'randomSecretKey',
      () => Uint8Array.of(7)
    );
    blocked('bls12_381.fields', bls12_381.fields as unknown as Record<string, unknown>, 'Fr', {
      ORDER: 1n,
    });

    frozen('bn254', bn254);
    frozen('bn254.G1', bn254.G1);
    frozen('bn254.G2', bn254.G2);
    frozen('bn254.params', bn254.params);
    frozen('bn254.utils', bn254.utils);
    frozen('bn254.fields', bn254.fields);
    blocked(
      'bn254.params',
      bn254.params as unknown as Record<string, unknown>,
      'twistType',
      'multiplicative'
    );
    blocked(
      'bn254.utils',
      bn254.utils as unknown as Record<string, unknown>,
      'randomSecretKey',
      () => Uint8Array.of(7)
    );
    blocked('bn254.fields', bn254.fields as unknown as Record<string, unknown>, 'Fp', {
      ORDER: 2n,
    });
  });

  should('freezes tower field instances', () => {
    const suites = [
      ['bn254', bn254.fields],
      ['bls12_381', bls12_381.fields],
    ] as const;
    for (const [name, fields] of suites) {
      frozen(`${name}.Fp2`, fields.Fp2);
      frozen(`${name}.Fp6`, fields.Fp6);
      frozen(`${name}.Fp12`, fields.Fp12);
      blocked(`${name}.Fp2`, fields.Fp2 as unknown as Record<string, unknown>, 'ORDER', 1n);
      blocked(`${name}.Fp2`, fields.Fp2 as unknown as Record<string, unknown>, 'mulByB', () => ({
        c0: 9n,
        c1: 9n,
      }));
      blocked(`${name}.Fp6`, fields.Fp6 as unknown as Record<string, unknown>, 'ORDER', 1n);
      blocked(
        `${name}.Fp6`,
        fields.Fp6 as unknown as Record<string, unknown>,
        'FROBENIUS_COEFFICIENTS_1',
        []
      );
      blocked(`${name}.Fp12`, fields.Fp12 as unknown as Record<string, unknown>, 'ORDER', 1n);
      blocked(
        `${name}.Fp12`,
        fields.Fp12 as unknown as Record<string, unknown>,
        'FROBENIUS_COEFFICIENTS',
        []
      );
    }
  });

  should('freezes exported debug arrays', () => {
    const arrays = [
      ['ED25519_TORSION_SUBGROUP', ED25519_TORSION_SUBGROUP],
      ['ED448_TORSION_SUBGROUP', ED448_TORSION_SUBGROUP],
    ] as const;
    for (const [name, items] of arrays) {
      frozen(name, items);
      blocked(name, items as unknown as Record<string, unknown>, '0', 'spoof');
    }
  });

  should('freezes factory-built weierstrass helper metadata', () => {
    const dh = ecdh(secp256r1.Point);
    const curve = ecdsa(secp256r1.Point, sha256);
    frozen('ecdh.lengths', dh.lengths);
    blocked('ecdh.lengths', dh.lengths as unknown as Record<string, unknown>, 'publicKey', 1);
    frozen('ecdsa.lengths', curve.lengths);
    blocked('ecdsa.lengths', curve.lengths as unknown as Record<string, unknown>, 'signature', 1);
  });

  should('freezes webcrypto and DER helper surfaces', () => {
    const suites = [
      ['webcrypto.ed25519', webcrypto.ed25519],
      ['webcrypto.ed448', webcrypto.ed448],
      ['webcrypto.p256', webcrypto.p256],
      ['webcrypto.p384', webcrypto.p384],
      ['webcrypto.p521', webcrypto.p521],
      ['webcrypto.x25519', webcrypto.x25519],
      ['webcrypto.x448', webcrypto.x448],
    ] as const;
    for (const [name, item] of suites) frozen(`${name}.utils`, item.utils);
    frozen('DER', DER);
  });
});

should.runWhen(import.meta.url);
