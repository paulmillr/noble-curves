import { ed25519, ristretto255 } from '@noble/curves/ed25519.js';
import { decaf448, ed448 } from '@noble/curves/ed448.js';
import { babyjubjub, jubjub } from '@noble/curves/misc.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';

const curves = [
  secp256k1, schnorr, p256, p384, p521, ed25519, ed448,
  ristretto255, decaf448,
  bls12_381.curves.G1, bls12_381.curves.G2, bn254.curves.G1, bn254.curves.G2,
  jubjub, babyjubjub
];
for (const curve of curves) {
  console.log(111, curve);
  const { info, Point } = curve;
  const { BASE, ZERO, Fp, Fn } = Point;
  const p = BASE.multiply(2n);

  // Initialization
  if (info.type === 'weierstrass') {
    // projective (homogeneous) coordinates: (X, Y, Z) ∋ (x=X/Z, y=Y/Z)
    const p_ = new Point(BASE.X, BASE.Y, BASE.Z);
  } else if (info.type === 'edwards') {
    // extended coordinates: (X, Y, Z, T) ∋ (x=X/Z, y=Y/Z)
    const p_ = new Point(BASE.X, BASE.Y, BASE.Z, BASE.T);
  }

  // Math
  const p1 = p.add(p);
  const p2 = p.double();
  const p3 = p.subtract(p);
  const p4 = p.negate();
  const p5 = p.multiply(451n);

  // MSM (multi-scalar multiplication)
  const pa = [BASE, BASE.multiply(2n), BASE.multiply(4n), BASE.multiply(8n)];
  const p6 = Point.msm(pa, [3n, 5n, 7n, 11n]);
  const truthful = p6.equals(BASE.multiply(129n)); // 129*G

  const pcl = p.clearCofactor();

  const r1 = p.toBytes();
  const r1_ = Point.fromBytes(r1);
  const r2 = p.toAffine();
  const { x, y } = r2;
  const r2_ = Point.fromAffine(r2);

  console.log(r1.toHex(), r2);
}
