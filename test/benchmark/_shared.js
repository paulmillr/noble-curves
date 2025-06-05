export function generateData(curve) {
  const priv = curve.utils.randomPrivateKey();
  const pub = curve.getPublicKey(priv, true);
  const msg = curve.utils.randomPrivateKey();
  const sig = curve.sign(msg, priv);
  const isWeierstrass = !!curve.ProjectivePoint;
  const Point = isWeierstrass ? curve.ProjectivePoint : curve.ExtendedPoint;
  const point = Point.fromHex(pub);
  return { priv, pub, msg, sig, point, Point, isWeierstrass };
}

export function title(str) {
  console.log(`\x1b[36m# ${str}\x1b[0m`);
}
