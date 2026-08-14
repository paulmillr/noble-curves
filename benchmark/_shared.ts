export function generateData(curve) {
  const priv = curve.utils.randomSecretKey();
  const pub = curve.getPublicKey(priv, true);
  const msg = curve.utils.randomSecretKey();
  const sig = curve.sign(msg, priv);
  const isWeierstrass = !!curve.Point;
  const Point = isWeierstrass ? curve.Point : curve.Point;
  const point = Point.fromBytes(pub);
  return { priv, pub, msg, sig, point, Point, isWeierstrass };
}
