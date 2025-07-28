export function generateData(curve) {
  const priv = curve.utils.randomSecretKey();
  const pub = curve.getPublicKey(priv, true);
  const msg = curve.utils.randomSecretKey();
  const sig = curve.sign(msg, priv);
  const Point = curve.Point;
  const point = Point.fromBytes(pub);
  return { priv, pub, msg, sig, point, Point };
}

export function title(str) {
  console.log(`\x1b[36m# ${str}\x1b[0m`);
}
