export function generateData(curve) {
  const priv = curve.utils.randomPrivateKey();
  const pub = curve.getPublicKey(priv);
  const msg = curve.utils.randomPrivateKey();
  const sig = curve.sign(msg, priv);
  return { priv, pub, msg, sig };
}
