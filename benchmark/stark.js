import { run, mark, compare, utils } from 'micro-bmark';
import * as starkwareCrypto from '@starkware-industries/starkware-crypto-utils';
import * as stark from '../lib/stark.js';

run(async () => {
  const RAM = false;
  if (RAM) utils.logMem();
  console.log(`\x1b[36msecp256k1\x1b[0m`);
  await mark('init', 1, () => stark.utils.precompute(8));
  const d = (() => {
    const priv = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
    const msg = 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47';
    const pub = stark.getPublicKey(priv);
    const sig = stark.sign(msg, priv);

    const privateKey = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
    const msgHash = 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47';
    const keyPair = starkwareCrypto.default.ec.keyFromPrivate(privateKey, 'hex');
    const publicKeyStark = starkwareCrypto.default.ec.keyFromPublic(
      keyPair.getPublic(true, 'hex'),
      'hex'
    );
    return { priv, sig, msg, pub, publicKeyStark, msgHash, keyPair };
  })();
  await compare('pedersen', 500, {
    old: () => {
      return starkwareCrypto.default.pedersen([
        '3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
        '208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a',
      ]);
    },
    noble: () => {
      return stark.pedersen(
        '3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
        '208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a'
      );
    },
  });
  await mark('poseidon', 10000, () => stark.poseidonHash(
    0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cbn,
    0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31an
  ));
  await compare('verify', 500, {
    old: () => {
      return starkwareCrypto.default.verify(
        d.publicKeyStark,
        d.msgHash,
        starkwareCrypto.default.sign(d.keyPair, d.msgHash)
      );
    },
    noble: () => {
      return stark.verify(stark.sign(d.msg, d.priv), d.msg, d.pub);
    },
  });
  if (RAM) utils.logMem();
});
