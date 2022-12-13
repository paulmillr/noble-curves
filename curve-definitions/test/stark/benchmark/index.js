import * as microStark from '../../../lib/starknet.js';
import * as starkwareCrypto from '@starkware-industries/starkware-crypto-utils';
import * as bench from 'micro-bmark';
const { run, mark } = bench; // or bench.mark

const privateKey = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
const msgHash = 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47';
const keyPair = starkwareCrypto.default.ec.keyFromPrivate(privateKey, 'hex');
const publicKeyStark = starkwareCrypto.default.ec.keyFromPublic(
  keyPair.getPublic(true, 'hex'),
  'hex'
);
const publicKeyMicro = microStark.getPublicKey(privateKey);

const FNS = {
  pedersenHash: {
    samples: 250,
    starkware: () =>
      starkwareCrypto.default.pedersen([
        '3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
        '208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a',
      ]),
    'micro-starknet': () =>
      microStark.pedersen(
        '3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
        '208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a'
      ),
  },
  signVerify: {
    samples: 500,
    starkware: () =>
      starkwareCrypto.default.verify(
        publicKeyStark,
        msgHash,
        starkwareCrypto.default.sign(keyPair, msgHash)
      ),
    'micro-starknet': () =>
      microStark.verify(microStark.sign(msgHash, privateKey), msgHash, publicKeyMicro),
  },
};

const main = () =>
  run(async () => {
    for (let [k, libs] of Object.entries(FNS)) {
      console.log(`==== ${k} ====`);
      for (const [lib, fn] of Object.entries(libs)) {
        if (lib === 'samples') continue;
        let title = `${k} (${lib})`;
        await mark(title, libs.samples, () => fn());
      }
      console.log();
    }
    // Log current RAM
    bench.logMem();
  });

main();
