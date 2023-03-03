import { deepStrictEqual, throws } from 'assert';
import { describe, should } from 'micro-should';
import { utf8ToBytes } from '@noble/hashes/utils';
import * as bip32 from '@scure/bip32';
import * as bip39 from '@scure/bip39';
import * as starknet from '../../stark.js';
import { default as sigVec } from './fixtures/rfc6979_signature_test_vector.json' assert { type: 'json' };
import { default as precomputedKeys } from './fixtures/keys_precomputed.json' assert { type: 'json' };

describe('starknet', () => {
  should('custom keccak', () => {
    const value = starknet.keccak(utf8ToBytes('hello'));
    deepStrictEqual(value, 0x8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8n);
    deepStrictEqual(value < 2n ** 250n, true);
  });

  should('RFC6979', () => {
    for (const msg of sigVec.messages) {
      const { r, s } = starknet.sign(msg.hash, sigVec.private_key);
      // const { r, s } = starknet.Signature.fromDER(sig);
      deepStrictEqual(r.toString(10), msg.r);
      deepStrictEqual(s.toString(10), msg.s);
    }
  });

  should('Signatures', () => {
    const vectors = [
      {
        // Message hash of length 61.
        msg: 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47',
        r: '5f496f6f210b5810b2711c74c15c05244dad43d18ecbbdbe6ed55584bc3b0a2',
        s: '4e8657b153787f741a67c0666bad6426c3741b478c8eaa3155196fc571416f3',
      },
      {
        // Message hash of length 61, with leading zeros.
        msg: '00c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47',
        r: '5f496f6f210b5810b2711c74c15c05244dad43d18ecbbdbe6ed55584bc3b0a2',
        s: '4e8657b153787f741a67c0666bad6426c3741b478c8eaa3155196fc571416f3',
      },
      {
        // Message hash of length 62.
        msg: 'c465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47a',
        r: '233b88c4578f0807b4a7480c8076eca5cfefa29980dd8e2af3c46a253490e9c',
        s: '28b055e825bc507349edfb944740a35c6f22d377443c34742c04e0d82278cf1',
      },
      {
        // Message hash of length 63.
        msg: '7465dd6b1bbffdb05442eb17f5ca38ad1aa78a6f56bf4415bdee219114a47a1',
        r: 'b6bee8010f96a723f6de06b5fa06e820418712439c93850dd4e9bde43ddf',
        s: '1a3d2bc954ed77e22986f507d68d18115fa543d1901f5b4620db98e2f6efd80',
      },
    ];
    const privateKey = '2dccce1da22003777062ee0870e9881b460a8b7eca276870f57c601f182136c';
    const publicKey = starknet.getPublicKey(privateKey);
    for (const v of vectors) {
      const sig = starknet.sign(v.msg, privateKey);
      const { r, s } = sig;
      // const { r, s } = starknet.Signature.fromDER(sig);
      deepStrictEqual(r.toString(16), v.r, 'r equality');
      deepStrictEqual(s.toString(16), v.s, 's equality');
      deepStrictEqual(starknet.verify(sig, v.msg, publicKey), true, 'verify');
    }
  });

  should('Invalid signatures', () => {
    /*

    it('should not verify invalid signature inputs lengths', () => {
      const ecOrder = starkwareCrypto.ec.n;
      const {maxEcdsaVal} = starkwareCrypto;
      const maxMsgHash = maxEcdsaVal.sub(oneBn);
      const maxR = maxEcdsaVal.sub(oneBn);
      const maxS = ecOrder.sub(oneBn).sub(oneBn);
      const maxStarkKey = maxEcdsaVal.sub(oneBn);

      // Test invalid message length.
      expect(() =>
        starkwareCrypto.verify(maxStarkKey, maxMsgHash.add(oneBn).toString(16), {
          r: maxR,
          s: maxS
        })
      ).to.throw('Message not signable, invalid msgHash length.');
      // Test invalid r length.
      expect(() =>
        starkwareCrypto.verify(maxStarkKey, maxMsgHash.toString(16), {
          r: maxR.add(oneBn),
          s: maxS
        })
      ).to.throw('Message not signable, invalid r length.');
      // Test invalid w length.
      expect(() =>
        starkwareCrypto.verify(maxStarkKey, maxMsgHash.toString(16), {
          r: maxR,
          s: maxS.add(oneBn)
        })
      ).to.throw('Message not signable, invalid w length.');
      // Test invalid s length.
      expect(() =>
        starkwareCrypto.verify(maxStarkKey, maxMsgHash.toString(16), {
          r: maxR,
          s: maxS.add(oneBn).add(oneBn)
        })
      ).to.throw('Message not signable, invalid s length.');
    });

    it('should not verify invalid signatures', () => {
      const privKey = generateRandomStarkPrivateKey();
      const keyPair = starkwareCrypto.ec.keyFromPrivate(privKey, 'hex');
      const keyPairPub = starkwareCrypto.ec.keyFromPublic(
        keyPair.getPublic(),
        'BN'
      );
      const msgHash = new BN(randomHexString(61));
      const msgSignature = starkwareCrypto.sign(keyPair, msgHash);

      // Test invalid public key.
      const invalidKeyPairPub = starkwareCrypto.ec.keyFromPublic(
        {x: keyPairPub.pub.getX().add(oneBn), y: keyPairPub.pub.getY()},
        'BN'
      );
      expect(
        starkwareCrypto.verify(
          invalidKeyPairPub,
          msgHash.toString(16),
          msgSignature
        )
      ).to.be.false;
      // Test invalid message.
      expect(
        starkwareCrypto.verify(
          keyPair,
          msgHash.add(oneBn).toString(16),
          msgSignature
        )
      ).to.be.false;
      expect(
        starkwareCrypto.verify(
          keyPairPub,
          msgHash.add(oneBn).toString(16),
          msgSignature
        )
      ).to.be.false;
      // Test invalid r.
      msgSignature.r.iadd(oneBn);
      expect(starkwareCrypto.verify(keyPair, msgHash.toString(16), msgSignature))
        .to.be.false;
      expect(
        starkwareCrypto.verify(keyPairPub, msgHash.toString(16), msgSignature)
      ).to.be.false;
      // Test invalid s.
      msgSignature.r.isub(oneBn);
      msgSignature.s.iadd(oneBn);
      expect(starkwareCrypto.verify(keyPair, msgHash.toString(16), msgSignature))
        .to.be.false;
      expect(
        starkwareCrypto.verify(keyPairPub, msgHash.toString(16), msgSignature)
      ).to.be.false;
    });
  });
    */
  });

  should('Pedersen', () => {
    deepStrictEqual(
      starknet.pedersen(
        '0x3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb',
        '0x208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a'
      ),
      '0x30e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662'
    );
    deepStrictEqual(
      starknet.pedersen(
        '0x58f580910a6ca59b28927c08fe6c43e2e303ca384badc365795fc645d479d45',
        '0x78734f65a067be9bdb39de18434d71e79f7b6466a4b66bbd979ab9e7515fe0b'
      ),
      '0x68cc0b76cddd1dd4ed2301ada9b7c872b23875d5ff837b3a87993e0d9996b87'
    );
  });

  should('Hash chain', () => {
    deepStrictEqual(starknet.hashChain([1, 2, 3]), starknet.pedersen(1, starknet.pedersen(2, 3)));
  });

  should('Key grinding', () => {
    deepStrictEqual(
      starknet.grindKey('86F3E7293141F20A8BAFF320E8EE4ACCB9D4A4BF2B4D295E8CEE784DB46E0519'),
      '5c8c8683596c732541a59e03007b2d30dbbbb873556fe65b5fb63c16688f941'
    );
    // Loops more than once (verified manually)
    deepStrictEqual(
      starknet.grindKey('94F3E7293141F20A8BAFF320E8EE4ACCB9D4A4BF2B4D295E8CEE784DB46E0595'),
      '33880b9aba464c1c01c9f8f5b4fc1134698f9b0a8d18505cab6cdd34d93dc02'
    );
  });

  should('Private to stark key', () => {
    deepStrictEqual(
      starknet.getStarkKey('0x178047D3869489C055D7EA54C014FFB834A069C9595186ABE04EA4D1223A03F'),
      '0x1895a6a77ae14e7987b9cb51329a5adfb17bd8e7c638f92d6892d76e51cebcf'
    );
    for (const [privKey, expectedPubKey] of Object.entries(precomputedKeys)) {
      deepStrictEqual(starknet.getStarkKey(privKey), expectedPubKey);
    }
  });

  should('Private stark key from eth signature', () => {
    const ethSignature =
      '0x21fbf0696d5e0aa2ef41a2b4ffb623bcaf070461d61cf7251c74161f82fec3a43' +
      '70854bc0a34b3ab487c1bc021cd318c734c51ae29374f2beb0e6f2dd49b4bf41c';
    deepStrictEqual(
      starknet.ethSigToPrivate(ethSignature),
      '766f11e90cd7c7b43085b56da35c781f8c067ac0d578eabdceebc4886435bda'
    );
  });

  should('Key derivation', () => {
    const layer = 'starkex';
    const application = 'starkdeployement';
    const mnemonic =
      'range mountain blast problem vibrant void vivid doctor cluster enough melody ' +
      'salt layer language laptop boat major space monkey unit glimpse pause change vibrant';
    const ethAddress = '0xa4864d977b944315389d1765ffa7e66F74ee8cd7';
    const VECTORS = [
      {
        index: 0,
        path: "m/2645'/579218131'/891216374'/1961790679'/2135936222'/0",
        privateKey: '6cf0a8bf113352eb863157a45c5e5567abb34f8d32cddafd2c22aa803f4892c',
      },
      {
        index: 7,
        path: "m/2645'/579218131'/891216374'/1961790679'/2135936222'/7",
        privateKey: '341751bdc42841da35ab74d13a1372c1f0250617e8a2ef96034d9f46e6847af',
      },
      {
        index: 598,
        path: "m/2645'/579218131'/891216374'/1961790679'/2135936222'/598",
        privateKey: '41a4d591a868353d28b7947eb132aa4d00c4a022743689ffd20a3628d6ca28c',
      },
    ];
    const hd = bip32.HDKey.fromMasterSeed(bip39.mnemonicToSeedSync(mnemonic));
    for (const { index, path, privateKey } of VECTORS) {
      const realPath = starknet.getAccountPath(layer, application, ethAddress, index);
      deepStrictEqual(realPath, path);
      deepStrictEqual(starknet.grindKey(hd.derive(realPath).privateKey), privateKey);
    }
  });

  // Verified against starknet.js
  should('Starknet.js cross-tests', () => {
    const privateKey = '0x019800ea6a9a73f94aee6a3d2edf018fc770443e90c7ba121e8303ec6b349279';
    // NOTE: there is no compressed keys here, getPubKey returns stark-key (which is schnorr-like X coordinate)
    // But it is not used in signing/verifying
    deepStrictEqual(
      starknet.getStarkKey(privateKey),
      '0x33f45f07e1bd1a51b45fc24ec8c8c9908db9e42191be9e169bfcac0c0d99745'
    );
    const msgHash = '0x6d1706bd3d1ba7c517be2a2a335996f63d4738e2f182144d078a1dd9997062e';
    const sig = starknet.sign(msgHash, privateKey);
    const { r, s } = sig;

    deepStrictEqual(
      r.toString(),
      '1427981024487605678086498726488552139932400435436186597196374630267616399345'
    );
    deepStrictEqual(
      s.toString(),
      '1853664302719670721837677288395394946745467311923401353018029119631574115563'
    );
    const hashMsg2 = starknet.pedersen(
      '0x33f45f07e1bd1a51b45fc24ec8c8c9908db9e42191be9e169bfcac0c0d99745',
      '1'
    );
    deepStrictEqual(hashMsg2, '0x2b0d4d43acce8ff68416f667f92ec7eab2b96f1d2224abd4d9d4d1e7fa4bb00');
    const pubKey =
      '04033f45f07e1bd1a51b45fc24ec8c8c9908db9e42191be9e169bfcac0c0d997450319d0f53f6ca077c4fa5207819144a2a4165daef6ee47a7c1d06c0dcaa3e456';
    const sig2 = new starknet.Signature(
      558858382392827003930138586379728730695763862039474863361948210004201119180n,
      2440689354481625417078677634625227600823892606910345662891037256374285369343n
    );
    deepStrictEqual(starknet.verify(sig2.toDERHex(), hashMsg2, pubKey), true);
  });
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
