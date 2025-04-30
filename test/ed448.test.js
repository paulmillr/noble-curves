import { bytesToHex, concatBytes, hexToBytes, randomBytes } from '@noble/hashes/utils';
import * as fc from 'fast-check';
import { describe, should } from 'micro-should';
import { deepStrictEqual, throws } from 'node:assert';
import { numberToBytesLE } from '../esm/abstract/utils.js';
import { ed448, ed448ph, x448 } from '../esm/ed448.js';
import { json } from './utils.js';

// Old vectors allow to test sign() because they include private key
const ed448vectorsOld = json('./ed448/ed448_test_OLD.json');
const ed448vectors = json('./wycheproof/ed448_test.json');
const x448vectors = json('./wycheproof/x448_test.json');

describe('ed448', () => {
  const ed = ed448;
  const hex = bytesToHex;
  ed.utils.precompute(4);
  const Point = ed.ExtendedPoint;

  should(`Basic`, () => {
    const G1 = Point.BASE.toAffine();
    deepStrictEqual(
      G1.x,
      224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710n
    );
    deepStrictEqual(
      G1.y,
      298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660n
    );
    const G2 = Point.BASE.multiply(2n).toAffine();
    deepStrictEqual(
      G2.x,
      484559149530404593699549205258669689569094240458212040187660132787056912146709081364401144455726350866276831544947397859048262938744149n
    );
    deepStrictEqual(
      G2.y,
      494088759867433727674302672526735089350544552303727723746126484473087719117037293890093462157703888342865036477787453078312060500281069n
    );
    const G3 = Point.BASE.multiply(3n).toAffine();
    deepStrictEqual(
      G3.x,
      23839778817283171003887799738662344287085130522697782688245073320169861206004018274567429238677677920280078599146891901463786155880335n
    );
    deepStrictEqual(
      G3.y,
      636046652612779686502873775776967954190574036985351036782021535703553242737829645273154208057988851307101009474686328623630835377952508n
    );
  });

  should('Basic/decompress', () => {
    const G1 = Point.BASE;
    const G2 = Point.BASE.multiply(2n);
    const G3 = Point.BASE.multiply(3n);
    const points = [G1, G2, G3];
    const getXY = (p) => p.toAffine();
    for (const p of points) deepStrictEqual(getXY(Point.fromHex(p.toHex())), getXY(p));
  });

  const VECTORS_RFC8032 = [
    {
      secretKey:
        '6c82a562cb808d10d632be89c8513ebf' +
        '6c929f34ddfa8c9f63c9960ef6e348a3' +
        '528c8a3fcc2f044e39a3fc5b94492f8f' +
        '032e7549a20098f95b',
      publicKey:
        '5fd7449b59b461fd2ce787ec616ad46a' +
        '1da1342485a70e1f8a0ea75d80e96778' +
        'edf124769b46c7061bd6783df1e50f6c' +
        'd1fa1abeafe8256180',
      message: '',
      signature:
        '533a37f6bbe457251f023c0d88f976ae' +
        '2dfb504a843e34d2074fd823d41a591f' +
        '2b233f034f628281f2fd7a22ddd47d78' +
        '28c59bd0a21bfd3980ff0d2028d4b18a' +
        '9df63e006c5d1c2d345b925d8dc00b41' +
        '04852db99ac5c7cdda8530a113a0f4db' +
        'b61149f05a7363268c71d95808ff2e65' +
        '2600',
    },
    {
      secretKey:
        'c4eab05d357007c632f3dbb48489924d' +
        '552b08fe0c353a0d4a1f00acda2c463a' +
        'fbea67c5e8d2877c5e3bc397a659949e' +
        'f8021e954e0a12274e',
      publicKey:
        '43ba28f430cdff456ae531545f7ecd0a' +
        'c834a55d9358c0372bfa0c6c6798c086' +
        '6aea01eb00742802b8438ea4cb82169c' +
        '235160627b4c3a9480',

      message: '03',
      signature:
        '26b8f91727bd62897af15e41eb43c377' +
        'efb9c610d48f2335cb0bd0087810f435' +
        '2541b143c4b981b7e18f62de8ccdf633' +
        'fc1bf037ab7cd779805e0dbcc0aae1cb' +
        'cee1afb2e027df36bc04dcecbf154336' +
        'c19f0af7e0a6472905e799f1953d2a0f' +
        'f3348ab21aa4adafd1d234441cf807c0' +
        '3a00',
    },
    {
      secretKey:
        'cd23d24f714274e744343237b93290f5' +
        '11f6425f98e64459ff203e8985083ffd' +
        'f60500553abc0e05cd02184bdb89c4cc' +
        'd67e187951267eb328',
      publicKey:
        'dcea9e78f35a1bf3499a831b10b86c90' +
        'aac01cd84b67a0109b55a36e9328b1e3' +
        '65fce161d71ce7131a543ea4cb5f7e9f' +
        '1d8b00696447001400',
      message: '0c3e544074ec63b0265e0c',
      signature:
        '1f0a8888ce25e8d458a21130879b840a' +
        '9089d999aaba039eaf3e3afa090a09d3' +
        '89dba82c4ff2ae8ac5cdfb7c55e94d5d' +
        '961a29fe0109941e00b8dbdeea6d3b05' +
        '1068df7254c0cdc129cbe62db2dc957d' +
        'bb47b51fd3f213fb8698f064774250a5' +
        '028961c9bf8ffd973fe5d5c206492b14' +
        '0e00',
    },
    {
      secretKey:
        '258cdd4ada32ed9c9ff54e63756ae582' +
        'fb8fab2ac721f2c8e676a72768513d93' +
        '9f63dddb55609133f29adf86ec9929dc' +
        'cb52c1c5fd2ff7e21b',
      publicKey:
        '3ba16da0c6f2cc1f30187740756f5e79' +
        '8d6bc5fc015d7c63cc9510ee3fd44adc' +
        '24d8e968b6e46e6f94d19b945361726b' +
        'd75e149ef09817f580',
      message: '64a65f3cdedcdd66811e2915',
      signature:
        '7eeeab7c4e50fb799b418ee5e3197ff6' +
        'bf15d43a14c34389b59dd1a7b1b85b4a' +
        'e90438aca634bea45e3a2695f1270f07' +
        'fdcdf7c62b8efeaf00b45c2c96ba457e' +
        'b1a8bf075a3db28e5c24f6b923ed4ad7' +
        '47c3c9e03c7079efb87cb110d3a99861' +
        'e72003cbae6d6b8b827e4e6c143064ff' +
        '3c00',
    },
    {
      secretKey:
        '7ef4e84544236752fbb56b8f31a23a10' +
        'e42814f5f55ca037cdcc11c64c9a3b29' +
        '49c1bb60700314611732a6c2fea98eeb' +
        'c0266a11a93970100e',
      publicKey:
        'b3da079b0aa493a5772029f0467baebe' +
        'e5a8112d9d3a22532361da294f7bb381' +
        '5c5dc59e176b4d9f381ca0938e13c6c0' +
        '7b174be65dfa578e80',
      message: '64a65f3cdedcdd66811e2915e7',
      signature:
        '6a12066f55331b6c22acd5d5bfc5d712' +
        '28fbda80ae8dec26bdd306743c5027cb' +
        '4890810c162c027468675ecf645a8317' +
        '6c0d7323a2ccde2d80efe5a1268e8aca' +
        '1d6fbc194d3f77c44986eb4ab4177919' +
        'ad8bec33eb47bbb5fc6e28196fd1caf5' +
        '6b4e7e0ba5519234d047155ac727a105' +
        '3100',
    },
    {
      secretKey:
        'd65df341ad13e008567688baedda8e9d' +
        'cdc17dc024974ea5b4227b6530e339bf' +
        'f21f99e68ca6968f3cca6dfe0fb9f4fa' +
        'b4fa135d5542ea3f01',
      publicKey:
        'df9705f58edbab802c7f8363cfe5560a' +
        'b1c6132c20a9f1dd163483a26f8ac53a' +
        '39d6808bf4a1dfbd261b099bb03b3fb5' +
        '0906cb28bd8a081f00',
      message:
        'bd0f6a3747cd561bdddf4640a332461a' +
        '4a30a12a434cd0bf40d766d9c6d458e5' +
        '512204a30c17d1f50b5079631f64eb31' +
        '12182da3005835461113718d1a5ef944',
      signature:
        '554bc2480860b49eab8532d2a533b7d5' +
        '78ef473eeb58c98bb2d0e1ce488a98b1' +
        '8dfde9b9b90775e67f47d4a1c3482058' +
        'efc9f40d2ca033a0801b63d45b3b722e' +
        'f552bad3b4ccb667da350192b61c508c' +
        'f7b6b5adadc2c8d9a446ef003fb05cba' +
        '5f30e88e36ec2703b349ca229c267083' +
        '3900',
    },
    {
      secretKey:
        '2ec5fe3c17045abdb136a5e6a913e32a' +
        'b75ae68b53d2fc149b77e504132d3756' +
        '9b7e766ba74a19bd6162343a21c8590a' +
        'a9cebca9014c636df5',
      publicKey:
        '79756f014dcfe2079f5dd9e718be4171' +
        'e2ef2486a08f25186f6bff43a9936b9b' +
        'fe12402b08ae65798a3d81e22e9ec80e' +
        '7690862ef3d4ed3a00',
      message:
        '15777532b0bdd0d1389f636c5f6b9ba7' +
        '34c90af572877e2d272dd078aa1e567c' +
        'fa80e12928bb542330e8409f31745041' +
        '07ecd5efac61ae7504dabe2a602ede89' +
        'e5cca6257a7c77e27a702b3ae39fc769' +
        'fc54f2395ae6a1178cab4738e543072f' +
        'c1c177fe71e92e25bf03e4ecb72f47b6' +
        '4d0465aaea4c7fad372536c8ba516a60' +
        '39c3c2a39f0e4d832be432dfa9a706a6' +
        'e5c7e19f397964ca4258002f7c0541b5' +
        '90316dbc5622b6b2a6fe7a4abffd9610' +
        '5eca76ea7b98816af0748c10df048ce0' +
        '12d901015a51f189f3888145c03650aa' +
        '23ce894c3bd889e030d565071c59f409' +
        'a9981b51878fd6fc110624dcbcde0bf7' +
        'a69ccce38fabdf86f3bef6044819de11',
      signature:
        'c650ddbb0601c19ca11439e1640dd931' +
        'f43c518ea5bea70d3dcde5f4191fe53f' +
        '00cf966546b72bcc7d58be2b9badef28' +
        '743954e3a44a23f880e8d4f1cfce2d7a' +
        '61452d26da05896f0a50da66a239a8a1' +
        '88b6d825b3305ad77b73fbac0836ecc6' +
        '0987fd08527c1a8e80d5823e65cafe2a' +
        '3d00',
    },
    {
      secretKey:
        '872d093780f5d3730df7c212664b37b8' +
        'a0f24f56810daa8382cd4fa3f77634ec' +
        '44dc54f1c2ed9bea86fafb7632d8be19' +
        '9ea165f5ad55dd9ce8',
      publicKey:
        'a81b2e8a70a5ac94ffdbcc9badfc3feb' +
        '0801f258578bb114ad44ece1ec0e799d' +
        'a08effb81c5d685c0c56f64eecaef8cd' +
        'f11cc38737838cf400',
      message:
        '6ddf802e1aae4986935f7f981ba3f035' +
        '1d6273c0a0c22c9c0e8339168e675412' +
        'a3debfaf435ed651558007db4384b650' +
        'fcc07e3b586a27a4f7a00ac8a6fec2cd' +
        '86ae4bf1570c41e6a40c931db27b2faa' +
        '15a8cedd52cff7362c4e6e23daec0fbc' +
        '3a79b6806e316efcc7b68119bf46bc76' +
        'a26067a53f296dafdbdc11c77f7777e9' +
        '72660cf4b6a9b369a6665f02e0cc9b6e' +
        'dfad136b4fabe723d2813db3136cfde9' +
        'b6d044322fee2947952e031b73ab5c60' +
        '3349b307bdc27bc6cb8b8bbd7bd32321' +
        '9b8033a581b59eadebb09b3c4f3d2277' +
        'd4f0343624acc817804728b25ab79717' +
        '2b4c5c21a22f9c7839d64300232eb66e' +
        '53f31c723fa37fe387c7d3e50bdf9813' +
        'a30e5bb12cf4cd930c40cfb4e1fc6225' +
        '92a49588794494d56d24ea4b40c89fc0' +
        '596cc9ebb961c8cb10adde976a5d602b' +
        '1c3f85b9b9a001ed3c6a4d3b1437f520' +
        '96cd1956d042a597d561a596ecd3d173' +
        '5a8d570ea0ec27225a2c4aaff26306d1' +
        '526c1af3ca6d9cf5a2c98f47e1c46db9' +
        'a33234cfd4d81f2c98538a09ebe76998' +
        'd0d8fd25997c7d255c6d66ece6fa56f1' +
        '1144950f027795e653008f4bd7ca2dee' +
        '85d8e90f3dc315130ce2a00375a318c7' +
        'c3d97be2c8ce5b6db41a6254ff264fa6' +
        '155baee3b0773c0f497c573f19bb4f42' +
        '40281f0b1f4f7be857a4e59d416c06b4' +
        'c50fa09e1810ddc6b1467baeac5a3668' +
        'd11b6ecaa901440016f389f80acc4db9' +
        '77025e7f5924388c7e340a732e554440' +
        'e76570f8dd71b7d640b3450d1fd5f041' +
        '0a18f9a3494f707c717b79b4bf75c984' +
        '00b096b21653b5d217cf3565c9597456' +
        'f70703497a078763829bc01bb1cbc8fa' +
        '04eadc9a6e3f6699587a9e75c94e5bab' +
        '0036e0b2e711392cff0047d0d6b05bd2' +
        'a588bc109718954259f1d86678a579a3' +
        '120f19cfb2963f177aeb70f2d4844826' +
        '262e51b80271272068ef5b3856fa8535' +
        'aa2a88b2d41f2a0e2fda7624c2850272' +
        'ac4a2f561f8f2f7a318bfd5caf969614' +
        '9e4ac824ad3460538fdc25421beec2cc' +
        '6818162d06bbed0c40a387192349db67' +
        'a118bada6cd5ab0140ee273204f628aa' +
        'd1c135f770279a651e24d8c14d75a605' +
        '9d76b96a6fd857def5e0b354b27ab937' +
        'a5815d16b5fae407ff18222c6d1ed263' +
        'be68c95f32d908bd895cd76207ae7264' +
        '87567f9a67dad79abec316f683b17f2d' +
        '02bf07e0ac8b5bc6162cf94697b3c27c' +
        'd1fea49b27f23ba2901871962506520c' +
        '392da8b6ad0d99f7013fbc06c2c17a56' +
        '9500c8a7696481c1cd33e9b14e40b82e' +
        '79a5f5db82571ba97bae3ad3e0479515' +
        'bb0e2b0f3bfcd1fd33034efc6245eddd' +
        '7ee2086ddae2600d8ca73e214e8c2b0b' +
        'db2b047c6a464a562ed77b73d2d841c4' +
        'b34973551257713b753632efba348169' +
        'abc90a68f42611a40126d7cb21b58695' +
        '568186f7e569d2ff0f9e745d0487dd2e' +
        'b997cafc5abf9dd102e62ff66cba87',
      signature:
        'e301345a41a39a4d72fff8df69c98075' +
        'a0cc082b802fc9b2b6bc503f926b65bd' +
        'df7f4c8f1cb49f6396afc8a70abe6d8a' +
        'ef0db478d4c6b2970076c6a0484fe76d' +
        '76b3a97625d79f1ce240e7c576750d29' +
        '5528286f719b413de9ada3e8eb78ed57' +
        '3603ce30d8bb761785dc30dbc320869e' +
        '1a00',
    },
  ];

  describe('RFC8032', () => {
    for (let i = 0; i < VECTORS_RFC8032.length; i++) {
      const v = VECTORS_RFC8032[i];
      should(`${i}`, () => {
        deepStrictEqual(hex(ed.getPublicKey(v.secretKey)), v.publicKey);
        deepStrictEqual(hex(ed.sign(v.message, v.secretKey)), v.signature);
        deepStrictEqual(ed.verify(v.signature, v.message, v.publicKey), true);
      });
    }
  });

  should('not accept >57byte private keys', () => {
    const invalidPriv =
      100000000000000000000000000000000000009000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800073278156000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000n;
    throws(() => ed.getPublicKey(invalidPriv));
  });

  function to57Bytes(numOrStr) {
    let hex = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16);
    return hexToBytes(hex.padStart(114, '0'));
  }

  should('verify recent signature', () => {
    fc.assert(
      fc.property(
        fc.hexaString({ minLength: 2, maxLength: 57 }),
        fc.bigInt(2n, ed.CURVE.n),
        (message, privateKey) => {
          const publicKey = ed.getPublicKey(to57Bytes(privateKey));
          const signature = ed.sign(to57Bytes(message), to57Bytes(privateKey));
          deepStrictEqual(publicKey.length, 57);
          deepStrictEqual(signature.length, 114);
          deepStrictEqual(ed.verify(signature, to57Bytes(message), publicKey), true);
        }
      ),
      { numRuns: 5 }
    );
  });
  should('not verify signature with wrong message', () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 0x00, max: 0xff })),
        fc.array(fc.integer({ min: 0x00, max: 0xff })),
        fc.bigInt(1n, ed.CURVE.n),
        (bytes, wrongBytes, privateKey) => {
          const message = new Uint8Array(bytes);
          const wrongMessage = new Uint8Array(wrongBytes);
          const priv = to57Bytes(privateKey);
          const publicKey = ed.getPublicKey(priv);
          const signature = ed.sign(message, priv);
          deepStrictEqual(
            ed.verify(signature, wrongMessage, publicKey),
            bytes.toString() === wrongBytes.toString()
          );
        }
      ),
      { numRuns: 5 }
    );
  });
  const privKey = to57Bytes('a665a45920422f9d417e4867ef');
  const msg = hexToBytes('874f9960c5d2b7a9b5fad383e1ba44719ebb743a');
  const wrongMsg = hexToBytes('589d8c7f1da0a24bc07b7381ad48b1cfc211af1c');
  describe('basic methods', () => {
    should('sign and verify', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      deepStrictEqual(ed.verify(signature, msg, publicKey), true);
    });
    should('not verify signature with wrong public key', () => {
      const publicKey = ed.getPublicKey(ed.utils.randomPrivateKey());
      const signature = ed.sign(msg, privKey);
      deepStrictEqual(ed.verify(signature, msg, publicKey), false);
    });
    should('not verify signature with wrong hash', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      deepStrictEqual(ed.verify(signature, wrongMsg, publicKey), false);
    });
  });
  describe('sync methods', () => {
    should('sign and verify', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      deepStrictEqual(ed.verify(signature, msg, publicKey), true);
    });
    should('not verify signature with wrong public key', () => {
      const publicKey = ed.getPublicKey(ed.utils.randomPrivateKey());
      const signature = ed.sign(msg, privKey);
      deepStrictEqual(ed.verify(signature, msg, publicKey), false);
    });
    should('not verify signature with wrong hash', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      deepStrictEqual(ed.verify(signature, wrongMsg, publicKey), false);
    });
  });

  should('BASE_POINT.multiply() throws in Point#multiply on TEST 5', () => {
    for (const num of [0n, 0, -1n, -1, 1.1]) {
      throws(() => ed.ExtendedPoint.BASE.multiply(num));
    }
  });

  should('input immutability: sign/verify are immutable', () => {
    const privateKey = ed.utils.randomPrivateKey();
    const publicKey = ed.getPublicKey(privateKey);

    for (let i = 0; i < 100; i++) {
      let pay = randomBytes(100); // payload
      let sig = ed.sign(pay, privateKey);
      if (!ed.verify(sig, pay, publicKey)) throw new Error('Signature verification failed');
      if (typeof Buffer === 'undefined') {
        if (!ed.verify(sig.slice(), pay.slice(), publicKey))
          throw new Error('Signature verification failed');
      } else {
        const signatureCopy = Buffer.alloc(sig.byteLength);
        signatureCopy.set(sig, 0); // <-- breaks
        pay = pay.slice();
        sig = sig.slice();

        if (!ed.verify(signatureCopy, pay, publicKey))
          throw new Error('Copied signature verification failed');
      }
    }
  });

  describe('wycheproof (OLD)', () => {
    for (let g = 0; g < ed448vectorsOld.testGroups.length; g++) {
      const group = ed448vectorsOld.testGroups[g];
      const key = group.key;
      should(`ED448(${g}, public)`, () => {
        deepStrictEqual(hex(ed.getPublicKey(key.sk)), key.pk);
      });
      should(`ED448`, () => {
        for (let i = 0; i < group.tests.length; i++) {
          const v = group.tests[i];
          const index = `${g}/${i} ${v.comment}`;
          if (v.result === 'valid' || v.result === 'acceptable') {
            deepStrictEqual(hex(ed.sign(v.msg, key.sk)), v.sig, index);
            deepStrictEqual(ed.verify(v.sig, v.msg, key.pk), true, index);
          } else if (v.result === 'invalid') {
            let failed = false;
            try {
              failed = !ed.verify(v.sig, v.msg, key.pk);
            } catch (error) {
              failed = true;
            }
            deepStrictEqual(failed, true, index);
          } else throw new Error('unknown test result');
        }
      });
    }
  });

  describe('wycheproof', () => {
    for (let g = 0; g < ed448vectors.testGroups.length; g++) {
      const group = ed448vectors.testGroups[g];
      const key = group.publicKey;
      should(`ED448`, () => {
        for (let i = 0; i < group.tests.length; i++) {
          const v = group.tests[i];
          const index = `${g}/${i} ${v.comment}`;
          if (v.result === 'valid' || v.result === 'acceptable') {
            deepStrictEqual(ed.verify(v.sig, v.msg, key.pk), true, index);
          } else if (v.result === 'invalid') {
            let failed = false;
            try {
              failed = !ed.verify(v.sig, v.msg, key.pk);
            } catch (error) {
              failed = true;
            }
            deepStrictEqual(failed, true, index);
          } else throw new Error('unknown test result');
        }
      });
    }
  });
  // should('X448: should convert base point to montgomery using fromPoint', () => {
  //   deepStrictEqual(
  //     hex(ed.montgomeryCurve.UfromPoint(Point.BASE)),
  //     ed.montgomeryCurve.BASE_POINT_U
  //   );
  // });

  // should('X448/getSharedSecret() should be commutative', async () => {
  //   for (let i = 0; i < 512; i++) {
  //     const asec = ed.utils.randomPrivateKey();
  //     const apub = ed.getPublicKey(asec);
  //     const bsec = ed.utils.randomPrivateKey();
  //     const bpub = ed.getPublicKey(bsec);
  //     try {
  //       deepStrictEqual(ed.getSharedSecret(asec, bpub), ed.getSharedSecret(bsec, apub));
  //     } catch (error) {
  //       console.error('not commutative', { asec, apub, bsec, bpub });
  //       throw error;
  //     }
  //   }
  // });

  describe('ed448ctx', () => {
    const VECTORS_RFC8032_CTX = [
      {
        secretKey:
          'c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e',
        publicKey:
          '43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480',
        message: '03',
        context: '666f6f',
        signature:
          'd4f8f6131770dd46f40867d6fd5d5055' +
          'de43541f8c5e35abbcd001b32a89f7d2' +
          '151f7647f11d8ca2ae279fb842d60721' +
          '7fce6e042f6815ea000c85741de5c8da' +
          '1144a6a1aba7f96de42505d7a7298524' +
          'fda538fccbbb754f578c1cad10d54d0d' +
          '5428407e85dcbc98a49155c13764e66c' +
          '3c00',
      },
    ];
    for (let i = 0; i < VECTORS_RFC8032_CTX.length; i++) {
      const v = VECTORS_RFC8032_CTX[i];
      should(`${i}`, () => {
        deepStrictEqual(hex(ed.getPublicKey(v.secretKey)), v.publicKey);
        deepStrictEqual(hex(ed.sign(v.message, v.secretKey, { context: v.context })), v.signature);
        deepStrictEqual(
          ed.verify(v.signature, v.message, v.publicKey, { context: v.context }),
          true
        );
      });
    }
  });

  describe('ed448ph', () => {
    const VECTORS_RFC8032_PH = [
      {
        secretKey:
          '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49',
        publicKey:
          '259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880',
        message: '616263',
        signature:
          '822f6901f7480f3d5f562c592994d969' +
          '3602875614483256505600bbc281ae38' +
          '1f54d6bce2ea911574932f52a4e6cadd' +
          '78769375ec3ffd1b801a0d9b3f4030cd' +
          '433964b6457ea39476511214f97469b5' +
          '7dd32dbc560a9a94d00bff07620464a3' +
          'ad203df7dc7ce360c3cd3696d9d9fab9' +
          '0f00',
      },
      {
        secretKey:
          '833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42ef7822e0d5104127dc05d6dbefde69e3ab2cec7c867c6e2c49',
        publicKey:
          '259b71c19f83ef77a7abd26524cbdb3161b590a48f7d17de3ee0ba9c52beb743c09428a131d6b1b57303d90d8132c276d5ed3d5d01c0f53880',
        message: '616263',
        context: '666f6f',
        signature:
          'c32299d46ec8ff02b54540982814dce9' +
          'a05812f81962b649d528095916a2aa48' +
          '1065b1580423ef927ecf0af5888f90da' +
          '0f6a9a85ad5dc3f280d91224ba9911a3' +
          '653d00e484e2ce232521481c8658df30' +
          '4bb7745a73514cdb9bf3e15784ab7128' +
          '4f8d0704a608c54a6b62d97beb511d13' +
          '2100',
      },
    ];
    for (let i = 0; i < VECTORS_RFC8032_PH.length; i++) {
      const v = VECTORS_RFC8032_PH[i];
      should(`${i}`, () => {
        deepStrictEqual(hex(ed448ph.getPublicKey(v.secretKey)), v.publicKey);
        deepStrictEqual(
          hex(ed448ph.sign(v.message, v.secretKey, { context: v.context })),
          v.signature
        );
        deepStrictEqual(
          ed448ph.verify(v.signature, v.message, v.publicKey, { context: v.context }),
          true
        );
      });
    }
  });

  should('not verify when sig.s >= CURVE.n', () => {
    function get56bSig() {
      const privateKey = ed448.utils.randomPrivateKey();
      const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
      const publicKey = ed448.getPublicKey(privateKey);
      const signature = ed448.sign(message, privateKey);

      const R = signature.slice(0, 56);
      let s = signature.slice(56, 112);

      s = bytesToHex(s.slice().reverse());
      s = BigInt('0x' + s);
      s = s + ed448.CURVE.n;
      s = numberToBytesLE(s, 56);

      const sig_invalid = concatBytes(R, s);
      return { sig_invalid, message, publicKey };
    }
    let sig;
    while (true) {
      try {
        sig = get56bSig();
        break;
      } catch (error) {
        // non-56b sig was generated, try again
      }
    }
    throws(() => {
      ed448.verify(sig.sig_invalid, sig.message, sig.publicKey);
    });
  });

  describe('RFC7748 X448 ECDH', () => {
    // ECDH
    const rfc7748Mul = [
      {
        scalar:
          '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3',
        u: '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086',
        outputU:
          'ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f',
      },
      {
        scalar:
          '203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f',
        u: '0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db',
        outputU:
          '884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d',
      },
    ];
    for (let i = 0; i < rfc7748Mul.length; i++) {
      const v = rfc7748Mul[i];
      should(`scalarMult (${i})`, () => {
        deepStrictEqual(hex(x448.scalarMult(v.scalar, v.u)), v.outputU);
      });
    }

    const rfc7748Iter = [
      {
        scalar:
          '3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113',
        iters: 1,
      },
      {
        scalar:
          'aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38',
        iters: 1000,
      },
      // { scalar: '077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37', iters: 1000000 },
    ];
    for (let i = 0; i < rfc7748Iter.length; i++) {
      const { scalar, iters } = rfc7748Iter[i];
      should(`scalarMult iterated ${iters}x`, () => {
        let k = x448.GuBytes;
        for (let i = 0, u = k; i < iters; i++) [k, u] = [x448.scalarMult(k, u), k];
        deepStrictEqual(hex(k), scalar);
      });
    }

    should('getSharedKey', () => {
      const alicePrivate =
        '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b';
      const alicePublic =
        '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0';
      const bobPrivate =
        '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d';
      const bobPublic =
        '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609';
      const shared =
        '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d';
      deepStrictEqual(alicePublic, hex(x448.getPublicKey(alicePrivate)));
      deepStrictEqual(bobPublic, hex(x448.getPublicKey(bobPrivate)));
      deepStrictEqual(hex(x448.scalarMult(alicePrivate, bobPublic)), shared);
      deepStrictEqual(hex(x448.scalarMult(bobPrivate, alicePublic)), shared);
    });

    should('wycheproof', () => {
      const group = x448vectors.testGroups[0];
      group.tests.forEach((v, i) => {
        const index = `(${i}, ${v.result}) ${v.comment}`;
        if (v.result === 'valid' || v.result === 'acceptable') {
          try {
            const shared = hex(x448.scalarMult(v.private, v.public));
            deepStrictEqual(shared, v.shared, index);
          } catch (e) {
            // We are more strict
            if (e.message.includes('invalid private or public key received')) return;
            throw e;
          }
        } else if (v.result === 'invalid') {
          let failed = false;
          try {
            x448.scalarMult(v.private, v.public);
          } catch (error) {
            failed = true;
          }
          deepStrictEqual(failed, true, index);
        } else throw new Error('unknown test result');
      });
    });

    should('have proper base point', () => {
      const { x, y } = Point.BASE;
      const { Fp } = ed448.CURVE;
      // const invX = Fp.invert(x * x); // x²
      const u = Fp.div(Fp.create(y * y), Fp.create(x * x)); // (y²/x²)
      // const u = Fp.create(y * y * invX);
      deepStrictEqual(numberToBytesLE(u, 56), x448.GuBytes);
    });
  });
});

should.runWhen(import.meta.url);
