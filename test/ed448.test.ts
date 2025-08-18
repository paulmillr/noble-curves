import {
  hexToBytes as bytes,
  concatBytes,
  bytesToHex as hex,
  randomBytes,
} from '@noble/hashes/utils.js';
import * as fc from 'fast-check';
import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, throws } from 'node:assert';
import { ed448, ed448ph, x448 } from '../src/ed448.ts';
import { numberToBytesLE } from '../src/utils.ts';
import { json } from './utils.ts';

const VECTORS_rfc8032_ed448 = json('./vectors/rfc8032-ed448.json');
// Old vectors allow to test sign() because they include private key
const ed448vectorsOld = json('./vectors/ed448/ed448_test_OLD.json');
const ed448vectors = json('./vectors/wycheproof/ed448_test.json');
const x448vectors = json('./vectors/wycheproof/x448_test.json');

describe('ed448', () => {
  const ed = ed448;
  ed448.Point.BASE.precompute(4, false);
  const Point = ed.Point;

  should(`Basic`, () => {
    const G1 = Point.BASE.toAffine();
    eql(
      G1.x,
      224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710n
    );
    eql(
      G1.y,
      298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660n
    );
    const G2 = Point.BASE.multiply(2n).toAffine();
    eql(
      G2.x,
      484559149530404593699549205258669689569094240458212040187660132787056912146709081364401144455726350866276831544947397859048262938744149n
    );
    eql(
      G2.y,
      494088759867433727674302672526735089350544552303727723746126484473087719117037293890093462157703888342865036477787453078312060500281069n
    );
    const G3 = Point.BASE.multiply(3n).toAffine();
    eql(
      G3.x,
      23839778817283171003887799738662344287085130522697782688245073320169861206004018274567429238677677920280078599146891901463786155880335n
    );
    eql(
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
    for (const p of points) eql(getXY(Point.fromBytes(p.toBytes())), getXY(p));
  });

  should('RFC8032', () => {
    for (let i = 0; i < VECTORS_rfc8032_ed448.length; i++) {
      const v = VECTORS_rfc8032_ed448[i];
      eql(hex(ed.getPublicKey(bytes(v.secretKey))), v.publicKey);
      eql(hex(ed.sign(bytes(v.message), bytes(v.secretKey))), v.signature);
      eql(ed.verify(bytes(v.signature), bytes(v.message), bytes(v.publicKey)), true);
    }
  });

  should('not accept >57byte private keys', () => {
    throws(() => ed.getPublicKey(new Uint8Array(58).fill(2)));
  });

  function bytes57(numOrStr) {
    let hex2 = typeof numOrStr === 'string' ? numOrStr : numOrStr.toString(16);
    return bytes(hex2.padStart(114, '0'));
  }

  function hexa() {
    const items = '0123456789abcdef';
    return fc.integer({ min: 0, max: 15 }).map((n) => items[n]);
  }
  function hexaString(constraints = {}) {
    return fc.string({ ...constraints, unit: hexa() });
  }

  should('verify recent signature', () => {
    fc.assert(
      fc.property(
        hexaString({ minLength: 2, maxLength: 57 }),
        fc.bigInt(2n, ed.Point.Fn.ORDER),
        (message, privateKey) => {
          const publicKey = ed.getPublicKey(bytes57(privateKey));
          const signature = ed.sign(bytes57(message), bytes57(privateKey));
          eql(publicKey.length, 57);
          eql(signature.length, 114);
          eql(ed.verify(signature, bytes57(message), publicKey), true);
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
        fc.bigInt(1n, ed.Point.Fn.ORDER),
        (bytes, wrongBytes, privateKey) => {
          const message = new Uint8Array(bytes);
          const wrongMessage = new Uint8Array(wrongBytes);
          const priv = bytes57(privateKey);
          const publicKey = ed.getPublicKey(priv);
          const signature = ed.sign(message, priv);
          eql(
            ed.verify(signature, wrongMessage, publicKey),
            bytes.toString() === wrongBytes.toString()
          );
        }
      ),
      { numRuns: 5 }
    );
  });
  const privKey = bytes57('a665a45920422f9d417e4867ef');
  const msg = bytes('874f9960c5d2b7a9b5fad383e1ba44719ebb743a');
  const wrongMsg = bytes('589d8c7f1da0a24bc07b7381ad48b1cfc211af1c');
  describe('basic methods', () => {
    should('sign and verify', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      eql(ed.verify(signature, msg, publicKey), true);
    });
    should('not verify signature with wrong public key', () => {
      const publicKey = ed.getPublicKey(ed.utils.randomSecretKey());
      const signature = ed.sign(msg, privKey);
      eql(ed.verify(signature, msg, publicKey), false);
    });
    should('not verify signature with wrong hash', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      eql(ed.verify(signature, wrongMsg, publicKey), false);
    });
  });
  describe('sync methods', () => {
    should('sign and verify', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      eql(ed.verify(signature, msg, publicKey), true);
    });
    should('not verify signature with wrong public key', () => {
      const publicKey = ed.getPublicKey(ed.utils.randomSecretKey());
      const signature = ed.sign(msg, privKey);
      eql(ed.verify(signature, msg, publicKey), false);
    });
    should('not verify signature with wrong hash', () => {
      const publicKey = ed.getPublicKey(privKey);
      const signature = ed.sign(msg, privKey);
      eql(ed.verify(signature, wrongMsg, publicKey), false);
    });
  });

  should('BASE_POINT.multiply() throws in Point#multiply on TEST 5', () => {
    for (const num of [0n, 0, -1n, -1, 1.1]) {
      throws(() => ed.Point.BASE.multiply(num));
    }
  });

  should('input immutability: sign/verify are immutable', () => {
    const privateKey = ed.utils.randomSecretKey();
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
        eql(hex(ed.getPublicKey(bytes(key.sk))), key.pk);
      });
      should(`ED448`, () => {
        for (let i = 0; i < group.tests.length; i++) {
          const v = group.tests[i];
          const index = `${g}/${i} ${v.comment}`;
          if (v.result === 'valid' || v.result === 'acceptable') {
            eql(hex(ed.sign(bytes(v.msg), bytes(key.sk))), v.sig, index);
            eql(ed.verify(bytes(v.sig), bytes(v.msg), bytes(key.pk)), true, index);
          } else if (v.result === 'invalid') {
            let failed = false;
            try {
              failed = !ed.verify(bytes(v.sig), bytes(v.msg), bytes(key.pk));
            } catch (error) {
              failed = true;
            }
            eql(failed, true, index);
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
            eql(ed.verify(bytes(v.sig), bytes(v.msg), bytes(key.pk)), true, index);
          } else if (v.result === 'invalid') {
            let failed = false;
            try {
              failed = !ed.verify(bytes(v.sig), bytes(v.msg), bytes(key.pk));
            } catch (error) {
              failed = true;
            }
            eql(failed, true, index);
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
  //     const asec = ed.utils.randomSecretKey();
  //     const apub = ed.getPublicKey(asec);
  //     const bsec = ed.utils.randomSecretKey();
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
        eql(hex(ed.getPublicKey(bytes(v.secretKey))), v.publicKey);
        eql(
          hex(ed.sign(bytes(v.message), bytes(v.secretKey), { context: bytes(v.context) })),
          v.signature
        );
        eql(
          ed.verify(bytes(v.signature), bytes(v.message), bytes(v.publicKey), {
            context: bytes(v.context),
          }),
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
        eql(hex(ed448ph.getPublicKey(bytes(v.secretKey))), v.publicKey);
        eql(
          hex(
            ed448ph.sign(bytes(v.message), bytes(v.secretKey), { context: bytes(v.context || '') })
          ),
          v.signature
        );
        eql(
          ed448ph.verify(bytes(v.signature), bytes(v.message), bytes(v.publicKey), {
            context: v.context ? bytes(v.context) : Uint8Array.of(),
          }),
          true
        );
      });
    }
  });

  should('not verify when sig.s >= CURVE.n', () => {
    function get56bSig() {
      const privateKey = ed448.utils.randomSecretKey();
      const message = Uint8Array.from([0xab, 0xbc, 0xcd, 0xde]);
      const publicKey = ed448.getPublicKey(privateKey);
      const signature = ed448.sign(message, privateKey);

      const R = signature.slice(0, 56);
      let s = signature.slice(56, 112);

      s = hex(s.slice().reverse());
      s = BigInt('0x' + s);
      s = s + ed448.Point.Fn.ORDER;
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
        eql(hex(x448.scalarMult(bytes(v.scalar), bytes(v.u))), v.outputU);
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
        eql(hex(k), scalar);
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
      eql(alicePublic, hex(x448.getPublicKey(bytes(alicePrivate))));
      eql(bobPublic, hex(x448.getPublicKey(bytes(bobPrivate))));
      eql(hex(x448.scalarMult(bytes(alicePrivate), bytes(bobPublic))), shared);
      eql(hex(x448.scalarMult(bytes(bobPrivate), bytes(alicePublic))), shared);
    });

    should('wycheproof', () => {
      const group = x448vectors.testGroups[0];
      group.tests.forEach((v, i) => {
        const index = `(${i}, ${v.result}) ${v.comment}`;
        if (v.result === 'valid' || v.result === 'acceptable') {
          try {
            const shared = hex(x448.scalarMult(bytes(v.private), bytes(v.public)));
            eql(shared, v.shared, index);
          } catch (e) {
            // We are more strict
            if (e.message.includes('invalid private or public key received')) return;
            throw e;
          }
        } else if (v.result === 'invalid') {
          let failed = false;
          try {
            x448.scalarMult(bytes(v.private), bytes(v.public));
          } catch (error) {
            failed = true;
          }
          eql(failed, true, index);
        } else throw new Error('unknown test result');
      });
    });

    should('have proper base point', () => {
      const { x, y } = Point.BASE;
      const { Fp } = ed448.Point;
      // const invX = Fp.invert(x * x); // x²
      const u = Fp.div(Fp.create(y * y), Fp.create(x * x)); // (y²/x²)
      // const u = Fp.create(y * y * invX);
      eql(numberToBytesLE(u, 56), x448.GuBytes);
    });
  });
});

should.runWhen(import.meta.url);
