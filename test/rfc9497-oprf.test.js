import { describe, should } from 'micro-should';
import { deepStrictEqual as eql, notDeepEqual, throws } from 'node:assert';
import * as mod from '../esm/abstract/modular.js';
import {
  bytesToHex,
  hexToBytes,
  numberToBytesBE,
  numberToBytesLE,
  utf8ToBytes,
} from '../esm/abstract/utils.js';
import { ristretto255_OPRF } from '../esm/ed25519.js';
import { decaf448_OPRF } from '../esm/ed448.js';
import { p256_OPRF, p384_OPRF, p521_OPRF } from '../esm/nist.js';
import { json } from './utils.js';
const VECTORS = json('./vectors/rfc9497-oprf.json'); // Generated using rfc9497-oprf-parser.js

const BufferRNG = (lst) => {
  return (len) => {
    const res = lst.shift();
    if (!res) throw new Error('RNG empty');
    if (res.length !== len) throw new Error(`RNG wrong length ${len} (expected ${res.length})`);
    return res;
  };
};

const MockScalar = (Fn, bytes) => {
  const n = Fn.fromBytes(bytes);
  return (Fn.isLE ? numberToBytesLE : numberToBytesBE)(n - 1n, mod.getMinHashLength(Fn.ORDER));
};

const SUITES = {
  'P256-SHA256': p256_OPRF,
  'P384-SHA384': p384_OPRF,
  'P521-SHA512': p521_OPRF,
  'ristretto255-SHA512': ristretto255_OPRF,
  'decaf448-SHAKE256': decaf448_OPRF,
};

function testExample(name, oprf) {
  describe(name, () => {
    should('OPRF mode (base protocol)', () => {
      // 1. SETUP (Server-side)
      // The server generates a key pair. The client does not need to know anything.
      const serverKeys = oprf.oprf.generateKeyPair();

      // 2. BLIND (Client-side)
      // The client takes its private input and "blinds" it.
      const clientInput = utf8ToBytes('my super secret password');
      const { blind, blinded } = oprf.oprf.blind(clientInput);
      // The client MUST store the `blind` scalar locally for the final step.

      // 3. EVALUATE (Server-side)
      // The client sends the `blinded` element to the server.
      // The server evaluates it with its secret key.
      const evaluated = oprf.oprf.blindEvaluate(serverKeys.secretKey, blinded);

      // 4. FINALIZE (Client-side)
      // The server sends the `evaluated` element back to the client.
      // The client uses its stored `blind` scalar to "unblind" the result and get the final output.
      const clientOutput = oprf.oprf.finalize(clientInput, blind, evaluated);

      // VERIFICATION (For testing)
      // The non-interactive `evaluate` function should produce the same output.
      const expectedOutput = oprf.oprf.evaluate(serverKeys.secretKey, clientInput);
      eql(clientOutput, expectedOutput);
    });

    should('VOPRF mode (verifiable)', () => {
      // 1. SETUP
      // Server generates a key pair.
      const serverKeys = oprf.voprf.generateKeyPair();
      // For VOPRF, the client must know the server's public key.
      const clientsKnownPublicKey = serverKeys.publicKey;

      // 2. BLIND (Client-side)
      const clientInput = utf8ToBytes('another secret input');
      const { blind, blinded } = oprf.voprf.blind(clientInput);

      // 3. EVALUATE (Server-side)
      // The client sends `blinded` to the server.
      // The server evaluates it and also generates a proof of correct key usage.
      const { evaluated, proof } = oprf.voprf.blindEvaluate(
        serverKeys.secretKey,
        serverKeys.publicKey,
        blinded
      );

      // 4. FINALIZE (Client-side)
      // The server sends `evaluated` and `proof` back to the client.
      // The client's finalize function will internally verify the proof before unblinding.
      const clientOutput = oprf.voprf.finalize(
        clientInput,
        blind,
        evaluated,
        blinded, // Client needs the original blinded element for verification
        clientsKnownPublicKey, // Client uses the known public key for verification
        proof
      );

      // VERIFICATION
      const expectedOutput = oprf.voprf.evaluate(serverKeys.secretKey, clientInput);
      eql(clientOutput, expectedOutput);

      // NEGATIVE TEST: Ensure it fails with a bad proof or wrong public key.
      const badProof = new Uint8Array(proof.length).fill(1);
      throws(() =>
        oprf.voprf.finalize(clientInput, blind, evaluated, blinded, clientsKnownPublicKey, badProof)
      );
      const otherKeys = oprf.voprf.generateKeyPair();
      throws(() =>
        oprf.voprf.finalize(clientInput, blind, evaluated, blinded, otherKeys.publicKey, proof)
      );
    });

    should('POPRF mode (partially oblivious with domain separation)', () => {
      // The key difference: The protocol is initialized with a public `info` string.
      const info = utf8ToBytes('example.com login v2');
      const poprf = oprf.poprf(info); // This returns the API for this specific domain.

      // 1. SETUP
      const serverKeys = poprf.generateKeyPair();
      const clientsKnownPublicKey = serverKeys.publicKey;

      // 2. BLIND (Client-side)
      const clientInput = utf8ToBytes('a password for a specific domain');
      // The client's blind function also needs the server's public key for POPRF.
      const { blind, blinded, tweakedKey } = poprf.blind(clientInput, clientsKnownPublicKey);
      // The client must store `blind` and `tweakedKey` for the final step.

      // 3. EVALUATE (Server-side)
      // The server already knows the `info` string because its `poprf` instance was created with it.
      const { evaluated, proof } = poprf.blindEvaluate(serverKeys.secretKey, blinded);

      // 4. FINALIZE (Client-side)
      // The server sends `evaluated` and `proof` back.
      const clientOutput = poprf.finalize(
        clientInput,
        blind,
        evaluated,
        blinded,
        proof,
        tweakedKey // The client uses its stored tweakedKey for verification.
      );

      // VERIFICATION
      const expectedOutput = poprf.evaluate(serverKeys.secretKey, clientInput);
      eql(clientOutput, expectedOutput);

      // NEGATIVE TEST: Show that a different domain (`info`) produces a different output.
      const differentInfo = utf8ToBytes('example.com password-reset');
      const poprfForReset = oprf.poprf(differentInfo);
      const outputForReset = poprfForReset.evaluate(serverKeys.secretKey, clientInput);
      notDeepEqual(
        clientOutput,
        outputForReset,
        'Different domains MUST produce different outputs'
      );
    });
  });
}

describe('RFC-9497 (OPRF)', () => {
  describe('Examples', () => {
    for (const [name, suite] of Object.entries(SUITES)) {
      testExample(name, suite);
    }
  });

  for (const { suite, modes } of VECTORS) {
    should(suite, () => {
      if (!SUITES[suite]) throw new Error('missing');
      const prf = SUITES[suite];
      const Fn = prf.__tests.Fn;
      const mockRng = (lst) => BufferRNG(lst.map((i) => MockScalar(Fn, hexToBytes(i))));

      for (const mode of modes) {
        const name = mode.mode.split(' ')[0].toLowerCase();
        const OPRF = prf[name];
        const seed = hexToBytes(mode.common.Seed);
        const keyInfo = hexToBytes(mode.common.KeyInfo);

        for (const t of mode.tests) {
          //console.log('T', name, t, mode, t.data);
          const items = [];
          for (let i = 0; i < t.data.Input.length; i++) {
            let cur = {};
            for (const k in t.data) {
              const v = t.data[k];
              if (!Array.isArray(v)) continue;
              if (v.length !== t.data.Input.length) throw new Error('arr length mismatch');
              const k2 = {
                Input: 'input',
                Blind: 'blind',
                BlindedElement: 'blinded',
                EvaluationElement: 'evaluated',
                Output: 'output',
              }[k];
              if (!k2) throw new Error('no field: ' + k);
              cur[k2] = hexToBytes(v[i]);
            }
            items.push(cur);
          }
          const finalizeItems = items.map((i) => ({
            input: i.input,
            blind: i.blind,
            evaluated: i.evaluated,
            blinded: i.blinded,
          }));

          if (name === 'oprf' || name === 'voprf') {
            const keys = OPRF.deriveKeyPair(seed, keyInfo);
            eql(bytesToHex(keys.secretKey), mode.common.skSm);
            if (mode.common.pkSm) eql(bytesToHex(keys.publicKey), mode.common.pkSm);

            for (let i = 0; i < t.data.Input.length; i++) {
              const input = hexToBytes(t.data.Input[i]);
              const b = OPRF.blind(input, mockRng([t.data.Blind[i]]));
              eql(bytesToHex(b.blind), t.data.Blind[i]);
              eql(bytesToHex(b.blinded), t.data.BlindedElement[i]);
            }
            if (name === 'oprf') {
              const ev = OPRF.blindEvaluate(keys.secretKey, hexToBytes(t.data.BlindedElement[0]));
              eql(bytesToHex(ev), t.data.EvaluationElement[0]);
              const input = hexToBytes(t.data.Input[0]);
              eql(
                bytesToHex(OPRF.finalize(input, hexToBytes(t.data.Blind[0]), ev)),
                t.data.Output[0]
              );
              eql(bytesToHex(OPRF.evaluate(keys.secretKey, input)), t.data.Output[0]);
            }
            if (name === 'voprf') {
              for (let i = 0; i < t.data.Input.length; i++) {
                const input = hexToBytes(t.data.Input[i]);
                const b = OPRF.blind(input, mockRng([t.data.Blind[i]]));
                eql(bytesToHex(b.blind), t.data.Blind[i]);
                eql(bytesToHex(b.blinded), t.data.BlindedElement[i]);
              }
              if (t.data.Input.length === 1) {
                const { evaluated, proof } = OPRF.blindEvaluate(
                  keys.secretKey,
                  keys.publicKey,
                  hexToBytes(t.data.BlindedElement[0]),
                  mockRng([t.data.ProofRandomScalar])
                );
                eql(bytesToHex(evaluated), t.data.EvaluationElement[0]);
                eql(bytesToHex(proof), t.data.Proof);
                eql(
                  bytesToHex(
                    OPRF.finalize(
                      hexToBytes(t.data.Input[0]),
                      hexToBytes(t.data.Blind[0]),
                      hexToBytes(t.data.EvaluationElement[0]),
                      hexToBytes(t.data.BlindedElement[0]),
                      keys.publicKey,
                      hexToBytes(t.data.Proof)
                    )
                  ),
                  t.data.Output[0]
                );
              }
              // Batch works for size=1 too!
              const { evaluated, proof } = OPRF.blindEvaluateBatch(
                keys.secretKey,
                keys.publicKey,
                t.data.BlindedElement.map(hexToBytes),
                mockRng([t.data.ProofRandomScalar])
              );
              eql(evaluated.map(bytesToHex), t.data.EvaluationElement);
              eql(bytesToHex(proof), t.data.Proof);
              eql(
                OPRF.finalizeBatch(finalizeItems, keys.publicKey, hexToBytes(t.data.Proof)).map(
                  bytesToHex
                ),
                t.data.Output
              );
              for (let i = 0; i < t.data.Input.length; i++) {
                eql(
                  bytesToHex(OPRF.evaluate(keys.secretKey, hexToBytes(t.data.Input[i]))),
                  t.data.Output[i]
                );
              }
            }
          }
          if (name === 'poprf') {
            const POPRF = OPRF(hexToBytes(t.data.Info));
            const keys = POPRF.deriveKeyPair(seed, keyInfo);

            for (let i = 0; i < t.data.Input.length; i++) {
              const input = hexToBytes(t.data.Input[i]);
              const b = POPRF.blind(input, keys.publicKey, mockRng([t.data.Blind[i]]));
              eql(bytesToHex(b.blind), t.data.Blind[i]);
              eql(bytesToHex(b.blinded), t.data.BlindedElement[i]);
            }
            if (t.data.Input.length === 1) {
              const { evaluated, proof } = POPRF.blindEvaluate(
                keys.secretKey,
                hexToBytes(t.data.BlindedElement[0]),
                mockRng([t.data.ProofRandomScalar])
              );
              eql(bytesToHex(evaluated), t.data.EvaluationElement[0]);
              eql(bytesToHex(proof), t.data.Proof);

              const b = POPRF.blind(
                hexToBytes(t.data.Input[0]),
                keys.publicKey,
                mockRng([t.data.Blind[0]])
              );
              eql(
                bytesToHex(
                  POPRF.finalize(
                    hexToBytes(t.data.Input[0]),
                    hexToBytes(t.data.Blind[0]),
                    hexToBytes(t.data.EvaluationElement[0]),
                    hexToBytes(t.data.BlindedElement[0]),
                    hexToBytes(t.data.Proof),
                    b.tweakedKey
                  )
                ),
                t.data.Output[0]
              );
            }
            // Batch works for size=1 too!
            const { evaluated, proof } = POPRF.blindEvaluateBatch(
              keys.secretKey,
              t.data.BlindedElement.map(hexToBytes),
              mockRng([t.data.ProofRandomScalar])
            );
            eql(evaluated.map(bytesToHex), t.data.EvaluationElement);
            eql(bytesToHex(proof), t.data.Proof);
            const b = POPRF.blind(
              hexToBytes(t.data.Input[0]),
              keys.publicKey,
              mockRng([t.data.Blind[0]])
            );
            eql(
              POPRF.finalizeBatch(finalizeItems, hexToBytes(t.data.Proof), b.tweakedKey).map(
                bytesToHex
              ),
              t.data.Output
            );
            for (let i = 0; i < t.data.Input.length; i++) {
              eql(
                bytesToHex(POPRF.evaluate(keys.secretKey, hexToBytes(t.data.Input[i]))),
                t.data.Output[i]
              );
            }
          }
        }
      }
    });
  }
});

should.runWhen(import.meta.url);
