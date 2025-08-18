import { describe, should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual as eql, notDeepEqual, throws } from 'node:assert';
import * as mod from '../src/abstract/modular.ts';
import { ristretto255_oprf } from '../src/ed25519.ts';
import { decaf448_oprf } from '../src/ed448.ts';
import { p256_oprf, p384_oprf, p521_oprf } from '../src/nist.ts';
import { asciiToBytes, numberToBytesBE, numberToBytesLE } from '../src/utils.ts';
import { deepHexToBytes, json } from './utils.ts';
const VECTORS = deepHexToBytes(json('./vectors/rfc9497-oprf.json')); // Generated using rfc9497-oprf-parser.js

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
  'P256-SHA256': p256_oprf,
  'P384-SHA384': p384_oprf,
  'P521-SHA512': p521_oprf,
  'ristretto255-SHA512': ristretto255_oprf,
  'decaf448-SHAKE256': decaf448_oprf,
};

function testExample(name, oprf) {
  describe(name, () => {
    should('OPRF mode (base protocol)', () => {
      // 1. SETUP (Server-side)
      // The server generates a key pair. The client does not need to know anything.
      const serverKeys = oprf.oprf.generateKeyPair();

      // 2. BLIND (Client-side)
      // The client takes its private input and "blinds" it.
      const clientInput = asciiToBytes('my super secret password');
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
      const clientInput = asciiToBytes('another secret input');
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
      const info = asciiToBytes('example.com login v2');
      const poprf = oprf.poprf(info); // This returns the API for this specific domain.

      // 1. SETUP
      const serverKeys = poprf.generateKeyPair();
      const clientsKnownPublicKey = serverKeys.publicKey;

      // 2. BLIND (Client-side)
      const clientInput = asciiToBytes('a password for a specific domain');
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
      const differentInfo = asciiToBytes('example.com password-reset');
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
      const mockRng = (lst) => BufferRNG(lst.map((i) => MockScalar(Fn, i)));

      for (const mode of modes) {
        const name = mode.mode.split(' ')[0].toLowerCase();
        const OPRF = prf[name];
        const seed = mode.common.Seed;
        const keyInfo = mode.common.KeyInfo;

        for (const t of mode.tests) {
          //console.log('T', name, t, mode, t.data);
          const Proof = t.data.Proof ? t.data.Proof : undefined;
          const ProofRandomScalar = t.data.ProofRandomScalar ? t.data.ProofRandomScalar : undefined;
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
              cur[k2] = v[i];
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
            eql(keys.secretKey, mode.common.skSm);
            if (mode.common.pkSm) eql(keys.publicKey, mode.common.pkSm);

            for (let i = 0; i < t.data.Input.length; i++) {
              const b = OPRF.blind(items[i].input, mockRng([items[i].blind]));
              eql(b.blind, items[i].blind);
              eql(b.blinded, items[i].blinded);
            }
            if (name === 'oprf') {
              const ev = OPRF.blindEvaluate(keys.secretKey, items[0].blinded);
              eql(ev, items[0].evaluated);
              const input = items[0].input;
              eql(OPRF.finalize(input, items[0].blind, ev), items[0].output);
              eql(OPRF.evaluate(keys.secretKey, input), items[0].output);
            }
            if (name === 'voprf') {
              for (let i = 0; i < t.data.Input.length; i++) {
                const b = OPRF.blind(items[i].input, mockRng([items[i].blind]));
                eql(b.blind, items[i].blind);
                eql(b.blinded, items[i].blinded);
              }
              if (t.data.Input.length === 1) {
                const { evaluated, proof } = OPRF.blindEvaluate(
                  keys.secretKey,
                  keys.publicKey,
                  items[0].blinded,
                  mockRng([ProofRandomScalar])
                );
                eql(evaluated, items[0].evaluated);
                eql(proof, Proof);
                eql(
                  OPRF.finalize(
                    items[0].input,
                    items[0].blind,
                    items[0].evaluated,
                    items[0].blinded,
                    keys.publicKey,
                    Proof
                  ),
                  items[0].output
                );
              }
              // Batch works for size=1 too!
              const { evaluated, proof } = OPRF.blindEvaluateBatch(
                keys.secretKey,
                keys.publicKey,
                items.map((i) => i.blinded),
                mockRng([ProofRandomScalar])
              );
              eql(
                evaluated,
                items.map((i) => i.evaluated)
              );
              eql(proof, Proof);
              eql(
                OPRF.finalizeBatch(finalizeItems, keys.publicKey, Proof),
                items.map((i) => i.output)
              );
              for (let i = 0; i < t.data.Input.length; i++) {
                eql(OPRF.evaluate(keys.secretKey, items[i].input), items[i].output);
              }
            }
          }
          if (name === 'poprf') {
            const POPRF = OPRF(t.data.Info);
            const keys = POPRF.deriveKeyPair(seed, keyInfo);

            for (let i = 0; i < t.data.Input.length; i++) {
              const b = POPRF.blind(items[i].input, keys.publicKey, mockRng([items[i].blind]));
              eql(b.blind, items[i].blind);
              eql(b.blinded, items[i].blinded);
            }
            if (t.data.Input.length === 1) {
              const { evaluated, proof } = POPRF.blindEvaluate(
                keys.secretKey,
                items[0].blinded,
                mockRng([ProofRandomScalar])
              );
              eql(evaluated, items[0].evaluated);
              eql(proof, Proof);

              const b = POPRF.blind(items[0].input, keys.publicKey, mockRng([items[0].blind]));
              eql(
                POPRF.finalize(
                  items[0].input,
                  items[0].blind,
                  items[0].evaluated,
                  items[0].blinded,
                  Proof,
                  b.tweakedKey
                ),
                items[0].output
              );
            }
            // Batch works for size=1 too!
            const { evaluated, proof } = POPRF.blindEvaluateBatch(
              keys.secretKey,
              items.map((i) => i.blinded),
              mockRng([ProofRandomScalar])
            );
            eql(
              evaluated,
              items.map((i) => i.evaluated)
            );
            eql(proof, Proof);
            const b = POPRF.blind(items[0].input, keys.publicKey, mockRng([items[0].blind]));
            eql(
              POPRF.finalizeBatch(finalizeItems, Proof, b.tweakedKey),
              items.map((i) => i.output)
            );
            for (let i = 0; i < t.data.Input.length; i++) {
              eql(POPRF.evaluate(keys.secretKey, items[i].input), items[i].output);
            }
          }
        }
      }
    });
  }
});

should.runWhen(import.meta.url);
