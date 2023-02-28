import { deepStrictEqual, throws } from 'assert';
import { describe, should } from 'micro-should';
import * as starknet from '../../esm/stark.js';
import { bytesToHex as hex } from '@noble/hashes/utils';
import * as fs from 'fs';

function parseTest(path) {
  let data = fs.readFileSync(path, 'ascii');
  // Remove whitespaces
  data = data.replace(/[ |\t]/g, '');
  const pattern =
    'Rate=(\\d+)\n' +
    'Capacity=(\\d+)\n' +
    'FullRounds=(\\d+)\n' +
    'PartialRounds=(\\d+)\n' +
    'MDS=\\[(.+)\\]\n' +
    'RoundKeys=\\(?\n?\\[\n?(.+)\n?\\]\n?\\)?';
  const r = data.match(new RegExp(pattern, 'ms'));

  function parseArray(s) {
    // Remove new lines
    s = s.replace(/\n/gms, '');
    return s.match(/(\[.+?\])/g).map((i) =>
      i
        .replace(/^\[(.+)\]$/, '$1')
        .split(',')
        .filter((i) => !!i)
    );
  }
  const res = {
    rate: +r[1],
    capacity: +r[2],
    roundsFull: +r[3],
    roundsPartial: +r[4],
    MDS: parseArray(r[5]).map((i) => i.map((j) => BigInt(j))),
    roundConstants: parseArray(r[6]).map((i) => i.map((j) => BigInt(j))),
  };
  return res;
}

function mapPoseidon(parsed) {
  return starknet.poseidonBasic(
    {
      Fp: starknet.Fp251,
      rate: parsed.rate,
      capacity: parsed.capacity,
      roundsFull: parsed.roundsFull,
      roundsPartial: parsed.roundsPartial,
    },
    parsed.MDS
  );
}

const parsed = {
  poseidon3: parseTest('./test/stark/poseidon/poseidon3.txt'),
  poseidon4: parseTest('./test/stark/poseidon/poseidon4.txt'),
  poseidon5: parseTest('./test/stark/poseidon/poseidon5.txt'),
  poseidon9: parseTest('./test/stark/poseidon/poseidon9.txt'),
};

function poseidonTest(name, parsed) {
  should(`${name}`, () => {
    const fn = mapPoseidon(parsed);
    deepStrictEqual(fn.roundConstants, parsed.roundConstants);
  });
}

describe('poseidon txt vectors', () => {
  poseidonTest('poseidon3', parsed.poseidon3);
  poseidonTest('poseidon4', parsed.poseidon4);
  poseidonTest('poseidon5', parsed.poseidon5);
  poseidonTest('poseidon9', parsed.poseidon9);
});

should('Poseidon examples', () => {
  const p3 = mapPoseidon(parsed.poseidon3);
  deepStrictEqual(p3([0n, 0n, 0n]), [
    3446325744004048536138401612021367625846492093718951375866996507163446763827n,
    1590252087433376791875644726012779423683501236913937337746052470473806035332n,
    867921192302518434283879514999422690776342565400001269945778456016268852423n,
  ]);
  const p4 = mapPoseidon(parsed.poseidon4);
  deepStrictEqual(p4([0n, 0n, 0n, 0n]), [
    535071095200566880914603862188010633478042591441142518549720701573192347548n,
    3567335813488551850156302853280844225974867890860330236555401145692518003968n,
    229995103310401763929738317978722680640995513996113588430855556460153357543n,
    3513983790849716360905369754287999509206472929684378838050290392634812839312n,
  ]);
  const p5 = mapPoseidon(parsed.poseidon5);
  deepStrictEqual(p5([0n, 0n, 0n, 0n, 0n]), [
    2337689130971531876049206831496963607805116499042700598724344149414565980684n,
    3230969295497815870174763682436655274044379544854667759151474216427142025631n,
    3297330512217530111610698859408044542971696143761201570393504997742535648562n,
    2585480844700786541432072704002477919020588246983274666988914431019064343941n,
    3595308260654382824623573767385493361624474708214823462901432822513585995028n,
  ]);
  const p9 = mapPoseidon(parsed.poseidon9);
  deepStrictEqual(p9([0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]), [
    1534116856660032929112709488204491699743182428465681149262739677337223235050n,
    1710856073207389764546990138116985223517553616229641666885337928044617114700n,
    3165864635055638516987240200217592641540231237468651257819894959934472989427n,
    1003007637710164252047715558598366312649052908276423203724288341354608811559n,
    68117303579957054409211824649914588822081700129416361923518488718489651489n,
    1123395637839379807713801282868237406546107732595903195840754789810160564711n,
    478590974834311070537087181212389392308746075734019180430422247431982932503n,
    835322726024358888065061514739954009068852229059154336727219387089732433787n,
    3129703030204995742174502162918848446737407262178341733578946634564864233056n,
  ]);
});

should('Poseidon 2', () => {
  // Cross-test with cairo-lang 0.11
  deepStrictEqual(
    starknet.poseidonHash(1n, 1n),
    315729444126170353286530004158376771769107830460625027134495740547491428733n
  );
  deepStrictEqual(
    starknet.poseidonHash(123n, 123n),
    3149184350054566761517315875549307360045573205732410509163060794402900549639n
  );
  deepStrictEqual(
    starknet.poseidonHash(1231231231231231231231231312312n, 1231231231231231231231231312312n),
    2544250291965936388474000136445328679708604225006461780180655815882994563864n
  );
  // poseidonHashSingle
  deepStrictEqual(
    starknet.poseidonHashSingle(1n),
    3085182978037364507644541379307921604860861694664657935759708330416374536741n
  );
  deepStrictEqual(
    starknet.poseidonHashSingle(123n),
    2751345659320901472675327541550911744303539407817894466726181731796247467344n
  );
  deepStrictEqual(
    starknet.poseidonHashSingle(1231231231231231231231231312312n),
    3083085683696942145160394401206391098729120397175152900096470498748103599322n
  );
  // poseidonHashMany
  throws(() => starknet.poseidonHash(new Uint8Array([1, 2, 3])));
  deepStrictEqual(
    starknet.poseidonHashMany([1n]),
    154809849725474173771833689306955346864791482278938452209165301614543497938n
  );
  deepStrictEqual(
    starknet.poseidonHashMany([1n, 2n]),
    1557996165160500454210437319447297236715335099509187222888255133199463084263n
  );
  deepStrictEqual(
    starknet.poseidonHashMany([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]),
    976552833909388839716191681593200982850734838655927116322079791360264131378n
  );
  deepStrictEqual(
    starknet.poseidonHashMany([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 1n, 2n, 3n, 4n, 5n, 6n, 7n]),
    1426681430756292883765769449684978541173830451959857824597431064948702170774n
  );
  deepStrictEqual(
    starknet.poseidonHashMany([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 1n, 2n, 3n, 4n, 5n, 6n]),
    3578895185591466904832617962452140411216018208734547126302182794057260630783n
  );
  deepStrictEqual(
    starknet.poseidonHashMany([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 1n, 2n, 3n, 4n, 5n]),
    2047942584693618630610564708884241243670450597197937863619828684896211911953n
  );
  deepStrictEqual(
    starknet.poseidonHashMany([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 1n, 2n, 3n, 4n]),
    717812721730784692894550948559585317289413466140233907962980309405694367376n
  );
  deepStrictEqual(
    starknet.poseidonHashMany([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 1n, 2n, 3n]),
    2926122208425648133778911655767364584769133265503722614793281770361723147648n
  );
  deepStrictEqual(
    starknet.poseidonHashMany([
      154809849725474173771833689306955346864791482278938452209165301614543497938n,
      1557996165160500454210437319447297236715335099509187222888255133199463084263n,
      976552833909388839716191681593200982850734838655927116322079791360264131378n,
      1426681430756292883765769449684978541173830451959857824597431064948702170774n,
      3578895185591466904832617962452140411216018208734547126302182794057260630783n,
    ]),
    1019392520709073131437410341528874594624843119359955302374885123884546721410n
  );
  // poseidon_hash_func
  deepStrictEqual(
    hex(starknet.poseidonHashFunc(new Uint8Array([1, 2]), new Uint8Array([3, 4]))),
    '01f87cbb9c58139605384d0f0df49b446600af020aa9dac92301d45c96d78c0a'
  );
  deepStrictEqual(
    hex(starknet.poseidonHashFunc(new Uint8Array(32).fill(255), new Uint8Array(32).fill(255))),
    '05fd546b5ee3bcbbcbb733ed90bfc33033169d6765ac37bba71794a11cbb51a6'
  );
  deepStrictEqual(
    hex(starknet.poseidonHashFunc(new Uint8Array(64).fill(255), new Uint8Array(64).fill(255))),
    '07dba6b4d94b3e32697afe0825d6dac2dccafd439f7806a9575693c93735596b'
  );
  deepStrictEqual(
    hex(starknet.poseidonHashFunc(new Uint8Array(256).fill(255), new Uint8Array(256).fill(255))),
    '02f048581901865201dad701a5653d946b961748ec770fc11139aa7c06a9432a'
  );
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
