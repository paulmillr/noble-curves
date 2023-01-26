import { deepStrictEqual, throws } from 'assert';
import { describe, should } from 'micro-should';
import * as starknet from '../../lib/esm/stark.js';
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

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
