import {writeFileSync} from 'node:fs';
import {ssz as phase0} from '@lodestar/types/phase0';
import {ssz as fulu} from '@lodestar/types/fulu';
import {createProof, ProofType} from '@chainsafe/persistent-merkle-tree';

const hex = (bytes) => `0x${Buffer.from(bytes).toString('hex')}`;
const ssz = {phase0, fulu};
const vectors = [];
for (const fork of ['phase0', 'fulu']) {
  const type = ssz[fork].BeaconState;
  const value = type.defaultValue();
  value.slot = 123;
  for (let i = 0; i < 9; i++) {
    const validator = ssz.phase0.Validator.defaultValue();
    validator.pubkey = Uint8Array.from({length: 48}, (_, j) => (i * 13 + j) % 256);
    validator.withdrawalCredentials = new Uint8Array(32).fill(i + 1);
    validator.effectiveBalance = 32_000_000_000 + i;
    validator.slashed = i % 2 === 0;
    validator.activationEligibilityEpoch = i;
    validator.activationEpoch = i + 1;
    validator.exitEpoch = i + 2;
    validator.withdrawableEpoch = i + 3;
    value.validators.push(validator);
    value.balances.push(42 + i * 100);
  }
  if (fork === 'fulu') {
    value.previousEpochParticipation = Array(9).fill(0);
    value.currentEpochParticipation = Array(9).fill(0);
    value.inactivityScores = Array(9).fill(0);
  }
  const view = type.toViewDU(value);
  view.commit();
  const width = fork === 'phase0' ? 32n : 64n;
  const validators = width + 11n;
  const balances = width + 12n;
  const record = ((validators * 2n) << 40n) + 8n;
  const indices = [1n, width + 2n, validators * 2n, validators * 2n + 1n, balances * 2n + 1n,
    record, record * 2n, ...Array.from({length: 8}, (_, field) => record * 8n + BigInt(field)),
    ...[0n, 1n, 2n].map(chunk => ((balances * 2n) << 38n) + chunk)];
  const root = hex(view.node.root);
  const proofs = indices.map(gindex => {
    const proof = createProof(view.node, {type: ProofType.single, gindex});
    return {gindex: gindex.toString(), leaf: hex(proof.leaf), witnesses: proof.witnesses.map(hex), root};
  });
  vectors.push({fork, state_ssz: hex(type.serialize(value)), proofs});
}
writeFileSync(process.argv[2], `${JSON.stringify(vectors, null, 2)}\n`);
console.log(vectors.map(({fork, state_ssz, proofs}) => ({fork, state_bytes: (state_ssz.length - 2) / 2, proofs: proofs.length})));
