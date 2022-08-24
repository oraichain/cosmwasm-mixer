const cosmwasmMixer = require('./pkg');

const noteSecret = Buffer.from(
  'lBk8zxOWE/eW50yNUAlylApekrmOC6oAdPDWc33AshIBjziLYEyNHe0bAwMSctJc88WgcIAlPAmwAiYvE/jyHQ==',
  'base64'
); // cosmwasmMixer.gen_note();
const [proof, root_hash, nullifier_hash, commitment_hash] =
  cosmwasmMixer.prepare_wasm_utils_zk_circuit(
    noteSecret,
    [],
    'orai1kejftqzx05y9rv00lw5m76csfmx7lf9se02dz4',
    'orai1jrj2vh6cstqwk3pg8nkmdf0r9z0n3q3f3jk5xn'
  );

console.log(
  Buffer.from(root_hash).toString('hex'),
  Buffer.from(nullifier_hash).toString('hex'),
  Buffer.from(commitment_hash).toString('hex')
);
