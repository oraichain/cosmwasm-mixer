import 'dotenv/config';
import * as cosmwasmMixer from './wasm/mixer_js/pkg';
import * as cosmwasm from '@cosmjs/cosmwasm-stargate';
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';

const address = 'orai1q0cz7c93e6zfedqkrty24hn0pkksm9ahjalhuu';
// for (let i = 0; i < 10; i++) {
//   console.log(Buffer.from(cosmwasmMixer.gen_note()).toString('base64'));
// }
const noteSecrets = [
  'HXoIWMmNaI2btxzOB2B6UY7LIrgN71XIIDNdlyGWU2wZOg9msElhfMBFMGytBemVY1KiXJgVm4JzxkSblgR9zQ==',
  'AvKMZekNDvDyoF3M8uIMiOHXPsvbTcHJx7sdsZdKS2nAMqiO3yAioFKWST1KWvuw5oPDcgIEigg5BKJOX9AYGw==',
  'Lzy9xtlvbIrJ9rS1Q3ZBCr2OdVIcxRCjo0eYc0ZS99zG6gg1lu/KJwpDi7MVU51LBZSf4flRWyQcXMSmj1BzyQ==',
  'kB8/BQlFwLWiBvt7G9iEsga/kXiSEpR3jEiihw4VaLOlmhZ98HqOH2uer2jU4M8sfve0GVLsPu8vzlwgkpkWTQ==',
  's7m+OYB2LAJ10CPAE09thR9HH6DnJhUvvwpTB3T/3wW0FVAbRvUiQVCGbQgJc9iRQxq/upVNDFjXJSXA+IGhRA==',
  '236cb5MBCAfxLmL70aky4S+08zDex2FxP0xRQVbDKKNn2AQeaBd2T+jxirX+6sdnquhe6DY5rMVKtEc64bjEqQ==',
  'TiXmUC84O3I92RgKatFx3QYp6iYX07s78EYE0J5YaWgc1em91u6bVP6/giIuBArftvt/VQexT4yFpRXCvDJW7Q==',
  'xPzvh1grKoYumCb4n9xhqYwKhvmMoRkjxwZikbw4zUoQl71fMEfRbGr7qB4h9Fdu406GVALyM7xoccNYxyJspg==',
  'GkesyRfpUROHh7qPQfleEloQMcliziEKB5dyaE4uJPaMXiSkx1XlasOKUj/+GwmXwW2F3uOE7wlvtugxlbDrGQ==',
  'lLxMwSkeMx9wHpt0a85DH7n+hpm6ElJGetbH7DW+lDVnn1y83ohUosrngWJPSygjzXM5802H2S9Hz9NabQoHyg=='
];

const getClient = async (): Promise<cosmwasm.SigningCosmWasmClient> => {
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(
    process.env.MNEMONIC,
    {
      prefix: process.env.PREFIX
    }
  );
  const accounts = await wallet.getAccounts();

  const client = await cosmwasm.SigningCosmWasmClient.connectWithSigner(
    process.env.RPC_URL,
    wallet
  );

  client.address = accounts[0].address;

  return client;
};

const runDeposit = async (i = 0) => {
  const client = await getClient();
  const noteSecret = Buffer.from(noteSecrets[i], 'base64'); // cosmwasmMixer.gen_note();
  const [proof, root_hash, nullifier_hash, commitment_hash] =
    cosmwasmMixer.prepare_wasm_utils_zk_circuit(
      noteSecret,
      [],
      address,
      client.address
    );

  // console.log(
  //   Buffer.from(root_hash).toString('hex'),
  //   Buffer.from(nullifier_hash).toString('hex'),
  //   Buffer.from(commitment_hash).toString('hex')
  // );
  const commitment = Array.from(commitment_hash);
  console.log(commitment);

  // const result = await client.execute(client.address, address, {
  //   deposit: {
  //     commitment
  //   }
  // });

  // console.log(result);
};

const runQuery = async () => {
  const client = await getClient();

  const data = await client.queryContractSmart(address, { config: {} });

  console.log(client.address, data);
};

runQuery();
// runDeposit();
