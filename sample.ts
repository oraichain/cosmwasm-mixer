import 'dotenv/config';
import * as cosmwasmMixer from './wasm/mixer_js/pkg';
import axios from 'axios';
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';
import * as cosmwasm from '@cosmjs/cosmwasm-stargate';
import { Decimal } from '@cosmjs/math';
import { GasPrice } from '@cosmjs/stargate';

let prefix = process.env.PREFIX;
let denom = process.env.DENOM;

const recipient = 'orai1602dkqjvh4s7ryajnz2uwhr8vetrwr8nekpxv5';
const contract_address =
  'orai1qxd52frq6jnd73nsw49jzp4xccal3g9v47pxwftzqy78ww02p75s62e94t';
// for (let i = 0; i < 10; i++) {
//   console.log(
//     Buffer.from(cosmwasmMixer.gen_note()).toString('base64').replace(/=+$/g, '')
//   );
// }
const noteSecrets = [
  'HXoIWMmNaI2btxzOB2B6UY7LIrgN71XIIDNdlyGWU2wZOg9msElhfMBFMGytBemVY1KiXJgVm4JzxkSblgR9zQ',
  'AvKMZekNDvDyoF3M8uIMiOHXPsvbTcHJx7sdsZdKS2nAMqiO3yAioFKWST1KWvuw5oPDcgIEigg5BKJOX9AYGw',
  'Lzy9xtlvbIrJ9rS1Q3ZBCr2OdVIcxRCjo0eYc0ZS99zG6gg1lu/KJwpDi7MVU51LBZSf4flRWyQcXMSmj1BzyQ',
  'kB8/BQlFwLWiBvt7G9iEsga/kXiSEpR3jEiihw4VaLOlmhZ98HqOH2uer2jU4M8sfve0GVLsPu8vzlwgkpkWTQ',
  's7m+OYB2LAJ10CPAE09thR9HH6DnJhUvvwpTB3T/3wW0FVAbRvUiQVCGbQgJc9iRQxq/upVNDFjXJSXA+IGhRA',
  '236cb5MBCAfxLmL70aky4S+08zDex2FxP0xRQVbDKKNn2AQeaBd2T+jxirX+6sdnquhe6DY5rMVKtEc64bjEqQ',
  'TiXmUC84O3I92RgKatFx3QYp6iYX07s78EYE0J5YaWgc1em91u6bVP6/giIuBArftvt/VQexT4yFpRXCvDJW7Q',
  'xPzvh1grKoYumCb4n9xhqYwKhvmMoRkjxwZikbw4zUoQl71fMEfRbGr7qB4h9Fdu406GVALyM7xoccNYxyJspg',
  'GkesyRfpUROHh7qPQfleEloQMcliziEKB5dyaE4uJPaMXiSkx1XlasOKUj/+GwmXwW2F3uOE7wlvtugxlbDrGQ',
  'lLxMwSkeMx9wHpt0a85DH7n+hpm6ElJGetbH7DW+lDVnn1y83ohUosrngWJPSygjzXM5802H2S9Hz9NabQoHyg'
];

function compare(a, b) {
  for (let i = a.length; -1 < i; i -= 1) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

let leaves = undefined;
const getLeaves = async (address: string): Promise<Uint8Array[]> => {
  if (!leaves) {
    const res = await axios.get(
      `${process.env.URL}/cosmos/tx/v1beta1/txs?events=wasm-mixer-deposit._contract_address%3d%27${address}%27`
    );
    leaves = res.data.txs.map((tx: any) =>
      Buffer.from(tx.body.messages[0].msg.deposit.commitment, 'base64')
    );
  }
  return leaves;
};

const query = async (
  client: cosmwasm.SigningCosmWasmClient,
  address: string,
  input: Record<string, any>
): Promise<any> => {
  try {
    const res = await client.queryContractSmart(address, input);

    return res;
  } catch (ex) {
    console.log(ex);
  }
};

const getNote = (index = 0): Buffer => {
  return Buffer.from(noteSecrets[index].padEnd(88, '='), 'base64');
};

const getProof = async (
  sender: string,
  noteSecret: Uint8Array,
  recipient: string
): Promise<Uint8Array[]> => {
  const commitment_hash = cosmwasmMixer.gen_commitment(noteSecret);
  const leaves = await getLeaves(contract_address);
  const leafIndex = leaves.findIndex((leaf) => compare(leaf, commitment_hash));
  return cosmwasmMixer.gen_zk(noteSecret, leafIndex, leaves, recipient, sender);
};

const runDeposit = async (
  client: cosmwasm.SigningCosmWasmClient,
  sender: string,
  index = 0
) => {
  const noteSecret = getNote(index);
  const commitment_hash = cosmwasmMixer.gen_commitment(noteSecret);

  const { deposit_size } = await query(client, contract_address, {
    config: {}
  });

  const result = await client.execute(
    sender,
    contract_address,
    {
      deposit: {
        commitment: Buffer.from(commitment_hash).toString('base64')
      }
    },
    'auto',
    undefined,
    [{ amount: deposit_size, denom }]
  );

  console.log(JSON.stringify(result));
};

const runWithdraw = async (
  client: cosmwasm.SigningCosmWasmClient,
  sender: string,
  recipient: string,
  index = 0
) => {
  const noteSecret = getNote(index);
  const [proof, root_hash, nullifier_hash] = await getProof(
    sender,
    noteSecret,
    recipient
  );

  // withdraw to this recipient
  const result = await client.execute(
    sender,
    contract_address,
    {
      withdraw: {
        proof_bytes: Buffer.from(proof).toString('base64'),
        root: Buffer.from(root_hash).toString('base64'),
        nullifier_hash: Buffer.from(nullifier_hash).toString('base64'),
        recipient,
        relayer: sender,
        fee: '0',
        refund: '0'
      }
    },
    'auto'
  );

  console.log(JSON.stringify(result));
};

(async () => {
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(
    process.env.MNEMONIC,
    {
      prefix
    }
  );
  const [firstAccount] = await wallet.getAccounts();
  const client = await cosmwasm.SigningCosmWasmClient.connectWithSigner(
    process.env.RPC_URL,
    wallet,
    {
      gasPrice: new GasPrice(Decimal.fromUserInput('0', 6), denom),
      prefix
    }
  );

  // should get leaves from relayer or contract logs
  // leaves = noteSecrets
  //   .map((secret) => Buffer.from(secret.padEnd(88, '='), 'base64'))
  //   .map((noteSecret) => cosmwasmMixer.gen_commitment(noteSecret));

  for (let i = 0; i < 10; i++) {
    await runDeposit(client, firstAccount.address, i);
  }

  await runWithdraw(client, firstAccount.address, recipient, 0);

  // for (let i = 0; i < 10; i++) {
  //   await runWithdraw(client, firstAccount.address, recipient, i);
  // }
})();
