import 'dotenv/config';
import * as cosmwasmMixer from './wasm/mixer_js/pkg';
import Cosmos from '@oraichain/cosmosjs';
const message = Cosmos.message;

const cosmos = new Cosmos(process.env.URL, process.env.CHAIN_ID);
const childKey = cosmos.getChildKey(process.env.MNEMONIC);
const sender = cosmos.getAddress(childKey);

const recipient = 'orai1602dkqjvh4s7ryajnz2uwhr8vetrwr8nekpxv5';
const address = 'orai1q0cz7c93e6zfedqkrty24hn0pkksm9ahjalhuu';
for (let i = 0; i < 10; i++) {
  console.log(
    Buffer.from(cosmwasmMixer.gen_note()).toString('base64').replace(/=+$/g, '')
  );
}
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

const getLeaves = async (address: string): Promise<Uint8Array[]> => {
  const { txs } = await cosmos.get(
    `cosmos/tx/v1beta1/txs?events=wasm.contract_address%3d%27${address}%27&events=wasm.action%3d%27deposit_native%27`
  );
  const leaves = txs.map((tx) =>
    Uint8Array.from(tx.body.messages[0].msg.deposit.commitment)
  );
  return leaves;
};

const query = async (
  address: string,
  input: Record<string, any>
): Promise<any> => {
  const url = `/wasm/v1beta1/contract/${address}/smart/${Buffer.from(
    JSON.stringify(input)
  ).toString('base64')}`;
  // console.log(url);
  try {
    const { code, message, data } = await cosmos.get(url);
    if (code) {
      throw new Error(message);
    }
    return data;
  } catch (ex) {
    console.log(ex);
  }
};

const getNote = (index = 0): Uint8Array => {
  return Buffer.from(noteSecrets[index].padEnd(88, '='), 'base64');
};

const getHandleMessage = (contract, msg, sender, amount, funds) => {
  const sent_funds = funds
    ? funds
    : amount
    ? [{ denom: cosmos.bech32MainPrefix, amount }]
    : null;
  const msgSend = new message.cosmwasm.wasm.v1beta1.MsgExecuteContract({
    contract,
    msg,
    sender,
    sent_funds
  });

  const msgSendAny = new message.google.protobuf.Any({
    type_url: '/cosmwasm.wasm.v1beta1.MsgExecuteContract',
    value:
      message.cosmwasm.wasm.v1beta1.MsgExecuteContract.encode(msgSend).finish()
  });

  return new message.cosmos.tx.v1beta1.TxBody({
    messages: [msgSendAny]
  });
};

const handle = async (
  address: string,
  input: Record<string, any>,
  { amount, fees, gas, sent_funds }: any = {}
): Promise<any> => {
  const txBody = getHandleMessage(
    address,
    Buffer.from(JSON.stringify(input)),
    sender,
    amount,
    sent_funds
  );

  try {
    const res = await cosmos.submit(
      childKey,
      txBody,
      'BROADCAST_MODE_BLOCK',
      fees,
      gas
    );
    return res;
  } catch (error) {
    console.log('error: ', error);
  }
};

const getProof = async (
  noteSecret: Uint8Array,
  recipient: string
): Promise<Uint8Array[]> => {
  const commitment_hash = cosmwasmMixer.gen_commitment(noteSecret);
  const leaves = await getLeaves(address);
  const leafIndex = leaves.findIndex((leaf) => compare(leaf, commitment_hash));
  return cosmwasmMixer.gen_zk(noteSecret, leafIndex, leaves, recipient, sender);
};

const runDeposit = async (index = 0) => {
  const noteSecret = getNote(index);
  const commitment_hash = cosmwasmMixer.gen_commitment(noteSecret);

  const { deposit_size } = await query(address, { config: {} });

  const result = await handle(
    address,
    {
      deposit: {
        commitment: Array.from(commitment_hash)
      }
    },
    { amount: deposit_size, gas: 2000000 }
  );

  console.log(result);
};

const runWithdraw = async (recipient: string, index = 0) => {
  const noteSecret = getNote(index);
  const [proof, root_hash, nullifier_hash, commitment_hash] = await getProof(
    noteSecret,
    recipient
  );

  // withdraw to this recipient
  const result = await handle(
    address,
    {
      withdraw: {
        proof_bytes: Array.from(proof),
        root: Array.from(root_hash),
        nullifier_hash: Array.from(nullifier_hash),
        recipient,
        relayer: sender,
        fee: '0',
        refund: '0'
      }
    },
    { gas: 20000000 }
  );

  console.log(result);
};

(async () => {
  // console.log(await getProof(getNote(1), recipient));
  // console.log(await query(address, { merkle_root: { id: 10 } }));
  // await runWithdraw(recipient, 1);
})();
