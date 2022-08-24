declare global {
  namespace NodeJS {
    interface ProcessEnv {
      MNEMONIC: string;
      URL: string;
      RPC_URL: string;
      DENOM: string;
      CHAIN_ID: string;
      PREFIX: string;
    }
  }
}

declare module '@cosmjs/cosmwasm-stargate' {
  class SigningCosmWasmClient {
    address: string;
  }
}

export {};
