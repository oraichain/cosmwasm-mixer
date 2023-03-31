<h1 align="center">CosmWasm Mixer</h1>

## Introduction

This repository contains the Cosmwasm implementation of **Webb Protocol**, which would be used for _Cosmos SDK_ blockchains.

## Contracts layout

```
contracts/
    |___mixer/                        # Mixer contract
wasm/
    |___mixer_js/                     # Mixer wasmjs
```

## Building the contracts(wasm)

### Building

To build the contract, run the following command.

```
yarn build
```

generate mixer js:

```
yarn build-wasm --target nodejs
```

## Testing

Run the following command to run the unit tests.

```bash
yarn test test_mixer_should_be_able_to_deposit_native_token --release
#testing mixer_js
cargo test --release --package cosmwasm-mixer-js --lib --target wasm32-unknown-unknown -- tests::test_zk
```

## License

<sup>
Licensed under <a href="LICENSE">Apache License 2.0</a>.
</sup>

<br/>
