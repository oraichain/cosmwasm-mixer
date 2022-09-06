use ark_bn254::Fr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_std::One;
use arkworks_native_gadgets::poseidon::FieldHasher;
use arkworks_native_gadgets::poseidon::Poseidon;
use arkworks_setups::common::setup_params;
use arkworks_utils::Curve;

use cosmwasm_std::testing::{mock_dependencies, mock_info, MockApi, MockQuerier, MockStorage};
use cosmwasm_std::Binary;
use cosmwasm_std::{
    attr, to_binary, BlockInfo, Coin, ContractInfo, Env, HumanAddr, OwnedDeps, Uint128,
};
use cw20::Cw20ReceiveMsg;

use crate::contract::{handle, init};
use crate::test_util::setup_wasm_utils_zk_circuit;
use protocol_cosmwasm::mixer::{Cw20HookMsg, DepositMsg, HandleMsg, InitMsg, WithdrawMsg};
use protocol_cosmwasm::utils::truncate_and_pad;

const MERKLE_TREE_LEVELS: u32 = 30;
const DEPOSIT_SIZE: &str = "1000000";
const CW20_ADDRESS: &str = "orai1fex9f78reuwhfsnc8sun6mz8rl9zwqh03fhwf3";
const NATIVE_TOKEN_DENOM: &str = "orai";

const CONTRACT_ADDR: &str = "orai1ulgw0td86nvs4wtpsc80thv6xelk76ut7a7apj";
const RECIPIENT: &str = "orai1kejftqzx05y9rv00lw5m76csfmx7lf9se02dz4";
const RELAYER: &str = "orai1jrj2vh6cstqwk3pg8nkmdf0r9z0n3q3f3jk5xn";
const FEE: u128 = 0;
const REFUND: u128 = 0;
const CK_BYTES: &[u8; 4194427] = include_bytes!("../../../bn254/x5/ck_key.bin");

#[derive(Debug, PartialEq)]
pub enum MixerType {
    Native,
    Cw20,
}

fn mock_env() -> Env {
    // Initialize the contract
    Env {
        block: BlockInfo {
            height: 12_345,
            time: 1_571_797_419,
            time_nanos: 879305533,
            chain_id: "Oraichain".to_string(),
        },
        contract: ContractInfo {
            address: HumanAddr::from(CONTRACT_ADDR),
        },
    }
}

fn create_mixer(ty: MixerType) -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
    let mut deps = mock_dependencies(&[]);
    // Initialize the contract
    let env = mock_env();
    let info = mock_info("anyone", &[]);
    let instantiate_msg = InitMsg {
        merkletree_levels: MERKLE_TREE_LEVELS,
        deposit_size: Uint128::try_from(DEPOSIT_SIZE).unwrap(),
        cw20_address: if ty == MixerType::Cw20 {
            Some(CW20_ADDRESS.to_string())
        } else {
            None
        },
        native_token_denom: if ty == MixerType::Native {
            Some(NATIVE_TOKEN_DENOM.to_string())
        } else {
            None
        },
    };

    let _ = init(deps.as_mut(), env, info, instantiate_msg).unwrap();

    deps
}

#[test]
fn test_mixer_proper_initialization() {
    let mut deps = mock_dependencies(&[]);

    let env = mock_env();
    let info = mock_info("anyone", &[]);
    let instantiate_msg = InitMsg {
        merkletree_levels: MERKLE_TREE_LEVELS,
        deposit_size: Uint128::try_from(DEPOSIT_SIZE).unwrap(),
        native_token_denom: Some(NATIVE_TOKEN_DENOM.to_string()),
        cw20_address: None,
    };

    // Should pass this "unwrap" if success.
    let response = init(deps.as_mut(), env, info, instantiate_msg).unwrap();

    assert_eq!(
        response.attributes,
        vec![attr("action", "instantiate"), attr("owner", "anyone"),]
    );
}

#[test]
fn test_mixer_should_be_able_to_deposit_native_token() {
    let mut deps = create_mixer(MixerType::Native);

    // Initialize the mixer
    let params = setup_params(Curve::Bn254, 5, 3);
    let poseidon = Poseidon::new(params);
    let res = poseidon.hash_two(&Fr::one(), &Fr::one()).unwrap();

    let element_bin = Binary::from(res.into_repr().to_bytes_le().as_slice());

    // Try the deposit with insufficient fund
    let info = mock_info("depositor", &[Coin::new(1_000_u128, NATIVE_TOKEN_DENOM)]);
    let deposit_msg = DepositMsg {
        commitment: Some(element_bin.clone()),
    };

    let err = handle(
        deps.as_mut(),
        mock_env(),
        info,
        HandleMsg::Deposit(deposit_msg),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "Insufficient_funds".to_string());

    // Try the deposit with empty commitment
    let info = mock_info(
        "depositor",
        &[Coin::new(1_000_000_u128, NATIVE_TOKEN_DENOM)],
    );
    let deposit_msg = DepositMsg { commitment: None };

    let err = handle(
        deps.as_mut(),
        mock_env(),
        info,
        HandleMsg::Deposit(deposit_msg),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "Commitment not found".to_string());

    // Try the deposit for success
    let info = mock_info(
        "depositor",
        &[Coin::new(1_000_000_u128, NATIVE_TOKEN_DENOM)],
    );
    let deposit_msg = DepositMsg {
        commitment: Some(element_bin),
    };

    let response = handle(
        deps.as_mut(),
        mock_env(),
        info,
        HandleMsg::Deposit(deposit_msg),
    )
    .unwrap();
    assert_eq!(response.attributes.len(), 3);
}

#[test]
fn test_mixer_should_be_able_to_deposit_cw20_token() {
    let mut deps = create_mixer(MixerType::Cw20);

    // Initialize the mixer
    let params = setup_params(Curve::Bn254, 5, 3);
    let poseidon = Poseidon::new(params);
    let res = poseidon.hash_two(&Fr::one(), &Fr::one()).unwrap();

    let element_bin = Binary::from(res.into_repr().to_bytes_le().as_slice());

    // Try the deposit for success
    let info = mock_info(CW20_ADDRESS, &[]);
    let deposit_cw20_msg = HandleMsg::Receive(Cw20ReceiveMsg {
        sender: HumanAddr(CW20_ADDRESS.to_string()),
        amount: Uint128::from(1_000_000_u128),
        msg: to_binary(&Cw20HookMsg::DepositCw20 {
            commitment: Some(element_bin),
        })
        .ok(),
    });

    let response = handle(deps.as_mut(), mock_env(), info, deposit_cw20_msg).unwrap();
    assert_eq!(response.attributes.len(), 3);
}

#[test]
fn test_mixer_should_work_with_wasm_utils() {
    let (proof_bytes, root_bytes, nullifier_hash, commitment_bytes) = setup_wasm_utils_zk_circuit(
        CK_BYTES,
        truncate_and_pad(RECIPIENT.as_bytes()),
        truncate_and_pad(RELAYER.as_bytes()),
        FEE,
        REFUND,
    );

    let mut deps = create_mixer(MixerType::Native);

    // Try the deposit for success
    let info = mock_info(
        "depositor",
        &[Coin::new(1_000_000_u128, NATIVE_TOKEN_DENOM)],
    );
    let deposit_msg = DepositMsg {
        commitment: Some(Binary::from(commitment_bytes.as_slice())),
    };

    let response = handle(
        deps.as_mut(),
        mock_env(),
        info,
        HandleMsg::Deposit(deposit_msg).clone(),
    )
    .unwrap();
    assert_eq!(response.attributes.len(), 3);
    let on_chain_root = crate::state::read_root(&deps.storage, 1).unwrap();
    let local_root = root_bytes.as_slice();

    assert_eq!(on_chain_root, local_root);

    // Should "succeed" to withdraw tokens.
    let withdraw_msg = WithdrawMsg {
        proof_bytes: Binary::from(proof_bytes.as_slice()),
        root: Binary::from(root_bytes.as_slice()),
        nullifier_hash: Binary::from(nullifier_hash.as_slice()),
        recipient: HumanAddr(RECIPIENT.to_string()),
        relayer: HumanAddr(RELAYER.to_string()),
        fee: Uint128::from(FEE),
        refund: Uint128::from(REFUND),
        cw20_address: None,
    };
    let info = mock_info("withdraw", &[]);
    let response = handle(
        deps.as_mut(),
        mock_env(),
        info,
        HandleMsg::Withdraw(withdraw_msg),
    )
    .unwrap();
    assert_eq!(response.attributes.len(), 4);
}
