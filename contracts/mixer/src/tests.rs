use ark_bn254::Fr;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use ark_std::One;
use arkworks_setups::Curve;

use cosmwasm_std::testing::{
    mock_dependencies, mock_env, mock_info, MockApi, MockQuerier, MockStorage,
};
use cosmwasm_std::Api;
use cosmwasm_std::Binary;
use cosmwasm_std::{attr, Coin, OwnedDeps, Uint128};

use crate::contract::{execute, instantiate};
use crate::msg::{DepositMsg, ExecuteMsg, InstantiateMsg, WithdrawMsg};
use crate::state::read_root;
use crate::test_util::Element;
use crate::test_util::MERKLE_TREE_LEVELS;
use crate::utils::truncate_and_pad;

const DEPOSIT_SIZE: &str = "1000000";
const NATIVE_TOKEN_DENOM: &str = "orai";

const RECIPIENT: &str = "orai1kejftqzx05y9rv00lw5m76csfmx7lf9se02dz4";
const RELAYER: &str = "orai1jrj2vh6cstqwk3pg8nkmdf0r9z0n3q3f3jk5xn";
const FEE: u128 = 0;
const REFUND: u128 = 0;

fn create_mixer() -> OwnedDeps<MockStorage, MockApi, MockQuerier> {
    let mut deps = mock_dependencies();
    // Initialize the contract
    let env = mock_env();
    let info = mock_info("anyone", &[]);
    let instantiate_msg = InstantiateMsg {
        merkletree_levels: MERKLE_TREE_LEVELS as u32,
        deposit_size: Uint128::try_from(DEPOSIT_SIZE).unwrap(),
        native_token_denom: NATIVE_TOKEN_DENOM.to_string(),
    };

    let _ = instantiate(deps.as_mut(), env, info, instantiate_msg).unwrap();

    deps
}

fn prepare_zk_circuit(
    index: u64,
    curve: Curve,
    relayer: &str,
    fee: u128,
    refund: u128,
) -> (Vec<u8>, Element, Element, Element) {
    let recipient_bytes = RECIPIENT.as_bytes();
    let relayer_bytes = relayer.as_bytes();
    let fee_value = fee;
    let refund_value = refund;

    // Setup zk circuit for withdraw
    crate::test_util::setup_zk_circuit(
        index,
        curve,
        truncate_and_pad(recipient_bytes),
        truncate_and_pad(relayer_bytes),
        fee_value,
        refund_value,
    )
}

#[test]
fn test_mixer_proper_initialization() {
    let mut deps = mock_dependencies();

    let env = mock_env();
    let info = mock_info("anyone", &[]);
    let instantiate_msg = InstantiateMsg {
        merkletree_levels: MERKLE_TREE_LEVELS as u32,
        deposit_size: Uint128::try_from(DEPOSIT_SIZE).unwrap(),
        native_token_denom: NATIVE_TOKEN_DENOM.to_string(),
    };

    // Should pass this "unwrap" if success.
    let response = instantiate(deps.as_mut(), env, info, instantiate_msg).unwrap();

    assert_eq!(
        response.attributes,
        vec![attr("action", "instantiate"), attr("owner", "anyone"),]
    );
}

#[test]
fn test_mixer_should_be_able_to_deposit_native_token() {
    let mut deps = create_mixer();

    // Initialize the mixer
    let res = deps
        .api
        .poseidon_hash(
            &Fr::one().into_repr().to_bytes_le(),
            &Fr::one().into_repr().to_bytes_le(),
            1,
        )
        .unwrap();
    let mut element: [u8; 32] = [0u8; 32];
    element.copy_from_slice(&res);

    let element_bin = Binary::from(element.as_slice());

    // Try the deposit with insufficient fund
    let info = mock_info("depositor", &[Coin::new(1_000_u128, NATIVE_TOKEN_DENOM)]);
    let deposit_msg = DepositMsg {
        commitment: element_bin.clone(),
    };

    let err = execute(
        deps.as_mut(),
        mock_env(),
        info,
        ExecuteMsg::Deposit(deposit_msg),
    )
    .unwrap_err();
    assert_eq!(err.to_string(), "Insufficient_funds".to_string());

    // Try the deposit for success
    let info = mock_info(
        "depositor",
        &[Coin::new(1_000_000_u128, NATIVE_TOKEN_DENOM)],
    );
    let deposit_msg = DepositMsg {
        commitment: element_bin,
    };

    let response = execute(
        deps.as_mut(),
        mock_env(),
        info,
        ExecuteMsg::Deposit(deposit_msg),
    )
    .unwrap();
    assert_eq!(response.events.len(), 1);
}

#[test]
fn test_mixer_should_withdraw_native_token() {
    let mut deps = create_mixer();

    let (proof_bytes, root_element, nullifier_hash_element, leaf_element) =
        prepare_zk_circuit(0, Curve::Bn254, RELAYER, FEE, REFUND);

    let proof_bytes_bin = Binary::from(proof_bytes);
    let root_element_bin = Binary::from(root_element.0.to_vec());
    let nullifier_hash_bin = Binary::from(nullifier_hash_element.0.to_vec());

    // Try the deposit for success
    let info = mock_info("anyone", &[Coin::new(1_000_000_u128, NATIVE_TOKEN_DENOM)]);
    let deposit_msg = DepositMsg {
        commitment: Binary::from(leaf_element.0.to_vec()),
    };

    let response = execute(
        deps.as_mut(),
        mock_env(),
        info,
        ExecuteMsg::Deposit(deposit_msg.clone()),
    )
    .unwrap();
    assert_eq!(response.events.len(), 1);

    let withdraw_msg = WithdrawMsg {
        proof_bytes: proof_bytes_bin,
        root: root_element_bin,
        nullifier_hash: nullifier_hash_bin,
        recipient: RECIPIENT.to_string(),
        relayer: RELAYER.to_string(),
        fee: Uint128::from(FEE),
        refund: Uint128::from(REFUND),
    };
    let info = mock_info("withdraw", &[]);
    let response = execute(
        deps.as_mut(),
        mock_env(),
        info,
        ExecuteMsg::Withdraw(withdraw_msg),
    )
    .unwrap();
    assert_eq!(response.events.len(), 1);
}

#[test]
fn test_mixer_should_fail_when_invalid_merkle_roots() {
    let (proof_bytes, mut root_element, nullifier_hash_element, leaf_element) =
        prepare_zk_circuit(0, Curve::Bn254, RELAYER, FEE, REFUND);

    let proof_bytes_bin = Binary::from(proof_bytes);
    let nullifier_hash_bin = Binary::from(nullifier_hash_element.0.to_vec());

    let mut deps = create_mixer();

    // Try the deposit for success
    let info = mock_info(
        "depositor",
        &[Coin::new(1_000_000_u128, NATIVE_TOKEN_DENOM)],
    );
    let deposit_msg = DepositMsg {
        commitment: Binary::from(leaf_element.0.to_vec()),
    };

    let response = execute(
        deps.as_mut(),
        mock_env(),
        info,
        ExecuteMsg::Deposit(deposit_msg.clone()),
    )
    .unwrap();
    assert_eq!(response.events.len(), 1);
    let on_chain_root = read_root(&deps.storage, 1);
    let local_root = root_element.0;
    assert_eq!(on_chain_root, local_root);

    // Invalid root_element leads to failure.
    root_element.0[0] = 0;
    let root_element_bin = Binary::from(root_element.0.to_vec());

    let withdraw_msg = WithdrawMsg {
        proof_bytes: proof_bytes_bin,
        root: root_element_bin,
        nullifier_hash: nullifier_hash_bin,
        recipient: RECIPIENT.to_string(),
        relayer: RELAYER.to_string(),
        fee: Uint128::from(FEE),
        refund: Uint128::from(REFUND),
    };
    let info = mock_info("withdraw", &[]);
    let err = execute(
        deps.as_mut(),
        mock_env(),
        info,
        ExecuteMsg::Withdraw(withdraw_msg),
    )
    .unwrap_err();
    assert_eq!(
        err.to_string(),
        "Generic error: Root is not known".to_string()
    );
}
