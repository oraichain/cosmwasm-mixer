use ark_bn254::Bn254;
use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
use ark_ff::PrimeField;
use cosmwasm_std::{
    attr, to_binary, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env, HandleResponse,
    InitResponse, MessageInfo, MigrateResponse, StdError, StdResult,
};
use plonk_gadgets::add_public_input_variable;

use plonk_circuits::utils::get_public_bytes;
use protocol_cosmwasm::error::ContractError;
use protocol_cosmwasm::mixer::{
    ConfigResponse, DepositMsg, HandleMsg, InitMsg, MerkleRootResponse, MerkleTreeInfoResponse,
    MigrateMsg, QueryMsg, WithdrawMsg,
};
use protocol_cosmwasm::mixer_verifier::MixerVerifier;
use protocol_cosmwasm::poseidon::Poseidon;
use protocol_cosmwasm::utils::{checked_sub, element_encoder, truncate_and_pad};
use protocol_cosmwasm::zeroes::zeroes;

use crate::state::{
    mixer_read, mixer_write, nullifier_read, nullifier_write, read_root, save_root, save_subtree,
    MerkleTree, Mixer,
};

pub fn init(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InitMsg,
) -> Result<InitResponse, ContractError> {
    // Validation 1. Check if the funds are sent with this message
    if !info.sent_funds.is_empty() {
        return Err(ContractError::UnnecessaryFunds {});
    }

    // Initialize the "Mixer"
    let merkle_tree: MerkleTree = MerkleTree {
        levels: msg.merkletree_levels,
        current_root_index: 0,
        next_index: 0,
    };
    let native_token_denom = msg.native_token_denom;

    let deposit_size = msg.deposit_size;

    let mixer: Mixer = Mixer {
        native_token_denom,
        deposit_size,
        merkle_tree,
    };
    mixer_write(deps.storage, &mixer)?;

    for i in 0..msg.merkletree_levels {
        save_subtree(deps.storage, i as u32, &zeroes(i));
    }

    save_root(deps.storage, 0_u32, &zeroes(msg.merkletree_levels));

    Ok(InitResponse {
        attributes: vec![attr("action", "instantiate"), attr("owner", info.sender)],
        messages: vec![],
    })
}

pub fn handle(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: HandleMsg,
) -> Result<HandleResponse, ContractError> {
    match msg {
        HandleMsg::Deposit(msg) => deposit(deps, info, msg),
        HandleMsg::Withdraw(msg) => withdraw(deps, env, info, msg),
    }
}

pub fn deposit(
    deps: DepsMut,
    info: MessageInfo,
    msg: DepositMsg,
) -> Result<HandleResponse, ContractError> {
    let mut mixer = mixer_read(deps.storage)?;

    let sent_tokens: Vec<Coin> = info
        .sent_funds
        .into_iter()
        .filter(|x| x.denom == mixer.native_token_denom)
        .collect();
    if sent_tokens.is_empty() || sent_tokens[0].amount < mixer.deposit_size {
        return Err(ContractError::InsufficientFunds {});
    }

    // Handle the "deposit"
    if let Some(commitment) = msg.commitment {
        let commitment_bytes = element_encoder(commitment.as_slice());

        let poseidon = Poseidon::new();
        // insert commitment into merke_tree
        let inserted_index = mixer
            .merkle_tree
            .insert(&poseidon, commitment_bytes, deps.storage)?;
        // update mixer
        mixer_write(deps.storage, &mixer)?;
        return Ok(HandleResponse {
            data: None,
            messages: vec![],
            attributes: vec![
                attr("action", "deposit"),
                attr("inserted_index", inserted_index.to_string()),
                attr("commitment", commitment.to_base64()),
            ],
        });
    }

    Err(ContractError::Std(StdError::NotFound {
        kind: "Commitment".to_string(),
    }))
}

pub fn withdraw(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: WithdrawMsg,
) -> Result<HandleResponse, ContractError> {
    let recipient = msg.recipient;
    let relayer = msg.relayer;
    let fee = msg.fee;
    let refund = msg.refund;
    let root_bytes = element_encoder(msg.root.as_slice());
    let nullifier_hash_bytes = element_encoder(msg.nullifier_hash.as_slice());

    let mixer = mixer_read(deps.storage)?;

    // Validations
    let sent_funds = info.sent_funds;
    if !refund.is_zero() && (sent_funds.len() != 1 || sent_funds[0].amount != refund) {
        return Err(ContractError::Std(StdError::GenericErr {
            msg: "Sent insufficent refund".to_string(),
        }));
    }

    let merkle_tree = mixer.merkle_tree;
    if !merkle_tree.is_known_root(root_bytes, deps.storage) {
        return Err(ContractError::Std(StdError::GenericErr {
            msg: "Root is not known".to_string(),
        }));
    }

    if nullifier_read(deps.storage, &nullifier_hash_bytes) {
        return Err(ContractError::Std(StdError::GenericErr {
            msg: "Nullifier is known".to_string(),
        }));
    }

    // Format the public input bytes
    let recipient_bytes = truncate_and_pad(recipient.as_bytes());
    let relayer_bytes = truncate_and_pad(relayer.as_bytes());

    let mut arbitrary_data_bytes = Vec::new();
    arbitrary_data_bytes.extend_from_slice(&recipient_bytes);
    arbitrary_data_bytes.extend_from_slice(&relayer_bytes);
    arbitrary_data_bytes.extend_from_slice(&fee.u128().to_le_bytes());
    arbitrary_data_bytes.extend_from_slice(&refund.u128().to_le_bytes());

    // Join the public input bytes
    let public_bytes = get_public_bytes::<Bn254, JubjubParameters, _>(&mut |c| {
        Ok({
            // Public Inputs
            add_public_input_variable(c, Fq::from_le_bytes_mod_order(&nullifier_hash_bytes));
            add_public_input_variable(c, Fq::from_le_bytes_mod_order(&root_bytes));
            add_public_input_variable(c, Fq::from_le_bytes_mod_order(&arbitrary_data_bytes));
        })
    })
    .map_err(|_| ContractError::InvalidArbitraryData)?;

    // Verify the proof
    let verifier = MixerVerifier::new();
    let result = verifier
        .verify(public_bytes, msg.proof_bytes.to_vec())
        .map_err(|_| ContractError::VerifyError)?;

    if !result {
        return Err(ContractError::Std(StdError::GenericErr {
            msg: "Invalid withdraw proof".to_string(),
        }));
    }

    // Set used nullifier to true after successful verification
    nullifier_write(
        deps.storage,
        &element_encoder(msg.nullifier_hash.as_slice()),
    );

    // Send the funds
    let mut msgs: Vec<CosmosMsg> = vec![];

    // Send the funds to "recipient"
    let amt_to_recipient = match checked_sub(mixer.deposit_size, fee) {
        Ok(v) => v,
        Err(e) => {
            return Err(ContractError::Std(StdError::GenericErr {
                msg: e.to_string(),
            }))
        }
    };

    if !amt_to_recipient.is_zero() {
        msgs.push(CosmosMsg::Bank(BankMsg::Send {
            from_address: env.contract.address.clone(),
            to_address: recipient.clone(),
            amount: vec![Coin {
                denom: mixer.native_token_denom.clone(),
                amount: amt_to_recipient,
            }],
        }));
    }
    if !fee.is_zero() {
        msgs.push(CosmosMsg::Bank(BankMsg::Send {
            from_address: env.contract.address.clone(),
            to_address: relayer,
            amount: vec![Coin {
                denom: mixer.native_token_denom,
                amount: fee,
            }],
        }));
    }

    if !refund.is_zero() {
        msgs.push(CosmosMsg::Bank(BankMsg::Send {
            from_address: env.contract.address.clone(),
            to_address: recipient.clone(),
            amount: sent_funds,
        }));
    }

    Ok(HandleResponse {
        messages: msgs,
        data: None,
        attributes: vec![
            attr("action", "withdraw"),
            attr("recipient", recipient),
            attr("root", msg.root.to_base64()),
            attr("nullifier_hash", msg.nullifier_hash.to_base64()),
        ],
    })
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&get_config(deps)?),
        QueryMsg::MerkleTreeInfo {} => to_binary(&get_merkle_tree_info(deps)?),
        QueryMsg::MerkleRoot { id } => to_binary(&get_merkle_root(deps, id)?),
    }
}

fn get_config(deps: Deps) -> StdResult<ConfigResponse> {
    let mixer = mixer_read(deps.storage)?;
    Ok(ConfigResponse {
        native_token_denom: mixer.native_token_denom,
        deposit_size: mixer.deposit_size.to_string(),
    })
}

fn get_merkle_tree_info(deps: Deps) -> StdResult<MerkleTreeInfoResponse> {
    let mixer = mixer_read(deps.storage)?;
    Ok(MerkleTreeInfoResponse {
        levels: mixer.merkle_tree.levels,
        current_root_index: mixer.merkle_tree.current_root_index,
        next_index: mixer.merkle_tree.next_index,
    })
}

fn get_merkle_root(deps: Deps, id: u32) -> StdResult<MerkleRootResponse> {
    let root = read_root(deps.storage, id);
    let root_binary = Binary::from(root.as_slice());
    Ok(MerkleRootResponse { root: root_binary })
}

pub fn migrate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: MigrateMsg,
) -> StdResult<MigrateResponse> {
    Ok(MigrateResponse::default())
}
