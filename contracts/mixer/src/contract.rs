use ark_bn254::Bn254;
use ark_ed_on_bn254::{EdwardsParameters as JubjubParameters, Fq};
use ark_ff::PrimeField;
use cosmwasm_std::{
    attr, from_binary, to_binary, BankMsg, Binary, Coin, CosmosMsg, Deps, DepsMut, Env,
    HandleResponse, HumanAddr, InitResponse, MessageInfo, MigrateResponse, StdError, StdResult,
    WasmMsg,
};
use cw2::set_contract_version;
use plonk_gadgets::add_public_input_variable;

use plonk_circuits::utils::get_public_bytes;
use protocol_cosmwasm::error::ContractError;
use protocol_cosmwasm::keccak::Keccak256;
use protocol_cosmwasm::mixer::{
    ConfigResponse, Cw20HookMsg, DepositMsg, HandleMsg, InitMsg, MerkleRootResponse,
    MerkleTreeInfoResponse, MigrateMsg, QueryMsg, WithdrawMsg,
};
use protocol_cosmwasm::mixer_verifier::MixerVerifier;
use protocol_cosmwasm::poseidon::Poseidon;
use protocol_cosmwasm::utils::{checked_sub, element_encoder, truncate_and_pad};
use protocol_cosmwasm::zeroes::zeroes;

use cw20::{Cw20HandleMsg, Cw20ReceiveMsg};

use crate::state::{
    mixer_read, mixer_write, nullifier_read, nullifier_write, read_root, save_root, save_subtree,
    MerkleTree, Mixer,
};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:cosmwasm-mixer";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

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

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    // Initialize the "Mixer"
    let merkle_tree: MerkleTree = MerkleTree {
        levels: msg.merkletree_levels,
        current_root_index: 0,
        next_index: 0,
    };
    let native_token_denom = msg.native_token_denom;
    let cw20_address = msg.cw20_address.map(HumanAddr);
    if native_token_denom.is_some() && cw20_address.is_some() {
        return Err(ContractError::Std(StdError::GenericErr {
            msg: "Both the native_token_denom and cw20_address cannot be set at the same time"
                .to_string(),
        }));
    }
    if native_token_denom.is_none() && cw20_address.is_none() {
        return Err(ContractError::Std(StdError::GenericErr {
            msg: "Both the native_token_denom and cw20_address cannot be empty at the same time"
                .to_string(),
        }));
    }
    let deposit_size = msg.deposit_size;

    let mixer: Mixer = Mixer {
        cw20_address,
        native_token_denom,
        deposit_size,
        merkle_tree,
    };
    mixer_write(deps.storage, &mixer)?;

    for i in 0..msg.merkletree_levels {
        save_subtree(deps.storage, i as u32, &zeroes(i))?;
    }

    save_root(deps.storage, 0_u32, &zeroes(msg.merkletree_levels))?;

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
        // Deposit the "native" tokens with commitment
        HandleMsg::Deposit(msg) => deposit_native(deps, info, msg),
        // Withdraw either "native" tokens or cw20 tokens.
        HandleMsg::Withdraw(msg) => withdraw(deps, env, info, msg),
        // Deposit the cw20 tokens with commitment
        HandleMsg::Receive(msg) => receive_cw20(deps, info, msg),
    }
}

pub fn deposit_native(
    deps: DepsMut,
    info: MessageInfo,
    msg: DepositMsg,
) -> Result<HandleResponse, ContractError> {
    let mixer = mixer_read(deps.storage)?;

    // Validations
    if mixer.native_token_denom.is_none() {
        return Err(ContractError::Std(StdError::GenericErr {
            msg: "This mixer is for native tokens".to_string(),
        }));
    }
    let native_token_denom = mixer.native_token_denom.unwrap();
    let sent_tokens: Vec<Coin> = info
        .sent_funds
        .into_iter()
        .filter(|x| x.denom == native_token_denom)
        .collect();
    if sent_tokens.is_empty() || sent_tokens[0].amount < mixer.deposit_size {
        return Err(ContractError::InsufficientFunds {});
    }

    // Handle the "deposit"
    if let Some(commitment) = msg.commitment {
        let commitment_bytes = element_encoder(commitment.as_slice());
        let mut merkle_tree = mixer.merkle_tree;
        let poseidon = Poseidon::new();
        // insert commitment into merke_tree
        let inserted_index = merkle_tree.insert(poseidon, commitment_bytes, deps.storage)?;
        mixer_write(
            deps.storage,
            &Mixer {
                native_token_denom: Some(native_token_denom),
                cw20_address: mixer.cw20_address,
                deposit_size: mixer.deposit_size,
                merkle_tree,
            },
        )?;
        return Ok(HandleResponse {
            data: None,
            messages: vec![],
            attributes: vec![
                attr("action", "deposit_native"),
                attr("inserted_index", inserted_index.to_string()),
                attr("commitment", commitment.to_base64()),
            ],
        });
    }

    Err(ContractError::Std(StdError::NotFound {
        kind: "Commitment".to_string(),
    }))
}

pub fn receive_cw20(
    deps: DepsMut,
    info: MessageInfo,
    cw20_msg: Cw20ReceiveMsg,
) -> Result<HandleResponse, ContractError> {
    let mixer = mixer_read(deps.storage)?;

    // Validations
    if mixer.cw20_address.is_none() {
        return Err(ContractError::Std(StdError::GenericErr {
            msg: "This mixer is for cw20 token".to_string(),
        }));
    }
    let cw20_address = mixer.cw20_address.unwrap();
    if cw20_address.ne(&info.sender) {
        return Err(ContractError::Unauthorized {});
    }

    let sent_cw20_token_amt = cw20_msg.amount;
    if sent_cw20_token_amt < mixer.deposit_size {
        return Err(ContractError::InsufficientFunds {});
    }

    match from_binary(&cw20_msg.msg.unwrap_or_default()) {
        Ok(Cw20HookMsg::DepositCw20 { commitment }) => {
            // Handle the "deposit"
            if let Some(commitment) = commitment {
                let mut merkle_tree = mixer.merkle_tree;
                let commitment_bytes = element_encoder(commitment.as_slice());
                let poseidon = Poseidon::new();
                let inserted_index = merkle_tree
                    .insert(poseidon, commitment_bytes, deps.storage)
                    .map_err(|_| ContractError::MerkleTreeIsFull)?;

                mixer_write(
                    deps.storage,
                    &Mixer {
                        native_token_denom: mixer.native_token_denom,
                        cw20_address: Some(cw20_address),
                        deposit_size: mixer.deposit_size,
                        merkle_tree,
                    },
                )?;

                return Ok(HandleResponse {
                    data: None,
                    messages: vec![],
                    attributes: vec![
                        attr("action", "deposit_cw20"),
                        attr("inserted_index", inserted_index.to_string()),
                        attr("commitment", commitment.to_base64()),
                    ],
                });
            }
            Err(ContractError::Std(StdError::NotFound {
                kind: "Commitment".to_string(),
            }))
        }
        Err(_) => Err(ContractError::Std(StdError::generic_err(
            "invalid cw20 hook msg",
        ))),
    }
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
    let proof_bytes_vec = msg.proof_bytes.to_vec();

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

    if nullifier_read(deps.storage, &nullifier_hash_bytes).is_ok() {
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
    let arbitrary_input =
        Keccak256::hash(&arbitrary_data_bytes).map_err(|_| ContractError::HashError)?;

    // Join the public input bytes
    let public_bytes = get_public_bytes::<Bn254, JubjubParameters, _>(&mut |c| {
        Ok({
            // Public Inputs
            add_public_input_variable(c, Fq::from_le_bytes_mod_order(&nullifier_hash_bytes));
            add_public_input_variable(c, Fq::from_le_bytes_mod_order(&root_bytes));
            add_public_input_variable(c, Fq::from_le_bytes_mod_order(&arbitrary_input));
        })
    })
    .map_err(|_| ContractError::InvalidArbitraryData)?;

    // Verify the proof
    let verifier = MixerVerifier::new();
    let result = verify(verifier, public_bytes, proof_bytes_vec)?;

    if !result {
        return Err(ContractError::Std(StdError::GenericErr {
            msg: "Invalid withdraw proof".to_string(),
        }));
    }

    // Set used nullifier to true after successful verification
    nullifier_write(
        deps.storage,
        &element_encoder(msg.nullifier_hash.as_slice()),
    )?;

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

    // If the "cw20_address" is set, then send the Cw20 tokens.
    // Otherwise, send the native tokens.
    if let Some(cw20_address) = msg.cw20_address {
        // Validate the "cw20_address".
        if mixer.cw20_address.unwrap() != cw20_address {
            return Err(ContractError::Std(StdError::GenericErr {
                msg: "Invalid cw20 address".to_string(),
            }));
        }
        if !amt_to_recipient.is_zero() {
            msgs.push(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: cw20_address.clone(),
                send: [].to_vec(),
                msg: to_binary(&Cw20HandleMsg::Transfer {
                    recipient: recipient.clone(),
                    amount: amt_to_recipient,
                })?,
            }));
        }

        if !fee.is_zero() {
            msgs.push(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: cw20_address,
                send: [].to_vec(),
                msg: to_binary(&Cw20HandleMsg::Transfer {
                    recipient: relayer,
                    amount: fee,
                })?,
            }));
        }
    } else {
        let native_token_denom = mixer.native_token_denom.unwrap();
        if !amt_to_recipient.is_zero() {
            msgs.push(CosmosMsg::Bank(BankMsg::Send {
                from_address: env.contract.address.clone(),
                to_address: recipient.clone(),
                amount: vec![Coin {
                    denom: native_token_denom.clone(),
                    amount: amt_to_recipient,
                }],
            }));
        }
        if !fee.is_zero() {
            msgs.push(CosmosMsg::Bank(BankMsg::Send {
                from_address: env.contract.address.clone(),
                to_address: relayer,
                amount: vec![Coin {
                    denom: native_token_denom,
                    amount: fee,
                }],
            }));
        }
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

fn verify(
    verifier: MixerVerifier,
    public_bytes: Vec<u8>,
    proof_bytes: Vec<u8>,
) -> Result<bool, ContractError> {
    verifier
        .verify(public_bytes, proof_bytes)
        .map_err(|_| ContractError::VerifyError)
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
    let native_token_denom = match mixer.native_token_denom {
        Some(v) => v,
        None => "".to_string(),
    };
    let cw20_address = match mixer.cw20_address {
        Some(v) => v.to_string(),
        None => "".to_string(),
    };
    let deposit_size = mixer.deposit_size.to_string();
    Ok(ConfigResponse {
        native_token_denom,
        cw20_address,
        deposit_size,
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
    let root = read_root(deps.storage, id)?;
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
