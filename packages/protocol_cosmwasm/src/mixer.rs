use cosmwasm_std::{Binary, HumanAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct InitMsg {
    pub deposit_size: Uint128,
    pub merkletree_levels: u32,
    pub native_token_denom: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    Deposit(DepositMsg),
    Withdraw(WithdrawMsg),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MigrateMsg {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct DepositMsg {
    pub commitment: Option<Binary>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct WithdrawMsg {
    pub proof_bytes: Binary,
    pub root: Binary,
    pub nullifier_hash: Binary,
    pub recipient: HumanAddr,
    pub relayer: HumanAddr,
    pub fee: Uint128,
    pub refund: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Config {},
    MerkleTreeInfo {},
    MerkleRoot { id: u32 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct ConfigResponse {
    pub native_token_denom: String,
    pub deposit_size: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct MerkleTreeInfoResponse {
    pub levels: u32,
    pub current_root_index: u32,
    pub next_index: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct MerkleRootResponse {
    pub root: Binary,
}
