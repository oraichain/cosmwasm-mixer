use cosmwasm_std::StdError;
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum OverflowOperation {
    Add,
    Sub,
    Mul,
    Pow,
    Shr,
    Shl,
}

impl fmt::Display for OverflowOperation {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
#[error("Cannot {operation} with {operand1} and {operand2}")]
pub struct OverflowError {
    pub operation: OverflowOperation,
    pub operand1: String,
    pub operand2: String,
}

impl OverflowError {
    pub fn new(
        operation: OverflowOperation,
        operand1: impl ToString,
        operand2: impl ToString,
    ) -> Self {
        Self {
            operation,
            operand1: operand1.to_string(),
            operand2: operand2.to_string(),
        }
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Unnecessary_funds")]
    UnnecessaryFunds {},

    #[error("Insufficient_funds")]
    InsufficientFunds {},
    // Add any other custom errors you like here.
    // Look at https://docs.rs/thiserror/1.0.21/thiserror/ for details.
    #[error("Invalid Cw20 Hook message")]
    InvalidCw20HookMsg,

    /* -------   mixer related error  ------- */
    /// Returned if the mixer is not initialized
    #[error("NotInitialized")]
    NotInitialized,
    /// Returned if the mixer is already initialized
    #[error("AlreadyInitialized")]
    AlreadyInitialized,
    /// Returned if the merkle tree is full.
    #[error("FullMerkleTree")]
    MerkleTreeIsFull,
    /// Hash error
    #[error("HashError")]
    HashError,
    /// Verify error
    #[error("VerifyError")]
    VerifyError,
    // Failing to decode a hex string
    #[error("DecodeError")]
    DecodeError,

    // Returned if a mapping item is not found
    #[error("Mapping item not found")]
    ItemNotFound,

    #[error("Invalid merkle roots")]
    InvaidMerkleRoots,

    #[error("Unknown root")]
    UnknownRoot,

    #[error("Invalid withdraw proof")]
    InvalidWithdrawProof,

    #[error("Invalid arbitrary data passed")]
    InvalidArbitraryData,

    #[error("Invalid nullifier that is already used")]
    AlreadyRevealedNullfier,

    #[error("Edge already exists")]
    EdgeAlreadyExists,

    #[error("Too many edges")]
    TooManyEdges,

    #[error("Nonce must be greater than current nonce. Nonce must not increment more than 1048")]
    InvalidNonce,

    /*  ------ TokenWrapper errors ------ */
    // For simplicity, it just converts all the cw20_base errors to Std error.
    #[error("Invalid CW20 token address")]
    InvalidCw20Token,
}

impl From<cw20_base::ContractError> for ContractError {
    fn from(err: cw20_base::ContractError) -> Self {
        match err {
            cw20_base::ContractError::Std(error) => ContractError::Std(error),
            cw20_base::ContractError::Unauthorized {}
            | cw20_base::ContractError::CannotSetOwnAccount {}
            | cw20_base::ContractError::InvalidZeroAmount {}
            | cw20_base::ContractError::Expired {}
            | cw20_base::ContractError::NoAllowance {}
            | cw20_base::ContractError::CannotExceedCap {} => {
                ContractError::Std(StdError::generic_err(err.to_string()))
            }
        }
    }
}
