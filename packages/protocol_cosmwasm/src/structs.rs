use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// History length of merkle tree root
pub const ROOT_HISTORY_SIZE: u32 = 100;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct MerkleTreeInfoResponse {
    pub levels: u32,
    pub curr_root_index: u32,
    pub next_index: u32,
}
