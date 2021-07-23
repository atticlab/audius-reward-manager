use super::UNINITIALIZED_VERSION;
use crate::PROGRAM_VERSION;
use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{program_pack::IsInitialized, pubkey::Pubkey};

/// Reward manager
#[derive(BorshSerialize, BorshDeserialize, PartialEq, Debug, Clone)]
pub struct RewardManager {
    /// Version
    pub version: u8,
    /// Token account for rewards to be sent via this program
    pub token_account: Pubkey,
    /// Account authorized managing this Reward Manager (adding/removing signers, updating params etc.)
    pub manager: Pubkey,
    /// Number of signer votes required for sending rewards
    pub min_votes: u8,
}

impl RewardManager {
    /// The struct size on bytes
    pub const LEN: usize = 66;

    /// Creates new `RewardManager`
    pub fn new(token_account: Pubkey, manager: Pubkey, min_votes: u8) -> Self {
        Self {
            version: PROGRAM_VERSION,
            token_account,
            manager,
            min_votes,
        }
    }
}

impl IsInitialized for RewardManager {
    fn is_initialized(&self) -> bool {
        self.version != UNINITIALIZED_VERSION
    }
}
